"""Terminal reporter: rich-styled output for the CLI.

This is the "screenshot moment". The first paragraph of output should be
share-worthy, with a clear count and the most consequential risk indicators
visible without scrolling.
"""
from __future__ import annotations

from rich.console import Console
from rich.markup import escape as rich_escape
from rich.padding import Padding
from rich.rule import Rule
from rich.text import Text

from ..cross_promo import build_upgrade_url, headline_finding, specialists_for_report
from ..frameworks import standards_for_flag
from ..types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_API,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Finding,
    Report,
)

CATEGORY_DISPLAY: dict[str, str] = {
    CATEGORY_LLM_SDK: "LLM SDK CALL SITES",
    CATEGORY_AGENT_FRAMEWORK: "AGENT FRAMEWORKS",
    CATEGORY_MCP_SERVER: "MCP SERVERS",
    CATEGORY_MODEL_GATEWAY: "MODEL GATEWAYS",
    CATEGORY_AI_INFRA: "AI INFRASTRUCTURE",
    CATEGORY_ENV_KEY: "AI PROVIDER API KEYS",
    CATEGORY_API: "API ENDPOINTS",
}

CATEGORY_ORDER: list[str] = [
    CATEGORY_LLM_SDK,
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
    CATEGORY_API,
]

# Rich styles for severity badges. Discovery-only findings (severity None)
# never get a badge; absence of severity is meaningful (inventoried, not
# assessed) so we deliberately render nothing for them.
SEVERITY_STYLE: dict[str, str] = {
    SEVERITY_CRITICAL: "bold white on red",
    SEVERITY_HIGH: "bold red",
    SEVERITY_MEDIUM: "bold yellow",
    SEVERITY_LOW: "cyan",
    SEVERITY_INFO: "dim",
}


def _severity_badge(severity: str | None) -> Text | None:
    """Return a colored severity badge, or None for unaudited findings."""
    if not severity:
        return None
    style = SEVERITY_STYLE.get(severity, "bold")
    return Text(f" [{severity.upper()}] ", style=style)


def render_terminal(
    report: Report,
    console: Console | None = None,
    verbose: bool = False,
) -> None:
    """Render `report` as a rich-styled CLI output.

    Args:
        report: the scan report to render.
        console: optional rich Console (defaults to stdout).
        verbose: when True, shows all files for each finding without truncation.
    """
    if console is None:
        console = Console()

    _render_header(report, console)
    if not report.findings:
        _render_empty(report, console)
        _render_footer(report, console, verbose=verbose)
        return

    _render_summary_line(report, console)

    by_cat = report.by_category()
    for cat in CATEGORY_ORDER:
        if cat in by_cat and by_cat[cat]:
            _render_category(cat, by_cat[cat], console, verbose=verbose)

    # Catch any categories not in CATEGORY_ORDER (forward compatibility)
    for cat, findings in by_cat.items():
        if cat not in CATEGORY_ORDER:
            _render_category(cat, findings, console, verbose=verbose)

    _render_risk_summary(report, console)
    _render_footer(report, console, verbose=verbose)


def _render_header(report: Report, console: Console) -> None:
    title = Text("AI Attack Surface Report", style="bold cyan")
    console.print()
    console.print(title)
    console.print(Rule(style="cyan"))
    console.print(
        Text("Project:    ", style="dim") + Text(report.scan_root, style="white"),
    )
    if report.repository:
        console.print(
            Text("Repository: ", style="dim") + Text(report.repository, style="white"),
        )


def _render_summary_line(report: Report, console: Console) -> None:
    surface_count = len(report.findings)
    risk_count = sum(len(f.risk_indicators) for f in report.findings)
    detector_count = len(report.detectors_run)

    surface_word = "surfaces" if surface_count != 1 else "surface"
    risk_word = "indicators" if risk_count != 1 else "indicator"

    parts: list[str] = [
        f"[bold green]{surface_count}[/bold green] production AI {surface_word}",
    ]
    if risk_count:
        parts.append(f"[bold yellow]{risk_count}[/bold yellow] risk {risk_word}")
    parts.append(f"[dim]across {detector_count} detector(s)[/dim]")

    console.print(" · ".join(parts))

    # Severity breakdown from the report summary (audited findings only).
    summary = report.summary or report.build_summary()
    if summary.by_severity:
        sev_parts: list[str] = []
        for sev in (
            SEVERITY_CRITICAL,
            SEVERITY_HIGH,
            SEVERITY_MEDIUM,
            SEVERITY_LOW,
            SEVERITY_INFO,
        ):
            count = summary.by_severity.get(sev)
            if count:
                style = SEVERITY_STYLE.get(sev, "bold")
                sev_parts.append(f"[{style}]{count} {sev}[/{style}]")
        if sev_parts:
            console.print("Severity: " + " · ".join(sev_parts))
    console.print()


def _render_empty(report: Report, console: Console) -> None:
    console.print()
    if report.detectors_run:
        console.print(
            "[green]No production AI surfaces detected.[/green] "
            "[dim]The codebase appears clean of LLM SDKs, agent frameworks, "
            "and MCP servers.[/dim]"
        )
    else:
        console.print(
            "[yellow]No detectors registered.[/yellow] "
            "[dim]This is expected during early development. "
            "Detectors are still being implemented.[/dim]"
        )
    # Detector errors are surfaced by _render_footer (with verbose-aware detail).


def _render_category(
    category: str,
    findings: list[Finding],
    console: Console,
    verbose: bool = False,
) -> None:
    title = CATEGORY_DISPLAY.get(category, category.upper())
    console.print(f"[bold]{title}[/bold]")
    for finding in findings:
        _render_finding(finding, console, verbose=verbose)
    console.print()


def _render_finding(finding: Finding, console: Console, verbose: bool = False) -> None:
    # Surface name on its own line, indented. Audited findings carry a colored
    # severity badge; discovery-only findings render exactly as before.
    surface_text = Text("  • ", style="dim") + Text(finding.surface, style="bold white")
    badge = _severity_badge(finding.severity)
    if badge is not None:
        surface_text = surface_text + badge
    console.print(surface_text)

    # API endpoint metadata (method/path/auth/framework) from evidence.metadata.
    if finding.category == CATEGORY_API:
        _render_api_metadata(finding, console)

    # Permissions / tools / capabilities
    if finding.permissions:
        perms_str = ", ".join(finding.permissions[:8])
        if len(finding.permissions) > 8:
            perms_str += f", … ({len(finding.permissions) - 8} more)"
        console.print(Padding(Text(f"  Tools/perms: {perms_str}", style="dim"), (0, 0, 0, 4)))

    # Models used (from llm-sdk metadata)
    models = finding.evidence.metadata.get("models_used") if finding.evidence else None
    if models:
        models_str = ", ".join(str(m) for m in models[:6])
        console.print(Padding(Text(f"  Models: {models_str}", style="dim"), (0, 0, 0, 4)))

    # File evidence
    files = finding.evidence.files if finding.evidence else []
    if files:
        if verbose or len(files) <= 3:
            file_str = ", ".join(files)
        else:
            file_str = ", ".join(files[:2]) + f", … +{len(files) - 2} more (use -v to show all)"
        console.print(Padding(Text(f"  → {file_str}", style="dim cyan"), (0, 0, 0, 4)))

    # Risk indicators (yellow warning bullets)
    for risk in finding.risk_indicators:
        console.print(Padding(Text(f"  ⚠ {risk}", style="yellow"), (0, 0, 0, 4)))

    # Deep-dive audit block (risk flags, secrets, trust) when present.
    if finding.audit is not None:
        _render_audit(finding, console)

    # Inline per-finding deep link to APIsec when this finding has risk
    # indicators. Conversion bridge points reviewers at the specific surface.
    if finding.risk_indicators:
        url = build_upgrade_url(finding, source="ai-surface", medium="cli")
        console.print(
            Padding(
                Text.from_markup(f"  [dim]→ [link={url}]validate this surface[/link][/dim]"),
                (0, 0, 0, 4),
            )
        )

    # Paid-platform upgrade bridges (the funnel). Short "validate at runtime"
    # line per bridge so reviewers can route the surface into APIsec.
    _render_bridges(finding, console)


def _render_api_metadata(finding: Finding, console: Console) -> None:
    """Render method + path + auth/framework for an API-category finding."""
    meta = finding.evidence.metadata if finding.evidence else {}
    method = str(meta.get("method", "")).strip()
    path = str(meta.get("path", "")).strip()
    if method or path:
        endpoint = f"{method} {path}".strip()
        console.print(Padding(Text(f"  Endpoint: {endpoint}", style="white"), (0, 0, 0, 4)))

    extras: list[str] = []
    framework = meta.get("framework")
    if framework:
        extras.append(f"framework: {framework}")
    auth = meta.get("auth")
    if auth:
        extras.append(f"auth: {auth}")
    source_spec = meta.get("source_spec")
    if source_spec:
        extras.append(f"spec: {source_spec}")
    if extras:
        console.print(Padding(Text("  " + " · ".join(extras), style="dim"), (0, 0, 0, 4)))


def _render_audit(finding: Finding, console: Console) -> None:
    """Render the deep-dive audit block: risk flags, secrets, and trust.

    Secrets render NAME/TYPE/location only. Per the privacy guarantee there is
    never a secret value in the report; we never read or print one.
    """
    audit = finding.audit
    if audit is None:
        return

    for rf in audit.risk_flags:
        sev_style = SEVERITY_STYLE.get(rf.severity, "bold")
        header = Text("  ⚑ ", style=sev_style)
        header += Text(f"[{rf.severity.upper()}] ", style=sev_style)
        header += Text(rf.flag, style="bold white")
        console.print(Padding(header, (0, 0, 0, 4)))
        if rf.description:
            console.print(Padding(Text(rf.description, style="default"), (0, 0, 0, 8)))
        if rf.owasp:
            console.print(
                Padding(Text("OWASP: " + ", ".join(rf.owasp), style="dim"), (0, 0, 0, 8))
            )
        standards = standards_for_flag(rf.flag)
        if standards:
            gov = ", ".join(f"{s['framework']} {s['clause']}" for s in standards)
            console.print(
                Padding(Text("Governance: " + gov, style="dim"), (0, 0, 0, 8))
            )
        if rf.remediation:
            console.print(Padding(Text(f"Fix: {rf.remediation}", style="green"), (0, 0, 0, 8)))

    for secret in audit.secrets:
        # NAME and TYPE only; never a value.
        bits = [secret.name]
        if secret.secret_type:
            bits.append(f"type: {secret.secret_type}")
        if secret.confidence:
            bits.append(f"confidence: {secret.confidence}")
        if secret.location:
            bits.append(f"at: {secret.location}")
        sev_style = SEVERITY_STYLE.get(secret.severity, "bold yellow")
        line = Text("  ⚿ ", style=sev_style)
        if secret.severity:
            line += Text(f"[{secret.severity.upper()}] ", style=sev_style)
        line += Text(" · ".join(bits), style="default")
        console.print(Padding(line, (0, 0, 0, 4)))

    if audit.trust_label:
        trust = f"Trust: {audit.trust_label}"
        if audit.trust_score is not None:
            trust += f" ({audit.trust_score:g}/100)"
        console.print(Padding(Text(f"  {trust}", style="dim"), (0, 0, 0, 4)))


def _render_bridges(finding: Finding, console: Console) -> None:
    """Render the paid-platform upgrade bridges for a finding."""
    for bridge in finding.bridges:
        console.print(
            Padding(
                Text.from_markup(
                    f"  [dim]→ validate at runtime: "
                    f"[link={bridge.url}]{rich_escape(bridge.label)}[/link][/dim]"
                ),
                (0, 0, 0, 4),
            )
        )


def _render_risk_summary(report: Report, console: Console) -> None:
    risks = report.all_risk_indicators()
    if not risks:
        return
    console.print(Rule(style="dim"))
    word = "indicators" if len(risks) != 1 else "indicator"
    console.print(f"[bold yellow]Risk {word} ({len(risks)}):[/bold yellow]")
    for r in risks:
        console.print(Text(f"  ⚠ {r}", style="yellow"))
    console.print()


def _render_footer(report: Report, console: Console, verbose: bool = False) -> None:
    console.print(Rule(style="dim"))
    if report.errors:
        if verbose:
            console.print(f"[red]Detector errors ({len(report.errors)}):[/red]")
            for err in report.errors:
                # Detector errors carry exception text that can include
                # fragments of attacker-controlled file contents (e.g. a
                # PyYAML parse error wrapping a malicious YAML snippet).
                # Escape rich markup so style codes or fake hyperlinks in
                # that text are rendered as literal characters rather than
                # interpreted.
                console.print(f"  [red]•[/red] {rich_escape(err)}")
        else:
            console.print(
                f"[dim]({len(report.errors)} detector error(s); run with -v for details)[/dim]"
            )

    # Specialist tools (lateral cross-promotion within the OSS family).
    # Only renders pointers for shipped specialists; future ones are silent.
    specialists = specialists_for_report(report.findings)
    for spec in specialists:
        console.print(
            f"[dim]{spec['tagline'].capitalize()}: "
            f"[link={spec['url']}]{spec['tool']}[/link][/dim]"
        )

    # Vertical cross-promotion to the APIsec validation platform.
    # Picks the most consequential finding so the deep link carries context.
    headline = headline_finding(report.findings)
    upgrade_url = build_upgrade_url(headline, source="ai-surface", medium="cli")
    console.print(
        f"Validate which surfaces are exploitable: "
        f"[link={upgrade_url}]apisec.ai/products[/link]"
    )

    # Runtime validation routes available from this scan (report.summary).
    summary = report.summary or report.build_summary()
    if summary.bridges_available:
        skus = ", ".join(summary.bridges_available)
        console.print(f"[dim]Validate at runtime in APIsec: {skus}[/dim]")
    console.print()
