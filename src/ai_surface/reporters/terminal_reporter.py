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
from ..types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
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
}

CATEGORY_ORDER: list[str] = [
    CATEGORY_LLM_SDK,
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
]


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
    title = Text("AI Surface Report", style="bold cyan")
    console.print()
    console.print(title)
    console.print(Rule(style="cyan"))
    console.print(
        Text("Scanned: ", style="dim") + Text(report.scan_root, style="white"),
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
    # Surface name on its own line, indented
    surface_text = Text("  • ", style="dim") + Text(finding.surface, style="bold white")
    console.print(surface_text)

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
        f"[link={upgrade_url}]apisec.ai/ai-validation[/link]"
    )
    console.print()
