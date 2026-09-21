"""ai-surface CLI entry point."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import typer
from rich.console import Console

from . import __version__
from .orchestrator import Orchestrator, default_detectors
from .types import (
    ALL_CATEGORIES,
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_API,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    CATEGORY_VECTOR_STORE,
)

app = typer.Typer(
    name="ai-surface",
    help="Inventory production AI surfaces in your application code.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


# Friendly aliases for category names so users can type --categories mcp,agents
# instead of --categories mcp-server,agent-framework.
CATEGORY_ALIASES: Dict[str, str] = {
    # MCP
    "mcp": CATEGORY_MCP_SERVER,
    "mcp-server": CATEGORY_MCP_SERVER,
    "mcp-servers": CATEGORY_MCP_SERVER,
    "mcps": CATEGORY_MCP_SERVER,
    # Agent frameworks
    "agent": CATEGORY_AGENT_FRAMEWORK,
    "agents": CATEGORY_AGENT_FRAMEWORK,
    "agent-framework": CATEGORY_AGENT_FRAMEWORK,
    "agent-frameworks": CATEGORY_AGENT_FRAMEWORK,
    # LLM SDKs
    "llm": CATEGORY_LLM_SDK,
    "llms": CATEGORY_LLM_SDK,
    "llm-sdk": CATEGORY_LLM_SDK,
    "llm-sdks": CATEGORY_LLM_SDK,
    "sdk": CATEGORY_LLM_SDK,
    "sdks": CATEGORY_LLM_SDK,
    # Model gateways
    "gateway": CATEGORY_MODEL_GATEWAY,
    "gateways": CATEGORY_MODEL_GATEWAY,
    "model-gateway": CATEGORY_MODEL_GATEWAY,
    "model-gateways": CATEGORY_MODEL_GATEWAY,
    # AI infra
    "infra": CATEGORY_AI_INFRA,
    "ai-infra": CATEGORY_AI_INFRA,
    # Env keys
    "env": CATEGORY_ENV_KEY,
    "env-key": CATEGORY_ENV_KEY,
    "env-keys": CATEGORY_ENV_KEY,
    "keys": CATEGORY_ENV_KEY,
    # API endpoints
    "api": CATEGORY_API,
    "apis": CATEGORY_API,
    "endpoint": CATEGORY_API,
    "endpoints": CATEGORY_API,
    # Vector stores / RAG
    "vector": CATEGORY_VECTOR_STORE,
    "vector-store": CATEGORY_VECTOR_STORE,
    "vector-stores": CATEGORY_VECTOR_STORE,
    "rag": CATEGORY_VECTOR_STORE,
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def _resolve_categories(requested: Optional[str]) -> Optional[Set[str]]:
    """Parse --categories input into a set of canonical category names.

    Returns None when `requested` is None (meaning "all categories").
    Raises typer.Exit on invalid input.
    """
    if not requested:
        return None
    parts = [p.strip().lower() for p in requested.split(",") if p.strip()]
    if not parts:
        return None
    canonical: Set[str] = set()
    invalid: List[str] = []
    for p in parts:
        if p in ALL_CATEGORIES:
            canonical.add(p)
        elif p in CATEGORY_ALIASES:
            canonical.add(CATEGORY_ALIASES[p])
        else:
            invalid.append(p)
    if invalid:
        valid_names = sorted(set(ALL_CATEGORIES))
        err_console.print(
            f"[red]error[/red]: unknown category/categories: {', '.join(invalid)}"
        )
        err_console.print(f"[dim]valid categories: {', '.join(valid_names)}[/dim]")
        err_console.print(
            "[dim]aliases accepted: mcp, agents, llm, gateway, infra, keys, api, vector[/dim]"
        )
        raise typer.Exit(code=2)
    return canonical


def _filter_detectors_by_category(detectors: list, allowed: Optional[Set[str]]) -> list:
    """Return only detectors whose category is in `allowed`, or all if None."""
    if allowed is None:
        return list(detectors)
    return [d for d in detectors if getattr(d, "category", None) in allowed]


def _print_quiet_summary(report) -> None:
    """One-line summary for CI / scripted use."""
    surfaces = len(report.findings)
    risks = sum(len(f.risk_indicators) for f in report.findings)
    detectors = len(report.detectors_run)
    errors = len(report.errors)
    parts = [f"{surfaces} surfaces", f"{risks} risks"]
    if errors:
        parts.append(f"{errors} errors")
    parts.append(f"{detectors} detectors")
    console.print(f"ai-surface: {', '.join(parts)}")


def _maybe_fail_on_risk(report, enabled: bool) -> None:
    """Exit non-zero when --fail-on-risk is set and any risk was detected.

    Exit code 1 is the gate-tripped signal (distinct from code 2, which this
    CLI reserves for usage errors). Lets any CI block a PR on risk, not just
    the GitHub Action.
    """
    if not enabled:
        return
    risks = sum(len(f.risk_indicators) for f in report.findings)
    if risks > 0:
        err_console.print(
            f"[red]fail-on-risk[/red]: {risks} risk indicator(s) detected; "
            "failing as requested."
        )
        raise typer.Exit(code=1)


# Severity-threshold gate (the painkiller). Gates on ASSESSED severity only, so
# the large inventory of severity-free discovery findings never trips it. Pair
# with --baseline to fire only on NEWLY introduced findings.
FAIL_ON_CHOICES = ("critical", "high", "medium", "low")


def _findings_at_or_above(findings, threshold: str) -> list:
    """Findings whose assessed severity is at or above `threshold`.

    Discovery findings (severity is None) are never included: they are
    inventory, not assessed risk.
    """
    from .types import SEVERITY_ORDER  # noqa: PLC0415

    def rank(sev: str) -> int:
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99

    limit = rank(threshold)
    return [f for f in findings if f.severity and rank(f.severity) <= limit]


def _print_gate_offenders(offending: list) -> None:
    """Show exactly what tripped the gate: severity, surface, file, and the
    top remediation, so a CI log is actionable, not just a count."""
    for f in offending:
        file = f.evidence.files[0] if f.evidence and f.evidence.files else ""
        fix = ""
        if f.audit and f.audit.risk_flags:
            rem = f.audit.risk_flags[0].remediation
            if rem:
                fix = f"  fix: {rem}"
        loc = f"  ({file})" if file else ""
        err_console.print(f"  [{f.severity}] {f.surface}{loc}{fix}")


def _maybe_fail_on_severity(report, threshold: str | None) -> None:
    """Exit non-zero when --fail-on <severity> is set and any finding is at or
    above that severity. The low-noise painkiller gate."""
    if not threshold:
        return
    offending = _findings_at_or_above(report.findings, threshold)
    if offending:
        err_console.print(
            f"[red]fail-on {threshold}[/red]: {len(offending)} finding(s) at or "
            f"above {threshold}:"
        )
        _print_gate_offenders(offending)
        raise typer.Exit(code=1)


def _maybe_fail_on_diff_severity(diff, threshold: str | None) -> None:
    """In --baseline mode, exit non-zero only when a NEWLY added finding is at
    or above `threshold`. Never blocks on pre-existing surfaces."""
    if not threshold:
        return
    offending = _findings_at_or_above(diff.added, threshold)
    if offending:
        err_console.print(
            f"[red]fail-on {threshold}[/red]: {len(offending)} NEW finding(s) at "
            f"or above {threshold} introduced since the baseline:"
        )
        _print_gate_offenders(offending)
        raise typer.Exit(code=1)


def _write_baseline_file(report, bp: Path) -> None:
    """Serialize the current scan as the baseline snapshot at `bp`.

    Creates parent directories if needed. Reports the captured counts on
    stderr so a CI log makes the snapshot visible.
    """
    from .reporters.json_reporter import render_json  # noqa: PLC0415

    try:
        bp.parent.mkdir(parents=True, exist_ok=True)
        bp.write_text(render_json(report), encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]error[/red]: cannot write baseline {bp}: {exc}")
        raise typer.Exit(code=2) from exc
    surfaces = len(report.findings)
    risks = sum(len(f.risk_indicators) for f in report.findings)
    err_console.print(
        f"[green]baseline[/green]: wrote {bp} "
        f"({surfaces} surfaces, {risks} risks captured)"
    )


def _load_and_diff_baseline(report, bp: Path, allowed_categories: Optional[Set[str]] = None):
    """Load the stored baseline at `bp` and return a Diff vs the current report.

    When `allowed_categories` is non-None the baseline is filtered to the
    same set of categories before the diff is computed. The current report
    has already been filtered upstream via the detector category filter, so
    without filtering the baseline too every surface in a non-matching
    category would falsely appear as "removed" in the diff.
    """
    from .diff import compute_diff, load_report_from_json  # noqa: PLC0415

    if not bp.is_file():
        err_console.print(
            f"[red]error[/red]: no baseline at {bp}. "
            "Run with --update-baseline first to capture the current state, "
            "then re-run with --baseline."
        )
        raise typer.Exit(code=2)
    try:
        base_text = bp.read_text(encoding="utf-8")
        base_report = load_report_from_json(base_text)
    except OSError as exc:
        err_console.print(f"[red]error[/red]: cannot read baseline {bp}: {exc}")
        raise typer.Exit(code=2) from exc
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        err_console.print(f"[red]error[/red]: invalid baseline JSON in {bp}: {exc}")
        raise typer.Exit(code=2) from exc
    if allowed_categories is not None:
        base_report.findings = [
            f for f in base_report.findings if f.category in allowed_categories
        ]
    return compute_diff(base_report, report)


def _render_diff(diff, output: str, quiet: bool) -> None:
    """Render a Diff in the requested output mode.

    Diff rendering reuses the existing markdown / JSON renderers from
    diff.py. Terminal mode prints the markdown directly: it is human
    readable and avoids inventing a second rich-styled diff renderer for
    v0.5.3. A dedicated rich diff view can land later.
    """
    from .diff import diff_to_dict, render_diff_markdown  # noqa: PLC0415

    if quiet:
        _print_quiet_diff_summary(diff)
        return
    if output == "json":
        console.print_json(json.dumps(diff_to_dict(diff)))
    else:
        # markdown is the default for diff output. Emit it as raw text via
        # plain print(): this output is captured verbatim by the GitHub Action
        # for the PR comment and redirected to files. Routing it through the
        # rich console would hard-wrap long URLs (breaking links) and consume
        # single-token link labels like [ai-surface] as rich markup.
        print(render_diff_markdown(diff))


def _print_quiet_diff_summary(diff) -> None:
    """One-line baseline-diff summary for CI / scripted use."""
    new_risks = _count_new_risks(diff)
    parts = [
        f"{len(diff.added)} new",
        f"{len(diff.modified)} modified",
        f"{len(diff.removed)} removed",
        f"{new_risks} new risks",
    ]
    console.print(f"ai-surface (vs baseline): {', '.join(parts)}")


def _count_new_risks(diff) -> int:
    """Risks introduced since baseline: risks on added surfaces + risks_added
    on modified surfaces. Risks present in baseline are intentionally NOT
    counted: --fail-on-risk in baseline mode gates on what changed, not on
    what was already accepted."""
    new_from_added = sum(len(f.risk_indicators) for f in diff.added)
    new_from_modified = sum(len(c.risks_added) for c in diff.modified)
    return new_from_added + new_from_modified


def _maybe_fail_on_diff_risk(diff, enabled: bool) -> None:
    """In baseline mode, gate only on NEW risks (since baseline)."""
    if not enabled:
        return
    new_risks = _count_new_risks(diff)
    if new_risks > 0:
        err_console.print(
            f"[red]fail-on-risk[/red]: {new_risks} new risk indicator(s) "
            "introduced since baseline; failing as requested."
        )
        raise typer.Exit(code=1)


def _maybe_fail_on_floor(report, floor: str | None) -> None:
    """Severity floor that ignores the baseline.

    Exit non-zero if ANY finding in the current scan is at or above `floor`,
    including pre-existing ones a baseline would otherwise accept. Closes the
    baseline-acceptance gap: a high finding cannot be silently snapshotted into
    the baseline and then slip a --baseline gate forever.
    """
    if not floor:
        return
    offending = _findings_at_or_above(report.findings, floor)
    if offending:
        err_console.print(
            f"[red]always-fail-on {floor}[/red]: {len(offending)} finding(s) at or "
            f"above {floor} in the current scan; the baseline does not suppress "
            f"this floor:"
        )
        _print_gate_offenders(offending)
        raise typer.Exit(code=1)


def _warn_baseline_suppression(report, diff) -> None:
    """Make baseline acceptance visible (a notice, not a failure).

    When --baseline passes, report how many high/critical findings in the
    current scan are being accepted as pre-existing, so a passing gate does not
    read as "nothing risky here". Printed to stderr so it shows in CI logs even
    when stdout is captured as the PR comment.
    """
    added_keys = {(f.surface, f.category) for f in diff.added}
    suppressed = [
        f
        for f in _findings_at_or_above(report.findings, "high")
        if (f.surface, f.category) not in added_keys
    ]
    if not suppressed:
        return
    err_console.print(
        f"[yellow]baseline[/yellow]: accepting {len(suppressed)} pre-existing "
        f"finding(s) at or above high as already-known. They are not new, so the "
        f"gate does not fail on them. Run without --baseline to see them, or add "
        f"--always-fail-on high to gate on the full surface."
    )


@app.command()
def scan(
    path: str = typer.Argument(".", help="Directory to scan."),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, json, markdown, cyclonedx (AI-BOM), sarif.",
    ),
    categories: Optional[str] = typer.Option(
        None,
        "--categories",
        "-c",
        help=(
            "Comma-separated categories to scan. "
            "Aliases: mcp, agents, llm, gateway, infra, keys. "
            "Default: all."
        ),
    ),
    write_inventory: bool = typer.Option(
        False,
        "--write-inventory",
        help="Generate .ai-inventory.md alongside the terminal output.",
    ),
    fail_on_risk: bool = typer.Option(
        False,
        "--fail-on-risk",
        help=(
            "Exit non-zero (code 1) if any risk indicators are detected. "
            "In --baseline mode, gates only on risks introduced since the baseline. "
            "Aggressive: gates on any indicator. Prefer --fail-on for a "
            "severity-threshold gate."
        ),
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help=(
            "Severity-threshold gate: exit non-zero (code 1) if any finding is at "
            "or above this severity (critical|high|medium|low). Gates on assessed "
            "severity only, so inventory does not trip it. With --baseline, fires "
            "only on NEW findings. Recommended PR gate: --baseline --fail-on high."
        ),
    ),
    always_fail_on: Optional[str] = typer.Option(
        None,
        "--always-fail-on",
        help=(
            "Severity floor the baseline cannot suppress: exit non-zero (code 1) "
            "if ANY finding in the current scan is at or above this severity, "
            "including pre-existing ones accepted by --baseline. Use this so a "
            "high finding can never be silently baselined away "
            "(critical|high|medium|low)."
        ),
    ),
    baseline: bool = typer.Option(
        False,
        "--baseline",
        help=(
            "Compare the scan against a stored baseline file and report only "
            "surfaces that are NEW / MODIFIED / REMOVED since the baseline. "
            "Default baseline path is .ai-surface-baseline.json at the scan "
            "root; override with --baseline-file."
        ),
    ),
    update_baseline: bool = typer.Option(
        False,
        "--update-baseline",
        help=(
            "Capture the current scan as the baseline file and exit. "
            "Use once after reviewing the inventory; subsequent --baseline "
            "runs compare against this snapshot."
        ),
    ),
    baseline_file: str = typer.Option(
        ".ai-surface-baseline.json",
        "--baseline-file",
        help=(
            "Path to the baseline JSON file (relative to scan root or "
            "absolute). Default: .ai-surface-baseline.json"
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="One-line summary output for CI / scripts. Suppresses other output.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose: show all files (no truncation), full detector errors.",
    ),
    governance: bool = typer.Option(
        False,
        "--governance",
        help=(
            "Show per-finding governance clauses (EU AI Act / NIST / ISO) under "
            "each risk flag in terminal and markdown output. Off by default; a "
            "one-line governance summary is always shown. JSON, AI-BOM, and --ui "
            "always carry full governance detail."
        ),
    ),
    ai_only: bool = typer.Option(
        False,
        "--ai-only",
        help=(
            "Focus on AI-specific surface: exclude plain (non-AI) API endpoints "
            "from results. Keeps agents, MCP, LLM calls, RAG, gateways, and keys."
        ),
    ),
    ui: bool = typer.Option(
        False,
        "--ui",
        help=(
            "Open the local visual UI viewer in a browser to explore results. "
            "Serves on loopback only; nothing leaves your machine."
        ),
    ),
    repo: Optional[str] = typer.Option(
        None,
        "--repo",
        help=(
            "Scan a remote git repo by https URL instead of PATH. The repo is "
            "cloned locally, scanned, then discarded. e.g. "
            "https://github.com/org/repo"
        ),
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="AI_SURFACE_GIT_TOKEN",
        help=(
            "Token to clone a private --repo. Read from AI_SURFACE_GIT_TOKEN if "
            "unset. Used only for the clone; never stored, logged, or reported."
        ),
    ),
) -> None:
    """Scan PATH (or a remote --repo) for production AI surfaces."""
    _setup_logging(verbose)

    if baseline and update_baseline:
        err_console.print(
            "[red]error[/red]: --baseline and --update-baseline are "
            "mutually exclusive"
        )
        raise typer.Exit(code=2)

    if fail_on is not None and fail_on.lower() not in FAIL_ON_CHOICES:
        err_console.print(
            f"[red]error[/red]: --fail-on must be one of "
            f"{', '.join(FAIL_ON_CHOICES)} (got {fail_on!r})"
        )
        raise typer.Exit(code=2)
    if fail_on is not None:
        fail_on = fail_on.lower()

    if always_fail_on is not None and always_fail_on.lower() not in FAIL_ON_CHOICES:
        err_console.print(
            f"[red]error[/red]: --always-fail-on must be one of "
            f"{', '.join(FAIL_ON_CHOICES)} (got {always_fail_on!r})"
        )
        raise typer.Exit(code=2)
    if always_fail_on is not None:
        always_fail_on = always_fail_on.lower()

    # --repo: clone the remote repo locally and scan that instead of PATH.
    # Baseline modes operate on a committed snapshot file, which a throwaway
    # clone does not have, so they are not supported together.
    _repo_cleanup = None
    if repo:
        if baseline or update_baseline:
            err_console.print(
                "[red]error[/red]: --baseline/--update-baseline are not "
                "supported with --repo (the clone is transient)"
            )
            raise typer.Exit(code=2)
        from .repo import RepoError, clone_repo_to_tmp  # noqa: PLC0415

        try:
            cloned, _repo_cleanup = clone_repo_to_tmp(repo, token)
        except RepoError as exc:
            err_console.print(f"[red]error[/red]: {exc}")
            raise typer.Exit(code=2) from exc
        path = str(cloned)

    root = Path(path).resolve()
    if not root.is_dir():
        if _repo_cleanup:
            _repo_cleanup()
        err_console.print(f"[red]error[/red]: {path} is not a directory")
        raise typer.Exit(code=2)

    allowed_categories = _resolve_categories(categories)

    # --ai-only: drop the plain (non-AI) API category so output focuses on the
    # AI-specific surface. Applied to both the live scan and the baseline diff
    # below, since both read allowed_categories.
    if ai_only:
        base = (
            allowed_categories
            if allowed_categories is not None
            else set(ALL_CATEGORIES)
        )
        allowed_categories = base - {CATEGORY_API}
        if not allowed_categories:
            err_console.print(
                "[red]error[/red]: --ai-only excluded every selected category "
                "(only 'api' was requested)"
            )
            raise typer.Exit(code=2)

    detectors = default_detectors()
    detectors = _filter_detectors_by_category(detectors, allowed_categories)
    if not detectors:
        if allowed_categories:
            err_console.print(
                f"[red]error[/red]: no detectors match categories: "
                f"{', '.join(sorted(allowed_categories))}"
            )
            raise typer.Exit(code=2)
        err_console.print(
            "[yellow]warning[/yellow]: no detectors registered yet. "
            "v0.5 detectors are still being implemented."
        )

    # Never let a scan re-ingest its own baseline output (self-poison): if the
    # baseline file lives inside the scan root, exclude it from the walk. The
    # default name is already in ALWAYS_SKIP_FILES; this covers custom
    # --baseline-file paths.
    from .utils import walk as _walk  # noqa: PLC0415

    _baseline_path = Path(baseline_file)
    if not _baseline_path.is_absolute():
        _baseline_path = root / _baseline_path
    _walk.set_runtime_skip([str(_baseline_path)])

    orch = Orchestrator(detectors=detectors)
    try:
        report = orch.run(str(root))
    finally:
        _walk.clear_runtime_skip()
        # The clone is only needed during the scan; the Report is in-memory,
        # so discard the clone before rendering regardless of outcome.
        if _repo_cleanup:
            _repo_cleanup()

    # --ui: serve the full scan in the local visual viewer and block until
    # the user stops it. Takes precedence over text reporters and baseline diff.
    if ui:
        try:
            from .ui_server import serve_ui  # noqa: PLC0415

            serve_ui(report)
        except FileNotFoundError as exc:
            err_console.print(f"[red]error[/red]: {exc}")
            raise typer.Exit(code=2) from exc
        return

    # Resolve the baseline file path once. Relative paths are anchored at
    # scan root so the same flag works from any working directory.
    bp = Path(baseline_file)
    if not bp.is_absolute():
        bp = root / bp

    # --update-baseline: capture current scan as the baseline snapshot and exit.
    # No diff is rendered; --fail-on-risk does not gate (the user is asking
    # the tool to ACCEPT the current state, gating on it would defeat the
    # purpose).
    if update_baseline:
        _write_baseline_file(report, bp)
        return

    # --baseline: load the snapshot, diff against the current scan, render
    # only the changes. --fail-on-risk in this mode counts only NEW risks.
    # The same --categories filter applied to the live scan is also applied
    # to the loaded baseline before diffing, otherwise every surface NOT in
    # the requested categories would falsely appear as "removed".
    if baseline:
        diff = _load_and_diff_baseline(report, bp, allowed_categories)
        _render_diff(diff, output, quiet)
        _warn_baseline_suppression(report, diff)
        _maybe_fail_on_diff_severity(diff, fail_on)
        _maybe_fail_on_diff_risk(diff, fail_on_risk)
        _maybe_fail_on_floor(report, always_fail_on)
        return

    # Quiet mode short-circuits all reporters and prints a single line.
    if quiet:
        _print_quiet_summary(report)
        _maybe_fail_on_severity(report, fail_on)
        _maybe_fail_on_risk(report, fail_on_risk)
        _maybe_fail_on_floor(report, always_fail_on)
        return

    # Render based on requested output
    if output == "json":
        from .reporters.json_reporter import render_json  # noqa: PLC0415

        console.print_json(render_json(report))
    elif output == "markdown":
        from .reporters.markdown_reporter import render_markdown  # noqa: PLC0415

        # Print raw, not via the rich console: markdown is captured verbatim by
        # the GitHub Action (PR comment) and redirected to files. The rich
        # console would hard-wrap long URLs and eat single-token [labels] as
        # markup, corrupting the document.
        print(render_markdown(report, governance=governance))
    elif output in ("cyclonedx", "ai-bom"):
        from .reporters.cyclonedx_reporter import render_cyclonedx  # noqa: PLC0415

        # Print raw so the AI-BOM is valid CycloneDX JSON for piping to a file.
        print(render_cyclonedx(report))
    elif output == "sarif":
        from .reporters.sarif_reporter import render_sarif  # noqa: PLC0415

        # Raw print so the SARIF is valid for upload to GitHub code scanning.
        print(render_sarif(report))
    else:
        # terminal is default
        try:
            from .reporters.terminal_reporter import render_terminal  # noqa: PLC0415

            render_terminal(report, console, verbose=verbose, governance=governance)
        except ImportError:
            # Fallback: dump findings as JSON if terminal reporter not yet built
            data = {
                "schema_version": report.schema_version,
                "tool_version": report.tool_version,
                "scan_root": report.scan_root,
                "scan_timestamp": report.scan_timestamp,
                "detectors_run": report.detectors_run,
                "findings_count": len(report.findings),
                "findings": [
                    {
                        "surface": f.surface,
                        "category": f.category,
                        "permissions": f.permissions,
                        "risk_indicators": f.risk_indicators,
                        "files": f.evidence.files,
                    }
                    for f in report.findings
                ],
                "errors": report.errors,
            }
            console.print_json(json.dumps(data))

    if write_inventory:
        try:
            from .reporters.markdown_reporter import render_markdown  # noqa: PLC0415

            inv_path = root / ".ai-inventory.md"
            inv_path.write_text(
                render_markdown(report, governance=governance), encoding="utf-8"
            )
            err_console.print(f"[green]wrote[/green] {inv_path}")
        except ImportError:
            err_console.print(
                "[yellow]warning[/yellow]: --write-inventory requested but "
                "markdown reporter not yet implemented."
            )

    _maybe_fail_on_severity(report, fail_on)
    _maybe_fail_on_risk(report, fail_on_risk)
    _maybe_fail_on_floor(report, always_fail_on)


@app.command()
def compare(
    base: str = typer.Argument(..., help="Path to the base JSON report (older)."),
    head: str = typer.Argument(..., help="Path to the head JSON report (newer)."),
    output: str = typer.Option(
        "markdown",
        "--output",
        "-o",
        help="Output format: markdown, json.",
    ),
) -> None:
    """Compare two JSON scan reports and print the AI surface changes."""
    from .diff import (  # noqa: PLC0415
        compute_diff,
        diff_to_dict,
        load_report_from_json,
        render_diff_markdown,
    )

    try:
        base_text = Path(base).read_text(encoding="utf-8")
        head_text = Path(head).read_text(encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]error[/red]: cannot read input: {exc}")
        raise typer.Exit(code=2) from exc

    try:
        base_report = load_report_from_json(base_text)
        head_report = load_report_from_json(head_text)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        err_console.print(f"[red]error[/red]: invalid JSON report: {exc}")
        raise typer.Exit(code=2) from exc

    diff = compute_diff(base_report, head_report)

    if output == "json":
        console.print_json(json.dumps(diff_to_dict(diff)))
    else:
        # markdown is default. Emit raw via plain print(): the GitHub Action
        # captures this stdout verbatim for the PR comment. The rich console
        # would hard-wrap long URLs (breaking the links) and eat single-token
        # [labels] as markup. See _render_diff for the same fix.
        print(render_diff_markdown(diff))


_INIT_WORKFLOW = """\
# ai-surface: gate pull requests on net-new AI attack surface.
# Generated by `ai-surface init`. Docs: https://github.com/apisec-inc/AI-Surface
name: AI Surface

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write   # required for the sticky PR comment

jobs:
  ai-surface:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required for base-vs-head diff
      - uses: apisec-inc/AI-Surface@v1
        with:
          path: '.'
          comment-on-pr: 'true'
          fail-on: 'high'  # fail only on NEW high-or-critical findings
"""

_PRE_COMMIT_SNIPPET = """\
repos:
  - repo: https://github.com/apisec-inc/AI-Surface
    rev: v1.0.7
    hooks:
      - id: ai-surface
"""


@app.command()
def init(
    path: str = typer.Argument(".", help="Repository root to set up."),
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing workflow file."
    ),
    claude_code: bool = typer.Option(
        False,
        "--claude-code",
        help=(
            "Instead of the CI workflow, wire ai-surface into Claude Code for this "
            "repo: an automatic post-edit hook in .claude/settings.json and the MCP "
            "server in .mcp.json. Existing entries in those files are kept."
        ),
    ),
) -> None:
    """Wire ai-surface into this repo with one command.

    Default: writes .github/workflows/ai-surface.yml so every pull request is
    gated on net-new AI attack surface, and prints the pre-commit snippet for
    local use. With --claude-code: sets up the Claude Code hook and MCP server
    for this repo instead.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]Not a directory:[/red] {root}")
        raise typer.Exit(code=2)

    if claude_code:
        _init_claude_code(root)
        return

    workflow_path = root / ".github" / "workflows" / "ai-surface.yml"
    if workflow_path.exists() and not force:
        err_console.print(
            f"[yellow]{workflow_path} already exists.[/yellow] "
            "Re-run with --force to overwrite."
        )
        raise typer.Exit(code=1)

    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(_INIT_WORKFLOW, encoding="utf-8")

    rel = workflow_path.relative_to(root)
    console.print(f"[green]Wrote[/green] {rel}")
    console.print(
        "Every pull request now gets an AI-surface check: a sticky inventory "
        "comment, and a failing check when the PR introduces a new "
        "high-or-critical finding."
    )
    console.print()
    console.print("Next steps:")
    console.print("  1. Commit the workflow file and push.")
    console.print("  2. Open a test PR to see the check and the comment.")
    console.print(
        "  3. Optional, for local scans before push: add this to "
        ".pre-commit-config.yaml:"
    )
    console.print()
    for line in _PRE_COMMIT_SNIPPET.rstrip().splitlines():
        console.print(f"     {line}")
    console.print()
    console.print(
        "[dim]Useful? Star the repo so more engineers find it: "
        "[link=https://github.com/apisec-inc/AI-Surface]"
        "github.com/apisec-inc/AI-Surface[/link][/dim]"
    )


_CLAUDE_HOOK_COMMAND = "ai-surface hook claude-code"
_CLAUDE_POST_TOOL_MATCHER = "Edit|Write|MultiEdit|NotebookEdit|Bash"


def _load_json_object(path: Path) -> Dict[str, object]:
    """Read a JSON object from ``path``; missing file -> {}; invalid -> exit 2."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (OSError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]error[/red]: cannot read {path}: {exc}")
        raise typer.Exit(code=2) from exc
    if not isinstance(data, dict):
        err_console.print(f"[red]error[/red]: {path} is not a JSON object")
        raise typer.Exit(code=2)
    return data


def _ensure_hook(settings: Dict[str, object], event: str, matcher: Optional[str]) -> bool:
    """Add the ai-surface hook for ``event`` unless an identical one exists."""
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        err_console.print("[red]error[/red]: settings 'hooks' is not an object")
        raise typer.Exit(code=2)
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        err_console.print(f"[red]error[/red]: settings hooks.{event} is not a list")
        raise typer.Exit(code=2)
    for group in groups:
        if not isinstance(group, dict):
            continue
        for h in group.get("hooks", []) or []:
            if isinstance(h, dict) and _CLAUDE_HOOK_COMMAND in str(h.get("command", "")):
                return False
    entry: Dict[str, object] = {"hooks": [{"type": "command", "command": _CLAUDE_HOOK_COMMAND}]}
    if matcher:
        entry["matcher"] = matcher
    groups.append(entry)
    return True


def _init_claude_code(root: Path) -> None:
    """Write the Claude Code hook + MCP server config for ``root`` (merging)."""
    settings_path = root / ".claude" / "settings.json"
    settings = _load_json_object(settings_path)
    added_post = _ensure_hook(settings, "PostToolUse", _CLAUDE_POST_TOOL_MATCHER)
    added_start = _ensure_hook(settings, "SessionStart", None)
    if added_post or added_start:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]Wrote[/green] {settings_path.relative_to(root)} (hook)")
    else:
        console.print(f"{settings_path.relative_to(root)}: hook already present")

    mcp_path = root / ".mcp.json"
    mcp_cfg = _load_json_object(mcp_path)
    servers = mcp_cfg.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        err_console.print("[red]error[/red]: .mcp.json 'mcpServers' is not an object")
        raise typer.Exit(code=2)
    if "ai-surface" in servers:
        console.print(f"{mcp_path.name}: MCP server already present")
    else:
        servers["ai-surface"] = {"command": "ai-surface", "args": ["mcp"]}
        mcp_path.write_text(json.dumps(mcp_cfg, indent=2) + "\n", encoding="utf-8")
        console.print(f"[green]Wrote[/green] {mcp_path.name} (MCP server)")

    console.print()
    console.print(
        "Claude Code will now run an AI-surface check after every edit in this "
        "repo and expose the scan_ai_surface / check_new_ai_surface tools."
    )
    console.print("Next steps:")
    console.print("  1. Start `claude` in this repo and approve the project hook and MCP server.")
    console.print(
        "  2. The MCP server needs the optional extra: "
        'pip install "apisec-ai-surface\\[mcp]" (Python 3.10+). The hook has no extra needs.'
    )
    console.print(
        "  3. Both must be able to find `ai-surface` on PATH from Claude Code "
        "(pipx installs satisfy this)."
    )


@app.command()
def mcp() -> None:
    """Run ai-surface as an MCP server over stdio (for Claude Code, Cursor, and others).

    Exposes scan_ai_surface and check_new_ai_surface. Read-only, offline, no
    network listener. Needs the optional extra: pip install "apisec-ai-surface[mcp]".
    """
    from .integrations.mcp_server import serve  # noqa: PLC0415

    try:
        serve()
    except RuntimeError as exc:
        err_console.print(f"[red]error[/red]: {exc}")
        raise typer.Exit(code=2) from exc


hook_app = typer.Typer(
    help="Editor hooks that run ai-surface automatically.",
    no_args_is_help=True,
)
app.add_typer(hook_app, name="hook")


@hook_app.command("claude-code")
def hook_claude_code(
    reset: bool = typer.Option(
        False,
        "--reset",
        help="Forget the rolling baseline for the current repo and exit.",
    ),
) -> None:
    """Claude Code PostToolUse / SessionStart hook (reads the payload on stdin).

    Reports AI attack surface that an edit just introduced. Silent otherwise.
    Never fails the tool call. Set up with: ai-surface init --claude-code
    """
    from .integrations import claude_code_hook  # noqa: PLC0415

    if reset:
        bp = claude_code_hook.reset()
        print(f"cleared {bp}")
        return
    raise typer.Exit(code=claude_code_hook.main())


@app.command()
def version() -> None:
    """Print ai-surface version."""
    console.print(f"ai-surface {__version__}")


def main() -> None:
    """Entrypoint for the `ai-surface` console_script."""
    app()


if __name__ == "__main__":
    main()
