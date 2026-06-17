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
        _maybe_fail_on_diff_severity(diff, fail_on)
        _maybe_fail_on_diff_risk(diff, fail_on_risk)
        return

    # Quiet mode short-circuits all reporters and prints a single line.
    if quiet:
        _print_quiet_summary(report)
        _maybe_fail_on_severity(report, fail_on)
        _maybe_fail_on_risk(report, fail_on_risk)
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
        print(render_markdown(report))
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

            render_terminal(report, console, verbose=verbose)
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
            inv_path.write_text(render_markdown(report), encoding="utf-8")
            err_console.print(f"[green]wrote[/green] {inv_path}")
        except ImportError:
            err_console.print(
                "[yellow]warning[/yellow]: --write-inventory requested but "
                "markdown reporter not yet implemented."
            )

    _maybe_fail_on_severity(report, fail_on)
    _maybe_fail_on_risk(report, fail_on_risk)


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


@app.command()
def version() -> None:
    """Print ai-surface version."""
    console.print(f"ai-surface {__version__}")


def main() -> None:
    """Entrypoint for the `ai-surface` console_script."""
    app()


if __name__ == "__main__":
    main()
