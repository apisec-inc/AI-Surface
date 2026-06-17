"""JSON reporter: machine-readable output for automation and CI integrations.

The schema is versioned. Bumps must be backward-compatible within a major or
explicitly noted as breaking. The GitHub Action wrapper consumes this output
to compute PR diffs.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from ..types import Report


def render_json(report: Report, indent: int = 2) -> str:
    """Render `report` as a JSON string. Returns valid JSON suitable for piping."""
    return json.dumps(report_to_dict(report), indent=indent, ensure_ascii=False)


def report_to_dict(report: Report) -> dict[str, Any]:
    """Convert Report to a plain dict (JSON-friendly).

    Schema 1.0 contract. This dict is the single source of truth consumed by:
      - the CI/PR diff in the GitHub Action
      - the local UI viewer (renders this directly, does NOT re-scan)
      - the funnel/cross-promo bridge links
    Optional fields (severity, audit, bridges, summary) are always present in
    the emitted JSON: null/[] when not applicable, so consumers need no guards.
    """
    summary = report.summary or report.build_summary()
    from ..frameworks import framework_evidence  # noqa: PLC0415

    return {
        "schema_version": report.schema_version,
        "tool_version": report.tool_version,
        "scan_root": report.scan_root,
        "repository": report.repository,
        "scan_timestamp": report.scan_timestamp,
        "detectors_run": list(report.detectors_run),
        "findings_count": len(report.findings),
        "summary": asdict(summary),
        # Governance-framework evidence this scan produces (honest evidence-for,
        # not a compliance claim). Lets the UI and reporters surface it.
        "frameworks": framework_evidence(report),
        "findings": [_finding_to_dict(f) for f in report.findings],
        "errors": list(report.errors),
    }


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """asdict-compatible conversion that flattens Evidence nicely."""
    from ..frameworks import standards_for_flag  # noqa: PLC0415

    d = asdict(finding)
    # Attach the specific governance clauses each risk flag evidences (beyond
    # OWASP, which is already on the flag). Lets the UI render framework badges.
    audit = d.get("audit")
    if audit:
        for rf in audit.get("risk_flags", []):
            rf["standards"] = standards_for_flag(rf.get("flag", ""))
    return d
