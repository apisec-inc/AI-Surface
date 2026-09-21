"""Shared engine for the editor integrations (MCP server, Claude Code hook).

Design rules:

- Scans run in-process through the same orchestrator the CLI uses, so an
  integration never depends on locating an ``ai-surface`` binary and never
  drifts from the CLI's detectors.
- Findings are serialized through the JSON reporter, which is the only place
  governance standards (EU AI Act, NIST AI RMF, ISO 42001 clauses) are joined
  onto risk flags. New, modified, and removed surfaces therefore all carry
  the same compliance block.
- The rolling baseline used to answer "what did this change introduce?" is
  stored OUTSIDE the repository, under a per-user state directory, so it can
  never overwrite the committed ``.ai-surface-baseline.json`` that teams use
  as a CI control, and never shows up as an untracked file.
- Python 3.9 compatible: no runtime ``X | Y`` unions, no ``match``.
"""
from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from ..diff import Diff, compute_diff, load_report_from_json
from ..orchestrator import Orchestrator, default_detectors
from ..reporters.json_reporter import finding_to_dict, render_json, report_to_dict
from ..types import Finding, Report

RUNTIME_NOTE = (
    "This is a static inventory of the AI attack surface. Static analysis "
    "cannot confirm which of these surfaces is actually exploitable against "
    "your running application; that depends on the deployed authentication, "
    "real data, and live configuration, and requires runtime testing to prove."
)

#: Namespaces keep the hook's rolling baseline and the MCP tool's rolling
#: baseline separate, so an automatic hook advancing its baseline does not
#: make an explicit tool call report "nothing changed".
NAMESPACE_HOOK = "claude-code-hook"
NAMESPACE_MCP = "mcp"

_MAX_SURFACES_DEFAULT = 50


# ---------------------------------------------------------------------------
# State directory (outside the repo)
# ---------------------------------------------------------------------------
def state_dir() -> Path:
    """Per-user directory for integration state. Never inside a scanned repo.

    Override with ``AI_SURFACE_STATE_DIR``. Defaults to ``$XDG_CACHE_HOME/ai-surface``
    (or ``~/.cache/ai-surface``), and ``%LOCALAPPDATA%\\ai-surface`` on Windows.
    """
    override = os.environ.get("AI_SURFACE_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    return base / "ai-surface"


def baseline_path_for(root: Path, namespace: str) -> Path:
    """Stable per-repo baseline file for ``namespace`` under :func:`state_dir`."""
    key = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    return state_dir() / namespace / f"{key}.json"


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def resolve_root(path: str) -> Path:
    """Resolve ``path`` to an absolute directory or raise ``NotADirectoryError``."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"{path} is not a directory")
    return root


def is_unsafe_root(root: Path) -> bool:
    """True for roots that should never be scanned automatically.

    A hook that fires with ``cwd`` set to a home directory or the filesystem
    root would walk the user's whole machine. Explicit tool calls may still do
    it; automatic ones must not.
    """
    root = root.resolve()
    if root == Path(root.anchor):
        return True
    try:
        home = Path.home().resolve()
    except Exception:  # noqa: BLE001 - no home is fine
        return False
    return root == home


def scan_report(root: Path, skip_files: Optional[list[str]] = None) -> Report:
    """Run the default detector set against ``root`` in-process."""
    from ..utils import walk as _walk  # noqa: PLC0415

    _walk.set_runtime_skip(list(skip_files or []))
    try:
        return Orchestrator(detectors=default_detectors()).run(str(root))
    finally:
        _walk.clear_runtime_skip()


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------
def write_baseline(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(render_json(report), encoding="utf-8")
    os.replace(tmp, path)


def load_baseline(path: Path) -> Optional[Report]:
    """Load a baseline, or return ``None`` when it is missing or unreadable."""
    try:
        return load_report_from_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Shaping: what an agent needs, nothing it does not
# ---------------------------------------------------------------------------
def compact_flags(flags: Optional[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Compact audit ``risk_flags`` (as emitted by the JSON reporter)."""
    out: list[dict[str, Any]] = []
    for fl in flags or []:
        out.append(
            {
                "flag": fl.get("flag"),
                "severity": fl.get("severity"),
                "description": fl.get("description"),
                "owasp": list(fl.get("owasp") or []),
                "standards": [
                    f"{s.get('framework', '')} {s.get('clause', '')}".strip()
                    for s in (fl.get("standards") or [])
                ],
                "remediation": fl.get("remediation"),
            }
        )
    return out


def compact_finding(fd: dict[str, Any]) -> dict[str, Any]:
    """Trim a reporter-shaped finding dict to the fields an agent needs."""
    ev = fd.get("evidence") or {}
    meta = ev.get("metadata") or {}
    out: dict[str, Any] = {
        "surface": fd.get("surface"),
        "category": fd.get("category"),
        "severity": fd.get("severity"),
        "verdict": fd.get("verdict"),
        "risk_indicators": list(fd.get("risk_indicators") or []),
        "files": list(ev.get("files") or []),
    }
    if fd.get("permissions"):
        out["permissions"] = list(fd["permissions"])
    if meta.get("tools"):
        out["exposes_tools"] = list(meta["tools"])
    flags = compact_flags((fd.get("audit") or {}).get("risk_flags"))
    if flags:
        out["compliance"] = flags
    return out


def compliance_by_surface(report: Report) -> dict[str, list[dict[str, Any]]]:
    """surface name -> compacted compliance flags, for joining onto diff entries."""
    out: dict[str, list[dict[str, Any]]] = {}
    for f in report.findings:
        flags = compact_flags((finding_to_dict(f).get("audit") or {}).get("risk_flags"))
        if flags:
            out[f.surface] = flags
    return out


def shape_report(report: Report, path: str, max_surfaces: int = _MAX_SURFACES_DEFAULT) -> dict[str, Any]:
    """Shape a full scan for an agent: counts, top risks, capped surface list."""
    d = report_to_dict(report)
    summary = d.get("summary") or {}
    findings = d.get("findings") or []
    ranked = sorted(findings, key=_severity_rank)
    shown = ranked[: max(0, max_surfaces)]
    out: dict[str, Any] = {
        "path": path,
        "tool_version": d.get("tool_version"),
        "total_surfaces": d.get("findings_count", 0),
        "by_category": summary.get("by_category", {}),
        "by_severity": summary.get("by_severity", {}),
        "confirmed_count": summary.get("confirmed_count", 0),
        "likely_count": summary.get("likely_count", 0),
        "top_risks": list(summary.get("top_risks") or [])[:8],
        "governance_frameworks": [fw.get("name") for fw in d.get("frameworks") or []],
        "surfaces": [compact_finding(f) for f in shown],
        "runtime_note": RUNTIME_NOTE,
    }
    if len(findings) > len(shown):
        out["surfaces_truncated"] = len(findings) - len(shown)
        out["surfaces_note"] = (
            f"Showing the {len(shown)} highest-severity of {len(findings)} surfaces. "
            "Raise max_surfaces to see more."
        )
    if d.get("errors"):
        out["scan_errors"] = list(d["errors"])
    return out


def _severity_rank(fd: dict[str, Any]) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(fd.get("severity") or "", 9)


def shape_diff(diff: Diff, head: Report, path: str) -> dict[str, Any]:
    """Shape a baseline diff as NEW / MODIFIED / REMOVED, all with compliance."""
    by_surface = compliance_by_surface(head) if (diff.added or diff.modified) else {}
    new_surfaces = [compact_finding(finding_to_dict(f)) for f in diff.added]
    modified: list[dict[str, Any]] = []
    risks_added_any = False
    for c in diff.modified:
        entry: dict[str, Any] = {"surface": c.surface, "category": c.category}
        for key in ("permissions_added", "permissions_removed", "risks_added", "risks_removed",
                    "files_added", "files_removed"):
            val = getattr(c, key)
            if val:
                entry[key] = list(val)
        if c.risks_added:
            risks_added_any = True
        flags = by_surface.get(c.surface)
        if flags:
            entry["compliance"] = flags
        modified.append(entry)
    removed = [compact_finding(_bare_finding_dict(f)) for f in diff.removed]
    total = diff.total_changes
    return {
        "path": path,
        "changed": total > 0,
        "total_changes": total,
        "new_surfaces": new_surfaces,
        "modified_surfaces": modified,
        "removed_surfaces": removed,
        "summary": (
            f"{len(diff.added)} new, {len(diff.modified)} modified, "
            f"{len(diff.removed)} removed AI surface(s) since baseline."
        ),
        "runtime_note": RUNTIME_NOTE if (diff.added or risks_added_any) else None,
    }


def _bare_finding_dict(f: Finding) -> dict[str, Any]:
    # Removed findings come from the loaded baseline, which strips audit data;
    # a plain asdict is all there is and compact_finding tolerates it.
    return asdict(f)


# ---------------------------------------------------------------------------
# The "what did this change introduce?" operation
# ---------------------------------------------------------------------------
def check_new_surface(
    root: Path,
    baseline_path: Path,
    *,
    advance: bool,
    path_label: Optional[str] = None,
) -> dict[str, Any]:
    """Diff the current AI surface at ``root`` against ``baseline_path``.

    - No baseline yet: record one and report ``baseline_created``.
    - Unreadable baseline: re-record it and report ``baseline_reset``.
    - Otherwise: return the shaped diff. When ``advance`` is true the baseline
      is replaced with the current scan AFTER a successful diff, so each change
      is reported exactly once and a failed diff never loses a finding.
    """
    label = path_label or str(root)
    skip = [str(baseline_path)] if _is_inside(baseline_path, root) else []
    report = scan_report(root, skip_files=skip)

    if not baseline_path.exists():
        write_baseline(report, baseline_path)
        return {
            "path": label,
            "baseline_created": True,
            "recorded_surfaces": len(report.findings),
            "baseline_file": str(baseline_path),
            "message": (
                "Baseline recorded. Re-run after edits to see the AI attack "
                "surface a change introduces."
            ),
        }

    base = load_baseline(baseline_path)
    if base is None:
        write_baseline(report, baseline_path)
        return {
            "path": label,
            "baseline_reset": True,
            "recorded_surfaces": len(report.findings),
            "baseline_file": str(baseline_path),
            "message": "Stored baseline was unreadable and has been re-recorded.",
        }

    diff = compute_diff(base, report)
    if advance:
        write_baseline(report, baseline_path)
    out = shape_diff(diff, report, label)
    out["baseline_file"] = str(baseline_path)
    return out


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
