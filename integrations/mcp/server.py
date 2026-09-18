"""
ai-surface MCP server.

Exposes ai-surface as Model Context Protocol tools so any MCP client (Claude Code,
Cursor, Windsurf, Cline) can inventory the AI attack surface of code it is writing,
and flag NEW surface introduced by a change, at the moment of creation.

Design notes:
- Transport is stdio. The client launches this as a local subprocess. There is no
  network listener, no port, no credentials, and no auth surface. The scan is
  read-only and fully offline, so nothing about your code leaves the machine.
- This wrapper shells out to the installed `ai-surface` binary, so it is independent
  of the core package's Python version. The server runs on 3.11; the CLI on 3.9.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

# ---------------------------------------------------------------------------
# locate the ai-surface CLI
#
# Resolution order, most specific first:
#   1. AI_SURFACE_BIN env var (explicit override).
#   2. The ai-surface installed alongside this interpreter (same venv). This is
#      the pinned, reproducible path: the server's own environment carries a
#      known ai-surface version, so behavior does not depend on global PATH state.
#   3. Whatever ai-surface is on PATH, as a last resort.
# ---------------------------------------------------------------------------
def _find_ai_surface() -> str:
    override = os.environ.get("AI_SURFACE_BIN")
    if override and os.path.exists(override):
        return override
    sibling = os.path.join(os.path.dirname(sys.executable), "ai-surface")
    if os.path.exists(sibling):
        return sibling
    exe = shutil.which("ai-surface")
    if exe:
        return exe
    raise RuntimeError(
        "ai-surface CLI not found. Install it into this environment with: "
        "pip install apisec-ai-surface"
    )


AI_SURFACE = _find_ai_surface()

RUNTIME_NOTE = (
    "This is a STATIC inventory of the AI attack surface. Static analysis cannot "
    "confirm which of these surfaces is actually exploitable against your running "
    "application; that depends on the deployed authentication, real data, and live "
    "configuration, and requires runtime testing to prove."
)

mcp = MCPServer(
    "ai-surface",
    instructions=(
        "Inventory and monitor the AI attack surface in application code: LLM SDK "
        "calls, agents and their tools, MCP servers, RAG / vector stores, model "
        "gateways, provider keys, and the API endpoints that expose them. Runs "
        "locally, read-only, offline. Use scan_ai_surface to inventory a path, and "
        "check_new_ai_surface after edits to catch AI surface a change just introduced."
    ),
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _run(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [AI_SURFACE, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _scan_json(path: str) -> dict[str, Any]:
    proc = _run(["scan", path, "-o", "json"])
    if not proc.stdout.strip():
        raise RuntimeError(f"ai-surface produced no output. stderr: {proc.stderr[:400]}")
    return json.loads(proc.stdout)


def _clean_error(exc: Exception) -> str:
    """Turn an internal failure into a short, actionable message for the agent."""
    msg = str(exc)
    if "is not a directory" in msg or "No such file" in msg:
        return "Path not found or not a directory. Pass a path to a code directory."
    return msg[:300]


def _compact_surface(f: dict[str, Any]) -> dict[str, Any]:
    """Trim a raw finding to the fields an agent needs."""
    ev = f.get("evidence", {}) or {}
    meta = ev.get("metadata", {}) or {}
    out = {
        "surface": f.get("surface"),
        "category": f.get("category"),
        "severity": f.get("severity"),
        "risk_indicators": f.get("risk_indicators", []),
        "verdict": f.get("verdict"),
        "files": ev.get("files", []),
    }
    if meta.get("tools"):
        out["exposes_tools"] = meta["tools"]
    flags = _compact_flags((f.get("audit") or {}).get("risk_flags"))
    if flags:
        out["compliance"] = flags
    return out


def _compact_flags(flags: list[dict] | None) -> list[dict]:
    """Compact audit risk_flags to what an agent needs to report compliance."""
    return [
        {
            "flag": fl.get("flag"),
            "severity": fl.get("severity"),
            "description": fl.get("description"),
            "owasp": fl.get("owasp") or [],
            "standards": [
                f"{s.get('framework')} {s.get('clause')}".strip()
                for s in (fl.get("standards") or [])
            ],
            "remediation": fl.get("remediation"),
        }
        for fl in (flags or [])
    ]


def _shape_report(report: dict[str, Any], path: str) -> dict[str, Any]:
    summary = report.get("summary", {}) or {}
    return {
        "path": path,
        "tool_version": report.get("tool_version"),
        "total_surfaces": report.get("findings_count", 0),
        "by_category": summary.get("by_category", {}),
        "by_severity": summary.get("by_severity", {}),
        "top_risks": (summary.get("top_risks", []) or [])[:8],
        "governance_frameworks": [fw.get("name") for fw in report.get("frameworks", [])],
        "surfaces": [_compact_surface(f) for f in report.get("findings", [])],
        "runtime_note": RUNTIME_NOTE,
    }


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------
@mcp.tool(
    title="Scan AI attack surface",
    description=(
        "Inventory the AI attack surface in code at PATH: LLM SDK calls, agents and "
        "their tools, MCP servers, RAG / vector stores, model gateways, provider keys, "
        "and the API endpoints that expose them. Returns counts by category and "
        "severity, the top risks, and the governance frameworks the surface maps to. "
        "Read-only, offline, no data leaves the machine."
    ),
)
def scan_ai_surface(path: str = ".") -> dict[str, Any]:
    """Static inventory of the AI attack surface at ``path``."""
    try:
        report = _scan_json(path)
    except Exception as exc:  # noqa: BLE001 - surface a clean message to the agent
        return {"path": path, "error": _clean_error(exc), "total_surfaces": None}
    return _shape_report(report, path)


@mcp.tool(
    title="Check for NEW AI attack surface",
    description=(
        "Compare the current AI attack surface at PATH against a stored baseline and "
        "report only what is NEW, MODIFIED, or REMOVED. Use this right after AI-written "
        "or hand-written edits to catch AI surface a change just introduced (a new MCP "
        "server, a new agent tool, a new LLM call). On first run it records the baseline "
        "and reports nothing changed; re-run after edits to see the delta."
    ),
)
def check_new_ai_surface(path: str = ".") -> dict[str, Any]:
    """Diff the current AI surface at ``path`` against its baseline."""
    baseline = Path(path) / ".ai-surface-baseline.json"
    if not baseline.exists():
        try:
            _run(["scan", path, "--update-baseline"])
            report = _scan_json(path)
        except Exception as exc:  # noqa: BLE001
            return {"path": path, "error": _clean_error(exc)}
        return {
            "path": path,
            "baseline_created": True,
            "recorded_surfaces": report.get("findings_count", 0),
            "message": (
                "Baseline recorded. Re-run check_new_ai_surface after edits to see the "
                "AI attack surface a change introduces."
            ),
        }

    proc = _run(["scan", path, "--baseline", "-o", "json"])
    data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return _shape_baseline_diff(data, path)


def _compact_modified(f: dict[str, Any], audit: dict[str, list]) -> dict[str, Any]:
    """Compact a diff `modified` entry, which carries deltas, not a full finding."""
    out: dict[str, Any] = {
        "surface": f.get("surface"),
        "category": f.get("category"),
    }
    for key in ("permissions_added", "permissions_removed", "risks_added", "risks_removed"):
        if f.get(key):
            out[key] = f[key]
    flags = _compact_flags(audit.get(f.get("surface")))
    if flags:
        out["compliance"] = flags
    return out


def _audit_by_surface(path: str) -> dict[str, list]:
    """Map surface name -> raw audit risk_flags from a full scan of `path`.

    Diff entries carry no audit data, so compliance has to be joined back in
    from the full report.
    """
    try:
        report = _scan_json(path)
    except Exception:  # noqa: BLE001 - enrichment only; the diff still stands
        return {}
    return {
        f.get("surface"): (f.get("audit") or {}).get("risk_flags") or []
        for f in report.get("findings", [])
    }


def _shape_baseline_diff(data: dict[str, Any], path: str) -> dict[str, Any]:
    """Shape a --baseline diff report into NEW / MODIFIED / REMOVED AI surface.

    ai-surface emits the delta as top-level ``added`` / ``modified`` / ``removed``
    lists plus ``total_changes``. ``added``/``removed`` entries are full findings;
    ``modified`` entries are permission/risk deltas.
    """
    added = data.get("added", []) or []
    modified = data.get("modified", []) or []
    removed = data.get("removed", []) or []
    total = data.get("total_changes", len(added) + len(modified) + len(removed))
    audit = _audit_by_surface(path) if (added or modified) else {}
    return {
        "path": path,
        "changed": total > 0,
        "total_changes": total,
        "new_surfaces": [_compact_surface(f) for f in added],
        "modified_surfaces": [_compact_modified(f, audit) for f in modified],
        "removed_surfaces": [_compact_surface(f) for f in removed],
        "summary": (
            f"{len(added)} new, {len(modified)} modified, {len(removed)} removed "
            f"AI surface(s) since baseline."
        ),
        "runtime_note": RUNTIME_NOTE if added else None,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
