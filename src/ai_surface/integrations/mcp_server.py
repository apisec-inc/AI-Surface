"""ai-surface as a Model Context Protocol server (stdio).

Any MCP client (Claude Code, Cursor, Windsurf, Cline, and others) can launch
``ai-surface mcp`` as a local subprocess and call two tools:

- ``scan_ai_surface``: inventory the AI attack surface at a path.
- ``check_new_ai_surface``: report only what a change introduced, relative to
  a rolling baseline kept outside the repository.

There is no network listener, no port, and no credentials. The scan is
read-only and offline, so nothing about the code leaves the machine.

The ``mcp`` package is an optional dependency (``pip install "apisec-ai-surface[mcp]"``)
and requires Python 3.10 or newer. Everything except :func:`serve` and
:func:`build_server` imports without it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from . import core

INSTRUCTIONS = (
    "Inventory and monitor the AI attack surface in application code: LLM SDK "
    "calls, agents and their tools, MCP servers, RAG / vector stores, model "
    "gateways, provider keys, and the API endpoints that expose them. Runs "
    "locally, read-only, offline. Use scan_ai_surface to inventory a path, and "
    "check_new_ai_surface after edits to catch AI surface a change just introduced. "
    "Findings carry OWASP LLM Top 10 ids and EU AI Act / NIST AI RMF / ISO 42001 "
    "clauses. A finding is static evidence, never proof of runtime exploitability."
)

SCAN_DESCRIPTION = (
    "Inventory the AI attack surface in code at PATH: LLM SDK calls, agents and "
    "their tools, MCP servers, RAG / vector stores, model gateways, provider keys, "
    "and the API endpoints that expose them. Returns counts by category and "
    "severity, the top risks, the governance frameworks the surface maps to, and "
    "the highest-severity surfaces (capped by max_surfaces). Read-only, offline, "
    "no data leaves the machine."
)

CHECK_DESCRIPTION = (
    "Compare the current AI attack surface at PATH against a rolling baseline and "
    "report only what is NEW, MODIFIED, or REMOVED, with the compliance mapping "
    "for each. Call it right after edits to catch AI surface a change just "
    "introduced (a new MCP server, a new agent tool, a new LLM call). The first "
    "call records the baseline and reports nothing changed; each later call "
    "reports the delta since the previous call. Pass baseline_file to compare "
    "against a specific committed baseline instead (that file is not modified)."
)


def _error(path: str, exc: Exception) -> dict[str, Any]:
    msg = str(exc)
    if isinstance(exc, NotADirectoryError) or "not a directory" in msg.lower():
        msg = f"{path}: not found or not a directory. Pass a path to a code directory."
    return {"path": path, "error": msg[:300]}


def scan_ai_surface(path: str = ".", max_surfaces: int = 50) -> dict[str, Any]:
    """Static inventory of the AI attack surface at ``path``."""
    try:
        root = core.resolve_root(path)
        report = core.scan_report(root)
    except Exception as exc:  # noqa: BLE001 - always answer the agent cleanly
        return _error(path, exc)
    out = core.shape_report(report, path, max_surfaces=max_surfaces)
    out["resolved_path"] = str(root)
    return out


def check_new_ai_surface(path: str = ".", baseline_file: Optional[str] = None) -> dict[str, Any]:
    """Diff the AI surface at ``path`` against its rolling (or a given) baseline."""
    try:
        root = core.resolve_root(path)
        if baseline_file:
            bp = Path(baseline_file).expanduser()
            if not bp.is_absolute():
                bp = root / bp
            if not bp.is_file():
                return {"path": path, "error": f"baseline_file not found: {baseline_file}"}
            out = core.check_new_surface(root, bp, advance=False, path_label=path)
        else:
            bp = core.baseline_path_for(root, core.NAMESPACE_MCP)
            out = core.check_new_surface(root, bp, advance=True, path_label=path)
    except Exception as exc:  # noqa: BLE001
        return _error(path, exc)
    out["resolved_path"] = str(root)
    return out


def _import_server_class() -> Any:
    try:
        from mcp.server.mcpserver import MCPServer  # type: ignore[import-not-found]  # noqa: PLC0415

        return MCPServer
    except ImportError:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]  # noqa: PLC0415

        return FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "The MCP server needs the 'mcp' package (Python 3.10+). Install it with: "
            'pip install "apisec-ai-surface[mcp]"'
        ) from exc


def build_server() -> Any:
    """Construct the MCP server with both tools registered."""
    server_cls = _import_server_class()
    server = server_cls("ai-surface", instructions=INSTRUCTIONS)
    server.tool(name="scan_ai_surface", description=SCAN_DESCRIPTION)(scan_ai_surface)
    server.tool(name="check_new_ai_surface", description=CHECK_DESCRIPTION)(check_new_ai_surface)
    return server


def serve() -> None:
    """Run the server over stdio until the client closes the pipe."""
    build_server().run(transport="stdio")
