"""Tests for the MCP server: tool functions always; protocol when mcp is installed."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from ai_surface.integrations import core, mcp_server
from tests.test_integrations_core import AGENT_AFTER, AGENT_BEFORE, NEW_AGENT


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "state"
    monkeypatch.setenv("AI_SURFACE_STATE_DIR", str(d))
    return d


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    (r / "src" / "agent.py").write_text(AGENT_BEFORE)
    return r


def test_scan_tool_shapes_report(repo):
    out = mcp_server.scan_ai_surface(str(repo), max_surfaces=5)
    assert out["total_surfaces"] >= 1
    assert out["resolved_path"] == str(repo.resolve())
    assert out["runtime_note"]
    assert "by_category" in out and "governance_frameworks" in out


def test_scan_tool_bad_path_returns_clean_error(tmp_path):
    out = mcp_server.scan_ai_surface(str(tmp_path / "missing"))
    assert "error" in out and "not a directory" in out["error"]
    assert "Traceback" not in out["error"]


def test_check_tool_rolling_baseline(state_dir, repo):
    first = mcp_server.check_new_ai_surface(str(repo))
    assert first["baseline_created"] is True
    (repo / "src" / "agent.py").write_text(AGENT_AFTER)
    (repo / "src" / "admin.py").write_text(NEW_AGENT)
    second = mcp_server.check_new_ai_surface(str(repo))
    assert second["changed"] is True
    assert len(second["new_surfaces"]) == 1
    assert second["new_surfaces"][0]["compliance"][0]["standards"]
    assert len(second["modified_surfaces"]) == 1
    third = mcp_server.check_new_ai_surface(str(repo))
    assert third["changed"] is False
    # MCP and hook namespaces are independent.
    assert core.baseline_path_for(repo, core.NAMESPACE_MCP).is_file()
    assert not core.baseline_path_for(repo, core.NAMESPACE_HOOK).exists()


def test_check_tool_against_committed_baseline_does_not_modify_it(state_dir, repo):
    bp = repo / "committed.json"
    core.write_baseline(core.scan_report(repo), bp)
    before = bp.read_text()
    (repo / "src" / "agent.py").write_text(AGENT_AFTER)
    out = mcp_server.check_new_ai_surface(str(repo), baseline_file="committed.json")
    assert out["changed"] is True
    assert bp.read_text() == before
    again = mcp_server.check_new_ai_surface(str(repo), baseline_file=str(bp))
    assert again["changed"] is True


def test_check_tool_missing_baseline_file(state_dir, repo):
    out = mcp_server.check_new_ai_surface(str(repo), baseline_file="nope.json")
    assert "error" in out


def test_build_server_without_mcp_has_actionable_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("mcp"):
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match=r"apisec-ai-surface\[mcp\]"):
        mcp_server.build_server()


def test_build_server_registers_both_tools():
    pytest.importorskip("mcp")
    server = mcp_server.build_server()
    assert server.name == "ai-surface"


@pytest.mark.skipif(sys.version_info < (3, 10), reason="mcp needs 3.10+")
def test_protocol_roundtrip(state_dir, repo, tmp_path):
    """Launch `ai-surface mcp` as a real stdio subprocess and call both tools."""
    pytest.importorskip("mcp")
    client = tmp_path / "client.py"
    client.write_text(
        '''
import asyncio, json, os, sys
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from ai_surface.cli import app; app()", "mcp"],
        env=dict(os.environ),
    )
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            names = sorted(t.name for t in tools.tools)
            r1 = await s.call_tool("check_new_ai_surface", {"path": sys.argv[1]})
            r2 = await s.call_tool("scan_ai_surface", {"path": sys.argv[1], "max_surfaces": 1})
            sc1 = getattr(r1, "structured_content", None) or getattr(r1, "structuredContent", None)
            sc2 = getattr(r2, "structured_content", None) or getattr(r2, "structuredContent", None)
            print(json.dumps({"tools": names, "first": sc1, "scan": sc2}))

asyncio.run(main())
'''
    )
    proc = subprocess.run(
        [sys.executable, str(client), str(repo)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data["tools"] == ["check_new_ai_surface", "scan_ai_surface"]
    assert data["first"]["baseline_created"] is True
    assert data["scan"]["total_surfaces"] >= 1
    assert len(data["scan"]["surfaces"]) == 1
