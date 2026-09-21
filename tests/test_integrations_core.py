"""Tests for the shared integrations engine (state dir, scan, diff shaping)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_surface.integrations import core

AGENT_BEFORE = '''
from langchain.agents import initialize_agent, Tool
tools = [
    Tool(name="lookup_order", func=lambda x: x, description="look up"),
]
support_agent = initialize_agent(tools, None)
'''

AGENT_AFTER = '''
from langchain.agents import initialize_agent, Tool
tools = [
    Tool(name="lookup_order", func=lambda x: x, description="look up"),
    Tool(name="refund_payment", func=lambda x: x, description="refund"),
]
support_agent = initialize_agent(tools, None)
'''

NEW_AGENT = '''
from langchain.agents import initialize_agent, Tool
tools = [
    Tool(name="delete_account", func=lambda x: x, description="d"),
    Tool(name="lookup_user", func=lambda x: x, description="l"),
]
admin_agent = initialize_agent(tools, None)
'''


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


def test_state_dir_honours_override(state_dir):
    assert core.state_dir() == state_dir


def test_state_dir_defaults_outside_any_repo(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_SURFACE_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(core.sys, "platform", "linux")
    assert core.state_dir() == tmp_path / "cache" / "ai-surface"


def test_baseline_path_is_stable_per_repo_and_namespace(state_dir, repo):
    a = core.baseline_path_for(repo, core.NAMESPACE_HOOK)
    b = core.baseline_path_for(repo, core.NAMESPACE_HOOK)
    c = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    assert a == b
    assert a != c
    assert state_dir in a.parents
    # Never inside the scanned repo.
    assert repo not in a.parents


def test_unsafe_roots():
    assert core.is_unsafe_root(Path("/"))
    assert core.is_unsafe_root(Path.home())
    assert not core.is_unsafe_root(Path(__file__).parent)


def test_resolve_root_rejects_files_and_missing(tmp_path):
    with pytest.raises(NotADirectoryError):
        core.resolve_root(str(tmp_path / "missing"))
    f = tmp_path / "f.txt"
    f.write_text("x")
    with pytest.raises(NotADirectoryError):
        core.resolve_root(str(f))


def test_first_call_records_baseline(state_dir, repo):
    bp = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    out = core.check_new_surface(repo, bp, advance=True)
    assert out["baseline_created"] is True
    assert out["recorded_surfaces"] >= 1
    assert bp.is_file()
    data = json.loads(bp.read_text())
    assert data["schema_version"] == "1.0"
    # No file was written into the repo.
    assert not (repo / ".ai-surface-baseline.json").exists()


def test_modified_surface_carries_compliance_standards(state_dir, repo):
    bp = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    core.check_new_surface(repo, bp, advance=True)
    (repo / "src" / "agent.py").write_text(AGENT_AFTER)
    out = core.check_new_surface(repo, bp, advance=True)
    assert out["changed"] is True
    assert out["new_surfaces"] == []
    mod = out["modified_surfaces"]
    assert len(mod) == 1
    assert "refund_payment" in mod[0]["permissions_added"]
    assert "financial action exposed" in mod[0]["risks_added"]
    flags = {c["flag"]: c for c in mod[0]["compliance"]}
    assert "financial-action" in flags
    assert "LLM06" in flags["financial-action"]["owasp"]
    assert "EU AI Act Art. 9" in flags["financial-action"]["standards"]
    # Risks were added, so the runtime caveat is present.
    assert out["runtime_note"]


def test_new_surface_carries_compliance_standards(state_dir, repo):
    """Regression: added entries must get the governance join, not only modified."""
    bp = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    core.check_new_surface(repo, bp, advance=True)
    (repo / "src" / "admin.py").write_text(NEW_AGENT)
    out = core.check_new_surface(repo, bp, advance=True)
    new = out["new_surfaces"]
    assert len(new) == 1
    assert new[0]["severity"] == "high"
    assert new[0]["verdict"] == "confirmed"
    assert "delete_account" in new[0]["permissions"]
    flags = {c["flag"]: c for c in new[0]["compliance"]}
    assert "destructive-action" in flags
    assert flags["destructive-action"]["standards"] == ["EU AI Act Art. 9"]
    assert out["runtime_note"]


def test_baseline_advances_only_when_asked(state_dir, repo):
    bp = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    core.check_new_surface(repo, bp, advance=True)
    (repo / "src" / "agent.py").write_text(AGENT_AFTER)
    first = core.check_new_surface(repo, bp, advance=False)
    again = core.check_new_surface(repo, bp, advance=False)
    assert first["changed"] and again["changed"]
    advanced = core.check_new_surface(repo, bp, advance=True)
    assert advanced["changed"]
    quiet = core.check_new_surface(repo, bp, advance=True)
    assert quiet["changed"] is False
    assert quiet["total_changes"] == 0


def test_unreadable_baseline_is_reset(state_dir, repo):
    bp = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    bp.parent.mkdir(parents=True)
    bp.write_text("{not json")
    out = core.check_new_surface(repo, bp, advance=True)
    assert out["baseline_reset"] is True
    assert json.loads(bp.read_text())["schema_version"] == "1.0"


def test_removed_surface_reported(state_dir, repo):
    bp = core.baseline_path_for(repo, core.NAMESPACE_MCP)
    core.check_new_surface(repo, bp, advance=True)
    (repo / "src" / "agent.py").unlink()
    out = core.check_new_surface(repo, bp, advance=True)
    assert len(out["removed_surfaces"]) >= 1
    assert out["runtime_note"] is None


def test_shape_report_caps_and_ranks(repo):
    (repo / "src" / "admin.py").write_text(NEW_AGENT)
    report = core.scan_report(repo)
    full = core.shape_report(report, ".", max_surfaces=50)
    assert full["total_surfaces"] == len(report.findings)
    assert "surfaces_truncated" not in full
    assert full["runtime_note"]
    capped = core.shape_report(report, ".", max_surfaces=1)
    assert len(capped["surfaces"]) == 1
    assert capped["surfaces_truncated"] == len(report.findings) - 1
    # Highest severity first.
    assert capped["surfaces"][0]["severity"] == "high"
    assert capped["surfaces"][0]["compliance"]


def test_baseline_inside_root_is_skipped_by_scan(state_dir, repo):
    """A user-supplied baseline living in the repo must not poison the scan."""
    bp = repo / "custom-baseline.json"
    core.check_new_surface(repo, bp, advance=True)
    out = core.check_new_surface(repo, bp, advance=False)
    assert out["changed"] is False
