"""Tests for the Claude Code hook (in-process and via the CLI)."""
from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from ai_surface.cli import app
from ai_surface.integrations import claude_code_hook as hook
from ai_surface.integrations import core
from tests.test_integrations_core import AGENT_AFTER, AGENT_BEFORE, NEW_AGENT

runner = CliRunner()


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
    subprocess.run(["git", "init", "-q", str(r)], check=False, capture_output=True)
    return r


def _run(payload):
    out = io.StringIO()
    code = hook.main(stdin=io.StringIO(json.dumps(payload)), stdout=out)
    text = out.getvalue().strip()
    return code, (json.loads(text) if text else None)


def test_session_start_seeds_baseline_silently(state_dir, repo):
    code, out = _run({"hook_event_name": "SessionStart", "cwd": str(repo)})
    assert code == 0 and out is None
    assert core.baseline_path_for(repo, core.NAMESPACE_HOOK).is_file()
    assert not (repo / ".ai-surface-baseline.json").exists()


def test_first_edit_without_session_start_is_silent(state_dir, repo):
    code, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Edit", "cwd": str(repo)})
    assert code == 0 and out is None


def test_edit_that_adds_financial_tool_is_reported_once(state_dir, repo):
    _run({"hook_event_name": "SessionStart", "cwd": str(repo)})
    (repo / "src" / "agent.py").write_text(AGENT_AFTER)
    # cwd inside a subdirectory still resolves to the git root.
    code, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Edit", "cwd": str(repo / "src")})
    assert code == 0
    assert out["systemMessage"].startswith("\U0001f6e1️ ai-surface")
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert "MODIFIED: LangChain Agent: support_agent" in ctx
    assert "permissions added: refund_payment" in ctx
    assert "OWASP LLM06" in ctx and "EU AI Act Art. 9" in ctx
    assert hook.ATTRIBUTION_LINE in ctx
    # Reported once: the baseline advanced.
    code, again = _run({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": str(repo)})
    assert again is None


def test_new_agent_is_reported_with_standards(state_dir, repo):
    _run({"hook_event_name": "SessionStart", "cwd": str(repo)})
    (repo / "src" / "admin.py").write_text(NEW_AGENT)
    _, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Write", "cwd": str(repo)})
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "ADDED: LangChain Agent: admin_agent" in ctx
    assert "exposes: delete_account" in ctx
    assert "EU AI Act Art. 9" in ctx


def test_non_mutating_tool_is_ignored(state_dir, repo):
    _run({"hook_event_name": "SessionStart", "cwd": str(repo)})
    (repo / "src" / "agent.py").write_text(AGENT_AFTER)
    _, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Read", "cwd": str(repo)})
    assert out is None
    # The change is still pending for the next mutating call.
    _, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Edit", "cwd": str(repo)})
    assert out is not None


def test_home_directory_is_never_scanned(state_dir, monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(core.Path, "home", classmethod(lambda cls: home))
    calls = []
    monkeypatch.setattr(core, "scan_report", lambda *a, **k: calls.append(a))
    _, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Edit", "cwd": str(home)})
    assert out is None and calls == []


def test_garbage_input_never_fails(state_dir, capsys):
    out = io.StringIO()
    assert hook.main(stdin=io.StringIO("not json"), stdout=out) == 0
    assert out.getvalue() == ""
    assert "skipped" in capsys.readouterr().err


def test_internal_error_never_fails(state_dir, repo, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(core, "check_new_surface", boom)
    _run({"hook_event_name": "SessionStart", "cwd": str(repo)})
    code, out = _run({"hook_event_name": "PostToolUse", "tool_name": "Edit", "cwd": str(repo)})
    assert code == 0 and out is None


def test_reset_removes_baseline(state_dir, repo, monkeypatch):
    _run({"hook_event_name": "SessionStart", "cwd": str(repo)})
    bp = core.baseline_path_for(repo, core.NAMESPACE_HOOK)
    assert bp.is_file()
    monkeypatch.chdir(repo)
    result = runner.invoke(app, ["hook", "claude-code", "--reset"])
    assert result.exit_code == 0, result.output
    assert not bp.exists()


def test_cli_hook_reads_stdin(state_dir, repo):
    payload = json.dumps({"hook_event_name": "SessionStart", "cwd": str(repo)})
    result = runner.invoke(app, ["hook", "claude-code"], input=payload)
    assert result.exit_code == 0, result.output
    assert core.baseline_path_for(repo, core.NAMESPACE_HOOK).is_file()


def test_cli_hook_as_subprocess_exit_zero_on_bad_input(state_dir):
    proc = subprocess.run(
        [sys.executable, "-c", "from ai_surface.cli import app; app()", "hook", "claude-code"],
        input="garbage",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""
