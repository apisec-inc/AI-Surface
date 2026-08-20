"""Tests for unsafe-command-allowlist detection (argv[0] allowlist bypass).

Ported from mcp-audit. Detects command allowlists (e.g. ALLOW_COMMANDS) that
name a binary with its own argument-level execution primitive, which makes the
argv[0]-only allowlist bypassable (git -c alias, find -exec, python -c).
"""
from __future__ import annotations

from ai_surface.data.mcp.allowlist_bypass_binaries import (
    detect_unsafe_command_allowlist,
    is_allowlist_env_key,
)


# --- true positives ---------------------------------------------------------- #
def test_bare_risky_binary_flags():
    assert detect_unsafe_command_allowlist({"ALLOW_COMMANDS": "git,ls"}) == ["git"]


def test_variant_key_and_separator():
    assert detect_unsafe_command_allowlist({"ALLOWED_COMMANDS": "find;cat"}) == ["find"]


def test_prefixed_key_and_path_form():
    assert detect_unsafe_command_allowlist(
        {"MCP_ALLOW_COMMANDS": "/usr/bin/python"}
    ) == ["python"]


def test_added_shell_and_exec_binaries():
    got = detect_unsafe_command_allowlist({"ALLOW_COMMANDS": "bash,sh,env,xargs,ssh"})
    assert got == ["bash", "env", "sh", "ssh", "xargs"]


def test_mixed_full_command_and_bare_binary():
    # "git status" is a full-argv allowlist (safe); bare "find" is bypassable.
    assert detect_unsafe_command_allowlist({"ALLOW_COMMANDS": "git status, find"}) == [
        "find"
    ]


# --- false positives we must not raise --------------------------------------- #
def test_denylist_key_not_flagged():
    assert detect_unsafe_command_allowlist({"DISALLOW_COMMANDS": "git"}) == []
    assert is_allowlist_env_key("DISALLOW_COMMANDS") is False


def test_deny_and_block_prefixes_not_flagged():
    assert detect_unsafe_command_allowlist({"DENY_COMMANDS": "git"}) == []
    assert detect_unsafe_command_allowlist({"BLOCK_COMMANDS": "find"}) == []


def test_unrelated_toggle_not_flagged():
    # ALLOW_COMMAND_LOGGING is a boolean toggle, not a command list.
    assert detect_unsafe_command_allowlist({"ALLOW_COMMAND_LOGGING": "true"}) == []
    assert is_allowlist_env_key("ALLOW_COMMAND_LOGGING") is False


def test_full_argv_allowlist_not_flagged():
    assert detect_unsafe_command_allowlist({"ALLOW_COMMANDS": "git status"}) == []


def test_clean_allowlist_not_flagged():
    assert detect_unsafe_command_allowlist({"ALLOW_COMMANDS": "ls,cat,echo"}) == []


def test_empty_env():
    assert detect_unsafe_command_allowlist({}) == []
