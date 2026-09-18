#!/usr/bin/env python3
"""
ai-surface PostToolUse hook for Claude Code.

Fires automatically after every Edit / Write / MultiEdit. It diffs the current
AI attack surface against a rolling baseline and, if a change introduced or
modified AI surface (a new agent tool, MCP server, LLM call, exposed key), it
returns that finding as additional context so Claude tells the user and can
offer a guard, at the moment of creation, without the model having to remember
to check.

Contract:
- Reads the PostToolUse JSON payload on stdin (uses `cwd`).
- Emits nothing (exit 0) when the edit introduced no new AI surface, so it stays
  quiet on ordinary changes.
- On a real change, prints a single JSON object with hookSpecificOutput
  .additionalContext, which Claude Code injects into the session.

Requires the `ai-surface` CLI on PATH (or AI_SURFACE_BIN set). Pure stdlib.
"""

import json
import os
import shutil
import subprocess
import sys


def _run(ai, args, timeout=120):
    try:
        return subprocess.run([ai, *args], capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _git_root(cwd):
    try:
        r = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() or cwd
    except Exception:
        return cwd


def _audit_map(ai, root):
    """Map surface name -> audit risk_flags from a full scan of the current state.

    The --baseline diff format carries only permission/risk deltas, so the
    compliance mapping (OWASP IDs, framework clauses) has to come from the
    full report and be joined back by surface name.
    """
    proc = _run(ai, ["scan", root, "-o", "json"])
    if not proc or not proc.stdout.strip():
        return {}
    try:
        report = json.loads(proc.stdout)
    except Exception:
        return {}
    out = {}
    for f in report.get("findings") or []:
        flags = (f.get("audit") or {}).get("risk_flags") or []
        if flags:
            out[f.get("surface")] = flags
    return out


def _compliance_refs(flags):
    """Dedup OWASP IDs and framework clauses from medium+ risk flags."""
    refs = []
    for fl in flags or []:
        if fl.get("severity") not in ("high", "medium"):
            continue
        for o in fl.get("owasp") or []:
            refs.append(f"OWASP {o}")
        for s in fl.get("standards") or []:
            refs.append(f"{s.get('framework')} {s.get('clause')}".strip())
    return list(dict.fromkeys(refs))


def _line(kind, f, flags=None):
    surface, cat = f.get("surface"), f.get("category")
    refs = _compliance_refs(flags)
    tail = f"  [maps to: {'; '.join(refs)}]" if refs else ""
    if kind == "modified":
        # diff entry shape: {permissions_added, risks_added, ...}
        parts = [f"- MODIFIED: {surface} ({cat})"]
        perms = ", ".join(f.get("permissions_added") or [])
        risks = ", ".join(f.get("risks_added") or [])
        if perms:
            parts.append(f"permissions added: {perms}")
        if risks:
            parts.append(f"risk added: {risks}")
        return "  ".join(parts) + tail
    # added: full finding shape
    meta = (f.get("evidence") or {}).get("metadata") or {}
    tools = meta.get("tools")
    extra = f" exposes {', '.join(tools)}" if tools else ""
    risks = ", ".join(f.get("risk_indicators") or [])
    s = f"- ADDED: {surface} ({cat}){extra}"
    return s + (f"  [risk: {risks}]" if risks else "") + tail


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    cwd = payload.get("cwd") or os.getcwd()
    ai = os.environ.get("AI_SURFACE_BIN") or shutil.which("ai-surface")
    if not ai:
        return 0  # tool not installed: stay out of the way

    root = _git_root(cwd)
    baseline = os.path.join(root, ".ai-surface-baseline.json")

    # First run in this repo: record the baseline and stay silent. Nothing is
    # "new" relative to a surface that already existed before we started watching.
    if not os.path.exists(baseline):
        _run(ai, ["scan", root, "--update-baseline"])
        return 0

    diff = _run(ai, ["scan", root, "--baseline", "-o", "json"])
    # Advance the baseline so each edit is diffed against the previous state and
    # a finding is reported once, not on every subsequent edit.
    _run(ai, ["scan", root, "--update-baseline"])

    if not diff or not diff.stdout.strip():
        return 0
    try:
        data = json.loads(diff.stdout)
    except Exception:
        return 0

    items = [("added", f) for f in (data.get("added") or [])]
    items += [("modified", f) for f in (data.get("modified") or [])]
    if not items:
        return 0

    audit = _audit_map(ai, root)
    body = "\n".join(_line(k, f, audit.get(f.get("surface"))) for k, f in items)
    ctx = (
        "ai-surface (automatic post-edit check) detected AI attack surface "
        "introduced by this change:\n"
        f"{body}\n"
        "Static analysis maps this surface; confirming whether it is exploitable "
        "against the running app needs runtime testing. Tell the user about this "
        "new surface, and if it involves a financial or destructive action or "
        "broad permissions, offer to add a human-in-the-loop approval step before "
        "they commit. Begin your report to the user with the exact line "
        "'\U0001f6e1️ **ai-surface** detected new AI attack surface:' so the "
        "finding is clearly attributed to ai-surface."
    )
    print(json.dumps({
        "systemMessage": "\U0001f6e1️ ai-surface: new AI attack surface detected by this edit",
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": ctx,
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
