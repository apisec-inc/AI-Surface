"""Claude Code hook: automatic, deterministic AI-surface check after edits.

Wire ``ai-surface hook claude-code`` as a ``PostToolUse`` hook (matcher
``Edit|Write|MultiEdit|NotebookEdit|Bash``) and as a ``SessionStart`` hook.

- ``SessionStart``: records the repository's current AI surface as the
  session baseline, silently, so the very first edit that adds surface is
  caught.
- ``PostToolUse``: diffs the current surface against the rolling baseline.
  If the change introduced or expanded AI surface, prints a JSON object with
  ``hookSpecificOutput.additionalContext`` (injected into the session) and a
  ``systemMessage`` (shown to the user). Otherwise prints nothing.

The hook never fails the tool call: every internal error exits 0 and stays
silent (a note goes to stderr). The baseline lives outside the repository,
under the per-user state directory, so it never touches a committed
``.ai-surface-baseline.json``.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from . import core

#: Tools whose calls can change files. Others are ignored even if matched.
MUTATING_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit", "Bash"})

ATTRIBUTION_LINE = "\U0001f6e1️ **ai-surface** detected new AI attack surface:"
CLEARED_LINE = "\U0001f6e1️ **ai-surface** confirmed a risk is cleared:"


def repo_root(cwd: str) -> Path:
    """Git top-level for ``cwd`` when available, else ``cwd`` itself."""
    try:
        proc = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        top = proc.stdout.strip()
        if proc.returncode == 0 and top:
            return Path(top)
    except Exception:  # noqa: BLE001 - git missing or broken: fall back
        pass
    return Path(cwd)


def _refs(flags: Optional[list[dict[str, Any]]]) -> list[str]:
    """Deduplicated OWASP ids and framework clauses from medium+ flags."""
    refs: list[str] = []
    for fl in flags or []:
        if fl.get("severity") not in ("critical", "high", "medium"):
            continue
        refs.extend(f"OWASP {o}" for o in fl.get("owasp") or [])
        refs.extend(fl.get("standards") or [])
    return list(dict.fromkeys(refs))


def _fmt_new(f: dict[str, Any]) -> str:
    tools = f.get("exposes_tools") or f.get("permissions") or []
    line = f"- ADDED: {f.get('surface')} ({f.get('category')})"
    if tools:
        line += f"  exposes: {', '.join(tools[:8])}"
    if f.get("risk_indicators"):
        line += f"  [risk: {', '.join(f['risk_indicators'])}]"
    refs = _refs(f.get("compliance"))
    if refs:
        line += f"  [maps to: {'; '.join(refs)}]"
    return line


def _fmt_modified(c: dict[str, Any]) -> str:
    line = f"- MODIFIED: {c.get('surface')} ({c.get('category')})"
    if c.get("permissions_added"):
        line += f"  permissions added: {', '.join(c['permissions_added'])}"
    if c.get("risks_added"):
        line += f"  risk added: {', '.join(c['risks_added'])}"
    refs = _refs(c.get("compliance"))
    if refs:
        line += f"  [maps to: {'; '.join(refs)}]"
    return line


def _fmt_cleared(c: dict[str, Any]) -> str:
    line = f"- CLEARED: {c.get('surface')} ({c.get('category')})"
    line += f"  risk cleared: {', '.join(c['risks_removed'])}"
    if c.get("permissions_removed"):
        line += f"  permissions removed: {', '.join(c['permissions_removed'])}"
    return line


def _introduced(result: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    added = result.get("new_surfaces") or []
    modified = [
        c for c in (result.get("modified_surfaces") or [])
        if c.get("permissions_added") or c.get("risks_added")
    ]
    return added, modified


def _cleared(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in (result.get("modified_surfaces") or []) if c.get("risks_removed")]


def build_context(result: dict[str, Any]) -> Optional[str]:
    """Turn a shaped diff into the context injected into the session.

    Returns ``None`` when the change neither introduced nor cleared anything
    worth reporting. Removed surfaces are not reported on their own: the hook
    exists to catch additions, and to confirm when a flagged risk is cleared.
    """
    added, modified = _introduced(result)
    cleared = _cleared(result)
    if added or modified:
        lines = [_fmt_new(f) for f in added] + [_fmt_modified(c) for c in modified]
        text = (
            "ai-surface (automatic post-edit check) detected AI attack surface "
            "introduced by this change:\n"
            + "\n".join(lines)
            + "\nStatic analysis maps this surface; confirming whether it is "
            "exploitable against the running app needs runtime testing. Tell the "
            "user about this new surface. If it involves a financial or destructive "
            "action, outbound messaging, or broad permissions, offer to add a "
            "human-in-the-loop approval step before they commit. Begin your report "
            f"to the user with the exact line '{ATTRIBUTION_LINE}' so the finding is "
            "clearly attributed to ai-surface."
        )
        if cleared:
            text += "\nThe same change also cleared:\n" + "\n".join(_fmt_cleared(c) for c in cleared)
        return text
    if cleared:
        return (
            "ai-surface (automatic post-edit check) confirmed that this change "
            "cleared a previously flagged risk:\n"
            + "\n".join(_fmt_cleared(c) for c in cleared)
            + "\nTell the user which risk is cleared and on which surface. Static "
            "analysis can see the gate on the path; whether it holds against the "
            "running app still needs runtime testing. Begin your report to the user "
            f"with the exact line '{CLEARED_LINE}' so the confirmation is clearly "
            "attributed to ai-surface."
        )
    return None


def system_message(result: dict[str, Any]) -> str:
    """The one-line banner shown to the user for a reportable change."""
    added, modified = _introduced(result)
    if added or modified:
        return "\U0001f6e1️ ai-surface: new AI attack surface detected by this edit"
    return "\u2705 ai-surface: a flagged risk was cleared by this edit"


def handle(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Process one hook payload. Returns the JSON to print, or ``None``."""
    event = payload.get("hook_event_name") or "PostToolUse"
    cwd = payload.get("cwd") or str(Path.cwd())
    root = repo_root(cwd)
    if core.is_unsafe_root(root):
        return None
    baseline = core.baseline_path_for(root, core.NAMESPACE_HOOK)

    if event == "SessionStart":
        core.write_baseline(core.scan_report(root), baseline)
        return None

    tool = payload.get("tool_name")
    if tool and tool not in MUTATING_TOOLS:
        return None

    result = core.check_new_surface(root, baseline, advance=True)
    if result.get("baseline_created") or result.get("baseline_reset"):
        return None
    ctx = build_context(result)
    if ctx is None:
        return None
    return {
        "systemMessage": system_message(result),
        "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": ctx},
    }


def reset(cwd: Optional[str] = None) -> Path:
    """Delete the rolling baseline for the repo containing ``cwd``."""
    root = repo_root(cwd or str(Path.cwd()))
    baseline = core.baseline_path_for(root, core.NAMESPACE_HOOK)
    if baseline.exists():
        baseline.unlink()
    return baseline


def main(stdin: Any = None, stdout: Any = None) -> int:
    """Entry point used by ``ai-surface hook claude-code``. Always exits 0."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        payload = json.load(stdin)
        if not isinstance(payload, dict):
            return 0
        out = handle(payload)
        if out is not None:
            stdout.write(json.dumps(out, ensure_ascii=False))
            stdout.write("\n")
            stdout.flush()
    except Exception as exc:  # noqa: BLE001 - never break the editor
        print(f"ai-surface hook: skipped ({exc.__class__.__name__}: {exc})", file=sys.stderr)
    return 0
