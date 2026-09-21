# Editor and agent integrations

`ai-surface` can run inside the AI coding tools that write your code, so a new agent tool, MCP server, or LLM call is flagged at the moment it is created rather than at PR time. Two pieces ship in the package:

- the **MCP server** (`ai-surface mcp`), for any MCP client
- the **Claude Code hook** (`ai-surface hook claude-code`), for automatic post-edit checks

Both are local, offline, and read-only. Nothing about your code leaves the machine. The pre-commit hook and the GitHub Action remain the editor-agnostic guarantees; these integrations add the in-the-loop moment.

## Contents

- [One-command setup for Claude Code](#one-command-setup-for-claude-code)
- [The MCP server](#the-mcp-server)
- [The Claude Code hook](#the-claude-code-hook)
- [Where state is kept](#where-state-is-kept)
- [Other clients: Cursor, Windsurf, Cline](#other-clients-cursor-windsurf-cline)
- [Troubleshooting](#troubleshooting)

## One-command setup for Claude Code

```bash
pip install "apisec-ai-surface[mcp]"   # or: pipx install "apisec-ai-surface[mcp]"
cd your-repo
ai-surface init --claude-code
```

This writes two project-scoped entries and merges with anything already present:

- `.claude/settings.json`: a `PostToolUse` hook (matcher `Edit|Write|MultiEdit|NotebookEdit|Bash`) and a `SessionStart` hook, both running `ai-surface hook claude-code`
- `.mcp.json`: the `ai-surface` server as `ai-surface mcp`

Re-running is safe; existing entries are detected and left alone. Start `claude` in the repo and approve the project hook and MCP server when prompted. Commit both files if you want the whole team to get the same setup.

`ai-surface` must be on the `PATH` that Claude Code inherits. A `pipx` install satisfies this. If you installed into a virtual environment, either activate it before starting `claude` or replace `ai-surface` in the two files with the absolute path to the binary.

The `[mcp]` extra is only needed for the MCP server and requires Python 3.10 or newer. The hook works on any supported Python with no extra.

## The MCP server

`ai-surface mcp` speaks the Model Context Protocol over stdio. The client launches it as a subprocess; there is no port, no network listener, and no credential. It supports both the 2.x and 1.x `mcp` SDKs.

### `scan_ai_surface(path=".", max_surfaces=50)`

Static inventory of the AI attack surface at `path`. Returns:

| Field | Meaning |
|---|---|
| `total_surfaces` | Number of surfaces found |
| `by_category`, `by_severity` | Counts (severity only where an audit assessed the finding) |
| `confirmed_count`, `likely_count` | Verdict counts |
| `top_risks` | Up to 8 severity-ordered risk phrases |
| `governance_frameworks` | Frameworks this scan produces evidence for |
| `surfaces` | The highest-severity surfaces, capped by `max_surfaces`, each with `severity`, `verdict`, `risk_indicators`, `files`, `permissions`, and a `compliance` block |
| `surfaces_truncated` | Present when the cap cut the list; raise `max_surfaces` to see more |
| `resolved_path` | The absolute directory that was scanned |
| `runtime_note` | Reminder that static findings are not proof of runtime exploitability |

Each `compliance` entry has `flag`, `severity`, `description`, `owasp` (LLM Top 10 ids), `standards` (for example `EU AI Act Art. 9`, `NIST AI RMF MEASURE 3`, `ISO 42001 A.6.2.6`), and `remediation`.

### `check_new_ai_surface(path=".", baseline_file=None)`

Reports only what changed. Without `baseline_file` it uses a rolling baseline: the first call records it and returns `baseline_created`; each later call returns the delta since the previous call and then advances the baseline, so a change is reported once. Returns `new_surfaces`, `modified_surfaces` (with `permissions_added`, `risks_added`, and so on), `removed_surfaces`, `changed`, `total_changes`, and `summary`. New and modified entries carry the same `compliance` block as a scan.

With `baseline_file` (absolute, or relative to `path`) it compares against that file and does not modify it. Use this to ask "what is new versus the committed CI baseline?".

A bad path returns `{"path": ..., "error": ...}` rather than a protocol error, so the agent can recover.

### Relationship to the hook

MCP tools are model-invoked: the agent decides when to call them, guided by the tool descriptions. The hook is deterministic: it runs after every edit whether or not the model thinks to check. Use both.

## The Claude Code hook

`ai-surface hook claude-code` reads the hook payload Claude Code sends on stdin and handles two events.

**`SessionStart`.** Scans the repository and records the session baseline, silently. This is what lets the very first edit that adds AI surface be caught.

**`PostToolUse`.** For `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, and `Bash` (the last so shell-driven edits cannot slip past), it scans the repository root once, diffs against the rolling baseline, and advances the baseline. If the change added a surface or added permissions or risks to an existing one, it prints:

```json
{
  "systemMessage": "🛡️ ai-surface: new AI attack surface detected by this edit",
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "ai-surface (automatic post-edit check) detected AI attack surface introduced by this change:\n- MODIFIED: LangChain Agent: support_agent (agent-framework)  permissions added: refund_payment  risk added: financial action exposed  [maps to: OWASP LLM06; EU AI Act Art. 9]\n..."
  }
}
```

Claude Code shows the `systemMessage` to you and injects the `additionalContext` into the conversation, so Claude reports the finding, attributed to ai-surface, and can offer a guard such as a human approval step before a financial tool runs.

Guarantees:

- Prints nothing when the edit introduced no AI surface. Removed surfaces are not reported.
- Always exits 0. Any internal error is noted on stderr and otherwise ignored, so the hook can never break a tool call.
- Refuses to scan a home directory or a filesystem root, which is what `cwd` would be if Claude Code were started there.
- Scans once per edit, in-process. A typical repository scans in well under a second.
- Never writes inside the repository.

`ai-surface hook claude-code --reset` forgets the rolling baseline for the current repo. The next `SessionStart` (or the next edit) records a fresh one.

If you prefer to write the config by hand, the snippet is:

```json
{
  "hooks": {
    "PostToolUse": [
      { "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
        "hooks": [ { "type": "command", "command": "ai-surface hook claude-code" } ] }
    ],
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "ai-surface hook claude-code" } ] }
    ]
  }
}
```

Put it in `.claude/settings.json` for one repo, or `~/.claude/settings.json` for every repo.

## Where state is kept

The rolling baselines are stored outside your repositories, keyed by repository path and namespaced per integration:

| Platform | Location |
|---|---|
| Linux, macOS | `$XDG_CACHE_HOME/ai-surface/` or `~/.cache/ai-surface/` |
| Windows | `%LOCALAPPDATA%\ai-surface\` |
| Any | `AI_SURFACE_STATE_DIR` overrides the above |

Inside: `claude-code-hook/<repo-key>.json` and `mcp/<repo-key>.json`. Deleting a file resets that baseline. These files are separate from a committed `.ai-surface-baseline.json`, which stays under your review as a CI control and is never touched by the integrations.

## Other clients: Cursor, Windsurf, Cline

Register the server as a stdio command. For Cursor, `.cursor/mcp.json`:

```json
{ "mcpServers": { "ai-surface": { "command": "ai-surface", "args": ["mcp"] } } }
```

Windsurf and Cline use the same shape in their own MCP config files. Once registered, ask the assistant to "check the AI attack surface I just added" or "scan this repo's AI attack surface"; the tool descriptions steer it to the right call. Automatic post-edit checks are a Claude Code hook feature today; for other editors, the git pre-commit hook gives the same guarantee at commit time.

## Troubleshooting

**The hook never says anything.** Confirm `ai-surface` resolves on the PATH Claude Code inherits (`which ai-surface` in the same shell you start `claude` from). Then run it by hand:

```bash
echo '{"hook_event_name":"PostToolUse","tool_name":"Edit","cwd":"'"$PWD"'"}' | ai-surface hook claude-code
```

It prints nothing when there is no new surface. To force a report, delete the baseline with `--reset`, run once (silent, records), add an agent tool, and run again.

**`ai-surface mcp` exits with "needs the 'mcp' package".** Install the extra on Python 3.10 or newer: `pip install "apisec-ai-surface[mcp]"`.

**The MCP tool reports nothing changed after an edit.** The hook and the MCP tool keep separate baselines, so one cannot hide the other's changes. Check that `path` points at the directory you edited; the result's `resolved_path` shows what was scanned.

**A large monorepo makes edits feel slow.** The hook scans the git root on each edit. Use `AI_SURFACE_STATE_DIR` and a narrower matcher, or start `claude` from the sub-project you are working in when it is not a git root.
