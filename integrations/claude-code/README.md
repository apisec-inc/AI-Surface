# ai-surface hook for Claude Code

Makes the AI-attack-surface check **automatic and deterministic**. After every
`Edit` / `Write` / `MultiEdit` / `Bash` call, Claude Code runs the hook, which
diffs the AI attack surface against a rolling baseline and, if a change
introduced new surface (a new agent tool, MCP server, LLM call, or exposed
key), feeds that finding back into the session so Claude tells you and can
offer a guard.

This does not depend on the model deciding to check. The hook fires every time.
`Bash` is in the matcher so code changes made through shell commands (sed,
python one-liners, heredocs) are caught too, not just tool-based edits.

## How it works

1. Claude finishes an edit. Claude Code invokes the hook with a JSON payload on
   stdin (it uses `cwd`).
2. The hook runs `ai-surface scan <repo> --baseline -o json` to get the delta.
3. If a surface was added or modified, it prints
   `hookSpecificOutput.additionalContext` describing it — including the
   compliance mapping (OWASP LLM Top 10 IDs and EU AI Act / NIST / ISO clauses)
   joined in from a full scan — which Claude Code injects into the
   conversation, plus a `systemMessage` shown directly to you. Claude then
   reports the finding, attributed to ai-surface.
4. It advances the baseline so each finding is reported once, not on every
   subsequent edit. On the first edit in a repo it just records the baseline and
   stays silent (nothing is "new" relative to pre-existing surface).

On edits that introduce no AI surface it prints nothing and stays out of the way.

## Install

Requires the `ai-surface` CLI on PATH (`pipx install apisec-ai-surface`), or set
`AI_SURFACE_BIN` to its path.

Add the block from `settings.snippet.json` to your Claude Code settings, with the
absolute path to `ai-surface-posttooluse.py`:

- **This project only:** `.claude/settings.json` in the repo root.
- **All projects:** `~/.claude/settings.json`.

Then start `claude`. Project-level hooks prompt for approval on first use;
hooks in your own `~/.claude/settings.json` are active immediately.

## Relationship to the MCP server

- The **MCP server** (`../mcp/`) exposes `scan_ai_surface` /
  `check_new_ai_surface` so the agent *can* call them (model-invoked, soft).
- This **hook** makes the check fire *automatically* after every edit
  (deterministic). Use both: the tools for on-demand queries, the hook for the
  always-on guardrail.

## Notes

- Runs the scan on each matched edit. On very large repos consider scoping the
  matcher or the scan; for typical repos it is fast.
- Editor-agnostic guarantees (independent of Claude Code) live at the git layer:
  a pre-commit hook and the PR GitHub Action catch the same surface regardless of
  which editor wrote the code.
