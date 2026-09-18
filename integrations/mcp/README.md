# ai-surface MCP server

Exposes ai-surface as Model Context Protocol tools so any MCP client (Claude
Code, Cursor, Windsurf, Cline) can inventory the AI attack surface of code it
is writing, and flag NEW surface introduced by a change, at the moment of
creation.

Transport is stdio: the client launches the server as a local subprocess. There
is no network listener and no credentials; scans are read-only and fully
offline, so nothing about your code leaves the machine.

## Tools

- **`scan_ai_surface(path)`** — full static inventory: LLM SDK calls, agents
  and their tools, MCP servers, RAG / vector stores, model gateways, provider
  keys, and the API endpoints that expose them. Each finding carries severity,
  risk indicators, and a compliance block (OWASP LLM Top 10 IDs, EU AI Act /
  NIST AI RMF / ISO 42001 clauses, remediation).
- **`check_new_ai_surface(path)`** — diff against a stored baseline and report
  only what is NEW, MODIFIED, or REMOVED. First run records the baseline;
  re-run after edits to see the delta, including permissions and risks added
  and their compliance mapping.

## Install

Requires the `ai-surface` CLI (`pipx install apisec-ai-surface`) and the `mcp`
package in the server's Python environment.

Register the server with your client. For Claude Code, a project `.mcp.json`:

```json
{
  "mcpServers": {
    "ai-surface": {
      "command": "python3",
      "args": ["/ABSOLUTE/PATH/TO/integrations/mcp/server.py"],
      "env": { "AI_SURFACE_BIN": "/ABSOLUTE/PATH/TO/ai-surface" }
    }
  }
}
```

`AI_SURFACE_BIN` is optional: without it the server uses the `ai-surface`
installed alongside its interpreter, then falls back to PATH.

## Relationship to the Claude Code hook

The MCP tools are model-invoked (the agent decides to call them). The
PostToolUse hook in `../claude-code/` makes the check fire automatically after
every edit. Use both: the tools for on-demand queries, the hook for the
always-on guardrail.
