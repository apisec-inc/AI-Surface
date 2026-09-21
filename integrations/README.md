# Integrations

The MCP server and the Claude Code hook ship inside the package; there is
nothing to copy from this folder.

```bash
pip install "apisec-ai-surface[mcp]"
ai-surface init --claude-code      # writes .claude/settings.json + .mcp.json for this repo
ai-surface mcp                     # the MCP server (stdio), for any MCP client
ai-surface hook claude-code        # the Claude Code PostToolUse / SessionStart hook
```

Reference and troubleshooting: [docs/INTEGRATIONS.md](../docs/INTEGRATIONS.md).

The files here are copy-paste examples for clients that are configured by hand:

- `claude-code.settings.example.json`: what `ai-surface init --claude-code` writes into `.claude/settings.json`
- `mcp.example.json`: the server entry for `.mcp.json` (Claude Code), `.cursor/mcp.json` (Cursor), and the equivalent Windsurf / Cline files
