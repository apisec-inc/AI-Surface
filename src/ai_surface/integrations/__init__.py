"""Editor and agent integrations: the MCP server and the Claude Code hook.

Both are thin shells over :mod:`ai_surface.integrations.core`, which owns the
in-process scan, the rolling-baseline state, and the result shaping. Keeping
the logic in one place means the MCP tools and the hook always agree on what
"new AI surface" means and always carry the same compliance mapping.
"""
