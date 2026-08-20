"""Risk-flag definitions for the MCP deep-dive audit.

Ported from mcp-audit (``mcp_audit/data/risk_definitions.py``). Each flag
carries an ai-surface ``severity`` (critical|high|medium|low), a plain-English
``description`` and short ``remediation`` guidance. Static and offline.

The ``mcp_audit`` detector turns each emitted flag id into an ``audit`` block
``RiskFlag`` using this table for severity/description/remediation and
:mod:`owasp_llm` for OWASP ids.
"""
from __future__ import annotations

from typing import Any

RISK_FLAGS: dict[str, dict[str, Any]] = {
    "shell-access": {
        "severity": "critical",
        "description": (
            "MCP can execute shell commands on the host. Prompt injection could "
            "run arbitrary commands."
        ),
        "remediation": (
            "Remove shell access unless required; if needed, restrict to an "
            "allowlist of commands and run in a sandbox."
        ),
    },
    "unsafe-command-allowlist": {
        "severity": "critical",
        "description": (
            "MCP is configured with a command allowlist (e.g. ALLOW_COMMANDS) that "
            "names a binary with its own argument-level execution primitive. "
            "Checking argv[0] alone does not restrict execution when the allowlisted "
            "binary can be told to run arbitrary commands (git -c alias, find -exec, "
            "python -c)."
        ),
        "remediation": (
            "Do not rely on binary-name allowlists alone; allowlist the full argument "
            "vector, strip dangerous flags (-c, -exec, -e, --checkpoint-action), or run "
            "the binary in a sandbox with no ambient credentials or network access."
        ),
    },
    "filesystem-access": {
        "severity": "high",
        "description": (
            "MCP can read/write files on the host. Could leak sensitive files or "
            "modify system configuration."
        ),
        "remediation": (
            "Restrict to specific directories; use read-only mode where possible; "
            "never expose home or system paths."
        ),
    },
    "filesystem-write": {
        "severity": "critical",
        "description": (
            "MCP can write files to the host. Could modify configs, drop malware, "
            "or corrupt data."
        ),
        "remediation": (
            "Remove write access unless required; restrict to a sandboxed "
            "directory and restrict file types."
        ),
    },
    "database-access": {
        "severity": "high",
        "description": (
            "MCP can query or modify database contents. Could leak sensitive data "
            "or corrupt records."
        ),
        "remediation": (
            "Use read-only, least-privilege credentials scoped to specific "
            "tables/schemas; never use admin credentials."
        ),
    },
    "network-access": {
        "severity": "medium",
        "description": (
            "MCP can make outbound network requests. Could enable SSRF or data "
            "exfiltration."
        ),
        "remediation": (
            "Restrict to an allowlist of domains/IPs; block internal ranges; "
            "monitor outbound traffic."
        ),
    },
    "secrets-detected": {
        "severity": "critical",
        "description": (
            "API keys, tokens, or passwords are present in the MCP configuration."
        ),
        "remediation": (
            "Rotate the exposed credential immediately; move secrets to a secrets "
            "manager and reference by name only."
        ),
    },
    "secrets-in-env": {
        "severity": "high",
        "description": (
            "Environment variables in the config appear to hold sensitive "
            "credentials."
        ),
        "remediation": (
            "Use a secrets manager instead of plain env values; keep config files "
            "out of version control; rotate exposed credentials."
        ),
    },
    "unverified-source": {
        "severity": "medium",
        "description": (
            "MCP is not from a known/verified publisher; its behaviour and "
            "security posture are unknown."
        ),
        "remediation": (
            "Review the source before use; prefer official/verified MCPs; run "
            "unverified MCPs in isolation."
        ),
    },
    "local-binary": {
        "severity": "medium",
        "description": (
            "MCP runs a local binary or script whose behaviour depends on a file "
            "that may have been modified."
        ),
        "remediation": (
            "Verify binary integrity with checksums/signatures and restrict write "
            "access to the binary location."
        ),
    },
    "inferred-capability": {
        "severity": "low",
        "description": (
            "Capability was inferred from patterns, not explicitly declared; actual "
            "behaviour may differ."
        ),
        "remediation": "Review the MCP source to confirm actual capabilities.",
    },
    "admin-credentials": {
        "severity": "critical",
        "description": (
            "MCP is configured with admin-level credentials, granting excessive "
            "permissions."
        ),
        "remediation": (
            "Replace with scoped, least-privilege credentials via a dedicated "
            "service account."
        ),
    },
    "duplicate-capability": {
        "severity": "low",
        "description": (
            "Multiple MCPs provide the same capability, expanding attack surface "
            "unnecessarily."
        ),
        "remediation": "Consolidate to a single trusted MCP per capability.",
    },
    "remote-mcp": {
        "severity": "medium",
        "description": (
            "MCP connects to a remote server via URL; server security and "
            "availability affect trust."
        ),
        "remediation": (
            "Verify the remote server is trusted; require HTTPS and validate "
            "certificates."
        ),
    },
    # ai-surface deep-dive additions (no mcp-audit equivalent flag id, but the
    # discovery layer already surfaces these as plain risk_indicators).
    "financial-action": {
        "severity": "high",
        "description": "MCP exposes financial tools (refund, charge, payout) to the model.",
        "remediation": "Gate financial tools behind human approval.",
    },
    "broad-permissions": {
        "severity": "medium",
        "description": (
            "MCP is granted broad permissions (admin/write/delete/wildcard scopes)."
        ),
        "remediation": "Scope permissions to the minimum the workflow requires.",
    },
}

_UNKNOWN_FLAG = {
    "severity": "medium",
    "description": "Unrecognised risk flag; review MCP configuration manually.",
    "remediation": "Review MCP configuration and capabilities manually.",
}


def get_risk_flag_info(flag: str) -> dict[str, Any]:
    """Return the static info for ``flag`` (severity/description/remediation)."""
    return RISK_FLAGS.get(flag, _UNKNOWN_FLAG)


def get_severity_for_flag(flag: str) -> str:
    """Return the ai-surface severity for ``flag`` (defaults to ``medium``)."""
    return RISK_FLAGS.get(flag, _UNKNOWN_FLAG)["severity"]


__all__ = ["RISK_FLAGS", "get_risk_flag_info", "get_severity_for_flag"]
