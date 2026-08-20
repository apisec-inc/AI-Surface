"""OWASP LLM Top 10 (2025) mappings for the MCP deep-dive audit.

Ported from mcp-audit (``mcp_audit/data/owasp_llm.py``). Maps MCP risk flags
to OWASP LLM Top 10 ids so each ``RiskFlag`` can carry its ``owasp`` list and
the ``Audit`` can expose a flattened ``owasp_mappings`` badge set.

Reference: https://genai.owasp.org/llm-top-10/
"""
from __future__ import annotations

# OWASP LLM Top 10 (2025) ids used by MCP mappings, with display names.
OWASP_LLM_TOP_10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Overreliance",
    "LLM10": "Unbounded Consumption",
}

# Per-flag OWASP id mapping. Mirrors mcp-audit's get_owasp_llm_for_risk_flag.
FLAG_TO_OWASP: dict[str, list[str]] = {
    "database-access": ["LLM06"],
    "shell-access": ["LLM06"],
    "filesystem-access": ["LLM06"],
    "filesystem-write": ["LLM06"],
    "network-access": ["LLM06"],
    "unsafe-command-allowlist": ["LLM06"],
    "secrets-in-env": ["LLM02", "LLM07"],
    "secrets-detected": ["LLM02", "LLM07"],
    "admin-credentials": ["LLM02", "LLM06"],
    "unverified-source": ["LLM03"],
    "local-binary": ["LLM03"],
    "remote-mcp": ["LLM03", "LLM10"],
    # ai-surface deep-dive additions.
    "financial-action": ["LLM06"],
    "broad-permissions": ["LLM06"],
    "no-human-oversight": ["LLM06", "LLM09"],
    "pii-to-llm": ["LLM02"],
}


def get_owasp_for_flag(flag: str) -> list[str]:
    """Return the OWASP LLM ids a risk flag maps to (possibly empty)."""
    return list(FLAG_TO_OWASP.get(flag, []))


def owasp_name(owasp_id: str) -> str:
    """Return the human display name for an OWASP LLM id (or the id itself)."""
    return OWASP_LLM_TOP_10.get(owasp_id, owasp_id)


__all__ = ["OWASP_LLM_TOP_10", "FLAG_TO_OWASP", "get_owasp_for_flag", "owasp_name"]
