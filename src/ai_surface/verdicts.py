"""Classify each finding's verdict: confirmed risk vs likely risk.

"Confirmed" is reserved for risks that are unambiguous facts of the code or
config as written: a capability the config declares (shell access, a financial
tool in an agent's toolset), a secret name present in an env block, a declared
remote MCP endpoint. Re-reading the same files reaches the same conclusion;
there is nothing to second-guess.

"Likely" covers everything inferred: pattern matches (a PII-shaped variable
flowing into a prompt), reputation signals (unverified publisher), and
absence-of-signal findings (no observability wired, no oversight gate found).
These are real risks, but a human or a runtime test can overturn them, so the
tool says so.

A verdict never claims runtime exploitability. Proving that a confirmed
surface is actually exploitable against the running application is exactly the
question the scan cannot answer; that is what the validate-runtime disposition
and the platform bridges exist for.

Findings with no risk signal at all (pure inventory) get no verdict; absence
of a verdict is meaningful, the same way absence of severity is.
"""
from __future__ import annotations

from .types import VERDICT_CONFIRMED, VERDICT_LIKELY, Finding

#: Risk-flag ids whose presence is a declared, re-checkable fact of the
#: code/config itself. Capabilities the config states, secrets whose names are
#: literally present, endpoints the config points at.
CONFIRMED_FLAGS = {
    "shell-access",
    "filesystem-access",
    "filesystem-write",
    "database-access",
    "network-access",
    "secrets-detected",
    "secrets-in-env",
    "admin-credentials",
    "remote-mcp",
    "financial-action",
    "destructive-action",
    "messaging-action",
    "broad-permissions",
    "high-blast-radius",
    "excessive-agency",
    "unsafe-command-allowlist",
}

#: Flags that are inference, reputation, or absence-of-signal. Named explicitly
#: (rather than "everything else") so a new flag id fails loudly in tests
#: instead of silently defaulting.
LIKELY_FLAGS = {
    "unverified-source",
    "local-binary",
    "inferred-capability",
    "duplicate-capability",
    "pii-to-llm",
    "no-human-oversight",
    "no-observability",
}


def verdict_for(finding: Finding) -> str | None:
    """Return the verdict for one finding, or None for pure inventory."""
    audit = finding.audit
    if audit is not None:
        # A detected secret is a name present in the tree: always a fact.
        if audit.secrets:
            return VERDICT_CONFIRMED
        if any(rf.flag in CONFIRMED_FLAGS for rf in audit.risk_flags):
            return VERDICT_CONFIRMED
        if audit.risk_flags:
            return VERDICT_LIKELY

    # Discovery-layer signal without a deep-dive audit: risk indicators are
    # plain-English pattern observations, so the honest ceiling is "likely".
    if finding.risk_indicators or finding.severity:
        return VERDICT_LIKELY
    return None


def attach_verdicts(findings: list[Finding]) -> None:
    """Set verdicts in place. Idempotent: skips findings already classified."""
    for f in findings:
        if f.verdict is None:
            f.verdict = verdict_for(f)
