"""Human-oversight (approval-gate) audit pass.

EU AI Act Art. 14 (human oversight): high-risk autonomous actions should sit
behind a human-in-the-loop / approval gate. This pass looks at findings that an
earlier deep-dive audit flagged with a high-risk action (financial, destructive,
or high-blast-radius) and checks the finding's OWN evidence for an approval /
human-in-the-loop pattern. When none is found it adds a ``no-human-oversight``
risk flag.

Design choices that keep this honest:

* Static and conservative. It inspects the finding's evidence snippet plus the
  evidence files the finding already points to. It does NOT scan the whole repo
  per finding, so if a gate lives in a module this finding never references, the
  flag can fire as a false positive. That is the safe direction for an oversight
  control: the remediation explicitly says "if approval is enforced elsewhere,
  confirm the gate is on this path."
* It checks for the *presence of a gate*, not whether the gate is correct.
* It never tests the model. This is a structural code/config check only.

Run after the deep-dive audits exist (agent audit + MCP audit) so both kinds of
finding can be assessed, and before disposition/bridge/summary so the new flag
and its severity flow through.
"""
from __future__ import annotations

import re
from pathlib import Path

from .types import (
    SEVERITY_ORDER,
    Audit,
    Finding,
    RiskFlag,
)
from .utils.walk import read_text_safe

# Audit risk flags that represent a high-risk autonomous action which, under
# Art. 14, should be gated by a human. Capability flags (filesystem/network)
# are deliberately NOT triggers: not every capability is an irreversible action.
_ACTION_FLAGS = frozenset(
    {
        "financial-action",
        "destructive-action",
        "high-blast-radius",
    }
)

# Patterns that indicate a human approval / human-in-the-loop gate. Framework
# agnostic on purpose: LangGraph interrupts, decorators/flags, approval
# middleware, and common naming conventions. Matched case-insensitively against
# the finding's evidence.
_OVERSIGHT_PATTERNS = (
    r"requires?_approval",
    r"approval_required",
    r"needs?_approval",
    r"await_approval",
    r"request_approval",
    r"human[_-]?in[_-]?the[_-]?loop",
    r"human[_-]?review",
    r"human[_-]?approval",
    r"humanapproval",
    r"humaninterrupt",
    r"interrupt_before",
    r"interrupt_after",
    r"nodeinterrupt",
    r"\binterrupt\s*\(",  # langgraph interrupt() call
    r"manual_approval",
    r"approval_gate",
    r"approval_node",
    r"confirmation_required",
    r"require_confirmation",
    r"prompt_for_confirmation",
)

_OVERSIGHT_RE = re.compile("|".join(_OVERSIGHT_PATTERNS), re.IGNORECASE)

# OWASP LLM Top 10 ids the missing-oversight flag maps to: Excessive Agency
# (the action runs unattended) and Overreliance (no human in the decision).
_OVERSIGHT_OWASP = ["LLM06", "LLM09"]

#: Severity-free indicator mirrored onto ``Finding.risk_indicators`` whenever
#: the ``no-human-oversight`` flag is added. Indicators survive the rolling
#: baseline (audit data does not), so this is what lets a later diff report
#: the risk as cleared once an approval gate lands.
OVERSIGHT_INDICATOR = "no human approval gate on a high-risk action"

#: Remediation shown on action flags once a gate IS detected on the path.
_GATED_REMEDIATION = (
    "Approval gate detected on this path. Keep it in front of the action and "
    "least-privilege the agent."
)


def has_oversight(text: str) -> bool:
    """True if ``text`` shows any human approval / human-in-the-loop pattern."""
    return bool(text) and _OVERSIGHT_RE.search(text) is not None


def _evidence_text(finding: Finding, scan_root: str | None) -> str:
    """Collect text to inspect: the evidence snippet plus the evidence files.

    Reads only the files this finding already points to (conservative; no
    repo-wide scan). The snippet is always included so the check still works
    when ``scan_root`` is unavailable (e.g. in-memory fixtures and unit tests).
    """
    parts: list[str] = []
    ev = finding.evidence
    if ev and ev.snippet:
        parts.append(ev.snippet)
    if scan_root and ev and ev.files:
        root = Path(scan_root)
        for rel in ev.files:
            text = read_text_safe(root / rel)
            if text:
                parts.append(text)
    return "\n".join(parts)


def _action_flags(audit: Audit) -> list[str]:
    return [rf.flag for rf in audit.risk_flags if rf.flag in _ACTION_FLAGS]


def oversight_flag(finding: Finding, scan_root: str | None = None) -> RiskFlag | None:
    """Return a ``no-human-oversight`` flag if the finding exposes a high-risk
    action with no detectable approval gate; otherwise ``None``."""
    audit = finding.audit
    if not audit:
        return None
    actions = _action_flags(audit)
    if not actions:
        return None
    if has_oversight(_evidence_text(finding, scan_root)):
        return None
    return RiskFlag(
        flag="no-human-oversight",
        severity="high",
        description=(
            "High-risk action ("
            + ", ".join(sorted(set(actions)))
            + ") runs with no human approval / in-the-loop gate detected"
        ),
        owasp=list(_OVERSIGHT_OWASP),
        remediation=(
            "Put a human-in-the-loop approval step in front of this action "
            "(approval gate, confirmation, or a LangGraph interrupt). If approval "
            "is enforced elsewhere, confirm the gate sits on this path."
        ),
    )


def _bump_severity(finding: Finding) -> None:
    """Roll finding severity up to the max across its audit risk flags."""
    if not finding.audit or not finding.audit.risk_flags:
        return
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sevs = [rf.severity for rf in finding.audit.risk_flags]
    finding.severity = min(sevs, key=lambda s: rank.get(s, 99))


def enrich_oversight(findings: list[Finding], scan_root: str | None = None) -> None:
    """Add ``no-human-oversight`` flags, in place, to findings that need them.

    Updates each affected finding's audit (``risk_flags`` and
    ``owasp_mappings``) and re-rolls ``finding.severity``. Idempotent: skips a
    finding that already carries the flag.
    """
    for f in findings:
        audit = f.audit
        if not audit:
            continue
        if any(rf.flag == "no-human-oversight" for rf in audit.risk_flags):
            continue
        actions = _action_flags(audit)
        if not actions:
            continue
        if has_oversight(_evidence_text(f, scan_root)):
            # A gate is on the path: say so on the action flags instead of
            # repeating "gate it", so a fixed finding does not read as unfixed.
            for rf in audit.risk_flags:
                if rf.flag in _ACTION_FLAGS:
                    rf.remediation = _GATED_REMEDIATION
            continue
        flag = oversight_flag(f, scan_root)
        if not flag:
            continue
        audit.risk_flags.append(flag)
        if OVERSIGHT_INDICATOR not in f.risk_indicators:
            f.risk_indicators.append(OVERSIGHT_INDICATOR)
        for oid in flag.owasp:
            if oid not in audit.owasp_mappings:
                audit.owasp_mappings.append(oid)
        _bump_severity(f)


__all__ = ["has_oversight", "oversight_flag", "enrich_oversight", "OVERSIGHT_INDICATOR"]
