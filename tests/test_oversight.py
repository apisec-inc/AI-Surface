"""Tests for the human-oversight (approval-gate) audit pass.

EU AI Act Art. 14: high-risk actions should sit behind a human approval gate.
The pass flags a high-risk action finding when no gate is detectable in its
evidence, and stays quiet when a gate is present or there is no high-risk action.
"""
from __future__ import annotations

from ai_surface.oversight import enrich_oversight, has_oversight, oversight_flag
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    Audit,
    Evidence,
    Finding,
    RiskFlag,
)


def _finding(flags: list[RiskFlag], snippet: str = "", files: list[str] | None = None) -> Finding:
    return Finding(
        surface="LangChain Agent: refund_agent",
        category=CATEGORY_AGENT_FRAMEWORK,
        evidence=Evidence(files=files or [], snippet=snippet),
        audit=Audit(
            risk_flags=flags,
            owasp_mappings=sorted({o for f in flags for o in f.owasp}),
        ),
    )


def _financial_flag() -> RiskFlag:
    return RiskFlag("financial-action", SEVERITY_HIGH, "can refund", ["LLM06"], "gate it")


def test_flags_high_risk_action_with_no_gate() -> None:
    f = _finding([_financial_flag()], snippet="def refund(amount): stripe.refund(amount)")
    flag = oversight_flag(f)
    assert flag is not None
    assert flag.flag == "no-human-oversight"
    assert flag.severity == SEVERITY_HIGH
    assert "LLM06" in flag.owasp and "LLM09" in flag.owasp


def test_no_flag_when_gate_in_snippet() -> None:
    f = _finding([_financial_flag()], snippet="if requires_approval: await human_review(req)")
    assert oversight_flag(f) is None


def test_langgraph_interrupt_counts_as_gate() -> None:
    f = _finding([_financial_flag()], snippet="value = interrupt({'action': 'refund'})")
    assert oversight_flag(f) is None


def test_no_flag_without_high_risk_action() -> None:
    low = RiskFlag("excessive-agency", SEVERITY_MEDIUM, "many tools", ["LLM06"], "")
    f = _finding([low], snippet="no approval here")
    assert oversight_flag(f) is None


def test_no_flag_when_no_audit() -> None:
    f = Finding(surface="x", category=CATEGORY_AGENT_FRAMEWORK, evidence=Evidence())
    assert oversight_flag(f) is None


def test_destructive_and_blast_radius_trigger() -> None:
    for flag_id in ("destructive-action", "high-blast-radius"):
        rf = RiskFlag(flag_id, SEVERITY_HIGH, "danger", ["LLM06"], "")
        assert oversight_flag(_finding([rf], snippet="plain code")) is not None


def test_enrich_is_idempotent_and_updates_audit() -> None:
    f = _finding([_financial_flag()], snippet="plain code, no gate")
    findings = [f]
    enrich_oversight(findings)
    enrich_oversight(findings)  # second pass must not duplicate
    flags = [rf.flag for rf in f.audit.risk_flags]
    assert flags.count("no-human-oversight") == 1
    assert f.severity == SEVERITY_HIGH
    assert "LLM09" in f.audit.owasp_mappings


def test_reads_gate_from_evidence_file(tmp_path) -> None:
    src = tmp_path / "agent.py"
    src.write_text("def refund(x):\n    if not human_approval():\n        return\n    stripe.refund(x)\n")
    # Snippet alone has no gate; the gate lives in the file the finding points to.
    f = _finding([_financial_flag()], snippet="stripe.refund(x)", files=["agent.py"])
    assert oversight_flag(f, str(tmp_path)) is None
    # Without scan_root, only the snippet is seen, so the gate is missed and it flags.
    assert oversight_flag(f, None) is not None


def test_flags_when_evidence_file_has_no_gate(tmp_path) -> None:
    src = tmp_path / "agent.py"
    src.write_text("def refund(x):\n    stripe.refund(x)\n")
    f = _finding([_financial_flag()], snippet="stripe.refund(x)", files=["agent.py"])
    assert oversight_flag(f, str(tmp_path)) is not None


def test_has_oversight_helper() -> None:
    assert has_oversight("needs_approval = True")
    assert has_oversight("HumanInterrupt()")
    assert not has_oversight("just some code")
    assert not has_oversight("")


# --- cleared-risk support: the indicator mirrors the flag, and a detected gate
# --- rewrites the action flags' remediation instead of repeating "gate it".

def test_enrich_adds_indicator_when_no_gate() -> None:
    from ai_surface.oversight import OVERSIGHT_INDICATOR

    f = _finding([_financial_flag()], snippet="def refund(amount): stripe.refund(amount)")
    enrich_oversight([f])
    assert OVERSIGHT_INDICATOR in f.risk_indicators
    assert any(rf.flag == "no-human-oversight" for rf in f.audit.risk_flags)
    # Idempotent on a second pass.
    enrich_oversight([f])
    assert f.risk_indicators.count(OVERSIGHT_INDICATOR) == 1


def test_enrich_marks_action_flags_as_gated_when_gate_present() -> None:
    from ai_surface.oversight import OVERSIGHT_INDICATOR

    f = _finding([_financial_flag()], snippet="if requires_approval: await human_review(req)")
    enrich_oversight([f])
    assert OVERSIGHT_INDICATOR not in f.risk_indicators
    assert not any(rf.flag == "no-human-oversight" for rf in f.audit.risk_flags)
    fin = next(rf for rf in f.audit.risk_flags if rf.flag == "financial-action")
    assert "Approval gate detected" in fin.remediation
    assert fin.severity == SEVERITY_HIGH  # severity is not downgraded by a gate
