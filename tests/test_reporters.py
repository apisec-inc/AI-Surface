"""Tests for the reporters."""
from __future__ import annotations

import json

import pytest
from rich.console import Console

from ai_surface.reporters.json_reporter import render_json, report_to_dict
from ai_surface.reporters.markdown_reporter import render_markdown
from ai_surface.reporters.terminal_reporter import render_terminal
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_API,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    Audit,
    Bridge,
    Evidence,
    Finding,
    Report,
    RiskFlag,
    Secret,
)


def _sample_report() -> Report:
    findings = [
        Finding(
            surface="Anthropic SDK",
            category=CATEGORY_LLM_SDK,
            evidence=Evidence(
                files=["src/llm/handler.py", "src/agents/refund.py"],
                snippet="from anthropic import Anthropic",
                metadata={"models_used": ["claude-3-5-sonnet-20241022"], "call_site_count": 3},
            ),
            risk_indicators=["non-literal data flows into LLM call"],
            detector_name="LlmSdkDetector",
        ),
        Finding(
            surface="LangChain Agent: refund_agent",
            category=CATEGORY_AGENT_FRAMEWORK,
            evidence=Evidence(
                files=["src/agents/refund.py"],
                snippet='AgentExecutor(tools=[query_db, refund_payment, send_email])',
                metadata={"framework": "langchain", "agent_name": "refund_agent"},
            ),
            permissions=["query_customer_db", "refund_payment", "send_email", "list_charges"],
            risk_indicators=[
                "financial action exposed",
                "high blast-radius combination",
            ],
            detector_name="AgentFrameworkDetector",
        ),
        Finding(
            surface="MCP Server: stripe-mcp",
            category=CATEGORY_MCP_SERVER,
            evidence=Evidence(
                files=[".mcp.json"],
                snippet='"stripe-mcp": {"capabilities": ["read", "refund"]}',
                metadata={},
            ),
            permissions=["read charges", "refund charges"],
            risk_indicators=["broad permissions"],
            detector_name="McpServerDetector",
        ),
    ]
    return Report(
        findings=findings,
        scan_root="/tmp/example-repo",
        scan_timestamp="2026-05-09T12:00:00+00:00",
        detectors_run=["LlmSdkDetector", "AgentFrameworkDetector", "McpServerDetector"],
    )


def _empty_report() -> Report:
    return Report(
        findings=[],
        scan_root="/tmp/clean-repo",
        scan_timestamp="2026-05-09T12:00:00+00:00",
        detectors_run=["LlmSdkDetector"],
    )


# The literal secret value that must NEVER appear in any rendered report.
LEAKED_SECRET_VALUE = "sk_live_DEADBEEF_must_not_leak"


def _schema1_report() -> Report:
    """A schema-1.0 report exercising severity, audit, the api category, and
    bridges. The audited MCP finding carries a Secret whose NAME/TYPE are set
    but whose value is intentionally absent (privacy guarantee)."""
    mcp = Finding(
        surface="MCP Server: stripe-mcp",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(
            files=[".mcp.json"],
            snippet='"stripe-mcp": {"command": "npx", "args": ["stripe-mcp"]}',
            metadata={},
        ),
        permissions=["create_charge", "refund", "list_customers"],
        risk_indicators=["financial action exposed", "secrets in env block"],
        detector_name="mcp_audit",
        severity=SEVERITY_CRITICAL,
        audit=Audit(
            risk_flags=[
                RiskFlag(
                    flag="secrets-in-env",
                    severity=SEVERITY_CRITICAL,
                    description="Live Stripe secret key present in MCP env block",
                    owasp=["LLM02"],
                    remediation="Move the key to a secrets manager; reference by name only.",
                ),
                RiskFlag(
                    flag="financial-action",
                    severity=SEVERITY_HIGH,
                    description="MCP exposes refund and charge tools to the model",
                    owasp=["LLM06"],
                    remediation="Gate financial tools behind human approval.",
                ),
            ],
            secrets=[
                Secret(
                    name="STRIPE_SECRET_KEY",
                    secret_type="stripe-key",
                    confidence="high",
                    severity=SEVERITY_CRITICAL,
                    location=".mcp.json:env",
                ),
            ],
            trust_score=None,
            trust_label="unknown",
            registry_match="unknown",
            owasp_mappings=["LLM02", "LLM06"],
        ),
        bridges=[
            Bridge(
                sku="mcp-runtime",
                label="Run MCP runtime validation in APIsec",
                url="https://www.apisec.ai/products?category=mcp-server&risk=secrets-in-env",
            ),
        ],
    )
    api = Finding(
        surface="REST API: POST /v1/orders/{id}/refund",
        category=CATEGORY_API,
        evidence=Evidence(
            files=["openapi.yaml"],
            snippet="paths:\n  /v1/orders/{id}/refund:\n    post:",
            line_numbers=[142],
            metadata={
                "method": "POST",
                "path": "/v1/orders/{id}/refund",
                "source_spec": "openapi.yaml",
                "auth": "bearer",
                "framework": "fastapi",
            },
        ),
        permissions=["mutates order state", "financial"],
        risk_indicators=["object-id in path (BOLA candidate)"],
        detector_name="api_endpoints",
        severity=None,
        audit=None,
        bridges=[
            Bridge(
                sku="api-runtime",
                label="Onboard this API for outside-in runtime testing in APIsec",
                url="https://www.apisec.ai/products?path=%2Fv1%2Forders%2F%7Bid%7D%2Frefund",
            ),
        ],
    )
    return Report(
        findings=[mcp, api],
        scan_root="/tmp/acme-payments",
        scan_timestamp="2026-06-11T00:00:00+00:00",
        detectors_run=["mcp_audit", "api_endpoints"],
    )


# ---- JSON reporter ----


def test_json_reporter_produces_valid_json() -> None:
    report = _sample_report()
    rendered = render_json(report)
    parsed = json.loads(rendered)
    assert parsed["schema_version"] == "1.0"
    assert parsed["findings_count"] == 3
    assert len(parsed["findings"]) == 3
    surfaces = [f["surface"] for f in parsed["findings"]]
    assert "Anthropic SDK" in surfaces
    assert "LangChain Agent: refund_agent" in surfaces


def test_json_reporter_preserves_evidence_metadata() -> None:
    report = _sample_report()
    parsed = json.loads(render_json(report))
    anthropic = next(f for f in parsed["findings"] if f["surface"] == "Anthropic SDK")
    assert "claude-3-5-sonnet-20241022" in anthropic["evidence"]["metadata"]["models_used"]


def test_json_reporter_handles_empty_report() -> None:
    parsed = json.loads(render_json(_empty_report()))
    assert parsed["findings_count"] == 0
    assert parsed["findings"] == []


def test_report_to_dict_round_trip() -> None:
    report = _sample_report()
    d = report_to_dict(report)
    json.dumps(d)  # raises if not serializable


# ---- Markdown reporter ----


def test_markdown_reporter_includes_header_and_counts() -> None:
    md = render_markdown(_sample_report())
    assert "# AI Inventory" in md
    assert "Production AI surfaces:" in md
    assert "Risk indicators:" in md


def test_markdown_reporter_includes_each_finding() -> None:
    md = render_markdown(_sample_report())
    assert "Anthropic SDK" in md
    assert "LangChain Agent: refund_agent" in md
    assert "MCP Server: stripe-mcp" in md
    assert "claude-3-5-sonnet-20241022" in md


def test_markdown_reporter_includes_risk_summary() -> None:
    md = render_markdown(_sample_report())
    assert "Risk Indicator Summary" in md
    assert "financial action exposed" in md


def test_markdown_reporter_handles_empty_report() -> None:
    md = render_markdown(_empty_report())
    assert "No production AI surfaces detected" in md


def test_markdown_reporter_includes_cross_sell() -> None:
    md = render_markdown(_sample_report())
    assert "apisec.ai/products" in md


# ---- Terminal reporter ----


def test_terminal_reporter_runs_without_error(capsys: pytest.CaptureFixture[str]) -> None:
    """We don't assert on rich-formatted output, just that it doesn't blow up."""
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(_sample_report(), console)
    text = console.export_text()
    assert "AI Attack Surface Report" in text
    assert "Anthropic SDK" in text
    assert "refund_agent" in text


def test_terminal_reporter_handles_empty_report() -> None:
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(_empty_report(), console)
    text = console.export_text()
    assert "No production AI surfaces detected" in text


def test_terminal_reporter_shows_summary_counts() -> None:
    console = Console(record=True, force_terminal=True, width=120)
    render_terminal(_sample_report(), console)
    text = console.export_text()
    assert "3" in text  # surface count
    assert "production AI surfaces" in text or "production AI surface" in text


# ---- Schema 1.0: severity, audit, api, bridges ----


def _render_terminal_text(report: Report, width: int = 200) -> str:
    console = Console(record=True, force_terminal=True, width=width)
    render_terminal(report, console)
    return console.export_text()


def test_markdown_renders_severity_badge() -> None:
    md = render_markdown(_schema1_report())
    assert "CRITICAL" in md
    # Severity breakdown line from report.summary.
    assert "**Severity:**" in md


def test_markdown_renders_audit_risk_flags() -> None:
    md = render_markdown(_schema1_report())
    assert "secrets-in-env" in md
    assert "financial-action" in md
    assert "Live Stripe secret key present in MCP env block" in md
    assert "LLM02" in md
    assert "Move the key to a secrets manager" in md


def test_markdown_renders_secret_names_only_no_value_leak() -> None:
    md = render_markdown(_schema1_report())
    assert "STRIPE_SECRET_KEY" in md
    assert "stripe-key" in md
    # The privacy guarantee: a secret VALUE must never appear in the report.
    assert LEAKED_SECRET_VALUE not in md


def test_markdown_renders_api_method_and_path() -> None:
    md = render_markdown(_schema1_report())
    assert "## API Endpoints" in md
    assert "POST /v1/orders/{id}/refund" in md
    assert "fastapi" in md
    assert "bearer" in md
    assert "object-id in path (BOLA candidate)" in md


def test_markdown_renders_bridges() -> None:
    md = render_markdown(_schema1_report())
    assert "Run MCP runtime validation in APIsec" in md
    assert "Onboard this API for outside-in runtime testing in APIsec" in md
    # Footer surfaces summary.bridges_available.
    assert "Validate at runtime in APIsec" in md
    assert "mcp-runtime" in md
    assert "api-runtime" in md


def test_terminal_renders_severity_badge() -> None:
    text = _render_terminal_text(_schema1_report())
    assert "CRITICAL" in text


def test_terminal_renders_audit_risk_flags_and_secrets() -> None:
    text = _render_terminal_text(_schema1_report())
    assert "secrets-in-env" in text
    assert "financial-action" in text
    assert "Live Stripe secret key present in MCP env block" in text
    assert "LLM02" in text
    assert "STRIPE_SECRET_KEY" in text
    assert "stripe-key" in text
    # The privacy guarantee: a secret VALUE must never appear in the report.
    assert LEAKED_SECRET_VALUE not in text


def test_terminal_renders_api_method_and_path() -> None:
    text = _render_terminal_text(_schema1_report())
    assert "API ENDPOINTS" in text
    assert "POST /v1/orders/{id}/refund" in text
    assert "fastapi" in text
    assert "bearer" in text


def test_terminal_renders_bridges() -> None:
    text = _render_terminal_text(_schema1_report())
    assert "Run MCP runtime validation in APIsec" in text
    assert "Onboard this API for outside-in runtime testing in APIsec" in text
    # Footer surfaces summary.bridges_available.
    assert "mcp-runtime" in text
    assert "api-runtime" in text


def test_discovery_only_finding_has_no_severity_badge_markdown() -> None:
    """Findings with severity None render as inventory, no badge invented."""
    md = render_markdown(_sample_report())
    # The plain sample report has no severities at all.
    assert "**Severity:**" not in md
    for badge in ("🔴 CRITICAL", "🟠 HIGH", "🟡 MEDIUM"):
        assert badge not in md
