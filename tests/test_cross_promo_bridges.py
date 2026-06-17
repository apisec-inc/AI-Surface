"""Tests for the schema-1.0 paid-platform bridge funnel."""
from __future__ import annotations

from ai_surface.cross_promo import attach_bridges, build_bridges
from ai_surface.types import (
    CATEGORY_API,
    CATEGORY_ENV_KEY,
    CATEGORY_MCP_SERVER,
    SEVERITY_CRITICAL,
    SEVERITY_MEDIUM,
    SKU_API_RUNTIME,
    SKU_MCP_RUNTIME,
    Audit,
    Evidence,
    Finding,
    RiskFlag,
)


def _mcp_finding() -> Finding:
    return Finding(
        surface="MCP Server: stripe-mcp",
        category=CATEGORY_MCP_SERVER,
        evidence=Evidence(files=[".mcp.json"]),
        severity=SEVERITY_CRITICAL,
        audit=Audit(
            risk_flags=[
                RiskFlag(flag="financial-action", severity=SEVERITY_MEDIUM),
                RiskFlag(flag="secrets-in-env", severity=SEVERITY_CRITICAL),
            ]
        ),
    )


def test_mcp_finding_gets_mcp_runtime_bridge_with_top_risk() -> None:
    bridges = build_bridges(_mcp_finding())
    assert len(bridges) == 1
    b = bridges[0]
    assert b.sku == SKU_MCP_RUNTIME
    # Deep-links to the highest-severity flag, not the first one listed.
    assert "risk=secrets-in-env" in b.url
    assert "category=mcp-server" in b.url
    assert "utm_source=ai-surface" in b.url
    assert "utm_campaign=oss-funnel" in b.url


def test_api_finding_gets_live_api_runtime_bridge() -> None:
    f = Finding(
        surface="REST API: POST /v1/orders/{id}/refund",
        category=CATEGORY_API,
        evidence=Evidence(metadata={"method": "POST", "path": "/v1/orders/{id}/refund"}),
    )
    bridges = build_bridges(f)
    assert len(bridges) == 1
    assert bridges[0].sku == SKU_API_RUNTIME
    # API is the one surface the platform validates today: the bridge is live
    # and lands on the public products page (no path context param).
    assert bridges[0].status == "live"
    assert bridges[0].url.startswith("https://www.apisec.ai/products")
    assert "path=" not in bridges[0].url
    assert "utm_source=ai-surface" in bridges[0].url


def test_env_key_finding_gets_no_bridge() -> None:
    f = Finding(
        surface="OPENAI_API_KEY",
        category=CATEGORY_ENV_KEY,
        evidence=Evidence(files=[".env"]),
    )
    assert build_bridges(f) == []


def test_attach_bridges_is_idempotent_and_in_place() -> None:
    findings = [_mcp_finding()]
    attach_bridges(findings)
    assert len(findings[0].bridges) == 1
    # Running again does not duplicate.
    attach_bridges(findings)
    assert len(findings[0].bridges) == 1
