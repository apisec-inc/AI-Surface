"""Tests for the diff engine."""
from __future__ import annotations

import json

from ai_surface.diff import (
    _MAX_FINDINGS,
    Diff,
    FindingChange,
    _sanitise_loaded_scan_root,
    compute_diff,
    diff_to_dict,
    load_report_from_json,
    render_diff_markdown,
)
from ai_surface.reporters.json_reporter import render_json
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    Evidence,
    Finding,
    Report,
)


def _f(
    surface: str,
    category: str = CATEGORY_LLM_SDK,
    files: list[str] | None = None,
    permissions: list[str] | None = None,
    risk_indicators: list[str] | None = None,
) -> Finding:
    return Finding(
        surface=surface,
        category=category,
        evidence=Evidence(files=list(files or []), snippet="", metadata={}),
        permissions=list(permissions or []),
        risk_indicators=list(risk_indicators or []),
    )


def _report(*findings: Finding, ts: str = "2026-05-09T00:00:00+00:00") -> Report:
    return Report(
        findings=list(findings),
        scan_root="/tmp/test",
        scan_timestamp=ts,
        detectors_run=["llm_sdks", "agent_frameworks"],
    )


# ---------------------------------------------------------------------------
# compute_diff
# ---------------------------------------------------------------------------


def test_diff_empty_when_reports_identical() -> None:
    a = _f("OpenAI SDK", files=["src/x.py"])
    diff = compute_diff(_report(a), _report(_f("OpenAI SDK", files=["src/x.py"])))
    assert diff.is_empty
    assert diff.total_changes == 0


def test_diff_detects_added_finding() -> None:
    base = _report(_f("OpenAI SDK", files=["x.py"]))
    head = _report(
        _f("OpenAI SDK", files=["x.py"]),
        _f("Anthropic SDK", files=["y.py"]),
    )
    diff = compute_diff(base, head)
    assert len(diff.added) == 1
    assert diff.added[0].surface == "Anthropic SDK"
    assert not diff.removed
    assert not diff.modified


def test_diff_detects_removed_finding() -> None:
    base = _report(
        _f("OpenAI SDK", files=["x.py"]),
        _f("Anthropic SDK", files=["y.py"]),
    )
    head = _report(_f("OpenAI SDK", files=["x.py"]))
    diff = compute_diff(base, head)
    assert len(diff.removed) == 1
    assert diff.removed[0].surface == "Anthropic SDK"


def test_diff_detects_widened_permissions() -> None:
    base = _report(
        _f(
            "MCP Server: stripe-mcp",
            category=CATEGORY_MCP_SERVER,
            permissions=["read"],
        )
    )
    head = _report(
        _f(
            "MCP Server: stripe-mcp",
            category=CATEGORY_MCP_SERVER,
            permissions=["read", "refund"],
        )
    )
    diff = compute_diff(base, head)
    assert len(diff.modified) == 1
    c = diff.modified[0]
    assert c.permissions_added == ["refund"]
    assert c.permissions_removed == []


def test_diff_detects_added_risk_indicator() -> None:
    base = _report(
        _f("LangChain Agent: refund (in src/r.py)", category=CATEGORY_AGENT_FRAMEWORK)
    )
    head = _report(
        _f(
            "LangChain Agent: refund (in src/r.py)",
            category=CATEGORY_AGENT_FRAMEWORK,
            risk_indicators=["financial action exposed"],
        )
    )
    diff = compute_diff(base, head)
    assert len(diff.modified) == 1
    assert diff.modified[0].risks_added == ["financial action exposed"]


def test_diff_detects_files_added() -> None:
    base = _report(_f("OpenAI SDK", files=["src/a.py"]))
    head = _report(_f("OpenAI SDK", files=["src/a.py", "src/b.py"]))
    diff = compute_diff(base, head)
    assert len(diff.modified) == 1
    assert diff.modified[0].files_added == ["src/b.py"]
    assert diff.modified[0].files_removed == []


def test_diff_does_not_flag_no_op_change() -> None:
    base = _report(_f("OpenAI SDK", files=["a.py"], permissions=["x"]))
    head = _report(_f("OpenAI SDK", files=["a.py"], permissions=["x"]))
    diff = compute_diff(base, head)
    assert diff.is_empty


def test_diff_handles_full_added_baseline() -> None:
    base = _report()
    head = _report(_f("OpenAI SDK", files=["a.py"]))
    diff = compute_diff(base, head)
    assert len(diff.added) == 1
    assert not diff.removed
    assert not diff.modified


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def test_render_diff_markdown_empty() -> None:
    md = render_diff_markdown(Diff())
    assert "AI Surface Changes" in md
    assert "No AI surface changes" in md


def test_render_diff_markdown_added() -> None:
    diff = Diff(
        added=[
            _f(
                "MCP Server: stripe-mcp",
                category=CATEGORY_MCP_SERVER,
                permissions=["refund"],
                risk_indicators=["broad permissions"],
                files=[".mcp.json"],
            )
        ]
    )
    md = render_diff_markdown(diff)
    assert "New AI surfaces" in md
    assert "MCP Server: stripe-mcp" in md
    assert "broad permissions" in md
    assert "`refund`" in md


def test_render_diff_markdown_modified_widened_perms() -> None:
    diff = Diff(
        modified=[
            FindingChange(
                surface="MCP Server: github-mcp",
                category=CATEGORY_MCP_SERVER,
                permissions_added=["repo:write"],
            )
        ]
    )
    md = render_diff_markdown(diff)
    assert "Modified AI surfaces" in md
    assert "Permissions added" in md
    assert "`repo:write`" in md


def test_render_diff_markdown_removed() -> None:
    diff = Diff(removed=[_f("OpenAI SDK", files=["legacy.py"])])
    md = render_diff_markdown(diff)
    assert "Removed AI surfaces" in md
    assert "OpenAI SDK" in md


# ---------------------------------------------------------------------------
# Round-trip via JSON reporter
# ---------------------------------------------------------------------------


def test_round_trip_through_json_reporter() -> None:
    """A scan -> JSON -> diff path that mirrors the GitHub Action workflow."""
    base = _report(_f("OpenAI SDK", files=["a.py"], permissions=["x"]))
    head = _report(
        _f("OpenAI SDK", files=["a.py"], permissions=["x", "y"]),
        _f("Anthropic SDK", files=["b.py"]),
    )

    base_json = render_json(base)
    head_json = render_json(head)

    base_loaded = load_report_from_json(base_json)
    head_loaded = load_report_from_json(head_json)

    diff = compute_diff(base_loaded, head_loaded)
    assert len(diff.added) == 1
    assert diff.added[0].surface == "Anthropic SDK"
    assert len(diff.modified) == 1
    assert diff.modified[0].permissions_added == ["y"]


def test_diff_to_dict_serializable() -> None:
    diff = Diff(
        added=[_f("OpenAI SDK", files=["a.py"])],
        modified=[
            FindingChange(
                surface="MCP Server: x",
                category=CATEGORY_MCP_SERVER,
                permissions_added=["w"],
            )
        ],
    )
    d = diff_to_dict(diff)
    json.dumps(d)  # raises if not JSON-serializable
    assert d["total_changes"] == 2


# ---------------------------------------------------------------------------
# Loaded-report hardening (defends against tampered baseline files)
# ---------------------------------------------------------------------------


def test_loaded_scan_root_is_sanitised_to_basename() -> None:
    """A baseline JSON whose scan_root is an absolute path must not let
    that path re-emerge in the diff output. The privacy contract says
    scan_root is always a basename; an attacker-edited baseline cannot
    override that promise."""
    assert _sanitise_loaded_scan_root("/home/victim/internal/repo") == "repo"
    assert _sanitise_loaded_scan_root("C:\\Users\\victim\\code\\project") == "project"
    assert _sanitise_loaded_scan_root("/etc/passwd") == "passwd"
    assert _sanitise_loaded_scan_root("normal-basename") == "normal-basename"
    assert _sanitise_loaded_scan_root("") == ""


def test_load_report_from_json_caps_findings_at_max() -> None:
    """A hostile baseline JSON with millions of findings entries must not
    force pathological memory use. Real scans produce hundreds at most."""
    huge = {
        "findings": [
            {"surface": f"s{i}", "category": "llm-sdk", "evidence": {"files": ["a"]}}
            for i in range(_MAX_FINDINGS + 100)
        ],
        "scan_root": "demo",
        "scan_timestamp": "",
        "detectors_run": [],
    }
    report = load_report_from_json(json.dumps(huge))
    assert len(report.findings) == _MAX_FINDINGS


def test_loaded_scan_root_redacts_path_in_diff_output() -> None:
    """End-to-end: a tampered baseline with an absolute scan_root produces
    a Diff whose base_scan_root is the sanitised basename."""
    tampered = {
        "findings": [],
        "scan_root": "/home/victim/secret-project",
        "scan_timestamp": "",
        "detectors_run": [],
    }
    base = load_report_from_json(json.dumps(tampered))
    head = _report()
    diff = compute_diff(base, head)
    assert "/" not in diff.base_scan_root
    assert "victim" not in diff.base_scan_root
