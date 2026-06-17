"""Tests for CLI helpers and the typer entrypoint."""
from __future__ import annotations

import pytest
import typer
from typer.testing import CliRunner

from ai_surface.cli import (
    CATEGORY_ALIASES,
    _filter_detectors_by_category,
    _resolve_categories,
    app,
)
from ai_surface.types import (
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
)

# ---------------------------------------------------------------------------
# _resolve_categories
# ---------------------------------------------------------------------------


def test_resolve_categories_none_returns_none() -> None:
    assert _resolve_categories(None) is None
    assert _resolve_categories("") is None


def test_resolve_categories_canonical() -> None:
    assert _resolve_categories("mcp-server") == {CATEGORY_MCP_SERVER}
    assert _resolve_categories("agent-framework,llm-sdk") == {
        CATEGORY_AGENT_FRAMEWORK,
        CATEGORY_LLM_SDK,
    }


def test_resolve_categories_aliases() -> None:
    assert _resolve_categories("mcp") == {CATEGORY_MCP_SERVER}
    assert _resolve_categories("agents") == {CATEGORY_AGENT_FRAMEWORK}
    assert _resolve_categories("llm,gateway") == {
        CATEGORY_LLM_SDK,
        CATEGORY_MODEL_GATEWAY,
    }


def test_resolve_categories_api_and_vector_aliases() -> None:
    from ai_surface.types import CATEGORY_API, CATEGORY_VECTOR_STORE

    assert _resolve_categories("api") == {CATEGORY_API}
    assert _resolve_categories("apis") == {CATEGORY_API}
    assert _resolve_categories("vector") == {CATEGORY_VECTOR_STORE}
    assert _resolve_categories("rag") == {CATEGORY_VECTOR_STORE}
    assert _resolve_categories("vector-store") == {CATEGORY_VECTOR_STORE}


def test_resolve_categories_case_insensitive() -> None:
    assert _resolve_categories("MCP") == {CATEGORY_MCP_SERVER}
    assert _resolve_categories("Agents") == {CATEGORY_AGENT_FRAMEWORK}


def test_resolve_categories_strips_whitespace() -> None:
    assert _resolve_categories(" mcp , agents ") == {
        CATEGORY_MCP_SERVER,
        CATEGORY_AGENT_FRAMEWORK,
    }


def test_resolve_categories_invalid_raises_exit() -> None:
    with pytest.raises(typer.Exit):
        _resolve_categories("totally-not-a-category")


def test_resolve_categories_aliases_table_complete() -> None:
    """Every alias must point at a real ALL_CATEGORIES value."""
    from ai_surface.types import ALL_CATEGORIES

    for alias, canonical in CATEGORY_ALIASES.items():
        assert canonical in ALL_CATEGORIES, (
            f"alias {alias!r} maps to non-canonical {canonical!r}"
        )


# ---------------------------------------------------------------------------
# _filter_detectors_by_category
# ---------------------------------------------------------------------------


class _StubDetector:
    def __init__(self, name: str, category: str) -> None:
        self.name = name
        self.category = category


def test_filter_detectors_none_returns_all() -> None:
    detectors: list[_StubDetector] = [
        _StubDetector("a", CATEGORY_MCP_SERVER),
        _StubDetector("b", CATEGORY_LLM_SDK),
    ]
    out = _filter_detectors_by_category(detectors, None)
    assert len(out) == 2


def test_filter_detectors_keeps_matching_only() -> None:
    detectors: list[_StubDetector] = [
        _StubDetector("a", CATEGORY_MCP_SERVER),
        _StubDetector("b", CATEGORY_LLM_SDK),
        _StubDetector("c", CATEGORY_AGENT_FRAMEWORK),
    ]
    out = _filter_detectors_by_category(detectors, {CATEGORY_MCP_SERVER, CATEGORY_LLM_SDK})
    names = sorted(d.name for d in out)
    assert names == ["a", "b"]


def test_filter_detectors_empty_when_no_match() -> None:
    detectors: list[_StubDetector] = [_StubDetector("a", CATEGORY_MCP_SERVER)]
    out = _filter_detectors_by_category(detectors, {CATEGORY_LLM_SDK})
    assert out == []


# ---------------------------------------------------------------------------
# CLI integration: typer Test Runner
# ---------------------------------------------------------------------------

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ai-surface" in result.stdout


def test_scan_quiet_outputs_one_line(tmp_path) -> None:
    # Empty dir, all detectors will run, none will find anything
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert result.exit_code == 0
    assert "ai-surface:" in result.stdout
    assert "0 surfaces" in result.stdout


def test_scan_invalid_category_exits_with_error(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--categories", "bogus-cat"])
    assert result.exit_code == 2
    # CliRunner merges stderr into output by default
    assert "unknown category" in result.output.lower()


def test_scan_categories_aliases_accepted(tmp_path) -> None:
    """Should not error: 'mcp' and 'agents' are valid aliases."""
    result = runner.invoke(app, ["scan", str(tmp_path), "--categories", "mcp,agents", "--quiet"])
    assert result.exit_code == 0


def test_scan_nonexistent_path_exits_with_error() -> None:
    result = runner.invoke(app, ["scan", "/path/that/does/not/exist"])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# --fail-on-risk gate
# ---------------------------------------------------------------------------


def _write_risky_env(tmp_path) -> None:
    """Three distinct provider keys trip the 'multiple AI provider keys' risk."""
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-x\nANTHROPIC_API_KEY=sk-y\nGROQ_API_KEY=sk-z\n",
        encoding="utf-8",
    )


def test_fail_on_risk_exits_one_when_risk_present(tmp_path) -> None:
    _write_risky_env(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on-risk", "--quiet"])
    assert result.exit_code == 1
    assert "fail-on-risk" in result.output.lower()


def test_no_fail_on_risk_exits_zero_despite_risk(tmp_path) -> None:
    _write_risky_env(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert result.exit_code == 0


def test_fail_on_risk_clean_dir_exits_zero(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on-risk", "--quiet"])
    assert result.exit_code == 0


def test_fail_on_risk_works_in_terminal_output_mode(tmp_path) -> None:
    """The gate must fire regardless of output format, not just --quiet."""
    _write_risky_env(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on-risk"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# --baseline / --update-baseline
# ---------------------------------------------------------------------------


def _write_two_provider_env(tmp_path) -> None:
    """Two distinct providers: a Finding exists, but no risk yet (risk needs 3+)."""
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-x\nANTHROPIC_API_KEY=sk-y\n", encoding="utf-8"
    )


def _add_third_provider(tmp_path) -> None:
    """Tip the env into the 'multiple AI provider keys present' risk."""
    with (tmp_path / ".env").open("a", encoding="utf-8") as f:
        f.write("GROQ_API_KEY=sk-z\n")


def test_update_baseline_writes_file_and_exits_zero(tmp_path) -> None:
    _write_two_provider_env(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"])
    assert result.exit_code == 0
    baseline_path = tmp_path / ".ai-surface-baseline.json"
    assert baseline_path.is_file()
    # Captured snapshot is a valid Report JSON.
    import json as _json

    data = _json.loads(baseline_path.read_text(encoding="utf-8"))
    assert data["findings_count"] == 1
    assert data["schema_version"] == "1.0"


def test_baseline_with_no_file_errors_helpfully(tmp_path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", "--quiet"])
    assert result.exit_code == 2
    assert "no baseline" in result.output.lower()
    assert "--update-baseline" in result.output


def test_baseline_unchanged_state_reports_zero_diff(tmp_path) -> None:
    _write_two_provider_env(tmp_path)
    snap = runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"])
    assert snap.exit_code == 0
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", "--quiet"])
    assert result.exit_code == 0
    assert "0 new" in result.output
    assert "0 modified" in result.output


def test_baseline_detects_new_risk_after_change(tmp_path) -> None:
    _write_two_provider_env(tmp_path)
    runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"])
    _add_third_provider(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", "--quiet"])
    assert result.exit_code == 0
    assert "1 modified" in result.output
    assert "1 new risks" in result.output


def test_baseline_fail_on_risk_gates_on_new_risk_only(tmp_path) -> None:
    """Risks already in the baseline must not trip the gate; only newly
    introduced risks should. The baseline mode's whole point."""
    # Start with three providers (a risk is already present in baseline).
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-x\nANTHROPIC_API_KEY=sk-y\nGROQ_API_KEY=sk-z\n",
        encoding="utf-8",
    )
    runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"])
    # No new change: --fail-on-risk in baseline mode must NOT trip,
    # even though the baseline-state surface still carries 1 risk.
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", "--fail-on-risk", "--quiet"]
    )
    assert result.exit_code == 0


def test_baseline_fail_on_risk_trips_when_new_risk_added(tmp_path) -> None:
    _write_two_provider_env(tmp_path)
    runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"])
    _add_third_provider(tmp_path)
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", "--fail-on-risk", "--quiet"]
    )
    assert result.exit_code == 1
    assert "new risk indicator" in result.output.lower()


def test_baseline_and_update_baseline_mutually_exclusive(tmp_path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", "--update-baseline"]
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_baseline_file_custom_path(tmp_path) -> None:
    """--baseline-file PATH overrides the default .ai-surface-baseline.json."""
    _write_two_provider_env(tmp_path)
    custom = tmp_path / "snapshots" / "my-baseline.json"
    snap = runner.invoke(
        app,
        ["scan", str(tmp_path), "--update-baseline", "--baseline-file", str(custom)],
    )
    assert snap.exit_code == 0
    assert custom.is_file()
    # The default path should NOT have been written.
    assert not (tmp_path / ".ai-surface-baseline.json").exists()
    # And --baseline against the same custom path should round-trip.
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--baseline",
            "--baseline-file",
            str(custom),
            "--quiet",
        ],
    )
    assert result.exit_code == 0
    assert "0 new" in result.output


def test_baseline_invalid_json_errors_helpfully(tmp_path) -> None:
    (tmp_path / ".ai-surface-baseline.json").write_text("not valid json", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", "--quiet"])
    assert result.exit_code == 2
    assert "invalid baseline" in result.output.lower()


def test_update_baseline_then_rescan_does_not_detect_baseline_file(tmp_path) -> None:
    """Regression: the baseline JSON captures env-key names like
    HELICONE_API_KEY in metadata. Without the artifact-skip rule, the
    source-level model_gateways detector matches that text inside the
    baseline file and produces a phantom Helicone gateway finding.
    """
    # Three providers including Helicone so the baseline captures its name.
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=a\nANTHROPIC_API_KEY=b\nHELICONE_API_KEY=c\n",
        encoding="utf-8",
    )
    snap = runner.invoke(app, ["scan", str(tmp_path), "--update-baseline", "--quiet"])
    assert snap.exit_code == 0
    # Re-scan now. We expect ONLY the env-keys finding, not a phantom
    # Helicone gateway dredged from the baseline JSON.
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert result.exit_code == 0
    assert "1 surfaces" in result.output, (
        f"expected 1 surface (env keys only), got: {result.output!r}"
    )


def test_baseline_with_categories_does_not_report_spurious_removed(tmp_path) -> None:
    """Regression: --baseline applies --categories to the live scan via
    detector filtering. The loaded baseline must be filtered to the same
    set, otherwise every surface outside the requested categories appears
    as 'removed' in the diff.
    """
    # Baseline captures everything (env keys finding).
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=a\nANTHROPIC_API_KEY=b\nGROQ_API_KEY=c\n",
        encoding="utf-8",
    )
    runner.invoke(app, ["scan", str(tmp_path), "--update-baseline", "--quiet"])
    # Now diff with --categories restricted to infra. There are no infra
    # findings in either state, so the diff must be all zeros, not "1 removed".
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--baseline", "--categories", "infra", "--quiet"],
    )
    assert result.exit_code == 0
    assert "0 removed" in result.output, (
        f"baseline + --categories should not report spurious removals, got: "
        f"{result.output!r}"
    )


def test_baseline_added_surface_counts_its_risks_as_new(tmp_path) -> None:
    """A wholly new surface (not in baseline) contributes its risk indicators
    to the new-risk count. Sanity check for the gate semantics."""
    # Baseline: empty repo, zero surfaces, zero risks.
    runner.invoke(app, ["scan", str(tmp_path), "--update-baseline"])
    # Now add a risky env from nothing.
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=a\nANTHROPIC_API_KEY=b\nGROQ_API_KEY=c\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", "--fail-on-risk", "--quiet"]
    )
    assert result.exit_code == 1
    assert "1 new" in result.output


# ---------------------------------------------------------------------------
# Markdown emission must be raw (regression guard)
#
# The GitHub Action captures `scan --output markdown` and `compare ... --output
# markdown` stdout verbatim and posts it as a PR comment. If that output is
# routed through the rich console it gets hard-wrapped at the console width
# (splitting long URLs so the links die) and single-token link labels such as
# [ai-surface] are consumed as rich markup. These tests assert the raw markdown
# survives the CLI boundary intact. They fail if emission regresses to
# console.print().
# ---------------------------------------------------------------------------

import re  # noqa: E402

# Build the key at runtime so the literal Stripe key never appears in source:
# GitHub push protection blocks a contiguous sk_live_ key, but the detector
# still matches the assembled value (sk_live_ + 24+ alphanumerics) at test time.
_FAKE_STRIPE_KEY = "sk_live_" + "AbCdEf01" * 4
_MCP_FIXTURE = (
    '{ "mcpServers": { "payments": { "command": "node", "args": ["s.js"], '
    '"env": { "STRIPE_SECRET_KEY": "' + _FAKE_STRIPE_KEY + '" } } } }'
)
_AI_SURFACE_LABEL = "[ai-surface](https://github.com/apisec-inc/AI-Surface)"
# A raw newline inside a (...) markdown link target means a URL was wrapped.
_SPLIT_URL_RE = re.compile(r"\(https?://[^)\s\n]*\n")


def _assert_markdown_intact(md: str) -> None:
    assert _AI_SURFACE_LABEL in md, "single-token link label was eaten as rich markup"
    assert not _SPLIT_URL_RE.search(md), "a URL was wrapped across lines (links break)"


def test_scan_markdown_output_is_raw_not_rich_wrapped(tmp_path) -> None:
    (tmp_path / ".mcp.json").write_text(_MCP_FIXTURE, encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", "markdown"])
    assert result.exit_code == 0
    _assert_markdown_intact(result.stdout)


def test_compare_markdown_output_is_raw_not_rich_wrapped(tmp_path) -> None:
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (head / ".mcp.json").write_text(_MCP_FIXTURE, encoding="utf-8")

    base_json = tmp_path / "base.json"
    head_json = tmp_path / "head.json"
    base_json.write_text(
        runner.invoke(app, ["scan", str(base), "--output", "json"]).stdout,
        encoding="utf-8",
    )
    head_json.write_text(
        runner.invoke(app, ["scan", str(head), "--output", "json"]).stdout,
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["compare", str(base_json), str(head_json), "--output", "markdown"]
    )
    assert result.exit_code == 0
    assert "1 new" in result.stdout
    _assert_markdown_intact(result.stdout)
