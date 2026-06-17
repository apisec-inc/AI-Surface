"""Tests for --repo cloning helpers and the UI /api/scan scan path.

No network: we exercise URL validation, token handling, and local-path
scanning. Actual clones are not performed here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_surface import repo as repo_mod
from ai_surface.repo import RepoError, clone_repo_to_tmp
from ai_surface.ui_server import scan_for_request

FIXTURE = str(Path(__file__).parent / "fixtures" / "e2e_app")


def test_invalid_urls_are_rejected_without_network() -> None:
    for bad in [
        "",
        "ssh://git@github.com/o/r.git",
        "file:///etc/passwd",
        "https://github.com/o/r; rm -rf /",
        "https://github.com/o/../../../r",
        "ftp://example.com/r",
    ]:
        with pytest.raises(RepoError):
            clone_repo_to_tmp(bad)


def test_internal_and_loopback_urls_are_rejected_ssrf() -> None:
    for bad in [
        "https://127.0.0.1/o/r.git",
        "https://169.254.169.254/latest/meta-data",  # cloud metadata
        "https://localhost:8080/o/r",
        "https://10.0.0.5/o/r",
        "https://192.168.1.1/o/r",
        "https://git.internal/o/r",
        "https://user:pass@github.com/o/r",  # embedded credentials
    ]:
        with pytest.raises(RepoError):
            clone_repo_to_tmp(bad)


def test_public_https_url_passes_validation() -> None:
    # Validation must not reject legitimate public forge URLs.
    repo_mod._validate_url("https://github.com/org/repo")
    repo_mod._validate_url("https://gitlab.com/org/repo.git")


def test_token_is_injected_into_clone_url() -> None:
    url = repo_mod._authed_url("https://github.com/org/repo", "ghp_secret")
    assert url == "https://x-access-token:ghp_secret@github.com/org/repo"
    # No token -> unchanged.
    assert repo_mod._authed_url("https://github.com/org/repo", None) == (
        "https://github.com/org/repo"
    )


def test_scan_for_request_scans_local_path() -> None:
    report = scan_for_request(path=FIXTURE)
    cats = {f.category for f in report.findings}
    assert "mcp-server" in cats and "api" in cats


def test_scan_for_request_bad_path_raises() -> None:
    with pytest.raises(FileNotFoundError):
        scan_for_request(path="/no/such/dir/ai-surface-test")


def test_ui_resolve_local_path_recovers_dropped_slash(tmp_path) -> None:
    from ai_surface.ui_server import _resolve_local_path

    # Absolute path works.
    assert _resolve_local_path(str(tmp_path)) == tmp_path.resolve()
    # Dropped leading slash on an absolute path is recovered.
    dropped = str(tmp_path).lstrip("/")
    assert _resolve_local_path(dropped) == tmp_path.resolve()


def test_ui_resolve_local_path_bad_dir_raises() -> None:
    from ai_surface.ui_server import _resolve_local_path

    with pytest.raises(FileNotFoundError):
        _resolve_local_path("/no/such/dir/anywhere/xyz")


def test_detect_repository_from_git_config(tmp_path) -> None:
    from ai_surface.repo import detect_repository

    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n'
        '[remote "origin"]\n\turl = https://github.com/apisec-inc/AI-Surface.git\n',
        encoding="utf-8",
    )
    assert detect_repository(str(tmp_path)) == "apisec-inc/AI-Surface"


def test_detect_repository_strips_credentials_and_ssh() -> None:
    from ai_surface.repo import _normalize_repo

    # embedded token must never leak
    assert _normalize_repo("https://x-access-token:ghp_secret@github.com/o/r.git") == "o/r"
    # ssh form
    assert _normalize_repo("git@github.com:o/r.git") == "o/r"
    # self-hosted keeps host
    assert _normalize_repo("https://git.example.com/team/app.git") == "git.example.com/team/app"


def test_detect_repository_none_when_not_a_repo(tmp_path) -> None:
    from ai_surface.repo import detect_repository

    assert detect_repository(str(tmp_path)) == ""
