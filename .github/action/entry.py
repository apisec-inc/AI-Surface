#!/usr/bin/env python3
"""GitHub Action entry point for ai-surface.

For pull requests, the script runs two scans (PR head and the merge base)
and posts a sticky PR comment showing the AI surface diff. When the base
ref is unavailable (push event, fork without base history, fetch failure),
the script falls back to a full-inventory comment.

Inputs are read from environment variables set by action.yml.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests


COMMENT_MARKER = "<!-- ai-surface-comment v0 -->"
DEFAULT_WORKSPACE = "/github/workspace"
BASE_CHECKOUT_PATH = "/tmp/ai-surface-base"

# Refspec validation for refs we hand to git on the command line. Git
# treats any argv element starting with ``-`` as an option, so an unvalidated
# ref of e.g. ``--upload-pack=cmd`` would cause ``git fetch`` to execute
# ``cmd`` as a transport helper. The regex matches what GitHub itself
# accepts for branch names (letters, digits, dot, dash, underscore, slash)
# and explicitly cannot start with a dash. In normal use this passes every
# real branch name; it only rejects refs that look like option flags.
_SAFE_GIT_REF_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]{0,254}$")


def _is_safe_git_ref(ref: str) -> bool:
    """Return True if ``ref`` is safe to pass as a git command-line argument."""
    return bool(_SAFE_GIT_REF_RE.fullmatch(ref))


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def _bool_input(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _read_inputs() -> Dict[str, Any]:
    return {
        "path": (os.environ.get("AI_SURFACE_INPUT_PATH") or ".").strip(),
        "comment_on_pr": _bool_input("AI_SURFACE_COMMENT_ON_PR", True),
        "fail_on_risk": _bool_input("AI_SURFACE_FAIL_ON_RISK", False),
        "write_inventory": _bool_input("AI_SURFACE_WRITE_INVENTORY", False),
        "github_token": (
            os.environ.get("AI_SURFACE_GITHUB_TOKEN")
            or os.environ.get("GITHUB_TOKEN")
            or ""
        ),
    }


def _resolve_scan_root(path_input: str, base: Optional[str] = None) -> str:
    """Resolve the scan path relative to a base (workspace by default)."""
    workspace = base or os.environ.get("GITHUB_WORKSPACE", DEFAULT_WORKSPACE)
    p = Path(path_input)
    if p.is_absolute():
        return str(p)
    return str(Path(workspace) / p)


# ---------------------------------------------------------------------------
# CLI invocations
# ---------------------------------------------------------------------------


def _run_cli(scan_root: str, fmt: str) -> subprocess.CompletedProcess:
    """Run `ai-surface scan <root> --output <fmt>`."""
    return subprocess.run(
        ["ai-surface", "scan", scan_root, "--output", fmt],
        capture_output=True,
        text=True,
        check=False,
    )


def _run_compare(base_json: str, head_json: str, fmt: str = "markdown") -> subprocess.CompletedProcess:
    """Run `ai-surface compare base.json head.json`."""
    return subprocess.run(
        ["ai-surface", "compare", base_json, head_json, "--output", fmt],
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Action outputs / event detection
# ---------------------------------------------------------------------------


def _set_action_output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    # Defence-in-depth: a value containing newline or carriage return would
    # let an attacker inject additional ``key=value`` lines into GITHUB_OUTPUT
    # that downstream workflow steps then consume as trusted (CVE-2024-27302
    # class of issue). Today every caller passes a numeric or fixed-string
    # value so this is hardening, not a live exploit.
    safe_value = value.replace("\r", " ").replace("\n", " ")
    try:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"{name}={safe_value}\n")
    except OSError:
        pass


def _is_pull_request() -> bool:
    # NOTE: ``pull_request_target`` is deliberately NOT accepted here. That
    # event runs in the context of the target branch with access to repo
    # secrets while still checking out attacker-controlled PR code by default,
    # which is the canonical "pwn request" supply-chain pattern. ai-surface
    # only supports the safe ``pull_request`` event. See ``main()`` for the
    # hard refusal on ``pull_request_target``.
    return os.environ.get("GITHUB_EVENT_NAME") == "pull_request"


def _pr_number() -> Optional[int]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).is_file():
        return None
    try:
        with open(event_path, encoding="utf-8") as f:
            event = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    pr = event.get("pull_request") or {}
    num = pr.get("number")
    return int(num) if isinstance(num, int) else None


# ---------------------------------------------------------------------------
# Base-branch checkout for diffing
# ---------------------------------------------------------------------------


def _setup_base_checkout(workspace: str) -> Optional[str]:
    """Create a git worktree of the PR's base ref. Returns its path or None.

    Failure cases (any of these returns None, falling back to inventory mode):
      - Not a PR event
      - GITHUB_BASE_REF not set
      - Workspace is not a git repo
      - Fetch of the base ref fails
      - Worktree creation fails
    """
    base_ref = os.environ.get("GITHUB_BASE_REF")
    if not base_ref:
        return None

    # Defence-in-depth: validate the ref before handing it to git on the
    # command line. GitHub itself sets GITHUB_BASE_REF from the PR target
    # branch (which is constrained by the target repo's branch names), so
    # in practice this is hardening rather than a live exploit. The validation
    # rejects refs that begin with ``-`` (which git would treat as an option,
    # enabling argument-injection patterns such as ``--upload-pack=cmd``).
    if not _is_safe_git_ref(base_ref):
        print(f"::warning::base ref {base_ref!r} failed validation; skipping base scan")
        return None

    if not (Path(workspace) / ".git").exists():
        # Some non-checkout workflows set GITHUB_WORKSPACE without a clone.
        return None

    # Defensive fetch (fetch-depth: 0 in the consumer workflow makes this a no-op).
    fetch = subprocess.run(
        ["git", "-C", workspace, "fetch", "--quiet", "origin", base_ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if fetch.returncode != 0:
        print(f"::warning::could not fetch base ref {base_ref}: {fetch.stderr.strip()}")
        return None

    # Clean up any stale worktree from a previous step.
    if Path(BASE_CHECKOUT_PATH).exists():
        subprocess.run(
            ["git", "-C", workspace, "worktree", "remove", "--force", BASE_CHECKOUT_PATH],
            capture_output=True,
            check=False,
        )

    add = subprocess.run(
        [
            "git",
            "-C",
            workspace,
            "worktree",
            "add",
            "--detach",
            BASE_CHECKOUT_PATH,
            f"origin/{base_ref}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if add.returncode != 0:
        print(f"::warning::could not create base worktree: {add.stderr.strip()}")
        return None

    return BASE_CHECKOUT_PATH


def _scan_to_json_file(scan_root: str, out_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Scan and persist JSON. Returns (report_dict, raw_json_text) on success."""
    proc = _run_cli(scan_root, "json")
    if proc.returncode != 0:
        print(f"::warning::scan failed for {scan_root}")
        if proc.stderr:
            print(proc.stderr)
        return None, None
    raw = proc.stdout
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"::warning::could not parse JSON from scan: {exc}")
        return None, None
    try:
        Path(out_path).write_text(raw, encoding="utf-8")
    except OSError as exc:
        print(f"::warning::could not write {out_path}: {exc}")
        return None, raw
    return report, raw


# ---------------------------------------------------------------------------
# PR comment posting
# ---------------------------------------------------------------------------


def _post_pr_comment(token: str, body: str) -> None:
    if not token:
        print("::warning::no GitHub token available; skipping PR comment")
        return
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr = _pr_number()
    if not repo or not pr:
        print("::warning::missing repo or PR number; skipping PR comment")
        return

    marker_body = f"{COMMENT_MARKER}\n{body}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base = f"https://api.github.com/repos/{repo}"

    existing_id: Optional[int] = None
    page = 1
    while True:
        url = f"{base}/issues/{pr}/comments?per_page=100&page={page}"
        resp = requests.get(url, headers=headers, timeout=15)
        if not resp.ok:
            print(f"::warning::failed to list comments: {resp.status_code}")
            break
        comments = resp.json() or []
        if not isinstance(comments, list) or not comments:
            break
        for c in comments:
            if COMMENT_MARKER in (c.get("body") or ""):
                existing_id = c.get("id")
                break
        if existing_id is not None or len(comments) < 100:
            break
        page += 1

    if existing_id is not None:
        url = f"{base}/issues/comments/{existing_id}"
        resp = requests.patch(url, headers=headers, json={"body": marker_body}, timeout=15)
        if resp.ok:
            print("Updated existing AI Surface PR comment.")
        else:
            print(f"::warning::failed to update comment: {resp.status_code} {resp.text[:200]}")
    else:
        url = f"{base}/issues/{pr}/comments"
        resp = requests.post(url, headers=headers, json={"body": marker_body}, timeout=15)
        if resp.ok:
            print("Posted new AI Surface PR comment.")
        else:
            print(f"::warning::failed to post comment: {resp.status_code} {resp.text[:200]}")


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------


def _format_diff_comment(diff_md: str, head_report: Dict[str, Any]) -> str:
    """Compose a PR comment body in diff mode.

    The CLI's diff markdown already contains its own header and footer; we
    prepend a small status banner with the post-merge totals so reviewers
    have full context, not just the delta.
    """
    surfaces = int(head_report.get("findings_count", 0))
    findings = head_report.get("findings", []) or []
    risks = sum(len(f.get("risk_indicators", []) or []) for f in findings)

    status = (
        f"<sub>After this PR merges: **{surfaces}** total AI surfaces, "
        f"**{risks}** total risk indicators.</sub>\n\n"
    )
    return status + diff_md


def _format_inventory_comment(report: Dict[str, Any], markdown_body: str) -> str:
    """Fallback comment used when we can't compute a diff."""
    surfaces = int(report.get("findings_count", 0))
    findings = report.get("findings", []) or []
    risks = sum(len(f.get("risk_indicators", []) or []) for f in findings)
    detectors = ", ".join(report.get("detectors_run", []) or [])

    if surfaces == 0:
        return (
            "### 🤖 AI Surface Check\n\n"
            "No production AI surfaces detected in this codebase.\n\n"
            "_LLM SDK call sites, agent frameworks, MCP servers, model gateways, "
            "and AI provider env keys are all clean._\n\n"
            "<sub>Powered by "
            "[ai-surface](https://github.com/apisec-inc/ai-surface) · "
            "[Validate exploitability](https://apisec.ai/ai-validation)</sub>"
        )

    summary = (
        f"### 🤖 AI Surface Check\n\n"
        f"**{surfaces} production AI surfaces** · "
        f"**{risks} risk indicators**\n\n"
        f"<sub>Detectors: {detectors}</sub>\n\n"
        f"<sub>Diff against the base branch was unavailable; showing full inventory.</sub>\n\n"
    )

    body = markdown_body
    if body.startswith("# AI Inventory"):
        first_blank = body.find("\n\n")
        if first_blank != -1:
            body = body[first_blank + 2 :]

    footer = (
        "\n---\n\n"
        "<sub>"
        "Powered by [ai-surface](https://github.com/apisec-inc/ai-surface). "
        "To validate which of these surfaces are exploitable in a running application: "
        "[apisec.ai/ai-validation](https://apisec.ai/ai-validation)."
        "</sub>"
    )
    return summary + body + footer


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    # Hard refusal: never run under ``pull_request_target``. That event
    # combines write-scoped secrets with attacker-controlled PR code and
    # is the standard supply-chain attack vector for GitHub Actions. Fail
    # fast so the workflow author switches to ``pull_request``.
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name == "pull_request_target":
        print(
            "::error::ai-surface refuses to run on the 'pull_request_target' "
            "event. That event runs with repo secrets against untrusted PR "
            "code and is unsafe for any tool that reads PR contents. Use the "
            "'pull_request' event instead."
        )
        return 2

    inputs = _read_inputs()
    workspace = os.environ.get("GITHUB_WORKSPACE", DEFAULT_WORKSPACE)
    head_scan_root = _resolve_scan_root(inputs["path"], base=workspace)

    if not Path(head_scan_root).is_dir():
        print(f"::error::scan path is not a directory: {head_scan_root}")
        return 2

    print(f"::group::ai-surface scan {head_scan_root}")

    head_report, head_raw = _scan_to_json_file(head_scan_root, "/tmp/ai-surface-head.json")
    if head_report is None:
        print("::endgroup::")
        return 1

    md_proc = _run_cli(head_scan_root, "markdown")
    head_markdown_body = md_proc.stdout if md_proc.returncode == 0 else ""

    surfaces = int(head_report.get("findings_count", 0))
    risks = sum(len(f.get("risk_indicators", []) or []) for f in head_report.get("findings", []) or [])
    print(f"AI surfaces detected: {surfaces}")
    print(f"Risk indicators: {risks}")

    # Persist artifacts for downstream steps.
    json_path = Path(workspace) / "ai-surface.json"
    try:
        json_path.write_text(json.dumps(head_report, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"::warning::could not write ai-surface.json: {exc}")

    if inputs["write_inventory"] and head_markdown_body:
        try:
            (Path(workspace) / ".ai-inventory.md").write_text(head_markdown_body, encoding="utf-8")
            print("Wrote .ai-inventory.md")
        except OSError as exc:
            print(f"::warning::could not write .ai-inventory.md: {exc}")

    _set_action_output("surfaces-count", str(surfaces))
    _set_action_output("risk-count", str(risks))
    _set_action_output("json-report", str(json_path))

    print("::endgroup::")

    # Diff path: only on PR events with a usable base ref.
    diff_md: Optional[str] = None
    if inputs["comment_on_pr"] and _is_pull_request():
        print("::group::ai-surface diff vs base")
        base_path = _setup_base_checkout(workspace)
        if base_path:
            base_scan_root = _resolve_scan_root(inputs["path"], base=base_path)
            if Path(base_scan_root).is_dir():
                base_report, _ = _scan_to_json_file(base_scan_root, "/tmp/ai-surface-base.json")
                if base_report is not None:
                    cmp = _run_compare(
                        "/tmp/ai-surface-base.json",
                        "/tmp/ai-surface-head.json",
                        "markdown",
                    )
                    if cmp.returncode == 0:
                        diff_md = cmp.stdout
                        print("Computed diff against base ref.")
                    else:
                        print(f"::warning::compare failed: {cmp.stderr[:200]}")
            else:
                print(
                    f"::warning::base scan path {base_scan_root} not present in base checkout"
                )
        else:
            print("Base ref unavailable; falling back to full-inventory comment.")
        print("::endgroup::")

    if inputs["comment_on_pr"] and _is_pull_request():
        if diff_md is not None:
            body = _format_diff_comment(diff_md, head_report)
        else:
            body = _format_inventory_comment(head_report, head_markdown_body)
        _post_pr_comment(inputs["github_token"], body)

    if inputs["fail_on_risk"] and risks > 0:
        print(f"::error::fail-on-risk is set and {risks} risk indicators were detected")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
