"""Diff engine: compute the change in AI surfaces between two scans.

Two scans of the same repo (typically base branch vs. PR head) are compared.
Findings are matched by their `surface` name, which is the user-facing
unique identifier per logical AI surface.

Three categories of change:
  - added: surface present in head, absent in base
  - removed: surface present in base, absent in head
  - modified: surface present in both, but with one of:
      * permissions added or removed
      * risk_indicators added or removed
      * files added (new file uses this surface)

Renaming a surface (same logical thing, different display name) shows up
as one removed + one added in v0.5. Cross-detector finding migration is
a v0.6 problem.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from . import __version__ as _TOOL_VERSION  # noqa: N812 - module-private alias
from .cross_promo import build_upgrade_url
from .types import Finding, Report
from .utils.markdown_safety import sanitise_inline as _sanitise_inline


@dataclass
class FindingChange:
    """A single 'modified' finding with the specific changes called out.

    All fields are lists of strings for easy rendering. Empty lists mean
    "no change in that aspect".
    """

    surface: str
    category: str
    permissions_added: list[str] = field(default_factory=list)
    permissions_removed: list[str] = field(default_factory=list)
    risks_added: list[str] = field(default_factory=list)
    risks_removed: list[str] = field(default_factory=list)
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)

    def is_meaningful(self) -> bool:
        """True if this change is worth showing in the PR comment."""
        return bool(
            self.permissions_added
            or self.permissions_removed
            or self.risks_added
            or self.risks_removed
            or self.files_added
            or self.files_removed
        )


@dataclass
class Diff:
    """The complete diff between two scans."""

    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    modified: list[FindingChange] = field(default_factory=list)
    base_scan_root: str = ""
    head_scan_root: str = ""
    base_timestamp: str = ""
    head_timestamp: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.modified)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified)


def compute_diff(base: Report, head: Report) -> Diff:
    """Return the change set between `base` (older) and `head` (newer) reports."""
    base_by_surface: dict[str, Finding] = {f.surface: f for f in base.findings}
    head_by_surface: dict[str, Finding] = {f.surface: f for f in head.findings}

    added = [head_by_surface[k] for k in head_by_surface if k not in base_by_surface]
    removed = [base_by_surface[k] for k in base_by_surface if k not in head_by_surface]

    modified: list[FindingChange] = []
    for surface in head_by_surface:
        if surface not in base_by_surface:
            continue
        before = base_by_surface[surface]
        after = head_by_surface[surface]
        change = _changes_between(before, after)
        if change.is_meaningful():
            modified.append(change)

    return Diff(
        added=added,
        removed=removed,
        modified=modified,
        base_scan_root=base.scan_root,
        head_scan_root=head.scan_root,
        base_timestamp=base.scan_timestamp,
        head_timestamp=head.scan_timestamp,
    )


def _changes_between(before: Finding, after: Finding) -> FindingChange:
    """Diff two findings for the same surface."""
    return FindingChange(
        surface=after.surface,
        category=after.category,
        permissions_added=_list_diff(after.permissions, before.permissions),
        permissions_removed=_list_diff(before.permissions, after.permissions),
        risks_added=_list_diff(after.risk_indicators, before.risk_indicators),
        risks_removed=_list_diff(before.risk_indicators, after.risk_indicators),
        files_added=_list_diff(after.evidence.files, before.evidence.files),
        files_removed=_list_diff(before.evidence.files, after.evidence.files),
    )


def _list_diff(a: list[str], b: list[str]) -> list[str]:
    """Items in `a` that are not in `b`, preserving order from `a`."""
    bset = set(b)
    return [x for x in a if x not in bset]


# ---------------------------------------------------------------------------
# Loading reports from JSON (the action persists JSON between steps)
# ---------------------------------------------------------------------------


def load_report_from_json(text: str) -> Report:
    """Parse a JSON report (as emitted by `ai-surface scan --output json`)."""
    data = json.loads(text)
    return _report_from_dict(data)


# Caps applied when loading a Report from external JSON (e.g. a baseline
# file under attacker control). Real scans produce reports far below these
# numbers; the caps exist to prevent a hostile baseline JSON from forcing
# pathological memory use or quadratic diffs.
_MAX_FINDINGS = 10_000
_MAX_LIST_PER_FINDING = 2_000


def _sanitise_loaded_scan_root(raw: str) -> str:
    """Strip any path-shaped value from a loaded scan_root.

    Reports produced by this tool always store ``scan_root`` as a single
    basename for privacy. An attacker who hand-edits a baseline JSON can
    set ``scan_root`` to an absolute path (e.g. ``/home/victim/internal``)
    which would then re-emerge in any diff output, defeating the path
    redaction contract. We accept only the basename of whatever they
    wrote, mirroring what a real scan would have produced.
    """
    if not raw:
        return ""
    # Strip any directory separators by taking the last component.
    last = raw.replace("\\", "/").rsplit("/", 1)[-1]
    return last[:255]


def _report_from_dict(data: Mapping[str, Any]) -> Report:
    from .types import Evidence  # local import to avoid circulars

    raw_findings = data.get("findings", []) or []
    if len(raw_findings) > _MAX_FINDINGS:
        raw_findings = raw_findings[:_MAX_FINDINGS]
    findings: list[Finding] = []
    for f in raw_findings:
        ev_data = f.get("evidence", {}) or {}
        files = list(ev_data.get("files", []) or [])[:_MAX_LIST_PER_FINDING]
        line_numbers = list(ev_data.get("line_numbers", []) or [])[:_MAX_LIST_PER_FINDING]
        permissions = list(f.get("permissions", []) or [])[:_MAX_LIST_PER_FINDING]
        risk_indicators = list(f.get("risk_indicators", []) or [])[:_MAX_LIST_PER_FINDING]
        ev = Evidence(
            files=files,
            snippet=str(ev_data.get("snippet", "") or ""),
            line_numbers=line_numbers,
            metadata=dict(ev_data.get("metadata", {}) or {}),
        )
        findings.append(
            Finding(
                surface=str(f.get("surface", "")),
                category=str(f.get("category", "")),
                evidence=ev,
                permissions=permissions,
                risk_indicators=risk_indicators,
                detector_name=str(f.get("detector_name", "")),
            )
        )
    return Report(
        findings=findings,
        scan_root=_sanitise_loaded_scan_root(str(data.get("scan_root", ""))),
        scan_timestamp=str(data.get("scan_timestamp", "")),
        detectors_run=list(data.get("detectors_run", []) or []),
        schema_version=str(data.get("schema_version", "0.5")),
        tool_version=str(data.get("tool_version", _TOOL_VERSION)),
        errors=list(data.get("errors", []) or []),
    )


def diff_to_dict(diff: Diff) -> dict[str, Any]:
    """Serialize a Diff to a JSON-friendly dict."""
    return {
        "added": [_finding_to_dict(f) for f in diff.added],
        "removed": [_finding_to_dict(f) for f in diff.removed],
        "modified": [asdict(c) for c in diff.modified],
        "base_scan_root": diff.base_scan_root,
        "head_scan_root": diff.head_scan_root,
        "base_timestamp": diff.base_timestamp,
        "head_timestamp": diff.head_timestamp,
        "total_changes": diff.total_changes,
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return asdict(finding)


# ---------------------------------------------------------------------------
# Markdown rendering for PR comments
# ---------------------------------------------------------------------------


def render_diff_markdown(diff: Diff) -> str:
    """Render a Diff as the body of a PR comment (markdown)."""
    if diff.is_empty:
        return _render_empty_diff()

    parts: list[str] = []
    parts.append(_render_header(diff))

    if diff.added:
        parts.append("### ➕ New AI surfaces")
        parts.append("")
        for f in diff.added:
            parts.append(_render_added_finding(f))
        parts.append("")

    if diff.modified:
        parts.append("### ✏️ Modified AI surfaces")
        parts.append("")
        for c in diff.modified:
            parts.append(_render_modified(c))
        parts.append("")

    if diff.removed:
        parts.append("### ➖ Removed AI surfaces")
        parts.append("")
        for f in diff.removed:
            parts.append(_render_removed_finding(f))
        parts.append("")

    parts.append(_render_footer())

    return "\n".join(parts)


def _render_header(diff: Diff) -> str:
    bits: list[str] = []
    if diff.added:
        bits.append(f"**{len(diff.added)} new**")
    if diff.modified:
        bits.append(f"**{len(diff.modified)} modified**")
    if diff.removed:
        bits.append(f"**{len(diff.removed)} removed**")
    summary = ", ".join(bits)
    return f"### 🤖 AI Surface Changes\n\n{summary}\n"


def _render_empty_diff() -> str:
    return (
        "### 🤖 AI Surface Changes\n\n"
        "No AI surface changes in this PR.\n\n"
        + _render_footer()
    )


def _render_added_finding(f: Finding) -> str:
    parts: list[str] = []
    parts.append(f"- **{_sanitise_inline(f.surface)}**")
    if f.permissions:
        perms = ", ".join(f"`{_sanitise_inline(p, max_len=80)}`" for p in f.permissions[:6])
        if len(f.permissions) > 6:
            perms += f", … +{len(f.permissions) - 6}"
        parts.append(f"  - Tools/permissions: {perms}")
    if f.evidence.files:
        files = ", ".join(f"`{_sanitise_inline(x)}`" for x in f.evidence.files[:3])
        if len(f.evidence.files) > 3:
            files += f", … +{len(f.evidence.files) - 3}"
        parts.append(f"  - Files: {files}")
    for risk in f.risk_indicators:
        parts.append(f"  - ⚠️ {_sanitise_inline(risk)}")
    if f.risk_indicators:
        # Per-finding deep link, surface context preserved through PR comment.
        url = build_upgrade_url(f, source="ai-surface", medium="pr-comment")
        parts.append(f"  - [Validate this surface →]({url})")
    return "\n".join(parts)


def _render_removed_finding(f: Finding) -> str:
    parts: list[str] = []
    parts.append(f"- ~~**{_sanitise_inline(f.surface)}**~~")
    if f.evidence.files:
        files = ", ".join(f"`{_sanitise_inline(x)}`" for x in f.evidence.files[:3])
        if len(f.evidence.files) > 3:
            files += f", … +{len(f.evidence.files) - 3}"
        parts.append(f"  - Was in: {files}")
    return "\n".join(parts)


def _render_modified(c: FindingChange) -> str:
    parts: list[str] = []
    parts.append(f"- **{_sanitise_inline(c.surface)}**")

    if c.permissions_added:
        added = ", ".join(f"`{_sanitise_inline(p, max_len=80)}`" for p in c.permissions_added[:6])
        if len(c.permissions_added) > 6:
            added += f", … +{len(c.permissions_added) - 6}"
        parts.append(f"  - ➕ Permissions added: {added}")
    if c.permissions_removed:
        removed = ", ".join(
            f"`{_sanitise_inline(p, max_len=80)}`" for p in c.permissions_removed[:6]
        )
        if len(c.permissions_removed) > 6:
            removed += f", … +{len(c.permissions_removed) - 6}"
        parts.append(f"  - ➖ Permissions removed: {removed}")

    if c.risks_added:
        for r in c.risks_added:
            parts.append(f"  - ⚠️ Risk added: {_sanitise_inline(r)}")
    if c.risks_removed:
        for r in c.risks_removed:
            parts.append(f"  - ✅ Risk cleared: {_sanitise_inline(r)}")

    if c.files_added:
        files = ", ".join(f"`{_sanitise_inline(x)}`" for x in c.files_added[:3])
        if len(c.files_added) > 3:
            files += f", … +{len(c.files_added) - 3}"
        parts.append(f"  - ➕ Now also in: {files}")
    if c.files_removed:
        files = ", ".join(f"`{_sanitise_inline(x)}`" for x in c.files_removed[:3])
        if len(c.files_removed) > 3:
            files += f", … +{len(c.files_removed) - 3}"
        parts.append(f"  - ➖ No longer in: {files}")

    return "\n".join(parts)


def _render_footer() -> str:
    # Footer link uses generic upgrade URL; per-finding context lives inline
    # next to each added/modified surface.
    upgrade_url = build_upgrade_url(source="ai-surface", medium="pr-comment")
    return (
        "<sub>"
        "Powered by [ai-surface](https://github.com/apisec-inc/ai-surface). "
        f"Validate which of these surfaces are exploitable: "
        f"[apisec.ai/ai-validation]({upgrade_url})."
        "</sub>"
    )
