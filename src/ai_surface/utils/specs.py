"""Shared parsing helpers for spec/config-shaped files.

Both the model-gateway and AI-infra detectors read the same families of
declarative files (YAML manifests, Helm values, Terraform/HCL, compose).
These helpers are the common, well-tested primitives they share:

* lenient YAML parsing (PyYAML when present, ``None`` otherwise)
* multi-document YAML splitting on ``---``
* best-effort scalar lookups by key / nested path
* image-value extraction
* a brace-balanced HCL body extractor that skips strings, comments and
  heredocs (so a literal ``}`` inside an inlined IAM policy does not close
  the block early)
* snippet helpers for evidence rendering

Keeping these in one place means the TF body extractor's edge-case handling
(heredocs, block comments, nested braces) is implemented and tested once.
"""
from __future__ import annotations

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

SNIPPET_MAX = 200

# YAML alias-expansion DoS ("billion laughs") defence. PyYAML's safe_load
# is safe against ``!!python/object`` but does not bound how many times an
# anchor can be aliased. A ~100 KB YAML file with nested aliases can expand
# to multi-GB at load time. Real documents almost never use more than a
# handful of anchors or aliases. We refuse to parse anything that crosses
# both thresholds, which catches all known bomb shapes while leaving normal
# YAML untouched.
_YAML_ALIAS_MAX = 200
_YAML_ANCHOR_MAX = 200


def _looks_like_yaml_bomb(text: str) -> bool:
    """Heuristic check that flags YAML with suspicious anchor / alias density."""
    # Cheap path: most YAML uses neither tokens at all.
    if "&" not in text and "*" not in text:
        return False
    anchors = sum(1 for _ in re.finditer(r"(?<![A-Za-z0-9_])&[A-Za-z0-9_]+", text))
    if anchors > _YAML_ANCHOR_MAX:
        return True
    aliases = sum(1 for _ in re.finditer(r"(?<![A-Za-z0-9_])\*[A-Za-z0-9_]+", text))
    return aliases > _YAML_ALIAS_MAX


# ---------------------------------------------------------------------------
# YAML helpers (PyYAML-first with regex fallback)
# ---------------------------------------------------------------------------


def parse_yaml_lenient(text: str) -> Any:
    """Parse YAML if PyYAML is available; return ``None`` otherwise.

    Never raises: a malformed document, a missing PyYAML, or a suspected
    YAML alias-expansion bomb all yield ``None`` so callers can fall back
    to regex extraction.
    """
    if _looks_like_yaml_bomb(text):
        log.debug("refusing to parse suspected YAML alias bomb")
        return None
    try:  # pragma: no cover - depends on environment
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return None
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("PyYAML failed to parse: %s", exc)
        return None


def split_yaml_documents(text: str) -> list[str]:
    """Split a YAML stream on ``---`` document markers (zero-aware)."""
    if "\n---" not in text and not text.lstrip().startswith("---"):
        return [text]
    parts: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            if buf:
                parts.append("\n".join(buf))
                buf = []
            continue
        buf.append(line)
    if buf:
        parts.append("\n".join(buf))
    return parts or [text]


def yaml_top_value(doc: str, key: str) -> str | None:
    """Extract a top-level scalar value (no indentation) from a YAML doc."""
    m = re.search(
        rf"^{re.escape(key)}\s*:\s*['\"]?([^'\"\n#]+?)['\"]?\s*$",
        doc,
        re.MULTILINE,
    )
    if not m:
        return None
    return m.group(1).strip() or None


def yaml_nested_value(doc: str, path: list[str]) -> str | None:
    """Best-effort nested scalar lookup by indentation depth.

    Walks the YAML line by line tracking the current key path via indentation;
    returns the scalar value at ``path`` if the path matches. Good enough for
    fixtures and well-formed manifests, not a full YAML parser.
    """
    if not path:
        return None
    stack: list[tuple[int, str]] = []  # (indent, key)
    for raw in doc.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:].strip()
            if not line:
                continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        # Pop deeper / equal-level frames before we descend.
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        current_path = [k for _, k in stack]
        if current_path == path and value:
            return value
    return None


def find_yaml_image_values(doc: str) -> list[str]:
    """Return every ``image: <value>`` value in the YAML document text."""
    out: list[str] = []
    for m in re.finditer(
        r"""^\s*image\s*:\s*['"]?([^'"#\n]+)""", doc, re.MULTILINE,
    ):
        candidate = m.group(1).strip()
        if candidate:
            out.append(candidate)
    return out


# ---------------------------------------------------------------------------
# HCL / Terraform body extraction
# ---------------------------------------------------------------------------

# HCL heredoc opener: ``<<TAG`` or ``<<-TAG`` (the leading-dash form strips
# indentation but still terminates on the same marker).
HEREDOC_OPENER_RE = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)")


def extract_hcl_body(text: str, open_brace_idx: int) -> str:
    """Return the body between the matching ``{...}`` starting at ``open_brace_idx``.

    Counts brace depth while skipping over the constructs that legally
    contain a stray ``}``:

    * Double / single-quoted string literals (with backslash escapes).
    * ``# ...`` and ``// ...`` line comments.
    * ``/* ... */`` block comments.
    * HCL heredocs: ``<<EOT ... EOT`` and ``<<-EOT ... EOT``. Common inside
      ``aws_sagemaker_endpoint`` blocks that inline IAM policy JSON, which
      contains literal ``}`` characters.

    Returns an empty string if no matching closing brace is found, or if
    a heredoc / block comment is opened but never terminated.

    ``open_brace_idx`` must point at the opening ``{`` itself.
    """
    n = len(text)
    if open_brace_idx >= n or text[open_brace_idx] != "{":
        return ""
    depth = 1
    i = open_brace_idx + 1
    body_start = i
    while i < n:
        ch = text[i]
        # String literals: skip until matching quote, honouring backslash escapes.
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        # Block comment ``/* ... */``.
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            close = text.find("*/", i + 2)
            if close == -1:
                return ""
            i = close + 2
            continue
        # Line comments.
        if ch == "#" or (ch == "/" and i + 1 < n and text[i + 1] == "/"):
            nl = text.find("\n", i)
            if nl == -1:
                return ""
            i = nl + 1
            continue
        # HCL heredoc: ``<<TAG`` or ``<<-TAG``. The terminating tag must
        # appear on a line by itself (whitespace allowed for the dash form).
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            opener = HEREDOC_OPENER_RE.match(text, i)
            if opener:
                tag = opener.group(1)
                # Find the end-of-line after the opener, then look for the
                # tag on its own line.
                eol = text.find("\n", opener.end())
                if eol == -1:
                    return ""
                search_pos = eol + 1
                # Closing tag on a line: optional leading whitespace, the
                # tag, optional trailing whitespace, end of line / file.
                closer_re = re.compile(
                    rf"^[ \t]*{re.escape(tag)}[ \t]*$",
                    re.MULTILINE,
                )
                close_m = closer_re.search(text, search_pos)
                if close_m is None:
                    return ""
                i = close_m.end()
                continue
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth -= 1
            if depth == 0:
                return text[body_start:i]
            i += 1
            continue
        i += 1
    return ""


# ---------------------------------------------------------------------------
# Snippet helpers
# ---------------------------------------------------------------------------


def first_line_containing(text: str, needle: str) -> str:
    if not needle:
        return head_snippet(text)
    idx = text.find(needle)
    if idx == -1:
        return head_snippet(text)
    line_start = text.rfind("\n", 0, idx) + 1
    line_end = text.find("\n", idx)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def first_match_line(patterns: tuple[re.Pattern, ...], text: str) -> str:
    for p in patterns:
        m = p.search(text)
        if not m:
            continue
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        if line_end == -1:
            line_end = len(text)
        return text[line_start:line_end].strip()
    return head_snippet(text)


def head_snippet(text: str) -> str:
    head = text[:SNIPPET_MAX]
    return head.replace("\n", " ").strip()


__all__ = [
    "SNIPPET_MAX",
    "parse_yaml_lenient",
    "split_yaml_documents",
    "yaml_top_value",
    "yaml_nested_value",
    "find_yaml_image_values",
    "HEREDOC_OPENER_RE",
    "extract_hcl_body",
    "first_line_containing",
    "first_match_line",
    "head_snippet",
]
