"""MCP deep-dive audit detector.

This is the audited counterpart to :mod:`ai_surface.detectors.mcp_servers`.
It discovers the same MCP surfaces (``.mcp.json`` / ``mcp.json`` configs,
per-server files under ``mcp_servers/``, and in-house MCP server source code)
and, for each, runs a static security audit ported from ``mcp-audit``:

* risk-flag identification (shell/db/filesystem/network/secret/source checks),
* secret detection in env blocks and direct string config values
  (NAME and TYPE only, never the value),
* registry/trust lookup against the bundled known-MCP list,
* OWASP LLM Top 10 mapping per risk flag.

The result is attached as a fully-populated :class:`~ai_surface.types.Audit`
on each :class:`~ai_surface.types.Finding`, and ``finding.severity`` is rolled
up to the maximum severity across the audit's risk flags. ``finding.bridges``
is left empty; the funnel layer (``cross_promo``) fills it.

Static only: no network access, no execution. Privacy: no secret value ever
enters a finding.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..data.mcp import owasp_llm, registry
from ..data.mcp.allowlist_bypass_binaries import detect_unsafe_command_allowlist
from ..data.mcp.risk_definitions import get_risk_flag_info
from ..data.mcp.secret_patterns import detect_secrets
from ..types import CATEGORY_MCP_SERVER as _CATEGORY
from ..types import (
    SEVERITY_ORDER,
    Audit,
    Evidence,
    Finding,
    RiskFlag,
    Secret,
)
from ..utils.walk import read_text_safe, relative_to_root, walk_files

# Reuse the discovery surface of the shallow MCP detector verbatim so both
# detectors see exactly the same set of servers.
from .mcp_servers import (
    _JS_PREFILTER_TOKENS,
    _JS_SERVER_PATTERNS,
    _PY_PREFILTER_TOKENS,
    _PY_SERVER_PATTERNS,
    _extract_tools,
    _first_match,
    _has_financial_action,
    _is_mcp_config_path,
    _parse_mcp_config,
    _permissions_from_cfg,
    _snippet_around,
    _snippet_for_server,
)

log = logging.getLogger(__name__)

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

_BROAD_PERMISSION_TOKENS = frozenset(
    {"admin", "write", "delete", "*", "all", "owner", "root"}
)

# Keys, in priority order, whose value (when a list of strings) we treat as the
# command's argv. Mirrors common MCP config shapes.
_ARG_KEYS = ("args", "arguments")


# --------------------------------------------------------------------------- #
# Ported static analysis (from mcp_audit/models.py: _parse_source/_identify_risks)
# --------------------------------------------------------------------------- #


def _parse_source(command: str, args: list[str], raw_config: dict[str, Any]) -> tuple[str, str]:
    """Determine an MCP's source string and transport type. Ported from mcp-audit."""
    command = command or ""

    url = (
        raw_config.get("url")
        or raw_config.get("serverUrl")
        or raw_config.get("endpoint")
        or raw_config.get("uri")
    )
    if isinstance(url, str) and url:
        return url, "remote"

    transport = str(raw_config.get("transport", "")).lower()
    if transport in ("sse", "http", "https", "websocket"):
        for key in ("baseUrl", "host", "server"):
            val = raw_config.get(key)
            if isinstance(val, str) and val:
                return val, "remote"
        return f"remote:{transport}", "remote"

    if command == "npx" and args:
        package_args = [a for a in args if a != "-y"]
        package = package_args[0] if package_args else "unknown"
        return package, "npm"

    if command == "node" and args:
        return args[0], "node"

    if command in ("python", "python3", "uvx", "uv"):
        return (args[0] if args else command), "python"

    if command == "docker":
        if "run" in args:
            idx = args.index("run")
            if idx + 1 < len(args):
                return args[idx + 1], "docker"
        return "docker", "docker"

    if command.startswith("/") or command.startswith("./"):
        return command, "local"

    return command or "unknown", "unknown"


def _identify_risks(
    command: str, args: list[str], env: dict[str, Any], name: str
) -> list[str]:
    """Identify risk-flag ids from an MCP config. Ported from mcp-audit."""
    risks: list[str] = []
    all_args = " ".join(str(a) for a in args).lower()
    name_lower = name.lower()

    filesystem_keywords = ["filesystem", "fs", "file", "directory", "path"]
    if any(kw in name_lower or kw in all_args for kw in filesystem_keywords) and any(
        p in all_args for p in ["/", "~", "$home", "."]
    ):
        risks.append("filesystem-access")

    db_keywords = ["postgres", "mysql", "sqlite", "mongo", "redis", "database", "db"]
    if any(kw in name_lower or kw in all_args for kw in db_keywords):
        risks.append("database-access")

    shell_keywords = ["shell", "exec", "command", "bash", "terminal"]
    if any(kw in name_lower or kw in all_args for kw in shell_keywords):
        risks.append("shell-access")

    api_keywords = ["http", "api", "fetch", "request", "url"]
    if any(kw in name_lower or kw in all_args for kw in api_keywords):
        risks.append("network-access")

    secret_keywords = ["key", "secret", "token", "password", "credential", "api_key"]
    for key in env:
        if any(kw in str(key).lower() for kw in secret_keywords):
            risks.append("secrets-in-env")
            break

    if command == "npx":
        package = args[0] if args else ""
        verified = ["@anthropic/", "@modelcontextprotocol/", "@openai/"]
        if not any(package.startswith(v) for v in verified) and not package.startswith("@"):
            risks.append("unverified-source")

    if command and (command.startswith("./") or command.startswith("/")):
        risks.append("local-binary")

    # A command allowlist (e.g. ALLOW_COMMANDS) that names a binary with its own
    # argument-level execution primitive does not actually restrict execution:
    # allowlisting argv[0] alone is bypassable (git -c alias, find -exec, python -c).
    if detect_unsafe_command_allowlist(env):
        risks.append("unsafe-command-allowlist")

    return risks


# --------------------------------------------------------------------------- #
# Config-shape extraction helpers
# --------------------------------------------------------------------------- #


def _str_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _command_args_env(cfg: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]]:
    """Pull (command, args, env) out of one server config block."""
    command = cfg.get("command")
    command = command if isinstance(command, str) else ""

    args: list[str] = []
    for key in _ARG_KEYS:
        val = cfg.get(key)
        if isinstance(val, list):
            args = [str(a) for a in val]
            break

    env = _str_dict(cfg.get("env"))
    return command, args, env


def _detect_reach(
    cfg: dict[str, Any], args: list[str], env: dict[str, Any], name: str
) -> tuple[list[dict[str, str]], list[str]]:
    """APIs/services this MCP reaches (masked) and AI models it uses (names).

    Ports mcp-audit's _detect_apis_in_config / _detect_model_in_config. Only
    masked URLs and model names cross; no credential value is ever surfaced.
    """
    reaches: list[dict[str, str]] = []
    models: list[str] = []
    try:
        from ..data.mcp.api_patterns import detect_apis  # noqa: PLC0415

        seen = set()
        for a in detect_apis(cfg, args, name) or []:
            d = a.to_dict() if hasattr(a, "to_dict") else {}
            key = (d.get("category"), d.get("url"))
            if key in seen:
                continue
            seen.add(key)
            reaches.append({
                "category": str(d.get("category", "")),
                "url": str(d.get("url", "")),  # masked by to_dict()
                "source_key": str(d.get("source_key", "")),
            })
    except Exception:  # noqa: BLE001 - reach detection must never break a scan
        pass
    try:
        from ..data.mcp.model_patterns import detect_model_from_config  # noqa: PLC0415

        m = detect_model_from_config(env, reaches, name)
        if m:
            md = m.to_dict() if hasattr(m, "to_dict") else {}
            name_val = md.get("model") or md.get("name") or md.get("model_id")
            if name_val:
                models.append(str(name_val))
    except Exception:  # noqa: BLE001
        pass
    return reaches, models


def _redact_snippet(snippet: str, secret_records: list[dict[str, Any]], cfg: dict[str, Any]) -> str:
    """Strip any detected secret value out of an evidence snippet.

    Privacy defence-in-depth: the snippet is rendered from raw config text, so
    a key/value pair like ``"STRIPE_SECRET_KEY": "sk_live_..."`` would otherwise
    surface the value. We replace the value of every key that produced a Secret
    with ``<redacted>``. The value is read transiently from ``cfg`` and never
    stored on the finding.
    """
    if not snippet or not secret_records:
        return snippet
    env = _str_dict(cfg.get("env"))
    out = snippet
    for rec in secret_records:
        key = rec["env_key"]
        value = env.get(key, cfg.get(key))
        if isinstance(value, str) and value:
            out = out.replace(value, "<redacted>")
    return out


def _non_env_string_values(cfg: dict[str, Any]) -> dict[str, Any]:
    """Top-level string config values that aren't env/name/command.

    Catches secrets hardcoded directly as config values (e.g. ``"apiKey": ...``)
    rather than inside an ``env`` block. Mirrors mcp-audit's behaviour.
    """
    out: dict[str, Any] = {}
    for k, v in cfg.items():
        if k in ("env", "name", "command"):
            continue
        if isinstance(v, str):
            out[k] = v
    return out


def _has_broad_permissions(permissions: list[str], cfg: dict[str, Any]) -> bool:
    haystack: list[str] = [p.lower() for p in permissions]
    for key in ("scope", "role", "access"):
        v = cfg.get(key)
        if isinstance(v, str):
            haystack.append(v.lower())
    tokens = _BROAD_PERMISSION_TOKENS
    for item in haystack:
        words = {w for w in _split_words(item) if w}
        if words & tokens:
            return True
    return False


def _split_words(s: str) -> list[str]:
    out: list[str] = []
    word = ""
    for ch in s:
        if ch.isalnum():
            word += ch
        else:
            if word:
                out.append(word)
            word = ""
    if word:
        out.append(word)
    return out


# --------------------------------------------------------------------------- #
# Audit construction
# --------------------------------------------------------------------------- #


def _max_severity(severities: list[str]) -> str | None:
    """Return the most severe value in ``severities`` (None if empty)."""
    ranked = [s for s in severities if s in _SEVERITY_RANK]
    if not ranked:
        return None
    return min(ranked, key=lambda s: _SEVERITY_RANK[s])


def _risk_flag(flag: str) -> RiskFlag:
    info = get_risk_flag_info(flag)
    return RiskFlag(
        flag=flag,
        severity=info["severity"],
        description=info["description"],
        owasp=owasp_llm.get_owasp_for_flag(flag),
        remediation=info.get("remediation", ""),
    )


def _build_audit(
    *,
    flag_ids: list[str],
    secret_records: list[dict[str, Any]],
    secret_location: str,
    source: str,
    name: str,
) -> Audit:
    """Assemble the deep-dive Audit block for one MCP server."""
    # Stable, de-duplicated flag order.
    seen_flags: set[str] = set()
    ordered_flags: list[str] = []
    for fid in flag_ids:
        if fid not in seen_flags:
            seen_flags.add(fid)
            ordered_flags.append(fid)

    risk_flags = [_risk_flag(fid) for fid in ordered_flags]

    secrets: list[Secret] = []
    for rec in secret_records:
        secrets.append(
            Secret(
                name=rec["env_key"],  # NAME ONLY - never the value
                secret_type=rec["type"],
                confidence=rec.get("confidence", ""),
                severity=rec.get("severity", ""),
                location=secret_location,
            )
        )

    # Registry / trust signals.
    signals = registry.trust_signals(source, name)

    # Flatten unique OWASP ids across risk flags (stable order).
    owasp_mappings: list[str] = []
    for rf in risk_flags:
        for oid in rf.owasp:
            if oid not in owasp_mappings:
                owasp_mappings.append(oid)

    return Audit(
        risk_flags=risk_flags,
        secrets=secrets,
        trust_score=signals["trust_score"],
        trust_label=signals["trust_label"],
        registry_match=signals["registry_match"],
        owasp_mappings=owasp_mappings,
    )


def _finalize_finding(finding: Finding, audit: Audit) -> Finding:
    """Attach the audit and roll severity up to the max across risk flags."""
    finding.audit = audit
    finding.severity = _max_severity([rf.severity for rf in audit.risk_flags])
    finding.bridges = []  # funnel layer fills this
    return finding


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #


class McpAuditDetector:
    """Discover MCP servers and attach a deep-dive security audit to each.

    Produces one :class:`Finding` per declared/implemented MCP server, with a
    populated :class:`Audit`. Safe to run on any directory tree; deterministic.
    """

    name = "mcp_audit"
    category = _CATEGORY

    def detect(self, root_path: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_configs(root_path))
        findings.extend(self._detect_source(root_path))
        return findings

    # -- config-declared MCP servers ---------------------------------------- #

    def _detect_configs(self, root_path: str) -> list[Finding]:
        out: list[Finding] = []
        root = Path(root_path).resolve()
        for path in walk_files(root_path, extensions=[".json", ".yaml", ".yml"]):
            if not _is_mcp_config_path(path, root):
                continue
            text = read_text_safe(path)
            if not text:
                continue
            servers = _parse_mcp_config(path, text)
            if not servers:
                continue
            rel = relative_to_root(path, root_path)
            for server_name, server_cfg in servers:
                out.append(self._audit_config_server(rel, server_name, server_cfg, text))
        return out

    def _audit_config_server(
        self,
        rel_path: str,
        server_name: str,
        server_cfg: dict[str, Any],
        full_text: str,
    ) -> Finding:
        cfg = _str_dict(server_cfg)
        command, args, env = _command_args_env(cfg)
        source, server_type = _parse_source(command, args, cfg)
        permissions = _permissions_from_cfg(cfg)

        # 1. Capability/source risk flags.
        flag_ids = _identify_risks(command, args, env, server_name)

        # 2. Secret detection: env block first, then direct string values.
        secret_records = detect_secrets(env, rel_path, server_name)
        secret_location = f"{rel_path}:env"
        non_env = _non_env_string_values(cfg)
        if non_env:
            existing = {s["env_key"] for s in secret_records}
            for s in detect_secrets(non_env, rel_path, server_name):
                if s["env_key"] not in existing:
                    secret_records.append(s)
                    secret_location = rel_path

        # If concrete secrets were found, upgrade secrets-in-env -> secrets-detected.
        if secret_records:
            if "secrets-in-env" in flag_ids:
                flag_ids.remove("secrets-in-env")
            if "secrets-detected" not in flag_ids:
                flag_ids.append("secrets-detected")

        # 3. Remote transport flag.
        if server_type == "remote" and "remote-mcp" not in flag_ids:
            flag_ids.append("remote-mcp")

        # 4. Financial / broad-permission flags (ai-surface discovery semantics).
        if _has_financial_action(list(permissions) + [server_name]):
            flag_ids.append("financial-action")
        if _has_broad_permissions(permissions, cfg):
            flag_ids.append("broad-permissions")

        # 5. Blast-radius context: APIs/services this MCP reaches and models it
        #    uses (masked, names only). Parity with the original mcp-audit.
        reaches, models = _detect_reach(cfg, args, env, server_name)

        risk_indicators = self._risk_indicators(flag_ids)
        snippet = _redact_snippet(_snippet_for_server(server_name, full_text), secret_records, cfg)

        meta: dict[str, Any] = {
            "server_name": server_name,
            "source": "config",
            "server_type": server_type,
            "mcp_source": source,
            "tools": list(permissions),
            "config_keys": sorted(cfg.keys()),
        }
        if reaches:
            meta["reaches"] = reaches
        if models:
            meta["models"] = models

        finding = Finding(
            surface=f"MCP Server: {server_name}",
            category=_CATEGORY,
            evidence=Evidence(
                files=[rel_path],
                snippet=snippet,
                metadata=meta,
            ),
            permissions=permissions,
            risk_indicators=risk_indicators,
        )

        audit = _build_audit(
            flag_ids=flag_ids,
            secret_records=secret_records,
            secret_location=secret_location,
            source=source,
            name=server_name,
        )
        return _finalize_finding(finding, audit)

    # -- in-house MCP server source code ------------------------------------ #

    def _detect_source(self, root_path: str) -> list[Finding]:
        out: list[Finding] = []
        exts = [".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
        for path in walk_files(root_path, extensions=exts, skip_tests=True):
            text = read_text_safe(path)
            if not text:
                continue
            is_python = path.suffix.lower() == ".py"
            tokens = _PY_PREFILTER_TOKENS if is_python else _JS_PREFILTER_TOKENS
            if not any(tok in text for tok in tokens):
                continue
            patterns = _PY_SERVER_PATTERNS if is_python else _JS_SERVER_PATTERNS
            match = _first_match(patterns, text)
            if match is None:
                continue
            tools = _extract_tools(text, is_python=is_python)
            rel = relative_to_root(path, root_path)
            out.append(self._audit_source_server(rel, text, match, tools))
        return out

    def _audit_source_server(
        self, rel_path: str, text: str, match: Any, tools: list[str]
    ) -> Finding:
        # In-house code is by definition not in the known registry: unverified.
        flag_ids: list[str] = ["unverified-source"]
        if _has_financial_action(tools):
            flag_ids.append("financial-action")

        risk_indicators = ["in-house MCP server (custom code, audit recommended)"]
        risk_indicators.extend(self._risk_indicators(flag_ids))

        finding = Finding(
            surface=f"MCP Server (in-house): {rel_path}",
            category=_CATEGORY,
            evidence=Evidence(
                files=[rel_path],
                snippet=_snippet_around(text, match.start()),
                line_numbers=[1 + text.count("\n", 0, match.start())],
                metadata={"tools": tools, "source": "code"},
            ),
            permissions=list(tools),
            risk_indicators=risk_indicators,
        )

        audit = _build_audit(
            flag_ids=flag_ids,
            secret_records=[],
            secret_location=rel_path,
            source=rel_path,
            name=Path(rel_path).stem,
        )
        return _finalize_finding(finding, audit)

    # -- shared --------------------------------------------------------------- #

    @staticmethod
    def _risk_indicators(flag_ids: list[str]) -> list[str]:
        """Plain-English, severity-free indicators derived from flag ids.

        These live alongside the structured ``audit.risk_flags`` and feed the
        discovery-layer presentation. De-duplicated, order-stable.
        """
        phrasing = {
            "secrets-detected": "secrets in config",
            "secrets-in-env": "secrets in env block",
            "financial-action": "financial action exposed",
            "broad-permissions": "broad permissions",
            "shell-access": "shell access",
            "filesystem-access": "filesystem access",
            "database-access": "database access",
            "network-access": "network access",
            "remote-mcp": "remote MCP endpoint",
            "unverified-source": "unverified source",
            "local-binary": "local binary",
        }
        out: list[str] = []
        for fid in flag_ids:
            phrase = phrasing.get(fid)
            if phrase and phrase not in out:
                out.append(phrase)
        return out


__all__ = ["McpAuditDetector"]
