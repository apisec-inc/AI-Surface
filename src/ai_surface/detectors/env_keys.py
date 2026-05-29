"""AI provider env-key detector.

Scans environment-variable definition files for the *names* of API keys
belonging to AI providers (LLMs, gateways, observability/tracing). Only
the **names** of the keys are surfaced; values are deliberately never
captured, logged, or returned. Any value that appears next to a matched
key in a snippet is replaced with ``<redacted>`` before that snippet
leaves this module.

Targeted file shapes (any of these triggers a parse, anywhere in the tree):

* exact filename: ``.env``, ``.envrc``, ``env.example``
* glob match:    ``.env.*`` (e.g. ``.env.production``, ``.env.local``)
* glob match:    ``*.env`` (e.g. ``staging.env``)

All matches across all files aggregate into ONE :class:`Finding` whose
``surface`` is the literal string ``"AI Provider API Keys"``.
"""
from __future__ import annotations

import re
from pathlib import Path
from re import Pattern

from ..types import CATEGORY_ENV_KEY, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

# ---------------------------------------------------------------------------
# Provider key catalogue
# ---------------------------------------------------------------------------
#
# Each rule pairs a regex (matched against the env-variable NAME, anchored
# fully) with a short provider label used for aggregation. Order matters:
# more specific rules come before broader ones (e.g. AZURE_OPENAI_* must be
# tried before generic OPENAI_*).
#
# Patterns are case-insensitive at match time. They match the entire key
# name (^...$), so substrings like ``MY_OPENAI_API_KEY`` won't match.

_KEY_RULES: tuple[tuple[str, str], ...] = (
    # --- Azure OpenAI (must precede plain OpenAI) ---
    (r"AZURE_OPENAI_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD|ENDPOINT)", "Azure OpenAI"),

    # --- AWS Bedrock ---
    # Narrowed from BEDROCK_[A-Z0-9_]+ so that non-credential envvars like
    # BEDROCK_TIMEOUT_MS or BEDROCK_REGION don't get flagged as keys.
    (r"AWS_BEDROCK_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "AWS Bedrock"),
    (r"BEDROCK_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "AWS Bedrock"),

    # --- OpenAI ---
    (r"OPENAI_API_KEY", "OpenAI"),
    (r"OPENAI_ORG_ID", "OpenAI"),
    (r"OPENAI_PROJECT_ID", "OpenAI"),
    (r"OPENAI_[A-Z0-9_]*KEY", "OpenAI"),

    # --- Anthropic ---
    # Narrowed from ANTHROPIC_[A-Z0-9_]+ so ANTHROPIC_BASE_URL / TIMEOUT etc.
    # are not flagged as credentials.
    (r"ANTHROPIC_API_KEY", "Anthropic"),
    (r"ANTHROPIC_AUTH_TOKEN", "Anthropic"),
    (r"ANTHROPIC_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "Anthropic"),

    # --- Google: Gemini / Generative AI / Vertex ---
    (r"GOOGLE_GENERATIVE_AI_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "Google Generative AI"),
    (r"GEMINI_API_KEY", "Google Generative AI"),
    (r"VERTEX_AI_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "Google Vertex AI"),
    (r"GOOGLE_VERTEX_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "Google Vertex AI"),
    # GOOGLE_API_KEY is ambiguous (Maps, YouTube, Generative AI all reuse it).
    # Tagged with a separate provider label so callers can see the caveat.
    (r"GOOGLE_API_KEY", "Google API (ambiguous)"),

    # --- Other providers ---
    (r"TOGETHER_API_KEY", "Together"),
    (r"MISTRAL_API_KEY", "Mistral"),
    (r"MISTRAL_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|CREDENTIAL|PASSWORD)", "Mistral"),
    (r"COHERE_API_KEY", "Cohere"),
    (r"CO_API_KEY", "Cohere"),
    (r"REPLICATE_API_TOKEN", "Replicate"),
    (r"GROQ_API_KEY", "Groq"),
    (r"HUGGINGFACE_TOKEN", "Hugging Face"),
    (r"HF_TOKEN", "Hugging Face"),
    (r"HF_API_TOKEN", "Hugging Face"),
    (r"OLLAMA_HOST", "Ollama"),
    (r"OPENROUTER_API_KEY", "OpenRouter"),
    (r"PERPLEXITY_API_KEY", "Perplexity"),
    (r"DEEPINFRA_API_KEY", "DeepInfra"),

    # --- Gateways ---
    (r"LITELLM_[A-Z0-9_]*(?:KEY|TOKEN|SECRET|MASTER_KEY|PROXY_TOKEN)", "LiteLLM"),
    (r"PORTKEY_API_KEY", "Portkey"),
    (r"HELICONE_API_KEY", "Helicone"),

    # --- Observability / tracing (AI-adjacent) ---
    (r"LANGCHAIN_API_KEY", "LangChain"),
    (r"LANGSMITH_API_KEY", "LangSmith"),
)

# Compiled, fully-anchored, case-insensitive.
_COMPILED_RULES: tuple[tuple[Pattern[str], str], ...] = tuple(
    (re.compile(rf"^{pat}$", re.IGNORECASE), label) for pat, label in _KEY_RULES
)


# Explicit observability-key set used to set the tracing risk indicator.
_OBSERVABILITY_KEYS = frozenset({"LANGCHAIN_API_KEY", "LANGSMITH_API_KEY"})


# ---------------------------------------------------------------------------
# File-shape filter
# ---------------------------------------------------------------------------

# Names that are env files exactly (post-walk filename match).
_ENV_EXACT_NAMES = frozenset({".env", ".envrc", "env.example"})


def _is_env_file(path: Path) -> bool:
    """Decide whether ``path`` looks like an env definition file.

    Recognised: exact names (``.env``, ``.envrc``, ``env.example``),
    any name beginning with ``.env.`` (``.env.local``, ``.env.production``,
    ``.env.example``, ``.env.sample``), and any file whose final suffix is
    ``.env`` (``staging.env``, ``prod.env``).
    """
    name = path.name
    if name in _ENV_EXACT_NAMES:
        return True
    if name.startswith(".env.") and len(name) > len(".env."):
        return True
    # *.env (e.g. staging.env). Excludes plain ".env" — already matched above.
    return bool(name.endswith(".env") and name != ".env")


# ---------------------------------------------------------------------------
# Per-line parsing
# ---------------------------------------------------------------------------

# Match KEY=... lines, allowing optional `export ` prefix and surrounding
# whitespace. Captures only the KEY name; the value is deliberately never
# captured into a regex group that leaves this module.
_KEY_LINE_RE = re.compile(
    r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=""",
)


def _classify_key(name: str) -> str | None:
    """Return the provider label for ``name`` or ``None`` if not an AI key."""
    upper = name.upper()
    for rx, label in _COMPILED_RULES:
        if rx.match(upper):
            return label
    return None


def _redacted_snippet(key_name: str) -> str:
    """Build a safe, value-free snippet showing the matched key.

    Always of the form ``KEY=<redacted>``. Truncated to 150 chars, though
    real-world keys won't approach that length.
    """
    snippet = f"{key_name}=<redacted>"
    return snippet[:150]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class EnvKeyDetector:
    """Detects AI provider API key *names* across env-shaped files.

    Aggregates ALL detected key names (across any number of env files) into
    a single :class:`Finding`. Values are never captured.
    """

    name = "env_keys"
    category = CATEGORY_ENV_KEY

    def detect(self, root_path: str) -> list[Finding]:
        files_with_hits: list[str] = []
        key_names: list[str] = []  # preserves discovery order; deduped via seen
        seen_keys: set[str] = set()
        providers: list[str] = []
        seen_providers: set[str] = set()
        first_snippet: str | None = None
        has_observability = False

        # Walk without an extension filter; we filter by filename shape.
        for path in walk_files(root_path):
            if not _is_env_file(path):
                continue
            text = read_text_safe(path)
            if not text:
                continue

            file_keys: list[str] = []
            for raw in text.splitlines():
                line = raw.lstrip()
                # Skip blank lines and full-line comments.
                if not line or line.startswith("#"):
                    continue
                m = _KEY_LINE_RE.match(line)
                if m is None:
                    continue
                key = m.group(1)
                provider = _classify_key(key)
                if provider is None:
                    continue
                normalised = key.upper()
                if normalised not in seen_keys:
                    seen_keys.add(normalised)
                    key_names.append(normalised)
                if provider not in seen_providers:
                    seen_providers.add(provider)
                    providers.append(provider)
                if normalised in _OBSERVABILITY_KEYS:
                    has_observability = True
                file_keys.append(normalised)

            if file_keys:
                rel = relative_to_root(path, root_path)
                if rel not in files_with_hits:
                    files_with_hits.append(rel)
                if first_snippet is None:
                    # Snippet is built from the FIRST key we matched in the
                    # FIRST file we hit. Never the line itself; always a
                    # synthetic redacted form.
                    first_snippet = _redacted_snippet(file_keys[0])

        if not key_names:
            return []

        risk_indicators: list[str] = []
        if len(providers) >= 3:
            risk_indicators.append("multiple AI provider keys present")
        if has_observability:
            risk_indicators.append(
                "observability/tracing key present (production telemetry to third party)"
            )

        evidence = Evidence(
            files=sorted(files_with_hits),
            snippet=first_snippet or "",
            metadata={
                "key_names": sorted(key_names),
                "providers": sorted(providers),
            },
        )
        return [
            Finding(
                surface="AI Provider API Keys",
                category=CATEGORY_ENV_KEY,
                evidence=evidence,
                permissions=[],
                risk_indicators=risk_indicators,
            )
        ]


__all__ = ["EnvKeyDetector"]
