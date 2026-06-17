"""Core types for ai-surface.

Every detector produces Findings against a shared schema. The orchestrator
aggregates findings into a Report which reporters render.

Python 3.9 compatible: uses `from __future__ import annotations` so newer
syntax (X | None, list[X]) is allowed in annotations only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from . import __version__ as _TOOL_VERSION  # noqa: N812 - module-private alias

# Categories that detectors can claim. Keep this list short and stable.
# New detectors should reuse one of these or propose adding a category.
CATEGORY_LLM_SDK = "llm-sdk"
CATEGORY_AGENT_FRAMEWORK = "agent-framework"
CATEGORY_MCP_SERVER = "mcp-server"
CATEGORY_MODEL_GATEWAY = "model-gateway"
CATEGORY_AI_INFRA = "ai-infra"
CATEGORY_ENV_KEY = "env-key"
CATEGORY_API = "api"  # HTTP/REST endpoints + OpenAPI specs (feeds API runtime SKU)
CATEGORY_VECTOR_STORE = "vector-store"  # vector DBs + RAG retrieval pipelines

ALL_CATEGORIES = (
    CATEGORY_LLM_SDK,
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
    CATEGORY_API,
    CATEGORY_VECTOR_STORE,
)

# Severity is OPTIONAL and only set by deep-dive audit layers (MCP and agent
# audits, plus the oversight and observability passes).
# Pure discovery findings leave severity as None. Do not invent severity for
# inventory-only findings; absence of severity means "inventoried, not assessed".
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

SEVERITY_ORDER = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)

# Paid-platform upgrade targets. One free scan can route a finding to one or
# more of these. The disconnect between free discovery and paid validation is
# intentional; these are upgrade paths, not integrations.
SKU_AGENT_VALIDATION = "agent-validation"  # AI/agent surface -> agent-native AEV
SKU_MCP_RUNTIME = "mcp-runtime"  # MCP findings -> MCP runtime validation
SKU_API_RUNTIME = "api-runtime"  # discovered APIs -> API outside-in runtime testing

# Disposition: the boundary between independent DevOps value and the platform
# journey. resolve-here = statically fixable now (no platform needed).
# validate-runtime = a candidate; only runtime can prove exploitability.
DISPOSITION_RESOLVE = "resolve-here"
DISPOSITION_VALIDATE = "validate-runtime"

# Runtime-validation availability for a validate-runtime finding. Honest about
# what the platform can do today: API is live, others are on the way. "n/a" is
# used for resolve-here findings (no runtime journey).
RUNTIME_LIVE = "live"
RUNTIME_COMING = "coming"
RUNTIME_NA = "n/a"


@dataclass
class Evidence:
    """Where a finding came from. Always include enough for a human to verify."""

    files: list[str] = field(default_factory=list)
    """File paths (relative to scan root) where the surface was found."""

    snippet: str = ""
    """A short code/config snippet showing the detection. Truncate to ~200 chars."""

    line_numbers: list[int] = field(default_factory=list)
    """Optional: specific line numbers in the primary file."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Detector-specific extras (model name, tool list, permissions, etc.).

    For CATEGORY_API findings, use these documented keys so the UI and the
    API-runtime onboarding bridge can read them uniformly:
      - "method": HTTP method or "*" (str)
      - "path": route path, e.g. "/v1/orders/{id}" (str)
      - "source_spec": path to the OpenAPI/swagger file if discovered (str)
      - "auth": detected auth style, e.g. "bearer", "none", "unknown" (str)
      - "framework": e.g. "fastapi", "express", "spring" (str)
    """


@dataclass
class RiskFlag:
    """One specific risk surfaced by a deep-dive audit layer (MCP and agents).

    This is the audit counterpart to Finding.risk_indicators (which stays
    severity-free, plain-English, for the discovery layer). RiskFlag carries
    severity and structured mappings because an audit layer has assessed it.
    """

    flag: str
    """Stable machine id, e.g. "shell-access", "secrets-in-env", "remote-mcp"."""

    severity: str
    """One of SEVERITY_* constants."""

    description: str = ""
    """Plain-English explanation for the UI and reports."""

    owasp: list[str] = field(default_factory=list)
    """OWASP LLM Top 10 ids this maps to, e.g. ["LLM06", "LLM02"]."""

    remediation: str = ""
    """Optional short remediation guidance."""


@dataclass
class Secret:
    """A detected secret. Name/type only, NEVER the value (privacy guarantee)."""

    name: str
    """The variable/key name only, e.g. "AWS_SECRET_ACCESS_KEY"."""

    secret_type: str = ""
    """Classified type, e.g. "aws-key", "github-pat", "openai-key"."""

    confidence: str = ""
    """"high" | "medium"."""

    severity: str = ""
    """One of SEVERITY_* constants."""

    location: str = ""
    """Where it was seen (file or config key). No value, ever."""


@dataclass
class Audit:
    """Deep-dive audit results attached to a discovery Finding.

    Optional. Present only when a deep-dive module (MCP and agents today, plus
    the oversight and observability passes) has assessed the discovered surface.
    Absent for inventory-only findings. This is the bridge between ai-surface's
    discovery layer and the mcp-audit depth merged in.
    """

    risk_flags: list[RiskFlag] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    trust_score: float | None = None
    """0-100 reputation score if the source is in a known registry."""
    trust_label: str = ""
    """e.g. "verified", "community", "unknown"."""
    registry_match: str = ""
    """"known" | "unknown" | "" (not applicable)."""
    owasp_mappings: list[str] = field(default_factory=list)
    """Flattened unique OWASP ids across risk_flags, for quick UI badges."""


@dataclass
class Bridge:
    """A paid-platform upgrade path surfaced for a finding (the funnel)."""

    sku: str
    """One of SKU_* constants."""

    label: str
    """User-facing CTA text."""

    url: str
    """UTM-tagged deep link into the APIsec platform."""

    status: str = "live"
    """Runtime-validation availability for this bridge: live or coming. "coming"
    means the platform validates this category soon, not today (honest funnel)."""


@dataclass
class Finding:
    """A single AI surface detected in the scanned codebase.

    One Finding represents one logical surface. Examples:
      - "Anthropic SDK used in src/agents/"  (one finding, multiple files)
      - "MCP server: stripe-mcp"             (one finding per configured server)
      - "LangChain agent: refund_agent"      (one finding per agent definition)

    Detectors should aggregate sensibly. If Anthropic SDK appears in 12 files,
    that is one Finding with 12 file evidence entries, not 12 findings.
    """

    surface: str
    """User-facing name. Examples: "Anthropic SDK", "MCP Server: stripe-mcp",
    "LangChain Agent: refund_agent"."""

    category: str
    """One of the CATEGORY_* constants above."""

    evidence: Evidence
    """Where this surface was detected."""

    permissions: list[str] = field(default_factory=list)
    """What this surface can reach. Examples: ["read pages", "write pages"],
    ["repo:read", "repo:write"], ["query_customer_db", "refund_payment"]."""

    risk_indicators: list[str] = field(default_factory=list)
    """Plain-English risk flags for human review. Examples:
      - "broad permissions"
      - "financial action exposed"
      - "unaudited (first appearance in repo)"
      - "PII flows into LLM call"
    Do NOT include severity scores. This is descriptive, not prescriptive."""

    detector_name: str = ""
    """The detector that produced this finding. Filled in by orchestrator."""

    severity: str | None = None
    """OPTIONAL. Set only by deep-dive audit layers. None = inventoried, not
    assessed. When set, it is the max severity across this finding's audit
    risk_flags. One of SEVERITY_* constants."""

    audit: Audit | None = None
    """OPTIONAL deep-dive audit results. None for pure discovery findings."""

    bridges: list[Bridge] = field(default_factory=list)
    """Paid-platform upgrade paths for this finding. Filled in by the funnel
    layer (cross_promo) based on category and audit results."""

    disposition: str | None = None
    """resolve-here (independent DevOps value) or validate-runtime (platform
    candidate). Filled in by the dispositions layer. None until classified."""

    runtime_status: str | None = None
    """For validate-runtime findings: live / coming / n/a. Honest about whether
    the platform can validate this category today."""

    runtime_question: str | None = None
    """For validate-runtime findings: the exact exploitability question only
    runtime can answer (e.g. 'Can user A read user B's object?')."""


@dataclass
class Summary:
    """Aggregates for the UI and CI gates. Computed by the reporter, not stored
    on detectors. Gives the UI everything it needs for the top-of-page cards
    without re-walking findings."""

    total_findings: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    """Counts of findings that HAVE a severity. Discovery-only findings are
    excluded (they have no severity)."""
    top_risks: list[str] = field(default_factory=list)
    """Up to ~10 "surface: risk" phrases, severity-ordered, for the UI banner."""
    bridges_available: list[str] = field(default_factory=list)
    """Distinct SKU_* values reachable from this scan. Drives the upgrade CTAs."""

    resolve_here_count: int = 0
    """Findings you can act on now without the platform (independent value)."""
    validate_runtime_count: int = 0
    """Candidates whose exploitability only runtime can prove (the journey)."""


@dataclass
class Report:
    """The complete output of one scan run."""

    findings: list[Finding]
    scan_root: str
    scan_timestamp: str
    detectors_run: list[str]
    schema_version: str = "1.0"
    tool_version: str = _TOOL_VERSION
    repository: str = ""
    """OPTIONAL provenance: the scanned repo's origin remote (e.g.
    ``apisec-inc/AI-Surface``), detected from .git/config. Empty when the scan
    root is not a git repo. Credentials in the remote URL are stripped."""
    errors: list[str] = field(default_factory=list)
    """Non-fatal errors from individual detectors. Surface to user but do not abort."""

    summary: Summary | None = None
    """OPTIONAL aggregates for UI/CI. Computed by the reporter via build_summary()
    if not already set. Detectors never set this."""

    @classmethod
    def now(cls) -> str:
        """Standard ISO timestamp for scan_timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def by_category(self) -> dict[str, list[Finding]]:
        """Group findings by category for reporting."""
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out

    def all_risk_indicators(self) -> list[str]:
        """Flatten unique risk indicators across all findings."""
        seen = []
        for f in self.findings:
            for r in f.risk_indicators:
                phrase = f"{f.surface}: {r}"
                if phrase not in seen:
                    seen.append(phrase)
        return seen

    def build_summary(self) -> Summary:
        """Compute UI/CI aggregates from the current findings."""
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        bridges: list[str] = []
        for f in self.findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
            if f.severity:
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            for b in f.bridges:
                if b.sku not in bridges:
                    bridges.append(b.sku)

        # Top risks, severity-ordered. Audit risk_flags first (they carry
        # severity), then plain discovery indicators.
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        flagged: list[tuple[int, str]] = []
        for f in self.findings:
            if f.audit:
                for rf in f.audit.risk_flags:
                    flagged.append(
                        (rank.get(rf.severity, 99), f"{f.surface}: {rf.description or rf.flag}")
                    )
        flagged.sort(key=lambda t: t[0])
        top = [phrase for _, phrase in flagged][:10]
        if not top:
            top = self.all_risk_indicators()[:10]

        resolve_here = sum(1 for f in self.findings if f.disposition == DISPOSITION_RESOLVE)
        validate_rt = sum(1 for f in self.findings if f.disposition == DISPOSITION_VALIDATE)

        return Summary(
            total_findings=len(self.findings),
            by_category=by_category,
            by_severity=by_severity,
            top_risks=top,
            bridges_available=bridges,
            resolve_here_count=resolve_here,
            validate_runtime_count=validate_rt,
        )


@runtime_checkable
class Detector(Protocol):
    """Detector protocol. Every detector implements this.

    Implementations should be classes with `name` and `category` set as class
    attributes (or instance attributes) and a `detect()` method.

    Detectors must:
      - Return [] (not raise) when nothing is found.
      - Be safe to run on any directory tree, including non-code directories.
      - Not mutate the filesystem.
      - Be deterministic for the same input.
      - Aggregate sensibly (one finding per logical surface, not per file).
    """

    name: str
    category: str

    def detect(self, root_path: str) -> list[Finding]:
        ...


# Convenience for orchestrator: optional detector context.
@dataclass
class DetectorContext:
    """Optional shared context passed to detectors at run time.

    Some detectors may want to know the scan root absolute path, whether
    git history is available, or share a cache. Passed as a kwarg if the
    detector accepts it.
    """

    scan_root: str
    has_git: bool = False
    cache: dict[str, Any] = field(default_factory=dict)
