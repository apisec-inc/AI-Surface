# Architecture

How `ai-surface` is structured internally, the contracts between components, and how to extend it.

This document is for contributors and operators who want to understand the tool beyond the user-facing README. If you just want to scan a repo, the [README](../README.md) is what you want.

## Contents

- [Design principles](#design-principles)
- [Component overview](#component-overview)
- [The data model](#the-data-model)
- [Detector protocol](#detector-protocol)
- [Scan lifecycle](#scan-lifecycle)
- [Reporter contracts](#reporter-contracts)
- [The diff engine](#the-diff-engine)
- [Validation and next-step links](#validation-and-next-step-links)
- [GitHub Action wrapper](#github-action-wrapper)
- [Adding a new detector](#adding-a-new-detector)
- [Performance characteristics](#performance-characteristics)

## Design principles

`ai-surface` was designed against these constraints:

1. **Local and static.** The CLI executes no code, makes no network calls, and needs no credentials; it runs on a developer laptop with nothing beyond a `pipx` / `uvx` / `pip` install. (The GitHub Action's only network call is posting a PR comment via GitHub's API; see the network boundary in the Action section.)
2. **Stateless per run.** Each scan walks the file tree from scratch. No persistent cache, no daemon, no incremental analysis. Cross-file effects mean incremental analysis would have to recompute most of the same work for correctness.
3. **Conservative findings.** False positives kill adoption faster than false negatives. We'd rather miss a surface than flag a non-surface.
4. **Composable outputs.** The same scan output feeds local dev, CI, audit logs, the AI-BOM, and optional next-step validation links. One scan, many consumers.
5. **Detector isolation.** A buggy detector should not kill the whole scan. The orchestrator catches per-detector exceptions and emits them as report errors.

## Component overview

```mermaid
flowchart TB
    CLI[cli.py - Typer entry point]
    Orch[orchestrator.py - aggregates findings]
    Det[detectors/ - one module per category]
    Rep[reporters/ - terminal, JSON, markdown, CycloneDX, SARIF, UI]
    Diff[diff.py - base vs head comparison]
    Walk[utils/walk.py - file walker, root .gitignore only]
    Links[cross_promo.py - optional next-step validation links]

    CLI --> Orch
    Orch --> Det
    Det --> Walk
    Orch --> Rep
    CLI --> Diff
    Rep --> Links
```

Each detector module is independent. They run sequentially today; parallel execution is on the roadmap.

## The data model

Three core types in `src/ai_surface/types.py`:

```python
@dataclass
class Evidence:
    files: list[str]              # Where the finding was located
    snippet: str                  # A representative line of source
    line_numbers: list[int]       # Optional line refs
    metadata: dict[str, Any]      # Detector-specific extras (models_used, tool_count, etc.)


@dataclass
class Finding:
    surface: str                  # Display name (e.g. "LangChain Agent: refund_agent")
    category: str                 # e.g. agent-framework, mcp-server, vector-store, llm-sdk, api, model-gateway, ai-infra, env-key
    evidence: Evidence
    permissions: list[str]        # Tools or capabilities exposed
    risk_indicators: list[str]    # Conservative, severity-free semantic flags
    detector_name: str            # Set by orchestrator
    severity: str | None          # Set only by the deep-dive audit; None for inventory findings
    audit: Audit | None           # Risk flags (OWASP + governance clauses), secrets, trust
    bridges: list[Bridge]         # Optional next-step validation links
    disposition: str              # resolve-here vs validate-runtime


@dataclass
class Report:
    findings: list[Finding]
    scan_root: str                # basename only (privacy-safe)
    scan_timestamp: str           # ISO 8601 with timezone
    detectors_run: list[str]
    schema_version: str           # frozen report contract (docs/SCHEMA_v1.md)
    tool_version: str
    repository: str               # origin remote (owner/repo) from .git/config; credentials stripped
    errors: list[str]             # Per-detector failures, captured not raised
    summary: Summary | None       # Aggregates for UI / CI
```

**The contract is stable across reporters.** Every reporter (terminal, JSON, markdown, CycloneDX, SARIF) and the diff engine consume the same `Report`. The JSON envelope is frozen as schema 1.0 (see [docs/SCHEMA_v1.md](SCHEMA_v1.md)); a new reporter just consumes this shape.

## Detector protocol

A detector is anything that satisfies this Python `Protocol`:

```python
class Detector(Protocol):
    name: str                                      # Unique identifier
    category: str                                  # One of the category constants

    def detect(self, root_path: str) -> list[Finding]:
        ...
```

That's it. The orchestrator calls `detect(root_path)`, captures exceptions, and aggregates results. A detector decides for itself how to walk files, what to read, and what shape its findings take.

Most detectors share infrastructure via `utils/walk.py` (a file walker that prunes a fixed set of build/vendor directories and honours the **scan-root** `.gitignore` only; nested `.gitignore` files, `.git/info/exclude`, and the global git excludesfile are NOT consulted) and `utils/io.py` (safe text reading with encoding fallback), but neither is required by the protocol.

The walker enforces hard resource caps so a pathological or hostile tree cannot stall the scanner: `MAX_FILES = 250,000` files per traversal and `MAX_TOTAL_BYTES = 5 GiB` of cumulative content size, accounted via `os.lstat` so symlinks count as their own inode size. Per-file reads via `read_text_safe` are bounded at 5 MB and symlinks are refused outright. See `SECURITY.md` for the full threat-model rationale.

## Scan lifecycle

```mermaid
sequenceDiagram
    actor User
    participant CLI as cli.py
    participant Orch as orchestrator.py
    participant Det as detectors[]
    participant Walk as walk.py
    participant Rep as reporter

    User->>CLI: ai-surface scan /path
    CLI->>Orch: Orchestrator(detectors).run(/path)

    loop For each detector
        Orch->>Det: detector.detect(/path)
        Det->>Walk: walk_files(/path, extensions=[...])
        Walk-->>Det: file paths (root .gitignore honoured)
        Det->>Det: pattern match per file
        Det-->>Orch: list[Finding]
    end

    Orch->>Orch: assemble Report
    Orch-->>CLI: Report
    CLI->>Rep: render(report)
    Rep-->>User: stdout / file
```

Per-detector errors are caught by the orchestrator. A detector that raises is reported in `report.errors` with the exception class name and message. Other detectors still run. The CLI shows the error count in default mode; `-v` shows the full error detail.

## Reporter contracts

The core reporters are:

| Reporter | Use case | Output |
|---|---|---|
| `terminal_reporter.py` | Local dev, interactive | Rich-styled stdout: sections, severities, OWASP + governance mappings |
| `json_reporter.py` | CI scripting, programmatic | Schema-1.0 JSON envelope |
| `markdown_reporter.py` | `.ai-inventory.md`, PR comments | Markdown with headings and risk callouts |
| `cyclonedx_reporter.py` | AI-BOM / governance artifact | CycloneDX document |
| `sarif_reporter.py` | GitHub code scanning | SARIF 2.1.0 |

The CLI also serves an interactive `--ui` attack-surface map on loopback, and the `--write-inventory` / `--quiet` modes reuse the markdown output and a one-line summary.

Each reporter exposes a function with the same shape:

```python
def render_<format>(report: Report, ...) -> str | None:
    ...
```

Terminal renders directly to a `rich.Console`; the others return strings the CLI prints. Adding a reporter: implement `render_<format>(report) -> str`, register it in `cli.py`, add tests.

## The diff engine

`diff.py` computes the delta between two scans. Used by:

1. The `ai-surface compare base.json head.json` CLI command
2. The GitHub Action, which analyzes the PR head and the PR base (a git worktree of the base ref) and diffs head against base

The diff algorithm:

```mermaid
flowchart LR
    Base[Base Report] --> Compare
    Head[Head Report] --> Compare
    Compare{Compare<br/>by surface_id}
    Compare -->|in head only| New[New surfaces]
    Compare -->|in base only| Removed[Removed surfaces]
    Compare -->|in both| Changed{Changed?}
    Changed -->|permissions or risk delta| Modified[Modified surfaces]
    Changed -->|no delta| Stable[Unchanged surfaces -<br/>not shown in diff]
```

Surfaces are matched by a stable `surface_id` derived from category + surface name + primary file path. This is the contract that the future specialist CLIs (`mcp-audit`, `agent-audit`, etc.) will share. same `surface_id` means same surface, enabling cross-tool joins.

## Validation and next-step links

`cross_promo.py` builds optional links from findings to deeper validation workflows and companion OSS tools. Links are rendered only in user-facing output and transmit no finding data.

```python
SPECIALIST_TOOLS = {
    "mcp-server": {
        "tool": "mcp-audit",
        "url": "https://github.com/apisec-inc/mcp-audit",
        "tagline": "deep audit of MCP server configs and capabilities",
        "available": True,
    },
    "agent-framework": {
        "tool": "agent-audit",
        "url": "https://github.com/apisec-inc/agent-audit",
        "tagline": "deep audit of agent tool authority and blast radius",
        "available": False,  # not yet shipped; hidden from output
    },
    ...
}
```

When a finding carries risk indicators, the reporter calls `build_upgrade_url(finding, ...)` to construct a deep link to the relevant validation workflow. The link encodes the finding's category and primary risk indicator, plus UTM parameters for attribution. It is a URL only; no source, findings, or metadata are transmitted.

## GitHub Action wrapper

The Action is in `.github/action/entry.py` plus `action.yml` and `Dockerfile`: Flow:

```mermaid
sequenceDiagram
    actor GH as GitHub
    participant CI as Action runner
    participant Entry as entry.py
    participant AS as ai-surface CLI
    participant API as GitHub API

    GH->>CI: workflow triggered (pull_request)
    CI->>Entry: docker run entry.py
    Entry->>AS: ai-surface scan . --output json
    AS-->>Entry: head report JSON

    alt base ref reachable (fetch-depth: 0)
        Entry->>Entry: git worktree of GITHUB_BASE_REF
        Entry->>AS: ai-surface scan (base worktree) --output json
        AS-->>Entry: base report JSON
        Entry->>AS: ai-surface compare base.json head.json
        AS-->>Entry: diff markdown (new / modified / removed)
    else base ref unavailable (push, first PR, fork)
        Entry->>Entry: fall back to a full current-state inventory
    end

    Entry->>API: POST sticky PR comment
    API-->>Entry: comment URL
    Entry->>CI: exit code (0 or 1 based on fail-on / fail-on-risk)
```

The Action is a thin shell. All the logic is in the Python CLI; the Action just orchestrates the analysis, comparison, and comment posting, so local CLI and CI behavior stay consistent.

**Network boundary.** The local CLI performs no network calls. When `comment-on-pr` is enabled in GitHub Actions, the action uses the repository's `GITHUB_TOKEN` to post or update a PR comment through the GitHub API. It does not send source code, findings, or metadata to APIsec.

## Adding a new detector

1. **Create the module:** `src/ai_surface/detectors/your_category.py`: Define a class with `name`, `category`, and `detect(root_path) -> list[Finding]`.
2. **Register it:** Add to `default_detectors()` in `orchestrator.py`.
3. **Add a category constant** if you're introducing one: `types.py`.
4. **Add display strings:** if the terminal reporter needs custom formatting, register in `CATEGORY_DISPLAY` in `terminal_reporter.py`.
5. **Add cross-promo registration** if a specialist tool exists for this category: `cross_promo.py`.
6. **Write tests:** fixtures under `tests/fixtures/your_category/`, test cases under `tests/test_your_category.py`: Cover the positive case, false-positive resistance, edge cases.
7. **Update docs:** README detector table, this file's coverage list.

A reasonable detector PR adds 100-300 lines of code, 50-150 lines of test coverage, and a few fixture files. The longest part is usually verifying coverage against real-world code samples.

## Performance characteristics

`ai-surface` is built for fast local feedback on typical project repos.

| Repo size (relevant files) | Typical scan time |
|---|---|
| Under 50 files | Under 0.3s |
| 50-200 files | 0.3-1s |
| 200-500 files | 1-2s |
| 500-2,000 files | 2-5s |
| 2,000-10,000 files | 5-10s |
| Larger monorepos | scales with file count; bounded by the walker caps |

Time is more sensitive to **how many surfaces exist** than to file count. Repos with zero AI surfaces scan very fast because we walk fast and decline to match fast. Repos with active AI surfaces take longer because we extract per-finding metadata (models, tool lists, file evidence).

## Where to learn more

- [README.md](../README.md). User-facing intro
- [docs/CI_INTEGRATION.md](CI_INTEGRATION.md). GitHub Action deep dive
- [docs/DETECTORS.md](DETECTORS.md). Full detector coverage matrix
- [CONTRIBUTING.md](../CONTRIBUTING.md). How to contribute
- [CHANGELOG.md](../CHANGELOG.md). Release history
