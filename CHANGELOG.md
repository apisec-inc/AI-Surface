# Changelog

All notable changes to `ai-surface` will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-06-17

### Changed

- Widened two dependency upper bounds so installs are not pinned to old majors: `rich` to `>=13.0.0,<16.0.0` (allows rich 14/15) and `pathspec` to `>=0.11.0,<2.0.0` (allows pathspec 1.x). The full suite passes against rich 15.0.0 and pathspec 1.1.1. This removes install conflicts for projects already on newer versions of those libraries.

## [1.0.1] - 2026-06-17

A maintenance release focused on the GitHub Action output, link correctness, and the `--ui` runtime-validation panel.

### Fixed

- **GitHub Action PR comments were corrupted.** The `compare` and `scan --output markdown` output was routed through the rich console, which hard-wrapped long URLs (breaking the links) and consumed single-token link labels such as `[ai-surface]` as markup. Markdown is now emitted as raw text, so the captured PR comment renders correctly. Added regression tests at the CLI boundary.
- Replaced every dead `apisec.ai/ai-validation` / `apisec.ai/api-validation` link (CLI footers, the PR comment, the README, the docs, and the committed sample outputs) with the live `apisec.ai/products` page.
- **The GitHub Action Docker image could not build.** `pyproject.toml` declares `readme = "README.md"`, but the Dockerfile did not copy `README.md` into the build context, so the in-image `pip install` failed metadata generation. `README.md` is now copied in.

### Changed

- **`--ui` runtime-validation panel.** Only the API surface, which the platform validates today, shows an active CTA; MCP and agent surfaces now render as disabled "coming soon" instead of links to a journey that does not exist yet. The panel is more compact.

### Added

- **`repository` field** on the report (owner/repo, derived from the local `.git/config` with any embedded credentials stripped) and a **`Governance:` line** (the EU AI Act / NIST / ISO clauses a flag evidences) in the terminal, markdown, and JSON reporters, so the governance mapping is visible outside the `--ui`.
- Vector-store / RAG and API (BOLA-candidate) examples in the bundled `examples/demo-app`, so the demo exercises all eight detector categories.

## [1.0.0] - 2026-06-15

The 1.0 release. The MCP deep-dive audit is merged in, two new detector categories ship, every audited finding now maps to AI-governance frameworks, and the whole tool has been validated against 19 popular public AI repositories.

### Added

- **Vector store / RAG detector (8th category).** Detects Pinecone, Weaviate, Chroma, Qdrant, Milvus, FAISS, LanceDB, pgvector, and Elasticsearch / OpenSearch / Vespa / Redis in vector mode, plus LangChain and LlamaIndex retrieval pipelines, across Python, JS/TS, and `.sql`. Flags managed-store egress, the RAG data flow, embeddings, and external ingestion (the poisoning surface). Maps to OWASP LLM08 and EU Art. 10 / ISO A.7.
- **API endpoint detector.** OpenAPI / Swagger specs and framework routes (FastAPI / Starlette with `APIRouter` prefix resolution, Flask, Express, Spring, Django), with method / path / auth-style capture and BOLA-candidate flagging on object-id path segments.
- **MCP deep-dive audit merged in** (the former `mcp-audit` tool): severity, risk flags with OWASP-LLM mappings and remediation, detected secrets by NAME and TYPE only (values redacted), and registry / trust signals.
- **Agent and RAG audits** with `financial-action`, `destructive-action`, `high-blast-radius`, `no-human-oversight`, `pii-to-llm`, and `no-observability` flags.
- **JS/TS agent detection**: LangChain.js, LangGraph.js, Vercel AI SDK, Mastra, OpenAI Agents, LlamaIndex.ts, with tool extraction.
- **Governance mapping.** Every audited finding maps to OWASP LLM Top 10 and the specific EU AI Act / NIST AI RMF / ISO 42001 clauses it evidences. Rendered as badges in the UI, as a `standards` array per risk flag in JSON, and in the CycloneDX AI-BOM. New `docs/COMPLIANCE.md`.
- **CycloneDX AI-BOM** (`--output cyclonedx`) and **SARIF 2.1.0** (`--output sarif`) reporters.
- **Interactive `--ui` attack-surface map** served on loopback, with the governance-evidence bar and AI-BOM download.
- **`--categories` aliases for `api` and `vector`/`rag`** so the new categories are selectable by short name.
- **`docs/STATE_OF_AI_SURFACE.md`**: results of scanning 19 popular public AI repos (about 941k combined stars); 12/12 applications trip at least one risk and one governance rule.

### Fixed

- These three efficacy bugs were found and fixed by running against the 19 public repos:
  - Agents defined only inside test/spec files were counted as real surfaces; test paths are now excluded.
  - Observability was credited from dependency manifests and lockfiles, so a transitive `langsmith` dependency of `langchain` made every such repo look "observed." Observability now requires real wiring (a source import or an enabled tracing flag); manifests and lockfiles are excluded.
  - The bare word `weave` matched inside minified Next.js `_next` build bundles; `_next` is now skipped and the signal requires real W&B Weave usage.

### Security and hardening (pre-release audit)

- Fixed two ReDoS vectors (a crafted YAML file that hung any scan via `yaml_top_value`, and the BOLA path-segment regex) so a single malicious file can no longer stall a scan or CI run.
- Added an SSRF guard to `--repo` / the UI scan: internal, loopback, link-local, and cloud-metadata addresses (and URL-embedded credentials) are rejected.
- Stopped the Portkey config detector from echoing a hardcoded value, closing the one path that bypassed the name/type-only secret guarantee.
- Test-file skipping now applies across all code-level detectors (was agent-only), so test fixtures no longer inflate the inventory.
- Excluded a custom `--baseline-file` inside the scan root from the walk, so the tool never re-ingests its own output.
- env-key detection no longer lists non-credential configuration (endpoint URLs, org/project ids, hosts) as keys.
- Django `re_path` routes no longer leak regex anchors into the displayed path.

### Changed

- The category count is now **8** (added vector/RAG and API endpoints). README, DETECTORS, and LANGUAGE_SUPPORT updated accordingly.
- Repo URL casing normalized to `apisec-inc/AI-Surface`; CI actions bumped to current Node-24 major versions.
- Test suite expanded to **348 passing**.

## [0.5.3] - 2026-05-28

### Added

- **Baseline mode for the `scan` command.** Three new flags work together so a team can capture an "accepted" snapshot of the AI inventory and from then on review only what has changed:
  - `--update-baseline` writes the current scan as the baseline snapshot at `.ai-surface-baseline.json` (or wherever `--baseline-file` points). Use it once after reviewing the initial inventory of a mature repo.
  - `--baseline` reads the snapshot back, runs the current scan, and prints the diff (new, modified, removed surfaces). The renderer is the same one the GitHub Action already uses for PR diff comments.
  - `--baseline-file PATH` overrides the default snapshot path so a team can store the baseline outside the scan root (for example in a separate config directory under CI control).
  - `--fail-on-risk` paired with `--baseline` gates only on risks introduced since the snapshot. Risks that were present in the baseline and have been accepted do not retrip the gate. This is the gating semantics most teams want once they are past initial onboarding.
- **`docs/PRIVACY.md`**, a procurement-grade data-handling contract that enumerates what the tool reads, what it writes, what network calls it makes (none for a CLI scan), what it explicitly does not do, and how to verify the claims with `strace`, `tcpdump`, or a no-network container. Linked from the README hero and from `SECURITY.md`.
- **README privacy callout** near the top, plus a "No Telemetry" badge, so a security-conscious reader is reassured about the data posture above the fold rather than after scrolling into the internals section.
- **Recommended first-run flow** added to the Quick Start section, walking through inventory, snapshot, and ongoing diff use.

### Changed

- Roadmap updated: baseline mode moves from the v0.6 planned list into the v0.5 shipped list. v0.6 now scopes to SARIF, AI-BOM export, the `.ai-surface.yml` policy file, AST-based tool resolution, and the GitLab CI component.

### Fixed

- End-to-end testing of baseline mode surfaced two correctness bugs that were fixed before the release was tagged.
- The file walker now skips ai-surface's own output artifacts (`.ai-surface-baseline.json`, `.ai-inventory.md`). Without this, re-scanning a repo that had run `--update-baseline` produced a phantom `Model Gateway: Helicone` finding because the baseline JSON captured env-key names such as `HELICONE_API_KEY` in metadata, and the source-level Helicone pattern in the gateway detector matched that text inside the baseline file. The artifact-skip rule covers the default paths; for custom `--baseline-file` paths outside the scan root the rule does not apply, and gitignoring or storing outside the scan root is the recommended pattern.
- `--baseline` combined with `--categories` now filters the loaded baseline to the same category set before diffing. Previously every surface in a non-matching category appeared as "removed" in the diff (e.g. `--baseline --categories infra` reported every non-infra surface as removed), which was misleading.

### Security

These items came out of a pre-public-flip code-quality and security-gaps review. None are known to be live exploits in v0.5.3, but each closes a class of attack that becomes interesting once the repo is public.

- The GitHub Action now validates `GITHUB_BASE_REF` against a strict refspec regex before passing it to `git fetch`. A ref of the shape `--upload-pack=cmd` would otherwise be interpreted by git as an option and could execute `cmd` as a transport helper. In practice `GITHUB_BASE_REF` is set by GitHub from the target repo's branch list (not by the PR author), so this is defence in depth rather than a live exploit, but the validation removes the entire argument-injection class.
- The Action's `_set_action_output` helper now strips carriage return and newline from any output value before writing to `GITHUB_OUTPUT`. Today every caller passes a numeric or fixed string, but a future caller could pass a free-text value; the hardening prevents the CVE-2024-27302 class of `GITHUB_OUTPUT` injection.
- The terminal reporter's verbose detector-error path now escapes Rich markup on the error text before printing. Detector exceptions can carry fragments of attacker-controlled source content (e.g. a YAML parse error that quotes the offending input), and unescaped markup in those strings could render fake hyperlinks or terminal styles in the operator's console.
- The baseline JSON loader (`_report_from_dict`) now sanitises the loaded `scan_root` to its basename and caps finding-list and per-finding list lengths. Without sanitisation, an attacker who committed a hand-crafted `.ai-surface-baseline.json` could write an absolute path (`/home/victim/internal-repo`) that would then re-emerge in the diff output, defeating the existing path-redaction contract. The list caps (10 000 findings, 2 000 per inner list) prevent baseline files that would force quadratic diffs or unbounded memory use.
- `parse_yaml_lenient` now refuses to invoke PyYAML on documents that exceed an anchor-or-alias density threshold (200 of either). PyYAML's `safe_load` is safe against `!!python/object` deserialisation but does not bound alias expansion, so a small file (under 100 KB) using nested aliases can expand to multi-GB at load time and OOM the scan host. The heuristic preserves every well-formed YAML file we have seen in the wild.

### Quality

Also from the pre-public review:

- Removed an unused `typing.List` import from `.github/action/entry.py`.
- Tightened bare `set` annotations in `env_keys.py` to `set[str]`.
- Tightened the `_f` test helper in `test_diff.py` to use `list[str] | None` instead of `list = None`.

### Tested

- 196 tests passing on Python 3.9 through 3.12; ruff and mypy clean.
- Three new regression tests cover the loaded-scan-root sanitisation, the loaded-findings cap, and the YAML alias-bomb refusal.

## [0.5.2] - 2026-05-27

### Added

- **AI infrastructure is now a first-class category with its own detector.** `ai-surface scan --categories infra` previously errored because no detector claimed the `ai-infra` category (the detection was bundled inside `model_gateways` and reported under the gateway detector's name). AI infrastructure now has a dedicated `ai_infra` detector, so the category is selectable and findings are attributed correctly. This completes the 6-category coverage the project advertises: LLM calls, agents, MCP, model gateways, **AI infrastructure**, provider keys.
- Expanded AI infrastructure coverage:
  - Kubernetes kinds beyond `Deployment` / `StatefulSet`: `DaemonSet`, `Pod`, `Job`, `CronJob`, `ReplicaSet`, and Argo `Rollout`.
  - More self-hosted runtime images: SGLang, NVIDIA Triton, llama.cpp, text-embeddings-inference, LocalAI, Aphrodite, Infinity, OpenLLM, NVIDIA NIM, Ray LLM, in addition to the existing ollama / vllm / TGI / FastChat / xinference.
  - **Dockerfiles** (`Dockerfile`, `*.Dockerfile`, `Containerfile`): matched on the `FROM` base image, with a fallback to serve commands (`vllm serve`, `ollama serve`, `text-generation-launcher`, `tritonserver`, etc.) so a generic base image that launches a runtime is still caught.
  - **docker-compose** (`docker-compose*.yml`, `compose*.yml`): service images matched against the runtime catalogue.
- **`--fail-on-risk` flag on the `scan` command.** Exits with code 1 when any risk indicator is detected, so a PR can be gated on risk in any CI (GitLab, CircleCI, Jenkins, pre-commit), not only via the GitHub Action. Works across all output modes including `--quiet`.
- Demo app (`examples/demo-app/`) gains a `deploy/` directory (a Kubernetes vllm deployment and a Terraform Bedrock provisioned-throughput resource) so a scan exercises all six categories. Sample outputs in `examples/sample-outputs/` regenerated accordingly (12 surfaces, 13 risk indicators, 6 detectors).

### Changed

- `model_gateways` detector now covers gateways only (LiteLLM, Portkey, Helicone, Cloudflare AI Gateway, OpenRouter). Kubernetes / Helm / Terraform detection moved to the new `ai_infra` detector.
- Shared YAML and HCL parsing helpers (multi-document split, nested-scalar lookup, image-value extraction, the brace-balanced HCL body extractor with heredoc / comment handling) extracted to `utils/specs.py` and used by both detectors, so the edge-case-heavy Terraform parser lives and is tested in one place.
- GitHub Action `fail-on-risk` now exits with code 1 (was 2) to match the CLI gate convention. Code 2 remains reserved for usage errors.

## [0.5.1] - 2026-05-12

### Added

- AWS Strands SDK detection (`from strands import Agent`, `from strands.models import BedrockModel`). Adds named-agent findings for `agent = Agent(model=..., tools=...)` patterns common in Strands code.
- Bedrock model-ID regex now accepts cross-region inference profile prefixes (e.g. `us.anthropic.claude-sonnet-4-...`, `eu.anthropic.claude-...`).
- Agent regex now matches indented assignments inside functions (previously only module-level Agent declarations were captured).
- Repo hygiene for public release: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue templates, PR template, PyPI Trusted Publisher workflow.
- Expanded README with "How it works (and what stays local)" section, Troubleshooting section, and explicit static-analysis / no-runtime / no-auth framing.
- Terraform parser handles nested braces, HCL heredocs (`<<EOT ... EOT`, `<<-EOT ... EOT`), and `/* ... */` block comments. Previous `[^}]*` body capture silently truncated bodies at the first inner `}`.

### Changed

- Detector name `mcp-servers` is now `mcp_servers` for consistency with the other detector identifiers (`env_keys`, `llm_sdks`, `agent_frameworks`, `model_gateways`). Anyone scripting against the detector list should update; the CLI alias `--categories mcp-servers` continues to work.
- Cross-promotion deep-link query parameter renamed from `?surface=` to `?category=` since the value being passed is the finding's category, not its surface name. The APIsec validation landing page accepts both during the v0.5 transition.
- `Report.scan_root` now contains the basename of the scan root (e.g. `demo-app`) rather than the resolved absolute filesystem path. Reports are routinely committed to git or posted as PR comments, and absolute paths leak the user's home directory, employer name, and internal mount layout. Detectors continue to receive the resolved path internally.
- File walker is documented as honouring the **root** `.gitignore` only. Nested per-directory `.gitignore` files, `.git/info/exclude`, and the global git excludesfile are not consulted (the implementation was always this narrow; the docs previously implied otherwise).

### Security

- GitHub Action refuses to run under the `pull_request_target` event. That event combines repo write secrets with attacker-controlled PR code and is the canonical supply-chain vector for Actions. The Action exits with an error before any input is read or scan is invoked. Use the `pull_request` event instead; for fork PRs, the recommended pattern is a downstream `workflow_run` workflow that consumes the artifact produced by the safe `pull_request` run.
- File walker enforces hard resource caps to prevent denial-of-service on pathological trees: `MAX_FILES = 250,000` per traversal, `MAX_TOTAL_BYTES = 5 GiB` cumulative content size accounted via `os.lstat`. A symlink to a 100 GiB blob outside the tree contributes the symlink's own inode size (~40 bytes), not the target's.
- `read_text_safe` refuses symlinks outright (`S_ISLNK` check after `os.lstat`) and re-bounds reads at `max_bytes` as defence-in-depth against TOCTOU races between stat and open.
- `relative_to_root` no longer falls back to the absolute path when a path lies outside the scan root. Returns `<outside-root>/{basename}` instead so the report makes it visible that a path was redacted rather than silently truncated.
- Fixed ReDoS in agent-framework constructor patterns. Previous DOTALL + lazy-quantifier regexes for crewai / autogen made the detector quadratic on adversarial input (~5 s per 5 K unmatched `Agent(` tokens, unresponsive at 5 MB). Patterns now anchor only the constructor opening; the body is extracted by a bracket-balanced scanner with per-call (16 KB) and per-file (256-attempt) caps. A regression test pins 5 MB of adversarial input under 8 s.
- Fixed markdown injection in PR comment and inventory output. Snippets are now wrapped in a length-aware code fence longer than any internal backtick run, so an attacker source line containing ``` cannot break out of the fence. Surface names, file paths, permissions, and risk indicators flow through a shared sanitiser that strips control characters, angle brackets, backticks, and leading markdown structural characters.

### Fixed

- `_PROMPT_NONLITERAL` flow detector no longer flags `None`, `True`, `False`, or other Python keywords as "non-literal data flow into LLM call."
- Word-boundary tokenisation in broad-permission / financial-action classifiers eliminates substring false positives (`install_app` no longer matches `all`, `customer_address` no longer matches `customer`, etc.).
- LLM SDK detector resolves model names to the SDK they belong to via affinity heuristics, so a file using both Anthropic and OpenAI SDKs no longer cross-attributes models.
- LangChain `AgentExecutor(agent=...)` wraps are now recognised and merged with the underlying agent rather than emitting a duplicate finding.

## [0.5.0] - 2026-05-11

Initial public alpha release.

### Added

- Static-analysis detection across 5 AI surface categories:
  - LLM SDK call sites (12+ providers: Anthropic, OpenAI, Azure OpenAI, AWS Bedrock, Google Generative AI, Vertex AI, Together, Mistral, Cohere, Replicate, Groq, LiteLLM)
  - Agent frameworks (8+ frameworks: LangChain, LangGraph, CrewAI, LlamaIndex, AutoGen, Haystack, Semantic Kernel, Pydantic AI, plus Anthropic-shape tool definitions)
  - MCP servers (configured and in-house, Python `FastMCP` + `mcp.Server`, JS `@modelcontextprotocol/sdk`)
  - AI provider environment variable names (names only, never values)
  - Model gateways and AI infrastructure (LiteLLM, Portkey, Helicone, Cloudflare AI Gateway, self-hosted runtimes via Kubernetes/Terraform)
- 13 named risk indicators with conservative semantics (broad permissions, financial action exposed, destructive action exposed, blast-radius combinations, non-literal data flow, etc.)
- Three output formats: rich terminal, JSON, markdown
- Committable `.ai-inventory.md` artifact
- Base-vs-head diff engine for PR comment generation
- GitHub Action wrapper with sticky PR comments showing surface changes
- Cross-promotion links to specialist tools (mcp-audit) and the APIsec platform
- Verbose mode for debugging detector errors

### Known limitations in v0.5

- Regex-based tool resolution (AST coming in v0.6)
- Single-document YAML parsing only
- No live cluster scanning (planned for v0.7)
- No multi-repo aggregation (planned for v0.8)
