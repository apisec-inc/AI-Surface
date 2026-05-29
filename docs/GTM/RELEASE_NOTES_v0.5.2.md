# ai-surface v0.5.2 release notes

**Date:** 2026-05-27
**Type:** alpha, additive (no breaking changes to the JSON schema or CLI surface)

This doc is both the GitHub Release body and the talking points for a prospect conversation. Copy the "Release body" section into the GitHub Release; use the "Why it matters" and "One-liners" sections in the meeting.

---

## Headline

`ai-surface` now covers all six AI surface categories it advertises, and it can fail your build when a PR introduces a risky surface. Visibility plus a kill switch, at PR time, in any CI.

---

## Release body (paste into GitHub Release)

### Added

- **AI infrastructure is now a first-class category.** `--categories infra` previously errored because no detector claimed the `ai-infra` category. There is now a dedicated `ai_infra` detector, completing the six-category coverage: LLM calls, agents, MCP, model gateways, AI infrastructure, provider keys.
- **Broader AI-infrastructure coverage:**
  - Kubernetes `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, `Job`, `CronJob`, `ReplicaSet`, and Argo `Rollout`.
  - Runtimes: ollama, vllm, TGI, SGLang, NVIDIA Triton, llama.cpp, text-embeddings-inference, LocalAI, Aphrodite, Infinity, OpenLLM, NVIDIA NIM, Ray LLM, xinference.
  - Dockerfiles (`FROM` base image plus serve-command fallback) and docker-compose service images.
- **`--fail-on-risk` on the CLI `scan` command.** Exits code 1 when any risk indicator is present, so you can gate a PR on risk in GitLab, CircleCI, Jenkins, or a pre-commit hook, not only via the GitHub Action.

### Changed

- `model_gateways` now covers gateways only; AI-infrastructure findings come from the new `ai_infra` detector with correct attribution.
- Shared YAML / HCL parsing extracted to `utils/specs.py`.
- GitHub Action `fail-on-risk` exits code 1 (was 2) to match the CLI. Code 2 stays reserved for usage errors.

### Tested

- 180 tests passing across Python 3.9 to 3.12. Ruff and mypy clean.

### Upgrade

```bash
pipx upgrade ai-surface   # or: pip install -U ai-surface
```

No migration needed. New behaviour is opt-in (`--fail-on-risk`) or additive (the new category appears automatically).

---

## Why it matters (prospect talking points)

- **The six-category claim is now fully true.** Before this release, a prospect who ran `--categories infra` hit an error. Now every category the tool advertises resolves to a real detector. No asterisks in the demo.
- **The kill switch works in their CI, not just ours.** A DevOps lead on GitLab or Jenkins can wire `--fail-on-risk` into a pipeline today and block a PR that ships an agent with refund authority or a self-hosted runtime nobody approved.
- **AI infrastructure is the surface DevOps actually owns.** Self-hosted vllm in a cluster, Bedrock provisioned throughput in Terraform: these are operational and billing exposures a platform team is accountable for. Surfacing them at PR time is squarely their problem to govern.

## What this release deliberately does NOT claim

Stay honest in the room:

- It does not detect PII or read secret values. It flags non-literal data flow into LLM calls and provider-key *names*. Point at gitleaks / GitGuardian for secret values.
- It does not emit a standardised AI-BOM (SPDX / CycloneDX) yet. The JSON and `.ai-inventory.md` are ai-surface's own formats. AI-BOM export is on the v0.6 roadmap.
- Tool resolution is still regex-based, so treat the inventory as a strong floor, not a completeness proof. AST resolution lands in v0.6.

## One-liners (pick per audience)

- DevOps lead: "Know every AI surface your team is shipping, and fail the build on the risky ones, before they hit prod. In CI, free, no agent."
- Platform / SRE: "The self-hosted runtimes and provisioned AI infra your team is about to deploy, surfaced at PR time."
- Security-curious: "PR-time AI inventory with a risk gate. Static, offline, no telemetry."

## Demo script

```bash
pipx run ai-surface scan examples/demo-app
# 12 surfaces, 13 risk indicators, 6 detectors, including AI INFRASTRUCTURE
pipx run ai-surface scan examples/demo-app --fail-on-risk --quiet ; echo "exit: $?"
# exit: 1   (gate trips on the demo app's risky surfaces)
```
