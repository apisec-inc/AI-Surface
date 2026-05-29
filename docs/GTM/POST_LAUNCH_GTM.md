# `ai-surface` Post-Launch GTM Plan

**Status:** Draft, v1.0 (May 2026)
**Owner:** OSS lane
**Scope:** ai-surface specifically, with cross-promo into the wider APIsec Labs OSS family

> This is a working document. Treat as candid internal strategy.

---

## 1. Where we are

- `ai-surface` v0.5.1 alpha, shipped 2026-05-12
- Repo: `apisec-inc/AI-Surface` (currently private, flipping public as part of launch)
- Sibling: `mcp-audit` v1.1.0 (launched, depth tool for MCP servers)
- Planned siblings: `agent-audit` (Q3 2026), watchlist (shape TBD)
- Parent brand: APIsec Labs
- Paid platform: APIsec (Runtime Validation tier, separate consumption model)

`ai-surface` sits in the Discovery band of the OSS pipeline. It is the generalist that finds every AI surface in a codebase. Specialist `*-audit` CLIs do depth on flagged categories. The paid platform does runtime exploit validation.

---

## 2. Value proposition

### The honest read

"Inventory the AI surfaces in your code" undersells what the tool actually does. Engineers can grep. The real value lives in the **risk indicators**: broad-permission MCP servers, financial-action exposed agents, blast-radius combinations, non-literal data flowing into LLM calls. DevOps cares about prevention, not listing.

### Reframe before broad launch

1. **Lead with prevention, not inventory.** "Catch the AI surfaces that break prod or fail audit, at PR time." Inventory becomes the secondary capability.
2. **Promote the diff engine.** The `compare` command and drift-mode story is the headline DevOps cares about (week-over-week change is more actionable than a one-time list).

### Three positioning lines to A/B test

1. "AI BOM for your CI. Free, OSS, no agent."
2. "Catch the AI surfaces that break prod, before they ship."
3. "Every LLM call, agent, and MCP server in your code, surfaced at PR time."

### Audience

Primary: **DevOps and platform engineers** who own CI/CD and care about what gets merged.
Secondary: **AppSec engineers** running inventory for compliance asks (SOC 2, EU AI Act, internal AI governance councils).
Not the target: ML engineers (they build the surfaces; they are not the ones governing them).

### What our wedge is, against competing AI-BOM tools

- Free and OSS, no commercial license fee
- Static analysis only, no agent, no network, no telemetry, runs offline
- CI-native: GitHub Action wrapper ships pre-built
- Posts a PR comment in the developer workflow, not a separate console
- Honest about limitations (alpha label, regex-based tool resolution today)

---

## 3. Friendly pilot phase (T-2 weeks before broad launch)

### Goal

Validate "would you block a PR on this?" with 3 named design partners before spending the broad-launch budget.

### Mechanics

- 30-minute onboarding call per pilot
- Office hours weekly
- Two issue templates already shipped for pilot feedback: `false-positive.yml`, `false-negative.yml`
- Debrief at end of week 2 with explicit GO / NO-GO decision

### Decision criteria

- 3 of 3 pilots say "yes I would block on this for at least one risk indicator"
- At least 1 pilot refers a peer (strongest signal of resonance)

### If pilots say NO

Do not launch broadly. Build the three product gaps before pilot round 2:

1. **Cost-cap detection.** LLM calls without `max_tokens`, agents without iteration cap, Bedrock invocations without retry budget. Flags map directly to "this could burn your provider bill at 3am."
2. **Drift mode polish.** Promote `compare` to a headline capability, ship a recommended nightly sweep recipe, add a "what changed this week" summary.
3. **AI-BOM compliance mode.** `--format aibom --standard soc2` for inventory reports that pass procurement.

Two pilot rounds before HN is cheaper than burning the launch slot on a tool that does not stick.

---

## 4. Broad launch sequence

### T-2 weeks: harden

- Pilot debrief complete, GO decision made
- v0.5.2 shipped with pilot-driven fixes
- Tier 4 supply-chain in place (SLSA provenance, SBOM, signed artifacts, CodeQL, OpenSSF Scorecard badge)

### T-1 week: assets

- 60-second asciinema cast on the README
- Sample PR comment screenshot
- Landing page live at `labs.apisec.ai/ai-surface` (or equivalent), separate from the GitHub repo
- LinkedIn post drafted, scheduled
- HN Show post drafted, dry-run reviewed

### T-0 Monday: LinkedIn launch

- Raj's network, OSS pipeline framing
- Lead with the Discovery-band hero from the OSS pipeline infographic
- Link to demo and repo

### T-0 Tuesday: Hacker News Show post

- 9am Pacific
- Title: *Show HN: ai-surface, find the AI surfaces in your code before they ship*
- Lead with PR comment screenshot, not README text
- Author engages comments aggressively for the first 6 hours (this matters more than the post itself)

### T+1 week: Reddit and newsletters

- r/devops: cost-cap and prevention framing
- r/Python: architecture, tree-walker, regex-without-AST tradeoffs
- r/MachineLearning: agent-framework coverage angle
- Newsletter submissions: TLDR DevOps, Pointer, Last Week in AI, AI Safety Newsletter, DevOps Weekly

### T+2 weeks: podcasts and direct outreach

- Pitch Raj as guest to Software Engineering Daily, Latent Space, Practical AI
- Short, targeted DM list of staff DevOps engineers at OSS-friendly companies (held in private memory, not this doc)

### T+4 weeks: conference CFPs

- KubeCon NA Atlanta November (CFP open)
- BSides cities through summer 2026
- DEF CON AI Village
- RSAC 2027 (CFP opens late June)

---

## 5. Channels in priority order

| Rank | Channel | Lead time | Why this rank |
|------|---------|-----------|---------------|
| 1 | Hacker News Show | Same-day | Highest single-day awareness lever for a dev-tool launch |
| 2 | LinkedIn | Same-day | Raj's network, AI-security framing, decision-maker audience |
| 3 | Reddit | 1-3 days | Segment by sub for different framings |
| 4 | Newsletters | 1-2 weeks | High-quality readership, low effort per send |
| 5 | Podcasts | 4-6 weeks | Long-tail awareness, founder-story format |
| 6 | Conferences | 3-12 months | Trust signal, slow but durable |
| 7 | Cross-promo (mcp-audit) | Already live | Reciprocate the existing tagline pointer |
| 8 | Direct outreach | Same-day | Small, targeted, high-signal |

---

## 6. Cross-promotion across the OSS family

### From `ai-surface` outward

- README "see also" table listing all sibling specialists with status (Launched / Coming soon)
- JSON output gains a `recommended_audits` field per finding category (e.g. an MCP finding suggests `mcp-audit`)
- Existing deep-link to the APIsec platform validation page via `?category=...` (shipped in commit c72675c)

### Into `ai-surface`

- `mcp-audit` already points at `ai-surface` source-scan capability (commit 312fcb2). Reciprocate.
- Future audits in the family carry the same "see also `ai-surface`" pattern. Standardise this in the family CLI conventions doc.

### OSS pipeline infographic

- Update live repo URLs once the repo flips public
- Reflect v0.5.1 AWS Strands detector
- Reconcile the diagram's 8-specialist roadmap with the locked decision matrix (a separate strategy memo)

---

## 7. What NOT to do

These are durable principles, not tactical choices.

- **Do not lead with APIsec branding.** APIsec Labs is the umbrella; `ai-surface` stands on its own first. Open-core trojan horse smell will kill OSS adoption faster than any other mistake.
- **Do not push the paid platform early.** Cross-promo links in tool output are fine. Banner ads in the README are not. Let the OSS tool earn trust first.
- **Do not add usage telemetry.** DevOps will reject anything that phones home. Static-analysis-no-network is the wedge against Wiz, Snyk, and the rest. Breaking it is the most expensive mistake we could make.
- **Do not gate features behind contact-us.** Every README CTA is free and immediately actionable. No email walls.
- **Do not launch broadly on a NO-GO pilot.** The HN launch slot is a one-shot resource. Do not burn it on a tool that did not pass the friendly-pilot bar.

---

## 8. Conversion funnel to APIsec platform

OSS user runs `ai-surface` → sees a risk indicator → clicks "validate this surface" → lands on APIsec platform validation page → eventually a paid-platform conversation.

The OSS lane owns the deep-link mechanism (shipped: `?category=` query parameter). The platform landing page and conversion experience are owned separately by the platform team.

This document does not design the platform-side funnel. It only ensures the OSS tool feeds it cleanly.

---

## 9. Success metrics

| Stage | Metric | Target (90 days post-launch) |
|-------|--------|------------------------------|
| Awareness | GitHub stars | 500+ |
| Awareness | HN points on launch day | 100+ (Front Page) |
| Trial | PyPI weekly downloads | 500+ |
| Trial | GitHub Action installs | 50+ repos |
| Activation | % of installs producing a non-empty report | 70%+ |
| Retention | Repeat scans per repo per week | 3+ for active users |
| Advocacy | Forks | 25+ |
| Advocacy | External mentions / inbound blog links | 10+ |
| Funnel | Click-through on "validate this surface" links | 5%+ of risk-indicator views |

Targets are first-pass. Revise after the 30-day checkpoint.

---

## 10. Validation gate before broad launch

If any of the following are true at T-1 week, hold the launch:

- Repo is still private
- `pip install ai-surface` does not work
- `uses: apisec-inc/ai-surface@v0` example workflow fails for an external user
- Fewer than 2 of 3 pilots gave a GO
- Any P0 security finding from the pre-launch security pass is still open

Slip a week. The cost of slipping is days. The cost of a flat launch is months.

---

## Appendix: live document expectations

- Update after the friendly pilot debrief
- Update after the HN launch day debrief
- Update after the 30-day post-launch checkpoint
- Archive and replace at v0.6 launch (different value prop, different framing)
