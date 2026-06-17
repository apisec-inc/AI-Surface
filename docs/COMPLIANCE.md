# Compliance and governance mapping

`ai-surface` maps audited findings to the OWASP LLM Top 10 and to evidence-relevant clauses in the EU AI Act, NIST AI RMF, and ISO/IEC 42001. This document is the reference for those mappings.

## Scope and assurance boundary

`ai-surface` produces structured evidence for AI governance review. It does not certify, attest, or assert compliance.

What it can provide:

- an inventory of AI surfaces found in source code
- AI-BOM output in CycloneDX format
- risk indicators and audited findings where enough evidence exists
- framework mappings tied to the evidence produced
- signals for review, such as missing observability, missing human oversight, PII-to-prompt flow, or high-blast-radius agent authority

What remains outside the tool:

- legal interpretation of regulatory obligations
- organizational policies and approvals
- runtime behavior and exploitability validation
- human review and acceptance of risk
- operational controls that do not appear in source code

A framework requirement is reported only when the analysis produced supporting evidence. An empty repo maps to nothing. Use the output as structured evidence for your AI governance process, not as a certification artifact.

## Evidence kinds

Each framework requirement is backed by one kind of evidence. A requirement is
only reported when the matching evidence kind is present in the scan.

| Evidence kind | Produced when the scan finds | Example |
|---|---|---|
| `inventory` | Any AI surface at all (the AI-BOM) | An MCP server, an agent, a vector store |
| `risk` | A risk indicator, severity, or audit finding | A financial-action tool, a BOLA candidate |
| `owasp` | An OWASP LLM Top 10 mapping on an audited finding | `secrets-detected` -> LLM02 |
| `oversight` | A high-risk action with no approval gate | `no-human-oversight` on a refund tool |
| `observability` | An execution surface with no tracing wired | `no-observability` on an agent / MCP |
| `data` | A vector/RAG layer, or PII into a prompt | pgvector store, `pii-to-llm` |

## What each framework gets from a scan

| Framework | Inventory | Risk assessment | Human oversight | Logging / monitoring | Data governance |
|---|:--:|:--:|:--:|:--:|:--:|
| **EU AI Act** | Art. 11-12 | Art. 9 | Art. 14 | Art. 12 | Art. 10 |
| **NIST AI RMF** | MAP | MEASURE | (n/a) | MEASURE 3 | MEASURE (data) |
| **ISO/IEC 42001** | Annex A | Risk assessment | (n/a) | A.6.2.6 | A.7 |
| **OWASP LLM Top 10** | per-finding LLM01-LLM10 mapping on audited findings | | | | |

NIST AI RMF and ISO 42001 fold human-oversight expectations into their broader
govern/measure functions rather than a single clause, so `ai-surface` maps the
`no-human-oversight` flag to the EU AI Act Art. 14 clause only.

## How each risk flag maps to clauses

The deep-dive audit layer (MCP, agents, RAG) attaches structured risk flags.
Each carries a severity, an OWASP-LLM id, and the governance clauses below. Only
strong, defensible mappings are listed; capability flags
(`shell` / `filesystem` / `database` / `network` / `broad-permissions`) are
Excessive Agency in OWASP terms and carry OWASP only.

| Risk flag | OWASP | EU AI Act | NIST AI RMF | ISO 42001 |
|---|---|---|---|---|
| `secrets-detected` | LLM02 | Art. 15 | - | - |
| `secrets-in-env` | LLM02 | Art. 15 | - | - |
| `admin-credentials` | LLM02 | Art. 15 | - | - |
| `financial-action` | LLM06 | Art. 9 | - | - |
| `destructive-action` | LLM06 | Art. 9 | - | - |
| `high-blast-radius` | LLM06 | Art. 9 | - | - |
| `no-human-oversight` | LLM06 / LLM09 | Art. 14 | - | - |
| `no-observability` | - | Art. 12 | MEASURE 3 | A.6.2.6 |
| `pii-to-llm` | LLM02 | Art. 10 | - | A.7 |
| `unverified-source` | LLM03 | - | - | A.10 |
| `remote-mcp` | LLM03 | - | - | A.10 |
| `local-binary` | LLM03 | - | - | A.10 |
| vector store / RAG present | LLM08 | Art. 10 | data | A.7 |

`no-observability` is a record-keeping control, not an OWASP LLM Top 10 weakness,
so it carries the EU / NIST / ISO clauses but no OWASP id.

## Where the mappings appear in output

- **`--ui`**: framework badges (EU blue, NIST purple, ISO green) render beside the
  OWASP badges in each finding's detail drawer, and a governance-evidence bar
  summarizes the frameworks the whole scan maps to.
- **`--output json`**: each risk flag carries a `standards` array of
  `{framework, framework_id, clause}` objects, and the report summary lists the
  frameworks with backed requirements.
- **`--output cyclonedx`**: the AI-BOM carries the inventory plus the governance
  mappings as component properties.

## Generating the AI-BOM in CI

Emit the AI-BOM the same way your pipeline already emits an SBOM:

```bash
ai-surface scan . --output cyclonedx > ai-bom.cdx.json
```

Commit it, attach it to releases, or feed it to your governance tooling. It is a
standard CycloneDX document with the AI components and their framework mappings.

## A note on completeness

Because tool resolution is regex/AST-light today (see the README "What it does
not do"), the `financial-action`, `destructive-action`, and `no-human-oversight`
flags can under-fire on large platforms that build agent tools via factory
functions. The governance footprint a scan reports is therefore a **floor, not a
ceiling**: real exposure is at least what is shown, often more. AST/dataflow
resolution is the top roadmap item.
