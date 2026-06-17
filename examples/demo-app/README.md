# Demo App

A small synthetic codebase that demonstrates every category `ai-surface` detects. **Not meant to be run.** Meant to be scanned.

## What's in it

| File | Demonstrates |
|---|---|
| `src/chat_agent.py` | LangChain agent with refund + cancellation tools. Triggers `financial action exposed`, `high blast-radius combination` |
| `src/llm_service.py` | Direct Anthropic SDK + OpenAI SDK calls with user-input variables flowing into messages. Triggers `non-literal data flows into LLM call` |
| `src/orders_mcp_server.py` | In-house FastMCP server exposing order management tools. Triggers `in-house MCP server`, `financial action exposed`, `destructive action exposed`, `database write exposed` |
| `src/support_workflow.py` | AWS Strands agent with Bedrock model. Demonstrates Strands SDK detection and cross-region inference profile extraction (`us.anthropic.claude-sonnet-4-...`) |
| `.mcp.json` | Two configured MCP servers (github, stripe). Triggers `broad permissions` and `financial action exposed` |
| `.env.example` | OpenAI + Anthropic + observability keys. Triggers `multiple AI provider keys present` and `observability/tracing key present` |
| `litellm.config.yaml` | LiteLLM proxy config routing across 3 providers with fallback chains. Triggers `multi-model routing layer` |
| `src/knowledge_base.py` | pgvector store + a LangChain retrieval pipeline with an external loader. Triggers the vector-store / RAG indicators (managed-store egress, RAG data flow, external ingestion) |
| `src/api.py` | FastAPI routes including `/customers/{customer_id}`. Triggers `object-id in path (BOLA candidate)` |

## Run a scan against it

From the `ai-surface` repo root:

```bash
ai-surface scan examples/demo-app
```

You should see all eight detector categories represented.

## What the scan should find

| Detector | Surfaces |
|---|---|
| **Agent frameworks** | LangChain (named agent), AWS Strands (named agent) |
| **MCP servers** | github-mcp, stripe-mcp (configured), orders-mcp (in-house) |
| **Vector stores / RAG** | pgvector store + LangChain retrieval pipeline (`src/knowledge_base.py`) |
| **LLM SDK** | OpenAI, Anthropic, AWS Bedrock (via Strands) |
| **API endpoints** | FastAPI routes incl. `/customers/{customer_id}` (BOLA candidate) |
| **Model gateways** | LiteLLM multi-provider routing config |
| **AI infrastructure** | K8s vllm deployment (`deploy/`), Terraform Bedrock provisioned throughput |
| **AI provider env keys** | OpenAI + Anthropic + LangSmith + Helicone keys |

Captured outputs from a real scan are in [`../sample-outputs/`](../sample-outputs/).
