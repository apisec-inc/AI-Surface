<!--
This is what the GitHub Action posts as a sticky PR comment when the demo-app
is the base and a PR adds:
- A new stripe-mcp tool with refund authority
- An expanded LangChain agent with cancel_subscription added

The Action automatically updates this comment in place on subsequent pushes.
-->

### AI Surface Changes

**1 new, 1 modified**

---

#### New AI surfaces

- **MCP Server: stripe-mcp**
  - Tools/permissions: `read_charges`, `refund`, `customer:read`
  - Files: `.mcp.json`
  - ⚠️ financial action exposed
  - [Validate this surface →](https://www.apisec.ai/products?category=mcp-server&risk=financial-action&utm_source=ai-surface&utm_medium=pr-comment&utm_campaign=oss-funnel)

#### Modified AI surfaces

- **LangChain Agent: support_agent (in src/chat_agent.py)**
  - Permissions added: `cancel_subscription`
  - ⚠️ Risk added: `high blast-radius combination`
  - [Validate this surface →](https://www.apisec.ai/products?category=agent-framework&risk=high-blast-radius&utm_source=ai-surface&utm_medium=pr-comment&utm_campaign=oss-funnel)

---

<sub>
🔍 Powered by <a href="https://github.com/apisec-inc/AI-Surface">ai-surface</a>.
Deep MCP analysis: <a href="https://github.com/apisec-inc/mcp-audit">mcp-audit</a>.
Validate exploitability: <a href="https://www.apisec.ai/products">APIsec platform</a>.
</sub>
