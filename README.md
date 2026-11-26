# FieldScope

**FieldScope** is an enterprise AI API permission middleware (**HTTP Reverse Proxy + MCP Streamable HTTP Gateway**) designed to govern how AI Agents access third-party platform APIs.

## Key Capabilities

- **Zero-Dependency Core & Gateway**: Built on native Node.js 22+ TypeScript runtime (`node:http`, `node:crypto`, `node:sqlite`, `node:test`) with zero third-party runtime dependencies.
- **Dual-Protocol Gateway (HTTP + MCP)**:
  - `ALL /proxy/:connectorId/*`: Transparent HTTP reverse proxy for standard tool calls.
  - `POST /mcp`: Standard MCP JSON-RPC 2.0 gateway supporting both **REST-to-MCP tool mapping** and **upstream MCP server proxying**, with permission-aware `tools/list` filtering.
- **Endpoint & Tool Governance (`@fieldscope/policy-engine`)**: Default-deny + explicit-deny-overrides-allow RBAC/ABAC engine, safe recursive-descent expression validation (no `eval`), and forced parameter injection (`query.*`, `body.*`, `args.*`) to neutralize prompt-injection privilege escalation.
- **FieldScope Response Engine (`@fieldscope/field-engine`)**: Path-based allowlist/denylist JSON pruning (`issues[*].fields.summary`) and built-in PII masking/redaction (`mask_email`, `mask_phone`, `mask_middle`, `hash`, `redact`, `redact_pii`).
- **Hybrid Credential Vault (`@fieldscope/vault`)**: AES-256-GCM encrypted credential storage (In-Memory & SQLite) supporting both **managed Service Accounts** and **per-user OAuth 2.0 delegation** with automatic single-flight token refresh.
- **Structured Audit Trail**: Logs principal, protocol, matched policy, enforced parameters, pruned fields, and transformed fields for every call.

## Monorepo Structure

```text
packages/
  core/            # Shared domain models & runtime config/principal validators
  field-engine/    # JSON field pruning & masking engine
  policy-engine/   # Policy matcher, safe expression evaluator, parameter enforcer, MCP visibility
  vault/           # AES-256-GCM cipher, InMemory/SQLite stores, OAuth 2.0 auto-refresh manager
  mcp-adapter/     # MCP JSON-RPC 2.0 handler (REST-to-MCP & upstream MCP proxy)
apps/
  gateway/         # Node.js HTTP + MCP dual-mode gateway
examples/
  fieldscope.json  # Sample declarative policy, connector & MCP tool config
  mock-upstream.ts # Local mock Jira upstream server for interactive testing
```

## Quick Start

```bash
# Link workspace packages (works completely offline)
pnpm install --offline

# Run all unit & end-to-end tests
pnpm test

# Interactive local testing (terminal 1 & terminal 2)
pnpm dev:mock
JIRA_BASE_URL=http://127.0.0.1:9001 JIRA_API_TOKEN=real-secret pnpm dev:gateway
```
