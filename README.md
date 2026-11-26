# FieldScope

**FieldScope** is an enterprise AI API permission middleware (HTTP reverse proxy + upcoming MCP proxy) designed to govern how AI Agents access third-party platform APIs.

## Key Capabilities (Phase 1 MVP)

- **Zero-Dependency Core & Gateway**: Built on native Node.js 22+ TypeScript runtime with zero third-party runtime dependencies for minimal supply-chain attack surface and instant startup.
- **Endpoint-level Governance**: Default-deny + explicit-deny-overrides-allow RBAC/ABAC policy engine (`@fieldscope/policy-engine`).
- **Parameter Validation & Enforcement**: Safe recursive-descent expression evaluator (no `eval`) plus forced parameter injection/override from verified principal attributes to neutralize prompt-injection privilege escalation.
- **FieldScope Response Engine**: Path-based allowlist/denylist JSON pruning (`issues[*].fields.summary`) and built-in PII masking/redaction (`mask_email`, `mask_phone`, `mask_middle`, `hash`, `redact`, `redact_pii`) (`@fieldscope/field-engine`).
- **Credential Isolation**: Strips internal user tokens and injects managed upstream credentials (`bearer`, `header`, `query`, `basic`) before proxying.
- **Structured Audit Trail**: Logs principal, matched policy, enforced parameters, pruned fields, and transformed fields for every call.

## Monorepo Structure

```text
packages/
  core/            # Shared domain models & runtime config/principal validators
  field-engine/    # JSON field pruning & masking engine
  policy-engine/   # Policy matcher, safe expression evaluator, parameter enforcer
apps/
  gateway/         # Node.js HTTP reverse proxy gateway
examples/
  fieldscope.json  # Sample declarative policy & connector config (JSON)
  fieldscope.yaml  # Sample declarative policy & connector config (YAML reference)
```

## Quick Start

```bash
# Link workspace packages (works completely offline)
pnpm install --offline

# Run all unit & end-to-end tests
pnpm test

# Start gateway with the sample config
pnpm dev:gateway
```
