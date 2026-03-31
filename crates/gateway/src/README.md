# Gateway Module (`src/gateway/`)

The Agent Capability Gateway — a security proxy that sits between AI agents and the APIs they use. Credentials are injected at the network boundary; the agent never possesses them.

## Architecture

```
Agent (zero credentials)
  │
  │  GET /github/user/repos
  │  Authorization: (none)
  │
  ▼
┌──────────────────────────────────────────────┐
│  Proxy (proxy.rs)                            │
│                                              │
│  1. Extract provider from URL path           │
│  2. Look up adapter (adapter/)               │
│  3. Parse request → ParsedOperation          │
│  4. Evaluate policy (policy.rs)              │
│     - per-provider rules                     │
│     - intersection restrictions              │
│  5. If blocked → 403 JSON                    │
│  6. If allowed → inject credential,          │
│     forward to upstream                      │
│  7. Log audit event (audit.rs)               │
│  8. Ship to control plane (events.rs)        │
│  9. Record in harvester + profiler           │
└──────────────────────────────────────────────┘
  │
  ▼
Upstream API (api.github.com, api.stripe.com, ...)
```

## Module Map

| File | What it does | Key types |
|---|---|---|
| `proxy.rs` | HTTP server (axum). Routes requests, orchestrates the full flow above. Also serves internal management API (`/internal/*`). | `GatewayState`, `ProviderEntry`, `run_proxy()` |
| `config.rs` | YAML config loading. Defines the shape of `gateway.yaml`. | `GatewayConfig`, `ProviderConfig`, `PolicyConfig` |
| `adapter/` | Per-provider request parsing. Each adapter knows how to read a provider's API format and extract structured operations. | `ProviderAdapter` trait, `ParsedOperation`, `Registry` |
| `policy.rs` | Policy evaluation engine. 7-step evaluation: methods, paths, operations, parameter constraints (amounts, currencies, recipients). | `PolicyEvaluator`, `Decision` |
| `intersection.rs` | Cross-API intersection policies. The novel differentiator — restricts one provider's policy when another provider is also active. Intersections can only tighten, never loosen. | `IntersectionRule`, `compute_intersections()`, `merge_intersections()` |
| `audit.rs` | Structured audit logging + in-memory query. Every decision is recorded. | `AuditEvent`, `AuditLogger`, `AuditFilter`, `AuditStats` |
| `events.rs` | Event shipping to the control plane. Buffers events and flushes in batches (100 events or 5s) to `POST /v1/events`. | `Event`, `EventBatch`, `EventSender`, `spawn_event_shipper()` |
| `harvester.rs` | Credential observation. Detects credentials in agent requests (Bearer, Basic, API key headers/query params), fingerprints them with SHA-256. Powers zero-friction onboarding. | `Harvester`, `ObservedCredential` |
| `profiler.rs` | Behavior profiling. Tracks what each session does (operations, methods, paths) and generates policy suggestions. | `Profiler`, `BehaviorProfile`, `PolicySuggestion` |
| `session.rs` | Session context types. A session links an agent to its providers, credentials, and policies. | `SessionContext`, `ProviderSession` |
| `mockapi.rs` | Mock API server for GitHub/Stripe/Gmail. Used by integration tests and the investor demo. Returns realistic responses, requires auth, echoes received credentials. | `run_mock_api()`, `build_mock_router()` |

## Key Design Decisions

1. **Network-level identity, not tokens.** Credentials are injected at the network boundary. The agent's env vars are irrelevant to security — the proxy handles everything.

2. **Observe-first, scope-second.** The gateway starts in learning mode (logs everything, blocks nothing). It builds a behavior profile, recommends policies, then enforces. Set `learning_mode: true` in the session config.

3. **Intersection policies are the differentiator.** When an agent has both Stripe and Gmail access, the Stripe charge cap drops from $50 to $10. No other product does cross-API policy enforcement.

4. **Event batching to the control plane.** The daemon buffers audit events and ships them in batches via `POST /v1/events` (schema v1). The `GATEWAY_CONTROL_PLANE_URL` env var enables shipping; if unset, events are silently drained.

5. **Daemon ID is persistent and unique per instance.** Stored at `~/.config/diff/gateway-daemon-id`, format `{hostname}-{uuid_prefix}`. Not per-host — multiple daemons on the same machine get distinct IDs.

## Running

```bash
# Start the proxy (standalone mode, YAML config)
getdiff gateway --config config/gateway-test.yaml --port 8080

# Start the mock API server (for testing)
getdiff mock-api --port 9999

# Run the 30-scenario integration test suite
make gateway-test

# Run the investor demo (self-contained, no real tokens needed)
make investor-demo
```

## Config Format

See `config/gateway-test.yaml` for the full example. The key sections:

- `session.id` — session identifier
- `session.learning_mode` — true = observe only, false = enforce
- `providers.{name}.upstream` — where to forward requests
- `providers.{name}.credential` — env var holding the real API key
- `providers.{name}.policies` — per-provider rules (methods, paths, operations, amounts, recipients)
- `intersection_policies` — cross-provider rules that activate when multiple providers are present

## Test Coverage

- **196 unit tests** across all modules (inline `#[cfg(test)]`)
- **30 integration tests** (`scripts/integration-test.sh`) covering all 9 categories:
  GitHub (5), Stripe (6), Gmail (5), Intersection (3), Learning Mode (3), Harvesting (2), Profiling (2), Audit (3), Unknown Provider (1)
