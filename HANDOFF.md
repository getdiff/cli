# Gateway Daemon — Handoff Document

Context for agents picking up roadmap items. Read this before reading code.

## What exists

A config-driven security proxy with two deployment modes:

1. **CLI subcommand** — `getdiff gateway --config gateway.yaml --port 8080`. Runs alongside the CLI's other features (session upload, watch, artifacts). For developer laptop use.

2. **Sidecar binary** — `gateway-sidecar [config] [port]`. Minimal standalone binary that runs only the proxy. For container deployment alongside agent sandboxes. Configured via env vars (`GATEWAY_CONFIG`, `GATEWAY_PORT`, `GATEWAY_CONTROL_PLANE_URL`).

Both share all gateway code in `src/gateway/`. The sidecar entry point is `src/sidecar.rs` (~40 lines). The Dockerfile is `Dockerfile.sidecar`.

**12 source files** in `src/gateway/`, **196 unit tests**, **30 integration tests**. Zero warnings.

## Binaries

| Binary | Entry point | What it is |
|---|---|---|
| `getdiff` | `src/main.rs` | Full CLI: upload, watch, login, artifacts, + `gateway` subcommand |
| `gateway-sidecar` | `src/sidecar.rs` | Minimal proxy-only binary for container sidecar deployment |

Both are `[[bin]]` targets in the same `Cargo.toml`. Build with `cargo build --release` (both) or `cargo build --release --bin gateway-sidecar` (sidecar only). Docker: `docker build -f Dockerfile.sidecar -t gateway-sidecar:latest .`

## File map

```
src/sidecar.rs           Sidecar entry point (env var config, runs proxy, nothing else)
src/gateway/
├── mod.rs               Module root
├── proxy.rs             HTTP server (axum). THE central file. Request handler,
│                        forwarding, internal management API, state construction.
├── config.rs            GatewayConfig, SessionConfig, ProviderConfig, PolicyConfig.
│                        Loaded from YAML via serde_yaml.
├── adapter/
│   ├── mod.rs           ProviderAdapter trait, ParsedOperation, Registry
│   └── generic.rs       Config-driven adapter. 4 body format plugins:
│                        json, form, gmail_mime, jsonrpc (MCP).
├── policy.rs            7-step PolicyEvaluator. Checks: methods, paths,
│                        operations, amounts, currencies, recipients.
├── intersection.rs      Cross-provider policy tightening. compute + merge.
├── audit.rs             AuditLogger: JSON lines + in-memory query + stats.
├── events.rs            Event shipping to control plane. Batched via tokio channel.
│                        EventBatch, Event, EventSender, spawn_event_shipper().
│                        Daemon ID persisted at ~/.config/diff/gateway-daemon-id.
├── harvester.rs         Credential observation. SHA-256 fingerprinting.
├── profiler.rs          Behavior tracking. Policy suggestions.
├── session.rs           SessionContext, ProviderSession types (for future dynamic sessions).
└── mockapi.rs           Mock GitHub/Stripe/Gmail server for tests.
```

## Key types and where they live

| Type | File | What it is |
|---|---|---|
| `GatewayConfig` | config.rs | Top-level YAML config. Has `session`, `providers`, `intersection_policies`. |
| `SessionConfig` | config.rs | Session ID, `learning_mode`, `agent_type`, `project_id`, `environment`. |
| `ProviderConfig` | config.rs | Per-provider: `upstream`, `credential`, `policies`, optional `adapter` block. |
| `PolicyConfig` | config.rs | Allow/block rules. Used by policy engine AND intersection merge. |
| `AdapterConfig` | adapter/generic.rs | Describes API shape: `host`, `body_format`, `operations` with extraction rules. |
| `GatewayState` | proxy.rs | Shared axum state (Arc). Holds session info, providers (behind Mutex), all subsystems. |
| `ProviderEntry` | proxy.rs | Per-provider runtime state: upstream URL, credential string, PolicyEvaluator. |
| `PolicyEvaluator` | policy.rs | Stateless evaluator. `evaluate(method, path, operation, params) -> Decision`. |
| `Decision` | policy.rs | `allowed: bool`, `reason: String`, `matched_rule: String`. |
| `EventBatch` | events.rs | Wire format for `POST /v1/events`. Schema version 1. |
| `Event` | events.rs | Per-event wire format. 6 required fields, 16 optional. |
| `EventSender` | events.rs | Channel handle. Clone-cheap. `send(event)` is non-blocking. |
| `ParsedOperation` | adapter/mod.rs | Adapter output: provider, operation name, method, path, parameters map. |

## Request flow (proxy.rs handle_proxy_request)

```
1. Extract provider name from URL: /github/user → provider="github", sub_path="/user"
2. Lock state.providers, get ProviderEntry for "github"
3. Find adapter via state.adapter_registry.find_by_name("github")
4. adapter.parse_request("GET", "/user", body) → ParsedOperation
5. entry.evaluator.evaluate("GET", "/user", "get_user", params) → Decision
6. Compute body_hash and params_json for event shipping
7. harvester.observe() — record any credentials the agent sent
8. If blocked and not learning_mode → return 403 JSON
9. If blocked and learning_mode → forward anyway, log would_block
10. If allowed → forward_request() to upstream with credential injected
11. profiler.record() — track operation for behavior analysis
12. log_audit_event_with_body() → writes to AuditLogger AND ships via EventSender
```

## Server-side contract

**Endpoint:** `POST /v1/events` on the control plane (env var `GATEWAY_CONTROL_PLANE_URL`).

**Batch envelope:**
```json
{
  "schema_version": 1,
  "daemon_id": "hostname-a1b2c3d4",
  "events": [...]
}
```

**6 required fields per event:** `timestamp` (RFC 3339), `session_id`, `provider`, `method`, `path`, `decision` ("allowed" or "denied").

**Optional fields we populate today:** `operation`, `learning_mode`, `would_block`, `would_reason`, `parameters`, `request_body_hash`, `intersection_rules`, `policy_rule`, `agent_type`, `project_id`, `environment`.

**Optional fields we don't populate yet:** `task_id` (needs dynamic sessions), `credential_id` / `credential_ttl` (needs credential management), `mcp_tool_name` / `mcp_server` (available in params but not promoted to top-level event fields — one-line fix in `log_audit_event_with_body`).

**Batching:** 100 events or 5 seconds, whichever first. Max 1000 per batch. Channel buffer is 200. Events dropped silently if buffer full (back-pressure safety). If `GATEWAY_CONTROL_PLANE_URL` is empty, events are drained but never shipped.

**Response format:** `{"accepted": N, "rejected": M, "errors": [{"index": I, "reason": "..."}]}`. Partial success is handled — rejected events are logged to stderr.

**No auth on event shipping currently.** The reqwest client sends POST with no Authorization header. Adding auth is a roadmap item.

## Internal management API

All on the proxy port, under `/internal/`:

| Endpoint | Handler | Status |
|---|---|---|
| `GET /internal/audit?session=&provider=&decision=&limit=` | handle_audit_query | Works |
| `GET /internal/audit/stats` | handle_audit_stats | Works |
| `GET /internal/harvested` | handle_harvested | Works |
| `GET /internal/harvested/stats` | handle_harvested_stats | Works |
| `GET /internal/profile/{session_id}` | handle_profile | Works |
| `GET /internal/profile/{session_id}/suggest` | handle_suggest | Works |
| `POST /internal/sessions` | handle_add_session | **Partially works** — inserts providers into the mutex but doesn't track session-to-provider mapping, so DELETE can't clean up. See dynamic sessions roadmap item. |
| `DELETE /internal/sessions/{id}` | handle_remove_session | **Stub** — acknowledges but doesn't remove anything. |

## Config format

```yaml
session:
  id: "sess-001"
  learning_mode: false
  agent_type: "coding"        # Optional, for profiling
  project_id: "proj-acme"     # Optional, for scoping
  environment: "sandbox"      # Optional: laptop/sandbox/ci/staging/production

providers:
  stripe:
    upstream: "https://api.stripe.com"
    credential:
      type: "bearer"
      env_var: "STRIPE_KEY"   # Real credential loaded from this env var
    adapter:                  # Config-driven adapter (no Rust code per provider)
      host: "api.stripe.com"
      body_format: "form"     # json | form | gmail_mime | jsonrpc
      operations:
        - match: { method: "POST", path: "/v1/charges" }
          name: "create_charge"
          extract:
            - { param: "amount", field: "amount", type: "integer" }
            - { param: "currency", field: "currency" }
    policies:
      allowed_methods: ["GET", "POST"]
      blocked_methods: ["DELETE"]
      max_amount_cents: 5000
      allowed_currencies: ["usd"]

intersection_policies:
  - name: "payment-data-restriction"
    when:
      all_of: [{ provider: stripe }, { provider: gmail }]
    then:
      stripe: { max_amount_cents: 1000 }
```

## How to run and test

```bash
# Run unit tests
cargo test

# Run 30-scenario integration tests (builds binary, starts proxy + mock, runs curl tests)
make gateway-test

# Run the investor demo (self-contained, no real API tokens needed)
make investor-demo

# Start the proxy manually
GATEWAY_GITHUB_TOKEN=xxx getdiff gateway --config config/gateway-test.yaml --port 8080

# Start mock API server
getdiff mock-api --port 9999
```

## Gotchas for future agents

1. **Providers need `adapter` blocks in config.** The three built-in hard-coded adapters were deleted. If a provider has no `adapter` block, the Registry won't have an adapter for it. Requests still route (the proxy forwards based on the provider name in the URL), but operations parse as "unknown" and operation-level policies won't work.

2. **The policy evaluator is stateless.** It has no counter backend. `daily_limit_cents` is in the config type but never enforced. Don't assume aggregate limits work — they don't yet.

3. **`gmail_mime` body format only merges recipients/subject when the body is non-empty.** This was a bug fix — empty-body GET requests to Gmail were getting `recipients: ["unknown"]` and failing the recipient policy check. If you add a new body format plugin that auto-merges fields, apply the same guard.

4. **The EventSender drops events silently when the channel is full.** This is intentional (back-pressure safety), but it means event loss under extreme load. The channel buffer is 200 events. If the control plane is slow and events arrive faster than they flush, the newest events are dropped.

5. **Intersection merge is tighten-only.** `merge_intersections` can add blocked items, lower numeric caps, and narrow allowed lists. It can never loosen. If a test expects an intersection to grant more access than the base policy, that's a bug in the test, not the code.

6. **The `handle_add_session` endpoint partially works but has a design gap.** It inserts providers into `GatewayState.providers` but doesn't record which providers belong to which session. So `handle_remove_session` can't look up "remove all providers that were added for session X." The fix: add a `HashMap<String, Vec<String>>` mapping session_id → provider names, populated on add, used on delete.

7. **The proxy identifies providers by URL path prefix, not by network source.** In the current explicit mode, `/github/user` → provider is "github". There's no IP-to-session mapping. Transparent proxy mode (iptables) would change this — the provider would be identified by the original destination hostname, not the URL.

8. **`mcp_tool_name` is in `ParsedOperation.parameters` but not promoted to the top-level `Event` field.** The jsonrpc adapter puts it in `parameters["mcp_tool_name"]`. The server schema expects it as a top-level optional field. Fix: in `log_audit_event_with_body`, check if `parameters` contains `mcp_tool_name` and copy it to `event.mcp_tool_name`.

## Dependency chain for roadmap items

```
Dynamic Sessions (daemon)
    ↓ enables
Shadow Mode Activate (platform)   ← also needs platform to write policy to DB
    ↓ enables
Observe → Recommend → Enforce loop (the product)

Daemon Registration (daemon + platform)
    ↓ enables
Staleness detection, daemon inventory, health monitoring

API Authentication (daemon + platform)
    ↓ enables
Production deployment (without auth, control plane is open to anyone on the network)

Counter-Based Enforcement (daemon only)
    ↓ enables
daily_limit_cents, rate limiting, aggregate spending caps

Transparent Proxy / Sidecar (daemon only)
    ↓ enables
"Zero agent changes" — agent calls real API, iptables redirects to proxy
```

Dynamic sessions, daemon registration, and API auth are the three items that unblock the platform. They should be done first.
