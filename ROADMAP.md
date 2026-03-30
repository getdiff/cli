# Roadmap

Work to be done across the getDiff CLI, organized by feature area.

## Agent Gateway Security

The gateway proxy (`src/gateway/`) sits between AI agents and the APIs they use, enforcing policies and injecting credentials at the network boundary. The core is complete; the following items extend it.

### Dynamic Session Management

**Priority: High** — blocks the platform's ability to push policies to the daemon.

The `/internal/sessions` POST/DELETE endpoints exist but don't mutate the live provider map. The control plane can't push session configs at runtime — the proxy only reads from the YAML config at startup.

**What's needed:** When POST `/internal/sessions` receives a session config (providers, credentials, policies), it should build `ProviderEntry` instances and insert them into the `GatewayState.providers` mutex. DELETE should remove them. This enables the control plane to create scoped sessions per agent task without restarting the proxy.

**Why high priority:** The platform's shadow mode "activate" feature (converting a recommendation into an enforced policy) depends on pushing updated policies to the daemon. Without dynamic sessions, the observe → recommend → enforce loop is broken at the last step. This is the daemon-side dependency for closing that loop.

### Daemon Registration

**Priority: High** — the platform has no way to track daemon health.

The platform currently accepts any `daemon_id` string in event batches. There's no concept of known daemons, no heartbeat, no staleness detection.

**What's needed on the daemon side:**
- On startup, call `POST /v1/daemons/register` with the daemon_id, hostname, version, and capabilities
- Event batches already serve as implicit heartbeats — the platform updates `last_seen_at` per daemon on each batch
- No shared secret / auth token per daemon yet (see API authentication below)

**What the platform does with this:** Tracks daemon inventory, detects when a daemon stops reporting (stale after 5 minutes of silence), powers the dashboard's agent inventory view.

### API Authentication

**Priority: High** — there is currently no auth on any platform endpoint.

The daemon ships events to `POST /v1/events` with no token. The platform's dashboard endpoints have no auth. For a security product's control plane, this needs at minimum Bearer token auth.

**What's needed on the daemon side:** Include the getDiff API key (from `getdiff login` / `DIFF_API_KEY`) in the `Authorization: Bearer {token}` header on all requests to the control plane. The event shipper in `events.rs` currently sends batches with no auth header.

### Counter-Based Policy Enforcement

**Priority: Medium** — needed for aggregate limits but not blocking other work.

The policy config supports `daily_limit_cents` and similar aggregate limits, but there's no counter backend. Every request is evaluated independently — a $49 charge passes even if 100 $49 charges already happened today.

**What's needed:** An in-memory counter store keyed by `{session_id}:{provider}:{counter_name}` with configurable TTL (typically 24h). The `PolicyEvaluator` already accepts the fields; it just needs a counter backend to query and increment. Redis integration is optional — an in-memory store with periodic reset is sufficient for single-daemon deployments.

### Transparent Proxy Mode

**Priority: Medium** — makes the "zero agent changes" story fully real.

Currently the agent must send requests to `http://proxy:8080/{provider}/{path}`. In transparent mode, the agent calls `api.github.com` directly and iptables redirects the connection to the sidecar. The proxy reads the original destination from `SO_ORIGINAL_DST` and routes accordingly.

**What's needed:**
- TLS termination with a generated CA cert (injected into the agent container)
- Read original destination from redirected TCP connections
- Use `Registry.find(host)` (hostname-based adapter lookup) instead of `find_by_name`
- iptables init script for the agent container's network namespace (same pattern as Istio's `istio-init`)

### stdio MCP Wrapping

**Priority: Medium** — extends MCP coverage beyond HTTP transport.

The `jsonrpc` body format plugin handles MCP servers accessed via HTTP+SSE. But many MCP servers use stdio transport — the agent spawns a local process and writes JSON-RPC to its stdin.

**What's needed:** A process wrapper that sits between the agent and the MCP server's stdin/stdout, parsing each JSON-RPC message in the stream and applying the same policy evaluation. The getDiff CLI already has process launching patterns (it shells out to `sqlite3` in the Cursor parser). The wrapper would:
1. Spawn the MCP server process
2. Read JSON-RPC messages from the agent (one per line)
3. Parse using the `jsonrpc` body format
4. Evaluate against the provider's policy
5. Forward allowed messages to the MCP server's stdin
6. Relay responses back to the agent

### GraphQL Body Format Plugin

**Priority: Low** — most GraphQL providers also have REST APIs.

GraphQL APIs send all requests as `POST /graphql` with the operation in the query body. The current generic adapter can't parse this — the operation name is inside the GraphQL query string, not the URL.

**What's needed:** A `graphql` body format plugin that:
- Extracts the operation name from the query (`mutation CreateUser(...)` → `CreateUser`)
- Extracts variables from the `variables` JSON field
- Enables policy enforcement per GraphQL operation

Covers: GitHub v4 API, Shopify Storefront API, Hasura, internal GraphQL services.

### Config Test Cleanup

**Priority: Low** — cosmetic.

Some config test constants in `config.rs` still reference the old built-in adapter patterns (providers without `adapter` blocks). These should be updated to use `adapter` blocks matching the current config-driven format.

## Platform Integration

Items that span the daemon and server-side platform, surfaced during cross-agent review.

### Event Field Coverage

The daemon currently populates 8 of 15 optional event fields. Three fields were added during review (`agent_type`, `project_id`, `environment` — now in `SessionConfig` and wired to every event). The remaining unpopulated fields depend on features not yet built:

| Field | Depends on |
|---|---|
| `task_id` | Dynamic session management (task ID comes from control plane) |
| `credential_id` | Credential management / OpenBao integration |
| `credential_ttl` | Credential management / OpenBao integration |
| `mcp_tool_name` | Populated for `jsonrpc` format; not yet surfaced to event level |
| `mcp_server` | stdio MCP wrapping (need to know which server process) |

`mcp_tool_name` is the easiest to close — it's already in `ParsedOperation.parameters["mcp_tool_name"]` from the jsonrpc adapter but isn't promoted to the top-level event field. A one-line fix in `log_audit_event_with_body`.

### Shadow Mode Activation Loop

The platform can observe, profile, and recommend. But "activate" (converting a recommendation into an enforced policy pushed to the daemon) is a placeholder on both sides:

- **Platform side:** needs to write the policy and push it to the daemon via `POST /internal/sessions`
- **Daemon side:** needs dynamic session management to accept the push (see above)

This is the single most important cross-cutting feature. Without it, the product is a read-only dashboard. With it, the observe-first philosophy becomes a complete workflow.

## Repo Structure

### Workspace Split

**Priority: Medium** — doesn't block features, but affects build hygiene and sidecar binary size.

Today the repo is a single crate with two `[[bin]]` targets (`getdiff` and `gateway-sidecar`). Both binaries compile all source files. The sidecar pulls in the entire CLI codebase — parser, watcher, auth, artifacts, redaction — none of which it uses. This inflates the sidecar binary, adds unnecessary dependencies, and produces dead code warnings.

**What's needed:** Restructure into a Cargo workspace with three crates:

```
crates/
  gateway/         ← library crate (shared proxy code)
    src/lib.rs
    src/adapter/, policy.rs, proxy.rs, events.rs, ...

  cli/             ← binary crate (getdiff CLI)
    src/main.rs, parser/, watcher.rs, auth.rs, ...
    Cargo.toml depends on gateway + cli-only deps (notify, open, glob)

  sidecar/         ← binary crate (gateway-sidecar)
    src/main.rs    ← 40-line entry point
    Cargo.toml depends on gateway only
```

This is a mechanical refactor — move files, update `use` paths, split `Cargo.toml`. No logic changes. Benefits: smaller sidecar binary, faster sidecar builds, the `gateway` crate becomes independently publishable as an open-source library.

---

*Future sections for session logging, analytics, and artifact management will be added here as those feature areas develop their own roadmaps.*
