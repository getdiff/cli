# getDiff CLI

Rust workspace with three crates:

- `crates/gateway/` — library crate: agent capability gateway (transparent proxy, policy enforcement, event shipping)
- `crates/cli/` — binary crate: `getdiff` CLI (gateway, init/uninit, session parsing, upload, file watching)
- `crates/sidecar/` — binary crate: `gateway-sidecar` (minimal proxy for container deployment, depends only on gateway)

## Before opening a PR

Run these checks — CI will reject the PR if they fail:

```sh
cargo fmt --all -- --check
cargo clippy --workspace
cargo test --workspace
```

## Build

```sh
cargo build -p getdiff          # CLI binary
cargo build -p gateway-sidecar  # Sidecar binary (smaller, no CLI deps)
```

## Test

```sh
cargo test --workspace           # All tests
cargo test -p getdiff-gateway    # Gateway library only
cargo test -p getdiff            # CLI + integration tests
```

## Architecture

### Gateway proxy (`crates/gateway/src/`)

The gateway is a transparent HTTP/HTTPS forward proxy. Agents route through it via `HTTP_PROXY`/`HTTPS_PROXY`. It observes traffic, classifies by hostname, and ships events to the platform.

**Request flow (two paths):**

1. **CONNECT** (HTTPS, most traffic) — `forward_proxy.rs:handle_connect_tunnel()` reads the CONNECT request at the TCP level, connects to upstream, sends `200 Connection established`, copies bytes bidirectionally. Logs hostname + timing only (can't inspect TLS).

2. **Absolute URI** (HTTP) — `forward_proxy.rs:handle_forward_proxy()` extracts hostname, forwards via `reqwest`, logs full request details (method, path, body hash, status, latency).

3. **Path-prefix** (legacy, `/github/...`) — `proxy.rs:handle_proxy_request()` extracts provider from first path segment, evaluates policy, forwards to configured upstream. Used when agents are explicitly configured with provider-specific URLs.

**Key files:**

| File | Purpose |
|---|---|
| `forward_proxy.rs` | TCP listener, CONNECT tunneling, HTTP forward proxy, hyper→axum routing |
| `proxy.rs` | GatewayState, axum router, path-prefix handler, policy evaluation, audit logging, `run_gateway()` entry point |
| `config.rs` | YAML config parsing, `default_config()`, `merge_with_defaults()`, `provider_for_host()` hostname→provider mapping |
| `events.rs` | Event struct (must match Go schema), batch shipping to platform, daemon ID, retry logic |
| `policy.rs` | PolicyEvaluator — method/path/operation allow/deny, amount caps, recipient limits |
| `adapter/generic.rs` | Config-driven request parsing (REST, JSON-RPC, GraphQL, form-encoded) |
| `intersection.rs` | Cross-capability policy merging (e.g., "when agent has stripe+gmail, lower caps") |
| `counter.rs` | In-memory aggregate counters for daily_limit_cents |
| `harvester.rs` | Credential observation — fingerprints auth headers passing through |
| `profiler.rs` | Behavior tracking per session — operation frequency, method distribution |
| `audit.rs` | Structured audit logger (stderr + in-memory queryable) |
| `transparent.rs` | Linux iptables redirect support (SO_ORIGINAL_DST, hostname resolution) |
| `session.rs` | Session context types for dynamic session management |
| `mockapi.rs` | Mock upstream servers for testing/demos |
| `mcp_stdio.rs` | MCP protocol policy evaluation for stdio-based tools |

**Shared state:** `GatewayState` (proxy.rs) is the central `Arc<>` shared across all handlers. Contains providers (`RwLock`), session tracking (`Mutex`), event sender, adapter registry, audit logger, profiler, harvester, counter store.

**Event schema:** `Event` struct in events.rs serializes to JSON matching the Go schema at `gateway/internal/events/schema.go` in the diff monorepo. Key: the field is `org_id` (not `project_id`), and the daemon sets it to `None` (platform derives from CLI token).

### CLI (`crates/cli/src/`)

**Key areas in main.rs:**

| Section | What it does |
|---|---|
| `Commands::Gateway` | Runs `init all`, installs signal handlers for `uninit all` on shutdown, then calls `run_gateway()` |
| `Commands::Init` / `Commands::Uninit` | Agent proxy configuration — see `init_agent()`, supports `all` to scan for installed agents |
| `init_json_env()` | Writes `HTTP_PROXY`/`HTTPS_PROXY` into JSON settings files (Claude Code, Copilot) |
| `init_cursor()` | Writes `http.proxy` into Cursor's VS Code settings |
| `init_wrapper()` | Creates shell wrapper scripts at `~/.getdiff/bin/` for agents without config-file env injection (Codex, Gemini, OpenCode) |
| Session parsing | `parser/` module — parsers for claude-code, codex, copilot, cursor, gemini, opencode session formats |
| `Commands::Watch` | Background file watcher that detects completed sessions and uploads them |

### Sidecar (`crates/sidecar/src/main.rs`)

Minimal binary — calls `run_gateway()` with config from env vars. Same transparent proxy as the CLI but no init/uninit, no signal handlers, no session parsing. Designed for containers where `HTTPS_PROXY` is set on the agent process.

## Conventions

- `Event.org_id` — derived from CLI token by the platform. The daemon sets it to `None`. Old configs may use `project_id` (accepted via serde alias, deprecated).
- `http_client` — always built with `.no_proxy()` and `.redirect(Policy::none())` to prevent proxy loops.
- Provider classification — `config::provider_for_host()` maps hostnames to friendly names. Unknown hostnames become the provider name. Nothing is dropped.
- Learning mode — default. All traffic forwarded, nothing blocked. Events tagged with `learning_mode: true` and `would_block`/`would_reason` if policy would have denied.
- The gateway runs `init all` on start and `uninit all` on stop (SIGINT/SIGTERM). Agents are never left pointing at a dead proxy.
