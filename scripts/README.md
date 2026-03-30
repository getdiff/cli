# Scripts

Test and demo scripts for the Agent Capability Gateway.

## Scripts

| Script | What it does | Duration | Dependencies |
|---|---|---|---|
| `integration-test.sh` | 30 integration tests across 9 categories. The definitive spec for gateway behavior. | ~10s | Rust binary (auto-built) |
| `investor-demo.sh` | Narrated demo showing all 9 gateway capabilities. Designed for recording/presenting. | ~22s | Rust binary (auto-built) |

## Running

```bash
# From the repo root:
make gateway-test      # Run 30 integration tests
make investor-demo     # Run the investor demo
```

Or directly:
```bash
./scripts/integration-test.sh
./scripts/investor-demo.sh          # With pauses between sections
./scripts/investor-demo.sh --fast   # No pauses
```

## Integration Test Categories

| # | Category | Tests | What it verifies |
|---|---|---|---|
| 1 | GitHub Adapter | 5 | Allowed reads, blocked path, blocked method, response content, credential injection |
| 2 | Stripe Adapter | 6 | Allowed reads, charge within cap, charge over intersection cap, blocked operation, blocked currency, blocked method |
| 3 | Gmail Adapter | 5 | Allowed list, send to allowed recipient, send to blocked recipient, blocked operation, blocked method |
| 4 | Intersection Policies | 3 | Cap lowered by intersection, charge just under cap succeeds, error message references intersection cap |
| 5 | Learning Mode | 3 | Blocked request forwarded, audit shows `would_block`, allowed request works |
| 6 | Credential Harvesting | 2 | Credential detected from agent request, stats accurate |
| 7 | Behavior Profiling | 2 | Profile reflects requests, suggestions generated |
| 8 | Audit | 3 | Query by provider, query by decision, stats |
| 9 | Unknown Provider | 1 | Returns 404 |

## How the Scripts Work

Both scripts:
1. Build the release binary (`cargo build --release`)
2. Start the mock API server (`getdiff mock-api --port 9999`) in background
3. Start the gateway proxy (`getdiff gateway --config ... --port 8081/8080`) in background
4. Wait for both to be ready
5. Run curl-based test scenarios
6. Clean up all background processes on exit (trap EXIT)

The integration test script also restarts the proxy in learning mode for categories 5-8, then starts an enforcement proxy again for category 9.

## Config Files

| File | Used by | Mode |
|---|---|---|
| `config/gateway-test.yaml` | integration tests | Enforcement (learning_mode: false) |
| `config/gateway-test-learning.yaml` | integration tests | Learning (learning_mode: true, no managed credentials) |

Both point upstreams at `http://localhost:9999/{provider}` (the mock API server).

## No Real API Tokens Needed

Everything runs against the mock API server. The proxy injects mock credentials (set via env vars in the scripts). The mock server validates that credentials arrived and echoes them back in `X-Received-Auth`.
