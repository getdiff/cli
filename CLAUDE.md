# getDiff CLI

Rust workspace with three crates:

- `crates/gateway/` — library crate: agent capability gateway (policy enforcement, credential injection, event shipping)
- `crates/cli/` — binary crate: `getdiff` CLI (session parsing, upload, file watching)
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
