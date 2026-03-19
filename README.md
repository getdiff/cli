# Diff CLI

`getdiff` captures coding-agent sessions, applies best-effort redaction, and uploads normalized session data to Diff for analysis.

## License

This project is licensed under the Apache License, Version 2.0. See `LICENSE`.

## What It Does

1. Parses supported coding-agent session logs into a normalized format
2. Applies best-effort redaction for many secrets and some sensitive data before upload
3. Uploads session data to the Diff API
4. Watches for completed sessions and uploads them automatically

## Supported Providers

- Claude Code
- Codex
- OpenCode

## Install

```bash
cargo install --path .
```

## Authentication And Setup

You can authenticate either with browser login or environment variables.

Browser login:

```bash
getdiff login
```

Environment variables:

```bash
export DIFF_API_KEY="your-api-key"
export DIFF_ORG_ID="your-org-id"
export DIFF_SERVER="https://getdiff.now"
```

`DIFF_SERVER` defaults to `https://getdiff.now`.

## Usage

Upload a single session by ID:

```bash
getdiff upload --session <SESSION_ID>
```

Preview the normalized payload without uploading:

```bash
getdiff upload --session <SESSION_ID> --dry-run
```

Parse a local session artifact directly:

```bash
getdiff parse --provider claude-code --file path/to/session.jsonl
```

Watch for completed sessions and upload them automatically:

```bash
getdiff watch --provider claude-code
```

Check login status:

```bash
getdiff status
```

Browse registry artifacts:

```bash
getdiff registry search --server https://getdiff.now
```

Publish a registry artifact:

```bash
getdiff publish --type prompt --name my-prompt --path ./artifact.json --server https://getdiff.now
```

Run `getdiff --help` or `getdiff <subcommand> --help` for the full command surface.

## Privacy And Data Handling

`getdiff` applies best-effort redaction before upload. It is designed to reduce the chance that common secrets and some sensitive values are sent to Diff, but it does not guarantee complete removal of all sensitive or identifying data.

Depending on the provider and session contents, uploaded data may include:

- prompts and assistant responses
- tool inputs and outputs
- file paths, file names, and repository context
- usernames, hostnames, and workspace metadata
- token usage and model metadata
- optional configuration snapshot metadata

If you are working with sensitive repositories or regulated data, inspect the payload locally before upload:

```bash
getdiff upload --session <SESSION_ID> --dry-run
```

## Redaction Model

Redaction combines:

- built-in detectors for common secrets and selected sensitive data
- optional detector packs fetched from the Diff server
- local redaction before upload

Detector coverage can evolve over time and may vary by detector pack version. You should treat redaction as a safety layer, not a guarantee.

## Architecture

```text
src/
  main.rs             CLI entry point
  auth.rs             Login and local config handling
  detectors.rs        Server-fetched detector pack support
  types.rs            Normalized session payload types
  parser/             Provider-specific session parsers
  redact/             Best-effort redaction pipeline
  watcher.rs          Background upload loop
tests/
  parser_tests.rs     Integration tests
  fixtures/           Sample session fixtures
```

## Testing

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Contributing

Issues and pull requests are welcome. For larger changes, open an issue first so the implementation approach can be discussed before you spend time on a PR.
