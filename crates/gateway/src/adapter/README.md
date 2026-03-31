# Adapters (`src/gateway/adapter/`)

Adapters parse raw HTTP requests into structured operations the policy engine can evaluate. There are two ways to define an adapter:

1. **Config-driven (generic)** — describe the API in YAML. No Rust code needed. Covers ~90% of REST APIs.
2. **Hand-coded (Rust)** — for APIs with unusual body encoding (Gmail MIME, GraphQL, gRPC). Write a struct that implements `ProviderAdapter`.

**Always prefer config-driven.** Only write Rust when the body format can't be handled by the generic parser.

## Adding a New Provider (Config-Driven)

Add an `adapter` block to the provider in your gateway YAML:

```yaml
providers:
  slack:
    upstream: "https://slack.com/api"
    credential:
      type: "bearer"
      env_var: "GATEWAY_SLACK_TOKEN"
    adapter:
      host: "slack.com"
      body_format: "json"
      operations:
        - match: { method: "POST", path: "/api/chat.postMessage" }
          name: "post_message"
          extract:
            - { param: "channel", field: "channel" }
            - { param: "text", field: "text" }
        - match: { method: "GET", path: "/api/conversations.history" }
          name: "read_messages"
        - match: { method: "POST", path: "/api/files.upload" }
          name: "upload_file"
    policies:
      allowed_operations: ["post_message", "read_messages"]
      blocked_operations: ["upload_file"]
```

That's it. No Rust code. The generic adapter handles path matching, body parsing, and field extraction. The policy engine evaluates operation names and extracted parameters against the policies.

## Config Reference

### `adapter` block

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | `""` | Hostname for transparent proxy mode matching |
| `body_format` | string | `"json"` | How to parse request bodies: `"json"`, `"form"`, or `"gmail_mime"` |
| `operations` | list | `[]` | Ordered list of operation definitions. First match wins. |

### Operation definition

| Field | Type | Description |
|---|---|---|
| `match.method` | string (optional) | HTTP method to match. Omit to match any method. |
| `match.path` | string | URL path pattern. `*` matches one path segment. |
| `name` | string | Operation name assigned to matching requests. |
| `extract` | list | Fields to extract from the body into parameters. |

### Field extraction

| Field | Type | Default | Description |
|---|---|---|---|
| `param` | string | required | Parameter name in `ParsedOperation.parameters` |
| `field` | string | required | Top-level field name in the decoded body |
| `type` | string | `"string"` | `"string"`, `"integer"`, or `"string_array"` |

### Body formats

| Format | When to use | How it works |
|---|---|---|
| `json` | Most REST APIs (default) | `serde_json::from_slice`, extracts top-level fields |
| `form` | Stripe, legacy APIs | `serde_urlencoded`, extracts form fields |
| `gmail_mime` | Gmail send only | Decodes base64url MIME from `raw` JSON field, extracts `To`/`Cc`/`Bcc`/`Subject` headers. Auto-populates `recipients` and `subject` parameters. |

## Fallback Behavior

- If a provider has no `adapter` block in the config, the registry falls back to a **built-in hard-coded adapter** if one exists (github, stripe, gmail).
- If a request doesn't match any operation definition, the operation is `"unknown"` and no parameters are extracted. Method/path policies still apply.
- If body parsing fails, it's treated as empty — no parameters extracted, request still processed.

## The `ProviderAdapter` Trait

Both generic and hand-coded adapters implement the same trait:

```rust
pub trait ProviderAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn match_host(&self, host: &str) -> bool;
    fn parse_request(&self, method: &str, path: &str, body: &[u8]) -> ParsedOperation;
    fn credential_header(&self, credential: &str) -> (String, String);
}
```

`ParsedOperation.parameters` is the bridge to the policy engine. The policy engine checks:
- `amount` (integer) — for `max_amount_cents` enforcement
- `currency` (string) — for `allowed_currencies` enforcement
- `recipients` (string array) — for `allowed_recipients` / `blocked_recipients` enforcement

## Built-In Adapters

Three hand-coded adapters exist as reference implementations. They're used as fallbacks when no `adapter` config is provided:

| File | Provider | Body format | Special logic |
|---|---|---|---|
| `github.rs` | GitHub | none (path-only) | — |
| `stripe.rs` | Stripe | form + json | Extracts amount/currency/customer |
| `gmail.rs` | Gmail | gmail_mime | Base64 MIME decoding for recipients |

These will eventually be replaced by config definitions. They remain as test references and for backward compatibility with configs that don't include `adapter` blocks.

## File Map

| File | What |
|---|---|
| `mod.rs` | `ProviderAdapter` trait, `ParsedOperation`, `Registry` |
| `generic.rs` | Config-driven generic adapter, body parsers, path matching |
| `github.rs` | Built-in GitHub adapter (fallback) |
| `stripe.rs` | Built-in Stripe adapter (fallback) |
| `gmail.rs` | Built-in Gmail adapter (fallback) |
