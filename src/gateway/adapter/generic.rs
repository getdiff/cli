//! Config-driven provider adapter.
//!
//! Instead of writing Rust code per API, providers are described declaratively:
//!
//! ```yaml
//! providers:
//!   stripe:
//!     upstream: "https://api.stripe.com"
//!     host: "api.stripe.com"
//!     credential: { type: "bearer", env_var: "STRIPE_KEY" }
//!     body_format: "form"          # "json" | "form" | "gmail_mime"
//!     operations:
//!       - match: { method: "POST", path: "/v1/charges" }
//!         name: "create_charge"
//!         extract:
//!           - { param: "amount", field: "amount", type: "integer" }
//!           - { param: "currency", field: "currency" }
//!       - match: { method: "GET", path: "/v1/charges" }
//!         name: "list_charges"
//! ```
//!
//! The `GenericAdapter` handles path matching, body parsing, and field extraction
//! for any REST API. Special body formats (Gmail MIME) are handled as built-in
//! format plugins rather than per-provider code.

use super::{ParsedOperation, ProviderAdapter};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Config types for operation definitions
// ---------------------------------------------------------------------------

/// Describes how to parse requests for a single provider, driven by config.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AdapterConfig {
    /// Hostname for transparent proxy mode matching (e.g., "api.stripe.com").
    #[serde(default)]
    pub host: String,

    /// How to decode request bodies: "json", "form", or "gmail_mime".
    /// Defaults to "json".
    #[serde(default = "default_body_format")]
    pub body_format: String,

    /// Ordered list of operation mappings. First match wins.
    #[serde(default)]
    pub operations: Vec<OperationDef>,
}

fn default_body_format() -> String {
    "json".to_string()
}

/// Maps a method + path pattern to an operation name with optional field extraction.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperationDef {
    /// Method + path to match. Method is optional (matches any if omitted).
    #[serde(rename = "match")]
    pub matcher: RequestMatcher,

    /// The operation name to assign (e.g., "create_charge").
    pub name: String,

    /// Fields to extract from the request body into parameters.
    #[serde(default)]
    pub extract: Vec<FieldExtraction>,
}

/// Matches an HTTP method and URL path.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestMatcher {
    /// HTTP method. If omitted, matches any method.
    #[serde(default)]
    pub method: Option<String>,

    /// URL path pattern with glob segments. `*` matches one path segment.
    pub path: String,
}

/// Describes how to extract a parameter from the request body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FieldExtraction {
    /// Parameter name in the resulting `ParsedOperation.parameters`.
    pub param: String,

    /// Field name in the decoded body (top-level key).
    pub field: String,

    /// Expected type: "string" (default), "integer", "string_array".
    /// "integer" parses the value as i64.
    /// "string_array" expects a JSON array or comma-separated string.
    #[serde(default = "default_field_type", rename = "type")]
    pub field_type: String,
}

fn default_field_type() -> String {
    "string".to_string()
}

// ---------------------------------------------------------------------------
// Generic adapter implementation
// ---------------------------------------------------------------------------

/// A config-driven adapter that works for any REST API.
pub struct GenericAdapter {
    provider_name: String,
    host: String,
    body_format: String,
    operations: Vec<OperationDef>,
}

impl GenericAdapter {
    /// Build a generic adapter from a provider name and adapter config.
    pub fn new(name: &str, config: AdapterConfig) -> Self {
        Self {
            provider_name: name.to_string(),
            host: config.host,
            body_format: config.body_format,
            operations: config.operations,
        }
    }

    /// Parse the request body into a flat key→string map based on body_format.
    fn parse_body(&self, body: &[u8]) -> HashMap<String, String> {
        if body.is_empty() && self.body_format != "gmail_mime" {
            return HashMap::new();
        }

        match self.body_format.as_str() {
            "form" => parse_form_body(body),
            "gmail_mime" => parse_gmail_mime_body(body),
            "jsonrpc" => parse_jsonrpc_body(body),
            _ => parse_json_body(body), // "json" or unknown → try JSON
        }
    }

    /// Extract specified fields from the parsed body into serde_json::Value parameters.
    fn extract_fields(
        &self,
        extractions: &[FieldExtraction],
        body_fields: &HashMap<String, String>,
    ) -> HashMap<String, serde_json::Value> {
        let mut params = HashMap::new();
        for ext in extractions {
            if let Some(raw) = body_fields.get(&ext.field) {
                let value = match ext.field_type.as_str() {
                    "integer" => {
                        if let Ok(n) = raw.parse::<i64>() {
                            serde_json::Value::Number(n.into())
                        } else {
                            serde_json::Value::String(raw.clone())
                        }
                    }
                    "string_array" => {
                        // Try JSON array first, then comma-separated.
                        if let Ok(arr) = serde_json::from_str::<Vec<String>>(raw) {
                            serde_json::json!(arr)
                        } else {
                            let parts: Vec<String> =
                                raw.split(',').map(|s| s.trim().to_string()).collect();
                            serde_json::json!(parts)
                        }
                    }
                    _ => serde_json::Value::String(raw.clone()),
                };
                params.insert(ext.param.clone(), value);
            }
        }
        params
    }
}

impl GenericAdapter {
    /// Standard REST parsing: match method + path to find the operation.
    fn parse_rest_request(&self, method: &str, path: &str, body: &[u8]) -> ParsedOperation {
        for op_def in &self.operations {
            if let Some(ref m) = op_def.matcher.method {
                if !m.eq_ignore_ascii_case(method) {
                    continue;
                }
            }
            if !match_path_pattern(&op_def.matcher.path, path) {
                continue;
            }

            let body_fields = self.parse_body(body);
            let mut params = self.extract_fields(&op_def.extract, &body_fields);

            // For gmail_mime, auto-merge recipients and subject from body parser,
            // but only when there are extraction rules OR the body actually had content.
            // This prevents GET requests (empty body) from getting recipients: ["unknown"].
            if self.body_format == "gmail_mime" && !body.is_empty() {
                for key in &["recipients", "subject"] {
                    if !params.contains_key(*key) {
                        if let Some(v) = body_fields.get(*key) {
                            if *key == "recipients" {
                                if let Ok(arr) = serde_json::from_str::<Vec<String>>(v) {
                                    params.insert(key.to_string(), serde_json::json!(arr));
                                }
                            } else {
                                params.insert(
                                    key.to_string(),
                                    serde_json::Value::String(v.clone()),
                                );
                            }
                        }
                    }
                }
            }

            return ParsedOperation {
                provider: self.provider_name.clone(),
                operation: op_def.name.clone(),
                method: method.to_string(),
                path: path.to_string(),
                parameters: params,
            };
        }

        ParsedOperation {
            provider: self.provider_name.clone(),
            operation: "unknown".to_string(),
            method: method.to_string(),
            path: path.to_string(),
            parameters: HashMap::new(),
        }
    }

    /// JSON-RPC (MCP) parsing: the operation comes from the body, not the URL.
    ///
    /// For `tools/call` requests, the operation is `params.name` (the MCP tool name).
    /// For other RPC methods, the operation is the RPC method itself.
    /// `params.arguments` is flattened into the parameters map.
    ///
    /// If the config has operation definitions, they act as a rename/filter:
    /// a `tools/call` with `params.name = "query_database"` is first looked up
    /// in the operations list by matching `tool_name`. If found, the config's
    /// `name` is used and its `extract` rules are applied. If not found, the
    /// tool name is used directly as the operation.
    fn parse_jsonrpc_request(&self, method: &str, path: &str, body: &[u8]) -> ParsedOperation {
        let body_fields = self.parse_body(body);

        // Extract the RPC method and tool name from the parsed body fields.
        let rpc_method = body_fields.get("_rpc_method").cloned().unwrap_or_default();
        let tool_name = body_fields.get("_tool_name").cloned().unwrap_or_default();
        let rpc_id = body_fields.get("_rpc_id").cloned().unwrap_or_default();

        // Determine the operation name.
        // For tools/call: use the tool name.
        // For other RPC methods (resources/read, prompts/get, etc.): use the RPC method.
        let raw_operation = if rpc_method == "tools/call" && !tool_name.is_empty() {
            tool_name.clone()
        } else if !rpc_method.is_empty() {
            rpc_method.clone()
        } else {
            "unknown".to_string()
        };

        // Check if the operations list has a mapping for this tool/method.
        // Operations with `match.path` matching the tool name or RPC method are used.
        let mut operation = raw_operation.clone();
        let mut extra_params = HashMap::new();

        for op_def in &self.operations {
            // For jsonrpc, match.path is compared against the tool name or RPC method.
            let match_target = &op_def.matcher.path;
            if match_target == &raw_operation || match_target == &tool_name {
                operation = op_def.name.clone();
                // Apply extraction rules against the body fields.
                extra_params = self.extract_fields(&op_def.extract, &body_fields);
                break;
            }
        }

        // Build parameters: start with the arguments from the body, overlay extractions.
        let mut params: HashMap<String, serde_json::Value> = HashMap::new();

        // Include flattened arguments from the JSON-RPC params.
        for (k, v) in &body_fields {
            if k.starts_with('_') {
                continue; // Skip internal fields (_rpc_method, _tool_name, _rpc_id).
            }
            // Try to parse as JSON value; fall back to string.
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(v) {
                params.insert(k.clone(), parsed);
            } else {
                params.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        }

        // Overlay explicit extraction results.
        params.extend(extra_params);

        // Add MCP-specific metadata for event shipping.
        if !tool_name.is_empty() {
            params.insert(
                "mcp_tool_name".to_string(),
                serde_json::Value::String(tool_name),
            );
        }
        if !rpc_method.is_empty() {
            params.insert(
                "mcp_rpc_method".to_string(),
                serde_json::Value::String(rpc_method),
            );
        }
        if !rpc_id.is_empty() {
            params.insert(
                "mcp_rpc_id".to_string(),
                serde_json::Value::String(rpc_id),
            );
        }

        ParsedOperation {
            provider: self.provider_name.clone(),
            operation,
            method: method.to_string(),
            path: path.to_string(),
            parameters: params,
        }
    }
}

impl ProviderAdapter for GenericAdapter {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn match_host(&self, host: &str) -> bool {
        !self.host.is_empty() && host == self.host
    }

    fn parse_request(&self, method: &str, path: &str, body: &[u8]) -> ParsedOperation {
        let path = path.trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };

        if self.body_format == "jsonrpc" {
            return self.parse_jsonrpc_request(method, path, body);
        }

        self.parse_rest_request(method, path, body)
    }

    fn credential_header(&self, credential: &str) -> (String, String) {
        (
            "Authorization".to_string(),
            format!("Bearer {}", credential),
        )
    }
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

/// Matches a URL path against a pattern. `*` matches exactly one path segment.
fn match_path_pattern(pattern: &str, path: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();

    if pat_parts.len() != path_parts.len() {
        return false;
    }

    pat_parts
        .iter()
        .zip(path_parts.iter())
        .all(|(pat, seg)| *pat == "*" || *pat == *seg)
}

// ---------------------------------------------------------------------------
// Body parsers
// ---------------------------------------------------------------------------

/// Parse a JSON body into a flat key→string map (top-level fields only).
fn parse_json_body(body: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(obj) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(obj) = obj.as_object() {
            for (k, v) in obj {
                match v {
                    serde_json::Value::String(s) => {
                        map.insert(k.clone(), s.clone());
                    }
                    serde_json::Value::Number(n) => {
                        map.insert(k.clone(), n.to_string());
                    }
                    serde_json::Value::Bool(b) => {
                        map.insert(k.clone(), b.to_string());
                    }
                    serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                        map.insert(k.clone(), v.to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    map
}

/// Parse a form-urlencoded body into a key→string map.
fn parse_form_body(body: &[u8]) -> HashMap<String, String> {
    let body_str = String::from_utf8_lossy(body);
    serde_urlencoded::from_str::<Vec<(String, String)>>(&body_str)
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Parse a JSON-RPC body (MCP protocol).
///
/// The body is a JSON-RPC 2.0 request:
/// ```json
/// {"jsonrpc": "2.0", "method": "tools/call", "id": 1,
///  "params": {"name": "query_database", "arguments": {"sql": "SELECT 1"}}}
/// ```
///
/// Returns a flat map with:
/// - `_rpc_method` → the JSON-RPC method (e.g., "tools/call")
/// - `_tool_name` → for tools/call, the tool name from params.name
/// - `_rpc_id` → the request ID (stringified)
/// - All keys from `params.arguments` flattened as top-level entries
fn parse_jsonrpc_body(body: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let obj: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return map,
    };

    // Extract RPC method.
    if let Some(method) = obj.get("method").and_then(|v| v.as_str()) {
        map.insert("_rpc_method".to_string(), method.to_string());
    }

    // Extract ID.
    if let Some(id) = obj.get("id") {
        map.insert("_rpc_id".to_string(), match id {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => id.to_string(),
        });
    }

    // Extract params.
    if let Some(params) = obj.get("params").and_then(|v| v.as_object()) {
        // For tools/call, extract the tool name.
        if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
            map.insert("_tool_name".to_string(), name.to_string());
        }

        // Flatten params.arguments into top-level fields.
        if let Some(args) = params.get("arguments").and_then(|v| v.as_object()) {
            for (k, v) in args {
                match v {
                    serde_json::Value::String(s) => {
                        map.insert(k.clone(), s.clone());
                    }
                    serde_json::Value::Number(n) => {
                        map.insert(k.clone(), n.to_string());
                    }
                    serde_json::Value::Bool(b) => {
                        map.insert(k.clone(), b.to_string());
                    }
                    _ => {
                        map.insert(k.clone(), v.to_string());
                    }
                }
            }
        }

        // Also flatten any non-arguments params (e.g., params.uri for resources/read).
        for (k, v) in params {
            if k == "name" || k == "arguments" {
                continue;
            }
            match v {
                serde_json::Value::String(s) => {
                    map.insert(k.clone(), s.clone());
                }
                serde_json::Value::Number(n) => {
                    map.insert(k.clone(), n.to_string());
                }
                _ => {
                    map.insert(k.clone(), v.to_string());
                }
            }
        }
    }

    map
}

/// Parse a Gmail MIME body: JSON with a "raw" field containing base64url-encoded MIME.
/// Returns a map with "recipients" (JSON array string) and "subject".
fn parse_gmail_mime_body(body: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();

    #[derive(serde::Deserialize)]
    struct Payload {
        #[serde(default)]
        raw: String,
    }

    let payload: Payload = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(_) => {
            map.insert(
                "recipients".to_string(),
                serde_json::json!(["unknown"]).to_string(),
            );
            return map;
        }
    };

    if payload.raw.is_empty() {
        map.insert(
            "recipients".to_string(),
            serde_json::json!(["unknown"]).to_string(),
        );
        return map;
    }

    // Base64url decode.
    use base64::Engine;
    let mime_data = base64::engine::general_purpose::URL_SAFE
        .decode(&payload.raw)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&payload.raw));

    let mime_data = match mime_data {
        Ok(data) => data,
        Err(_) => {
            map.insert(
                "recipients".to_string(),
                serde_json::json!(["unknown"]).to_string(),
            );
            return map;
        }
    };

    let mime_str = String::from_utf8_lossy(&mime_data);
    let headers = parse_mime_headers(&mime_str);

    let mut recipients: Vec<String> = Vec::new();
    for hdr in &["To", "Cc", "Bcc"] {
        if let Some(v) = headers.get(*hdr) {
            recipients.extend(parse_address_list(v));
        }
    }
    if recipients.is_empty() {
        recipients.push("unknown".to_string());
    }

    map.insert(
        "recipients".to_string(),
        serde_json::json!(recipients).to_string(),
    );
    if let Some(subj) = headers.get("Subject") {
        map.insert("subject".to_string(), subj.clone());
    }

    map
}

/// Simple MIME header parser. Reads lines until empty line.
fn parse_mime_headers(mime: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in mime.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim();
            let val = line[idx + 1..].trim();
            let key = canonical_header_key(key);
            headers.insert(key, val.to_string());
        }
    }
    headers
}

fn canonical_header_key(key: &str) -> String {
    key.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    let mut s = c.to_uppercase().to_string();
                    s.extend(chars.map(|ch| ch.to_ascii_lowercase()));
                    s
                }
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse an email address list, stripping display names.
/// "Foo <foo@bar.com>, baz@bar.com" → ["foo@bar.com", "baz@bar.com"]
fn parse_address_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|addr| {
            let addr = addr.trim();
            if addr.is_empty() {
                return None;
            }
            // Strip "Display Name <email>" format.
            if let Some(start) = addr.find('<') {
                if let Some(end) = addr.find('>') {
                    return Some(addr[start + 1..end].trim().to_lowercase());
                }
            }
            Some(addr.to_lowercase())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn stripe_adapter() -> GenericAdapter {
        GenericAdapter::new(
            "stripe",
            AdapterConfig {
                host: "api.stripe.com".to_string(),
                body_format: "form".to_string(),
                operations: vec![
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("GET".into()),
                            path: "/v1/balance".into(),
                        },
                        name: "get_balance".into(),
                        extract: vec![],
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("POST".into()),
                            path: "/v1/charges".into(),
                        },
                        name: "create_charge".into(),
                        extract: vec![
                            FieldExtraction {
                                param: "amount".into(),
                                field: "amount".into(),
                                field_type: "integer".into(),
                            },
                            FieldExtraction {
                                param: "currency".into(),
                                field: "currency".into(),
                                field_type: "string".into(),
                            },
                        ],
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("GET".into()),
                            path: "/v1/charges".into(),
                        },
                        name: "list_charges".into(),
                        extract: vec![],
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("POST".into()),
                            path: "/v1/transfers".into(),
                        },
                        name: "create_transfer".into(),
                        extract: vec![],
                    },
                ],
            },
        )
    }

    fn gmail_adapter() -> GenericAdapter {
        GenericAdapter::new(
            "gmail",
            AdapterConfig {
                host: "gmail.googleapis.com".to_string(),
                body_format: "gmail_mime".to_string(),
                operations: vec![
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("POST".into()),
                            path: "/gmail/v1/users/me/messages/send".into(),
                        },
                        name: "send_email".into(),
                        extract: vec![], // recipients extracted by gmail_mime body parser
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("GET".into()),
                            path: "/gmail/v1/users/me/messages".into(),
                        },
                        name: "list_messages".into(),
                        extract: vec![],
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("POST".into()),
                            path: "/gmail/v1/users/me/messages/*/modify".into(),
                        },
                        name: "modify_message".into(),
                        extract: vec![],
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: Some("DELETE".into()),
                            path: "/gmail/v1/users/me/messages/*".into(),
                        },
                        name: "delete_message".into(),
                        extract: vec![],
                    },
                ],
            },
        )
    }

    // --- Path matching ---

    #[test]
    fn test_path_exact() {
        assert!(match_path_pattern("/v1/charges", "/v1/charges"));
    }

    #[test]
    fn test_path_wildcard() {
        assert!(match_path_pattern("/v1/charges/*", "/v1/charges/ch_123"));
    }

    #[test]
    fn test_path_multi_wildcard() {
        assert!(match_path_pattern("/repos/*/*", "/repos/octocat/Hello-World"));
    }

    #[test]
    fn test_path_mismatch_length() {
        assert!(!match_path_pattern("/v1/charges", "/v1/charges/ch_123"));
    }

    #[test]
    fn test_path_mismatch_segment() {
        assert!(!match_path_pattern("/v1/customers", "/v1/charges"));
    }

    // --- Body parsing ---

    #[test]
    fn test_parse_json_body() {
        let body = br#"{"amount": 3000, "currency": "usd", "name": "Test"}"#;
        let fields = parse_json_body(body);
        assert_eq!(fields.get("amount").unwrap(), "3000");
        assert_eq!(fields.get("currency").unwrap(), "usd");
        assert_eq!(fields.get("name").unwrap(), "Test");
    }

    #[test]
    fn test_parse_form_body() {
        let body = b"amount=3000&currency=usd";
        let fields = parse_form_body(body);
        assert_eq!(fields.get("amount").unwrap(), "3000");
        assert_eq!(fields.get("currency").unwrap(), "usd");
    }

    #[test]
    fn test_parse_empty_body() {
        assert!(parse_json_body(b"").is_empty());
        assert!(parse_form_body(b"").is_empty());
    }

    // --- Field extraction ---

    #[test]
    fn test_extract_integer() {
        let adapter = stripe_adapter();
        let fields: HashMap<String, String> =
            [("amount".into(), "3000".into())].into_iter().collect();
        let extractions = vec![FieldExtraction {
            param: "amount".into(),
            field: "amount".into(),
            field_type: "integer".into(),
        }];
        let params = adapter.extract_fields(&extractions, &fields);
        assert_eq!(params["amount"], serde_json::json!(3000));
    }

    #[test]
    fn test_extract_string() {
        let adapter = stripe_adapter();
        let fields: HashMap<String, String> =
            [("currency".into(), "usd".into())].into_iter().collect();
        let extractions = vec![FieldExtraction {
            param: "currency".into(),
            field: "currency".into(),
            field_type: "string".into(),
        }];
        let params = adapter.extract_fields(&extractions, &fields);
        assert_eq!(params["currency"], serde_json::json!("usd"));
    }

    // --- Stripe via generic adapter ---

    #[test]
    fn test_stripe_create_charge() {
        let adapter = stripe_adapter();
        let op = adapter.parse_request("POST", "/v1/charges", b"amount=3000&currency=usd");
        assert_eq!(op.operation, "create_charge");
        assert_eq!(op.parameters["amount"], serde_json::json!(3000));
        assert_eq!(op.parameters["currency"], serde_json::json!("usd"));
    }

    #[test]
    fn test_stripe_list_charges() {
        let adapter = stripe_adapter();
        let op = adapter.parse_request("GET", "/v1/charges", b"");
        assert_eq!(op.operation, "list_charges");
    }

    #[test]
    fn test_stripe_create_transfer() {
        let adapter = stripe_adapter();
        let op = adapter.parse_request("POST", "/v1/transfers", b"");
        assert_eq!(op.operation, "create_transfer");
    }

    #[test]
    fn test_stripe_unknown() {
        let adapter = stripe_adapter();
        let op = adapter.parse_request("GET", "/v1/something/new", b"");
        assert_eq!(op.operation, "unknown");
    }

    // --- Gmail MIME via generic adapter ---

    #[test]
    fn test_gmail_send_email() {
        use base64::Engine;
        let mime = "To: user@acme.com\r\nSubject: Hello\r\n\r\nBody text";
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mime);
        let body = format!(r#"{{"raw":"{}"}}"#, raw);

        let adapter = gmail_adapter();
        let op = adapter.parse_request(
            "POST",
            "/gmail/v1/users/me/messages/send",
            body.as_bytes(),
        );
        assert_eq!(op.operation, "send_email");
        let recipients = op.parameters["recipients"].as_array().unwrap();
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0], "user@acme.com");
    }

    #[test]
    fn test_gmail_list_messages() {
        let adapter = gmail_adapter();
        let op = adapter.parse_request("GET", "/gmail/v1/users/me/messages", b"");
        assert_eq!(op.operation, "list_messages");
    }

    #[test]
    fn test_gmail_modify_message() {
        let adapter = gmail_adapter();
        let op = adapter.parse_request(
            "POST",
            "/gmail/v1/users/me/messages/msg123/modify",
            b"{}",
        );
        assert_eq!(op.operation, "modify_message");
    }

    #[test]
    fn test_gmail_delete_message() {
        let adapter = gmail_adapter();
        let op = adapter.parse_request("DELETE", "/gmail/v1/users/me/messages/msg123", b"");
        assert_eq!(op.operation, "delete_message");
    }

    #[test]
    fn test_gmail_empty_body() {
        let adapter = gmail_adapter();
        let op = adapter.parse_request("POST", "/gmail/v1/users/me/messages/send", b"");
        assert_eq!(op.operation, "send_email");
        // Empty body → no recipients extracted (avoids false policy blocks on non-send requests).
        assert!(!op.parameters.contains_key("recipients"));
    }

    // --- Config deserialization ---

    #[test]
    fn test_adapter_config_from_yaml() {
        let yaml = r#"
host: "api.stripe.com"
body_format: "form"
operations:
  - match: { method: "POST", path: "/v1/charges" }
    name: "create_charge"
    extract:
      - { param: "amount", field: "amount", type: "integer" }
      - { param: "currency", field: "currency" }
  - match: { method: "GET", path: "/v1/charges" }
    name: "list_charges"
"#;
        let config: AdapterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.host, "api.stripe.com");
        assert_eq!(config.body_format, "form");
        assert_eq!(config.operations.len(), 2);
        assert_eq!(config.operations[0].name, "create_charge");
        assert_eq!(config.operations[0].extract.len(), 2);
    }

    // --- match_host ---

    #[test]
    fn test_match_host() {
        let adapter = stripe_adapter();
        assert!(adapter.match_host("api.stripe.com"));
        assert!(!adapter.match_host("api.github.com"));
    }

    #[test]
    fn test_match_host_empty() {
        let adapter = GenericAdapter::new(
            "test",
            AdapterConfig {
                host: String::new(),
                ..Default::default()
            },
        );
        assert!(!adapter.match_host("anything.com"));
    }

    // --- MIME helpers ---

    #[test]
    fn test_parse_address_list_simple() {
        let addrs = parse_address_list("foo@bar.com, baz@qux.com");
        assert_eq!(addrs, vec!["foo@bar.com", "baz@qux.com"]);
    }

    #[test]
    fn test_parse_address_list_display_names() {
        let addrs = parse_address_list("Foo Bar <foo@bar.com>, Baz <baz@qux.com>");
        assert_eq!(addrs, vec!["foo@bar.com", "baz@qux.com"]);
    }

    // --- JSON-RPC / MCP ---

    fn mcp_database_adapter() -> GenericAdapter {
        GenericAdapter::new(
            "mcp-database",
            AdapterConfig {
                host: String::new(),
                body_format: "jsonrpc".to_string(),
                operations: vec![
                    OperationDef {
                        matcher: RequestMatcher {
                            method: None,
                            path: "query_database".into(),
                        },
                        name: "database_query".into(),
                        extract: vec![FieldExtraction {
                            param: "sql".into(),
                            field: "sql".into(),
                            field_type: "string".into(),
                        }],
                    },
                    OperationDef {
                        matcher: RequestMatcher {
                            method: None,
                            path: "insert_record".into(),
                        },
                        name: "database_insert".into(),
                        extract: vec![
                            FieldExtraction {
                                param: "table".into(),
                                field: "table".into(),
                                field_type: "string".into(),
                            },
                        ],
                    },
                ],
            },
        )
    }

    fn mcp_no_config_adapter() -> GenericAdapter {
        GenericAdapter::new(
            "mcp-raw",
            AdapterConfig {
                host: String::new(),
                body_format: "jsonrpc".to_string(),
                operations: vec![], // No operation definitions — use tool names directly.
            },
        )
    }

    #[test]
    fn test_jsonrpc_tools_call_with_config() {
        let adapter = mcp_database_adapter();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "query_database",
                "arguments": {
                    "sql": "SELECT * FROM users WHERE id = 1"
                }
            }
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());
        assert_eq!(op.operation, "database_query"); // Renamed by config
        assert_eq!(
            op.parameters["sql"],
            serde_json::json!("SELECT * FROM users WHERE id = 1")
        );
        assert_eq!(
            op.parameters["mcp_tool_name"],
            serde_json::json!("query_database")
        );
        assert_eq!(
            op.parameters["mcp_rpc_method"],
            serde_json::json!("tools/call")
        );
    }

    #[test]
    fn test_jsonrpc_tools_call_without_config() {
        let adapter = mcp_no_config_adapter();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 42,
            "params": {
                "name": "send_slack_message",
                "arguments": {
                    "channel": "#eng-agents",
                    "text": "deploy complete"
                }
            }
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());
        // No config mapping — operation is the tool name directly.
        assert_eq!(op.operation, "send_slack_message");
        assert_eq!(op.parameters["channel"], serde_json::json!("#eng-agents"));
        assert_eq!(op.parameters["text"], serde_json::json!("deploy complete"));
    }

    #[test]
    fn test_jsonrpc_non_tools_call() {
        let adapter = mcp_no_config_adapter();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "resources/read",
            "id": 2,
            "params": {
                "uri": "file:///tmp/data.csv"
            }
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());
        // Not tools/call — operation is the RPC method.
        assert_eq!(op.operation, "resources/read");
        assert_eq!(op.parameters["uri"], serde_json::json!("file:///tmp/data.csv"));
    }

    #[test]
    fn test_jsonrpc_empty_body() {
        let adapter = mcp_no_config_adapter();
        let op = adapter.parse_request("POST", "/", b"");
        assert_eq!(op.operation, "unknown");
    }

    #[test]
    fn test_jsonrpc_invalid_json() {
        let adapter = mcp_no_config_adapter();
        let op = adapter.parse_request("POST", "/", b"not json");
        assert_eq!(op.operation, "unknown");
    }

    #[test]
    fn test_jsonrpc_arguments_flattened() {
        let adapter = mcp_no_config_adapter();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "create_charge",
                "arguments": {
                    "amount": 3000,
                    "currency": "usd",
                    "customer": "cus_123"
                }
            }
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());
        assert_eq!(op.operation, "create_charge");
        // Numeric arguments are parsed as numbers.
        assert_eq!(op.parameters["amount"], serde_json::json!(3000));
        assert_eq!(op.parameters["currency"], serde_json::json!("usd"));
        assert_eq!(op.parameters["customer"], serde_json::json!("cus_123"));
    }

    #[test]
    fn test_jsonrpc_config_extraction_overrides() {
        let adapter = mcp_database_adapter();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "insert_record",
                "arguments": {
                    "table": "users",
                    "data": {"name": "Alice"}
                }
            }
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());
        assert_eq!(op.operation, "database_insert"); // Renamed by config
        assert_eq!(op.parameters["table"], serde_json::json!("users"));
    }

    #[test]
    fn test_jsonrpc_policy_integration() {
        // Verify that the parsed operation works with the policy engine.
        use crate::gateway::config::PolicyConfig;
        use crate::gateway::policy::PolicyEvaluator;

        let adapter = mcp_database_adapter();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "query_database",
                "arguments": {"sql": "DROP TABLE users"}
            }
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());

        // Policy: only allow database_query, block database_insert.
        let policy = PolicyEvaluator::new(PolicyConfig {
            allowed_operations: vec!["database_query".to_string()],
            blocked_operations: vec!["database_insert".to_string()],
            ..Default::default()
        });

        let decision = policy.evaluate("POST", "/", &op.operation, &op.parameters);
        assert!(decision.allowed); // database_query is allowed

        // Now try an insert.
        let body2 = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 2,
            "params": {
                "name": "insert_record",
                "arguments": {"table": "users"}
            }
        });
        let op2 = adapter.parse_request("POST", "/", body2.to_string().as_bytes());
        let decision2 = policy.evaluate("POST", "/", &op2.operation, &op2.parameters);
        assert!(!decision2.allowed); // database_insert is blocked
    }

    #[test]
    fn test_jsonrpc_adapter_config_from_yaml() {
        let yaml = r#"
body_format: "jsonrpc"
operations:
  - match: { path: "query_database" }
    name: "db_query"
    extract:
      - { param: "sql", field: "sql" }
  - match: { path: "execute_command" }
    name: "shell_exec"
"#;
        let config: AdapterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.body_format, "jsonrpc");
        assert_eq!(config.operations.len(), 2);
        assert_eq!(config.operations[0].name, "db_query");

        let adapter = GenericAdapter::new("mcp-test", config);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "query_database", "arguments": {"sql": "SELECT 1"}}
        });
        let op = adapter.parse_request("POST", "/", body.to_string().as_bytes());
        assert_eq!(op.operation, "db_query");
        assert_eq!(op.parameters["sql"], serde_json::json!("SELECT 1"));
    }
}
