//! Mock API server simulating GitHub, Stripe, and Gmail for demo and
//! integration testing purposes.
//!
//! Each provider's routes are mounted under its name prefix:
//! - `/github/*` — mock GitHub API
//! - `/stripe/*` — mock Stripe API
//! - `/gmail/*`  — mock Gmail API

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Start the mock API server on the given port. Blocks until shutdown.
pub async fn run_mock_api(port: u16) -> anyhow::Result<()> {
    let app = build_mock_router();

    let addr = format!("0.0.0.0:{}", port);
    eprintln!("mock API server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the axum router for the mock API (useful for testing without binding).
pub fn build_mock_router() -> Router {
    Router::new()
        .route("/health", get(handle_health))
        // Use a fallback to route by prefix, matching the Go mux behavior.
        .fallback(handle_mock_request)
}

async fn handle_health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// Main request dispatcher
// ---------------------------------------------------------------------------

/// Dispatch incoming requests to the appropriate provider handler based on
/// the first path segment.
async fn handle_mock_request(
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();

    if path.starts_with("/github/") || path == "/github" {
        handle_github(method, path, &headers, &body).await
    } else if path.starts_with("/stripe/") || path == "/stripe" {
        handle_stripe(method, path, &headers, &body).await
    } else if path.starts_with("/gmail/") || path == "/gmail" {
        handle_gmail(method, path, &headers, &body).await
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "not_found", "message": format!("Unknown path: {}", path) }),
        )
    }
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Check that an `Authorization` header is present. Returns the auth value
/// or an error response.
fn require_auth(headers: &HeaderMap) -> Result<String, Box<Response>> {
    match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(auth) if !auth.is_empty() => Ok(auth.to_string()),
        _ => Err(Box::new(json_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "unauthorized", "message": "No Authorization header" }),
        ))),
    }
}

/// Build a JSON response with the `X-Received-Auth` header set.
fn authed_json(status: StatusCode, auth: &str, body: Value) -> Response {
    let mut resp = json_response(status, body);
    resp.headers_mut().insert(
        "X-Received-Auth",
        HeaderValue::from_str(auth).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    resp
}

// ---------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------

async fn handle_github(
    method: Method,
    full_path: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let auth = match require_auth(headers) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };

    let path = full_path.trim_start_matches("/github");
    let path = if path.is_empty() { "/" } else { path };

    eprintln!("[github] {} {}", method, path);

    // GET /user
    if method == Method::GET && path == "/user" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "login": "demo-agent",
                "id": 1,
                "name": "Demo Agent",
                "email": "agent@acme.com",
                "type": "User"
            }),
        );
    }

    // GET /user/repos
    if method == Method::GET && path == "/user/repos" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!([
                {"id": 101, "name": "gateway", "full_name": "acme/gateway", "private": false, "description": "Agent Capability Gateway"},
                {"id": 102, "name": "frontend", "full_name": "acme/frontend", "private": false, "description": "Company frontend"},
                {"id": 103, "name": "backend", "full_name": "acme/backend", "private": true, "description": "Company backend"}
            ]),
        );
    }

    // GET /repos/{owner}/{repo}/issues
    if method == Method::GET && match_github_path(path, "/repos/*/*/issues") {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!([
                {"id": 1, "title": "Fix login flow", "state": "open", "user": {"login": "alice"}},
                {"id": 2, "title": "Update dependencies", "state": "open", "user": {"login": "bob"}},
                {"id": 3, "title": "Add tests", "state": "closed", "user": {"login": "charlie"}}
            ]),
        );
    }

    // POST /repos/{owner}/{repo}/issues
    if method == Method::POST && match_github_path(path, "/repos/*/*/issues") {
        let body_json: Value = serde_json::from_slice(body).unwrap_or(json!({}));
        let title = body_json
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Untitled");
        return authed_json(
            StatusCode::CREATED,
            &auth,
            json!({
                "id": 123,
                "number": 4,
                "title": title,
                "state": "open",
                "user": {"login": "demo-agent"}
            }),
        );
    }

    // GET /repos/{owner}/{repo}/pulls
    if method == Method::GET && match_github_path(path, "/repos/*/*/pulls") {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!([
                {"id": 10, "number": 1, "title": "Feature: add gateway support", "state": "open"},
                {"id": 11, "number": 2, "title": "Fix: resolve timeout issue", "state": "merged"}
            ]),
        );
    }

    // GET /repos/{owner}/{repo}
    if method == Method::GET && match_github_path(path, "/repos/*/*") {
        let trimmed = path.trim_start_matches("/repos/");
        let parts: Vec<&str> = trimmed.splitn(2, '/').collect();
        if parts.len() == 2 {
            return authed_json(
                StatusCode::OK,
                &auth,
                json!({
                    "id": 201,
                    "name": parts[1],
                    "full_name": format!("{}/{}", parts[0], parts[1]),
                    "private": false,
                    "description": "A mock repository",
                    "language": "Go",
                    "stargazers_count": 42
                }),
            );
        }
    }

    // GET /rate_limit
    if method == Method::GET && path == "/rate_limit" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "rate": {"limit": 5000, "remaining": 4999, "reset": 1700000000}
            }),
        );
    }

    authed_json(
        StatusCode::NOT_FOUND,
        &auth,
        json!({ "message": "Not Found" }),
    )
}

/// Match a GitHub-style wildcard path pattern (only `*` segments).
fn match_github_path(path: &str, pattern: &str) -> bool {
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let pattern_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();

    if path_parts.len() != pattern_parts.len() {
        return false;
    }

    for (pp, pat) in path_parts.iter().zip(pattern_parts.iter()) {
        if *pat == "*" {
            continue;
        }
        if pp != pat {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Stripe
// ---------------------------------------------------------------------------

async fn handle_stripe(
    method: Method,
    full_path: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Response {
    let auth = match require_auth(headers) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };

    let path = full_path.trim_start_matches("/stripe");
    let path = if path.is_empty() { "/" } else { path };

    eprintln!("[stripe] {} {}", method, path);

    // GET /v1/charges
    if method == Method::GET && path == "/v1/charges" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "object": "list",
                "data": [
                    {"id": "ch_1", "amount": 2000, "currency": "usd", "status": "succeeded"},
                    {"id": "ch_2", "amount": 3500, "currency": "usd", "status": "succeeded"}
                ]
            }),
        );
    }

    // POST /v1/charges
    if method == Method::POST && path == "/v1/charges" {
        let params = parse_stripe_body(headers, body);
        let amount = params.get("amount").cloned().unwrap_or_else(|| "0".into());
        let currency = params
            .get("currency")
            .cloned()
            .unwrap_or_else(|| "usd".into());
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": "ch_mock_123",
                "object": "charge",
                "amount": amount,
                "currency": currency,
                "status": "succeeded"
            }),
        );
    }

    // GET /v1/customers
    if method == Method::GET && path == "/v1/customers" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "object": "list",
                "data": [
                    {"id": "cus_1", "email": "alice@acme.com", "name": "Alice"},
                    {"id": "cus_2", "email": "bob@acme.com", "name": "Bob"}
                ]
            }),
        );
    }

    // POST /v1/customers
    if method == Method::POST && path == "/v1/customers" {
        let params = parse_stripe_body(headers, body);
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": "cus_mock_456",
                "object": "customer",
                "email": params.get("email").cloned().unwrap_or_default(),
                "name": params.get("name").cloned().unwrap_or_default()
            }),
        );
    }

    // POST /v1/refunds
    if method == Method::POST && path == "/v1/refunds" {
        let params = parse_stripe_body(headers, body);
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": "re_mock_789",
                "object": "refund",
                "charge": params.get("charge").cloned().unwrap_or_default(),
                "status": "succeeded"
            }),
        );
    }

    // GET /v1/balance
    if method == Method::GET && path == "/v1/balance" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "object": "balance",
                "available": [{"amount": 50000, "currency": "usd"}],
                "pending": [{"amount": 5000, "currency": "usd"}]
            }),
        );
    }

    // POST /v1/transfers
    if method == Method::POST && path == "/v1/transfers" {
        let params = parse_stripe_body(headers, body);
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": "tr_mock_101",
                "object": "transfer",
                "amount": params.get("amount").cloned().unwrap_or_default(),
                "currency": params.get("currency").cloned().unwrap_or_default(),
                "destination": params.get("destination").cloned().unwrap_or_default()
            }),
        );
    }

    // GET /v1/subscriptions/{id} — not in the Go code but listed in spec
    if method == Method::GET
        && let Some(sub_id) = path.strip_prefix("/v1/subscriptions/")
        && !sub_id.is_empty()
        && !sub_id.contains('/')
    {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": sub_id,
                "object": "subscription",
                "status": "active",
                "customer": "cus_1"
            }),
        );
    }

    authed_json(
        StatusCode::NOT_FOUND,
        &auth,
        json!({ "error": "not_found", "message": format!("Unknown path: {}", path) }),
    )
}

/// Parse a Stripe request body. Stripe accepts both `application/json` and
/// `application/x-www-form-urlencoded`.
fn parse_stripe_body(
    headers: &HeaderMap,
    body: &Bytes,
) -> std::collections::HashMap<String, String> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("application/json") {
        // Parse as JSON and flatten to string values.
        if let Ok(map) = serde_json::from_slice::<serde_json::Map<String, Value>>(body) {
            return map
                .into_iter()
                .map(|(k, v)| {
                    let s = match &v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k, s)
                })
                .collect();
        }
        return std::collections::HashMap::new();
    }

    // Default: form-urlencoded.
    let body_str = std::str::from_utf8(body).unwrap_or("");
    serde_urlencoded::from_str::<Vec<(String, String)>>(body_str)
        .unwrap_or_default()
        .into_iter()
        .collect()
}

// ---------------------------------------------------------------------------
// Gmail
// ---------------------------------------------------------------------------

async fn handle_gmail(
    method: Method,
    full_path: &str,
    headers: &HeaderMap,
    _body: &Bytes,
) -> Response {
    let auth = match require_auth(headers) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };

    // The Go code strips /gmail prefix, then matches against /gmail/v1/...
    // This means the upstream path is /gmail/v1/... after stripping the
    // router prefix /gmail.
    // The proxy sends /{upstream_prefix}/{api_path}.
    // Gmail API paths are /gmail/v1/..., so we may see /gmail/gmail/v1/...
    let mut path = full_path;
    while let Some(stripped) = path.strip_prefix("/gmail") {
        path = stripped;
    }
    let path = if path.is_empty() { "/" } else { path };

    eprintln!("[gmail] {} {}", method, path);

    // GET /gmail/v1/users/me/messages
    if method == Method::GET && path == "/v1/users/me/messages" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "messages": [
                    {"id": "msg_001", "threadId": "thread_001"},
                    {"id": "msg_002", "threadId": "thread_002"},
                    {"id": "msg_003", "threadId": "thread_003"}
                ],
                "resultSizeEstimate": 3
            }),
        );
    }

    // POST /v1/users/me/messages/send
    if method == Method::POST && path == "/v1/users/me/messages/send" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": "msg_123",
                "threadId": "thread_456",
                "labelIds": ["SENT"]
            }),
        );
    }

    // GET /v1/users/me/messages/{id}
    if method == Method::GET && path.starts_with("/v1/users/me/messages/") {
        let msg_id = path.trim_start_matches("/v1/users/me/messages/");
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "id": msg_id,
                "threadId": "thread_001",
                "snippet": "This is a mock email message body preview...",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "sender@acme.com"},
                        {"name": "To", "value": "recipient@acme.com"},
                        {"name": "Subject", "value": "Mock Email Subject"}
                    ]
                }
            }),
        );
    }

    // GET /gmail/v1/users/me/labels
    if method == Method::GET && path == "/v1/users/me/labels" {
        return authed_json(
            StatusCode::OK,
            &auth,
            json!({
                "labels": [
                    {"id": "INBOX", "name": "INBOX", "type": "system"},
                    {"id": "SENT", "name": "SENT", "type": "system"},
                    {"id": "DRAFT", "name": "DRAFT", "type": "system"},
                    {"id": "Label_1", "name": "Important", "type": "user"}
                ]
            }),
        );
    }

    authed_json(
        StatusCode::NOT_FOUND,
        &auth,
        json!({ "error": "not_found", "message": format!("Unknown path: {}", path) }),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a JSON response with the given status code and body.
fn json_response(status: StatusCode, body: Value) -> Response {
    let mut resp = Json(body).into_response();
    *resp.status_mut() = status;
    resp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_github_path() {
        assert!(match_github_path("/repos/acme/gateway", "/repos/*/*"));
        assert!(match_github_path(
            "/repos/acme/gateway/issues",
            "/repos/*/*/issues"
        ));
        assert!(!match_github_path("/repos/acme", "/repos/*/*"));
        assert!(!match_github_path(
            "/repos/acme/gateway/pulls",
            "/repos/*/*/issues"
        ));
    }

    #[test]
    fn test_match_github_path_exact() {
        assert!(match_github_path("/user/repos", "/user/repos"));
        assert!(!match_github_path("/user/repos", "/user/stars"));
    }

    #[test]
    fn test_parse_stripe_body_form() {
        let headers = HeaderMap::new();
        let body = Bytes::from("amount=2000&currency=usd");
        let params = parse_stripe_body(&headers, &body);
        assert_eq!(params.get("amount").unwrap(), "2000");
        assert_eq!(params.get("currency").unwrap(), "usd");
    }

    #[test]
    fn test_parse_stripe_body_json() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let body = Bytes::from(r#"{"amount":"5000","currency":"eur"}"#);
        let params = parse_stripe_body(&headers, &body);
        assert_eq!(params.get("amount").unwrap(), "5000");
        assert_eq!(params.get("currency").unwrap(), "eur");
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = build_mock_router();

        let resp = axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = {
            use tower::ServiceExt;
            app.into_service().oneshot(resp)
        }
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_github_requires_auth() {
        let app = build_mock_router();

        let req = axum::http::Request::builder()
            .uri("/github/user")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = {
            use tower::ServiceExt;
            app.into_service().oneshot(req)
        }
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_github_user() {
        let app = build_mock_router();

        let req = axum::http::Request::builder()
            .uri("/github/user")
            .header("Authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = {
            use tower::ServiceExt;
            app.into_service().oneshot(req)
        }
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("X-Received-Auth").unwrap(),
            "Bearer test-token"
        );
    }

    #[tokio::test]
    async fn test_stripe_charges() {
        let app = build_mock_router();

        let req = axum::http::Request::builder()
            .uri("/stripe/v1/charges")
            .header("Authorization", "Bearer sk_test")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = {
            use tower::ServiceExt;
            app.into_service().oneshot(req)
        }
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_gmail_messages() {
        let app = build_mock_router();

        let req = axum::http::Request::builder()
            .uri("/gmail/v1/users/me/messages")
            .header("Authorization", "Bearer gmail-token")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = {
            use tower::ServiceExt;
            app.into_service().oneshot(req)
        }
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
