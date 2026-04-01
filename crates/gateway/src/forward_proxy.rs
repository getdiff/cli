//! Transparent forward proxy mode.
//!
//! Handles two request types:
//!
//! 1. **HTTP forward proxy:** The client sends an absolute-URI request like
//!    `GET http://api.github.com/repos/foo HTTP/1.1`. The proxy extracts the
//!    hostname, classifies the provider, forwards the request, and logs an
//!    audit event with full visibility (method, path, body, status).
//!    Note: almost all APIs use HTTPS, so this path is rarely hit in practice.
//!
//! 2. **HTTPS CONNECT tunneling:** The client sends `CONNECT api.github.com:443`.
//!    The proxy logs the hostname (provider classification), then establishes a
//!    raw TCP tunnel. TLS is end-to-end between client and upstream — the proxy
//!    can't inspect request bodies, but gets hostname + timing visibility.
//!
//! ## CONNECT visibility limitations
//!
//! Each CONNECT request produces one event with `method: "CONNECT"` and
//! `path: "host:port"`. For HTTP/2 (which most APIs use), a single CONNECT
//! tunnel carries many multiplexed requests. The dashboard will show
//! "1 connection to api.github.com" rather than "50 requests to api.github.com."
//! Individual request-level visibility requires TLS termination (phase 2 —
//! deep observe mode with a local CA certificate).
//!
//! The forward proxy runs on the same TCP listener as the axum router.
//! CONNECT requests are handled at the TCP level; HTTP requests are routed
//! through hyper to either the forward proxy handler (absolute URIs) or the
//! existing axum router (path-prefix and internal endpoints).

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::config::provider_for_host;
use crate::events;
use crate::proxy::GatewayState;

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Returns true if the request is an HTTP forward-proxy request (absolute URI).
pub fn is_forward_proxy_request(method: &Method, uri: &Uri) -> bool {
    if *method == Method::CONNECT {
        return true;
    }
    // An absolute URI starts with a scheme (http://).
    // Axum normalizes the URI, but the scheme is preserved for proxy requests.
    uri.scheme().is_some()
}

/// Extract the hostname from a CONNECT target (host:port) or an absolute URI.
pub fn extract_target_host(method: &Method, uri: &Uri) -> Option<String> {
    if *method == Method::CONNECT {
        // CONNECT target is "host:port" in the URI authority.
        uri.authority()
            .map(|a| {
                let host = a.host();
                host.to_string()
            })
            .or_else(|| {
                // Fallback: parse the path as "host:port".
                let path = uri.path();
                path.split(':').next().map(|h| h.to_string())
            })
    } else {
        uri.host().map(|h| h.to_string())
    }
}

// ---------------------------------------------------------------------------
// HTTP forward proxy handler
// ---------------------------------------------------------------------------

/// Handle an HTTP forward proxy request (absolute-URI, not CONNECT).
///
/// Classifies the provider by hostname, evaluates platform policies (if any),
/// injects platform credentials, forwards the request, and logs an audit event.
pub async fn handle_forward_proxy(
    state: &Arc<GatewayState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let start = Instant::now();
    let learning_mode = state.is_learning_mode();

    let hostname = match extract_target_host(&method, &uri) {
        Some(h) => h,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "cannot determine target host"})),
            )
                .into_response();
        }
    };

    let provider = provider_for_host(&hostname);
    let path = uri.path().to_string();
    let query_string = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

    // Try to find adapter for this provider and parse operation + parameters.
    let adapter = state.adapter_registry.find_by_name(&provider);
    let (operation, parameters) = match &adapter {
        Some(a) => {
            let parsed = a.parse_request(method.as_str(), &path, &body);
            let op = if parsed.operation != "unknown" {
                Some(parsed.operation)
            } else {
                None
            };
            let params = if parsed.parameters.is_empty() {
                None
            } else {
                Some(parsed.parameters)
            };
            (op, params)
        }
        None => (None, None),
    };

    // Evaluate platform policy for this provider (if one exists).
    let policy_decision = {
        let platform = state.platform.read().unwrap();
        platform.policies.get(&provider).map(|evaluator| {
            let empty_params = std::collections::HashMap::new();
            let params_ref = parameters.as_ref().unwrap_or(&empty_params);
            evaluator.evaluate(
                method.as_str(),
                &path,
                operation.as_deref().unwrap_or(""),
                params_ref,
            )
        })
    };

    // If policy denies and we're in enforce mode, block the request.
    let (would_block, would_reason, policy_rule) = if let Some(ref decision) = policy_decision
        && !decision.allowed
    {
        if !learning_mode {
            // Enforce mode: block the request.
            let body_hash = events::hash_request_body(&body);
            let latency_ms = start.elapsed().as_millis() as u64;
            let mut event = events::Event {
                schema_version: events::SCHEMA_VERSION,
                timestamp: chrono::Utc::now().to_rfc3339(),
                session_id: state.session_id.clone(),
                provider: provider.clone(),
                method: method.to_string(),
                path: path.clone(),
                decision: "denied".to_string(),
                operation: operation.clone(),
                agent_type: state.agent_type.clone(),
                org_id: None,
                task_id: None,
                environment: state.environment.clone(),
                learning_mode: false,
                would_block: false,
                would_reason: None,
                parameters: parameters
                    .as_ref()
                    .and_then(|p| serde_json::to_value(p).ok()),
                request_body_hash: body_hash,
                mcp_tool_name: None,
                mcp_server: None,
                intersection_rules: None,
                policy_rule: Some(decision.matched_rule.clone()),
                response_status: Some(403),
                latency_ms: Some(latency_ms),
                credential_id: None,
                credential_ttl: None,
            };
            crate::proxy::enrich_event(&mut event, state, &provider, None);
            state.event_sender.send(event);

            eprintln!(
                "[proxy] {} {} {} → 403 denied: {} ({}ms)",
                method, hostname, path, decision.reason, latency_ms
            );

            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "error": "blocked by policy",
                    "reason": decision.reason,
                    "rule": decision.matched_rule,
                    "provider": provider,
                })),
            )
                .into_response();
        }
        // Observe mode: note would-block but continue forwarding.
        (
            true,
            Some(decision.reason.clone()),
            Some(decision.matched_rule.clone()),
        )
    } else {
        (false, None, None)
    };

    // Reconstruct the upstream URL.
    let scheme = uri.scheme_str().unwrap_or("http");
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or(&hostname);
    let upstream_url = format!("{}://{}{}{}", scheme, authority, path, query_string);

    // Look up platform credential for this provider.
    let platform_credential = state.platform_credential(&provider);

    // Build request to upstream.
    let client = &state.http_client;
    let mut req = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &upstream_url,
    );

    // Collect any extra hop-by-hop headers named in the Connection header.
    let connection_tokens: Vec<String> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|t| t.trim().to_lowercase()).collect())
        .unwrap_or_default();

    // Copy headers, stripping hop-by-hop headers per RFC 7230 §6.1.
    // If we have a platform credential, also skip the Authorization header
    // (we'll inject the platform credential instead).
    let has_platform_cred = platform_credential.is_some();
    for (key, value) in headers.iter() {
        let name = key.as_str().to_lowercase();
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        ) || connection_tokens.contains(&name)
        {
            continue;
        }
        // Skip auth headers when platform credential will be injected,
        // so agent secrets aren't leaked to the upstream.
        if has_platform_cred
            && matches!(
                name.as_str(),
                "authorization" | "x-api-key" | "api-key" | "x-auth-token"
            )
        {
            continue;
        }
        req = req.header(key.clone(), value.clone());
    }

    // Inject platform credential.
    let credential_id = if let Some(ref cred) = platform_credential {
        req = req.header("Authorization", format!("Bearer {}", cred));
        Some("platform_secret".to_string())
    } else {
        None
    };

    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    // Forward.
    let (response_status, response) = match req.send().await {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let mut builder = axum::http::Response::builder()
                .status(StatusCode::from_u16(status_code).unwrap_or(StatusCode::BAD_GATEWAY));

            // Collect response Connection tokens for hop-by-hop stripping.
            let resp_conn_tokens: Vec<String> = resp
                .headers()
                .get("connection")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').map(|t| t.trim().to_lowercase()).collect())
                .unwrap_or_default();

            for (key, value) in resp.headers().iter() {
                let name = key.as_str().to_lowercase();
                if matches!(
                    name.as_str(),
                    "connection"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "proxy-connection"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                        | "upgrade"
                ) || resp_conn_tokens.contains(&name)
                {
                    continue;
                }
                builder = builder.header(key.clone(), value.clone());
            }

            let resp_body = resp.bytes().await.unwrap_or_default();
            let axum_resp = builder
                .body(axum::body::Body::from(resp_body))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
                });
            (status_code, axum_resp)
        }
        Err(e) => {
            let resp = (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": format!("upstream error: {}", e)})),
            )
                .into_response();
            (502, resp)
        }
    };

    // Compute body hash for event.
    let body_hash = events::hash_request_body(&body);

    // Log audit event.
    let latency_ms = start.elapsed().as_millis() as u64;
    // In observe mode, even would-block requests are forwarded and logged as "allowed".
    // If the upstream send failed (502), log as "error" to match proxy.rs convention.
    let decision_str = if response_status == 502 {
        "error"
    } else {
        "allowed"
    };
    let mut event = events::Event {
        schema_version: events::SCHEMA_VERSION,
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: state.session_id.clone(),
        provider: provider.clone(),
        method: method.to_string(),
        path: path.clone(),
        decision: decision_str.to_string(),
        operation,
        agent_type: state.agent_type.clone(),
        org_id: None,
        task_id: None,
        environment: state.environment.clone(),
        learning_mode,
        would_block,
        would_reason,
        parameters: parameters
            .as_ref()
            .and_then(|p| serde_json::to_value(p).ok()),
        request_body_hash: body_hash,
        mcp_tool_name: None,
        mcp_server: None,
        intersection_rules: None,
        policy_rule,
        response_status: Some(response_status),
        latency_ms: Some(latency_ms),
        credential_id,
        credential_ttl: None,
    };

    crate::proxy::enrich_event(&mut event, state, &provider, None);
    state.event_sender.send(event);

    // Log to stderr.
    let block_note = if would_block { " [would_block]" } else { "" };
    let cred_note = if has_platform_cred {
        " [injected cred]"
    } else {
        ""
    };
    eprintln!(
        "[proxy] {} {} {} → {} ({}ms){}{}",
        method, hostname, path, response_status, latency_ms, block_note, cred_note
    );

    response
}

/// Parse "host:port" into (host, port). Defaults to port 443 if no port is
/// specified. Returns `Err` if a port is present but not a valid number.
fn parse_host_port(authority: &str) -> Result<(String, u16), String> {
    // Handle IPv6 bracket notation: [::1]:443
    if let Some(bracket_end) = authority.find(']') {
        let host = &authority[..=bracket_end];
        let port_part = &authority[bracket_end + 1..];
        let port = if let Some(p) = port_part.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| format!("invalid port in '{}'", authority))?
        } else {
            443
        };
        return Ok((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port in '{}'", authority))?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 443)),
    }
}

// ---------------------------------------------------------------------------
// Forward proxy TCP listener
// ---------------------------------------------------------------------------

/// Run the transparent forward proxy on the given port.
///
/// This is a raw TCP listener that:
/// 1. Peeks at the first bytes to determine if it's a CONNECT request
/// 2. For CONNECT: establishes a tunnel (bidirectional TCP copy)
/// 3. For HTTP: delegates to the axum router. The router handles both
///    path-prefix proxy requests and internal management endpoints.
///    Absolute-URI forward proxy requests are handled by the fallback.
pub async fn run_forward_proxy(
    state: Arc<GatewayState>,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    // Build the axum router for non-CONNECT requests.
    let router = crate::proxy::build_router(state.clone());

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let state = state.clone();
        let router = router.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, router, stream, peer_addr).await {
                eprintln!("[proxy] connection error from {}: {}", peer_addr, e);
            }
        });
    }
}

/// Handle a single incoming TCP connection.
///
/// Peeks at the first bytes to determine if it's a CONNECT request.
/// CONNECT gets a raw TCP tunnel; everything else is handled by hyper+axum.
async fn handle_connection(
    state: Arc<GatewayState>,
    router: axum::Router,
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    // Peek at the first bytes to detect CONNECT (non-destructive).
    let mut buf = [0u8; 8];
    let n = stream.peek(&mut buf).await?;
    let first_bytes = &buf[..n];

    if first_bytes.starts_with(b"CONNECT") {
        handle_connect_tunnel(state, stream, peer_addr).await
    } else {
        handle_http_on_stream(state, router, stream, peer_addr).await
    }
}

/// Handle a CONNECT tunnel directly at the TCP level.
///
/// Reads the CONNECT request line, connects to the upstream, sends back
/// "200 Connection established", then copies bytes bidirectionally.
async fn handle_connect_tunnel(
    state: Arc<GatewayState>,
    mut client: tokio::net::TcpStream,
    _peer_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let start = Instant::now();
    let learning_mode = state.is_learning_mode();

    // Read the CONNECT request line + headers (until blank line).
    // We read raw bytes to avoid BufReader buffering issues.
    let mut header_buf = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        use tokio::io::AsyncReadExt;
        let n = client.read(&mut one).await?;
        if n == 0 {
            return Ok(()); // Connection closed.
        }
        header_buf.push(one[0]);
        // Check for \r\n\r\n terminator.
        if header_buf.len() >= 4 && header_buf[header_buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
    }

    let header_str = String::from_utf8_lossy(&header_buf);
    let request_line = header_str.lines().next().unwrap_or("");

    // Parse: "CONNECT host:port HTTP/1.1"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    }
    let target = parts[1];
    let (hostname, port) = match parse_host_port(target) {
        Ok(hp) => hp,
        Err(e) => {
            eprintln!("[proxy] CONNECT bad target '{}': {}", target, e);
            client
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
            return Ok(());
        }
    };
    let provider = provider_for_host(&hostname);

    // Connect to upstream.
    let upstream_addr = format!("{}:{}", hostname, port);
    let upstream = match tokio::net::TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[proxy] CONNECT {} failed: {}", upstream_addr, e);
            let error_resp = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}\r\n", e);
            client.write_all(error_resp.as_bytes()).await?;

            // Log failure event.
            let mut event = events::Event {
                schema_version: events::SCHEMA_VERSION,
                timestamp: chrono::Utc::now().to_rfc3339(),
                session_id: state.session_id.clone(),
                provider: provider.clone(),
                method: "CONNECT".to_string(),
                path: format!("{}:{}", hostname, port),
                decision: "error".to_string(),
                operation: Some("connect".to_string()),
                agent_type: state.agent_type.clone(),
                org_id: None,
                task_id: None,
                environment: state.environment.clone(),
                learning_mode,
                would_block: false,
                would_reason: None,
                parameters: None,
                request_body_hash: None,
                mcp_tool_name: None,
                mcp_server: None,
                intersection_rules: None,
                policy_rule: None,
                response_status: Some(502),
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credential_id: None,
                credential_ttl: None,
            };
            crate::proxy::enrich_event(&mut event, &state, &provider, None);
            state.event_sender.send(event);
            return Ok(());
        }
    };

    let connect_ms = start.elapsed().as_millis() as u64;

    // Log success event.
    let mut event = events::Event {
        schema_version: events::SCHEMA_VERSION,
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: state.session_id.clone(),
        provider: provider.clone(),
        method: "CONNECT".to_string(),
        path: format!("{}:{}", hostname, port),
        decision: "allowed".to_string(),
        operation: Some("connect".to_string()),
        agent_type: state.agent_type.clone(),
        org_id: None,
        task_id: None,
        environment: state.environment.clone(),
        learning_mode,
        would_block: false,
        would_reason: None,
        parameters: None,
        request_body_hash: None,
        mcp_tool_name: None,
        mcp_server: None,
        intersection_rules: None,
        policy_rule: None,
        response_status: Some(200),
        latency_ms: Some(connect_ms),
        credential_id: None,
        credential_ttl: None,
    };
    crate::proxy::enrich_event(&mut event, &state, &provider, None);
    state.event_sender.send(event);

    eprintln!(
        "[proxy] CONNECT {} ({}) → tunnel ({}ms)",
        upstream_addr, provider, connect_ms
    );

    // Send 200 to client.
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;

    // Bidirectional tunnel — wait for both directions to finish.
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let c2u = tokio::io::copy(&mut client_read, &mut upstream_write);
    let u2c = tokio::io::copy(&mut upstream_read, &mut client_write);

    let (r1, r2) = tokio::join!(c2u, u2c);
    if let Err(e) = r1 {
        eprintln!("[proxy] tunnel c→u error: {}", e);
    }
    if let Err(e) = r2 {
        eprintln!("[proxy] tunnel u→c error: {}", e);
    }

    Ok(())
}

/// Handle an HTTP request by routing to either the forward proxy or the axum
/// router depending on whether the request has an absolute URI.
async fn handle_http_on_stream(
    state: Arc<GatewayState>,
    router: axum::Router,
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let io = TokioIo::new(stream);

    http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(
            io,
            service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let state = state.clone();
                let router = router.clone();
                let peer_addr = peer_addr;
                async move {
                    let is_absolute = req.uri().scheme().is_some();

                    if is_absolute {
                        // Forward-proxy request: absolute URI like
                        // "GET http://api.github.com/user"
                        let (parts, body) = req.into_parts();
                        use http_body_util::BodyExt;
                        let body_bytes = body
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();

                        let resp = handle_forward_proxy(
                            &state,
                            parts.method,
                            parts.uri,
                            parts.headers,
                            body_bytes,
                        )
                        .await;
                        Ok::<_, std::convert::Infallible>(resp)
                    } else {
                        // Path-prefix or internal request — delegate to axum.
                        // Inject ConnectInfo for the loopback check.
                        use axum::extract::connect_info::ConnectInfo;

                        let (mut parts, body) = req.into_parts();
                        parts.extensions.insert(ConnectInfo(peer_addr));
                        let axum_req = axum::http::Request::from_parts(parts, body);
                        use tower_service::Service;
                        let resp = router.into_service().call(axum_req).await;
                        match resp {
                            Ok(r) => Ok(r),
                            Err(e) => match e {},
                        }
                    }
                }
            }),
        )
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = parse_host_port("api.github.com:443").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_without_port() {
        let (host, port) = parse_host_port("api.github.com").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_custom_port() {
        let (host, port) = parse_host_port("localhost:8080").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:443").unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        assert!(parse_host_port("host:badport").is_err());
        assert!(parse_host_port("[::1]:notaport").is_err());
    }

    #[test]
    fn test_extract_target_host_connect() {
        let uri: Uri = "api.github.com:443".parse().unwrap();
        let host = extract_target_host(&Method::CONNECT, &uri);
        // CONNECT URIs may be parsed as path, so we test the fallback.
        assert!(host.is_some());
        assert!(host.unwrap().contains("api.github.com"));
    }

    #[test]
    fn test_extract_target_host_absolute_uri() {
        let uri: Uri = "http://api.github.com/user/repos".parse().unwrap();
        let host = extract_target_host(&Method::GET, &uri);
        assert_eq!(host, Some("api.github.com".to_string()));
    }

    #[test]
    fn test_is_forward_proxy_connect() {
        let uri: Uri = "api.github.com:443".parse().unwrap();
        assert!(is_forward_proxy_request(&Method::CONNECT, &uri));
    }

    #[test]
    fn test_is_forward_proxy_absolute_uri() {
        let uri: Uri = "http://api.github.com/user".parse().unwrap();
        assert!(is_forward_proxy_request(&Method::GET, &uri));
    }

    #[test]
    fn test_is_not_forward_proxy_relative_uri() {
        let uri: Uri = "/github/user".parse().unwrap();
        assert!(!is_forward_proxy_request(&Method::GET, &uri));
    }

    // -----------------------------------------------------------------------
    // Integration tests — spin up proxy + upstream, send real requests
    // -----------------------------------------------------------------------

    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::audit::AuditLogger;
    use crate::counter::CounterStore;
    use crate::events::{self, EventShipperConfig};
    use crate::harvester::Harvester;
    use crate::profiler::Profiler;
    use crate::proxy::{GatewayState, SessionInfo};

    /// Build a test GatewayState with no providers (forward proxy doesn't need them).
    fn make_forward_proxy_state() -> Arc<GatewayState> {
        let mut sp = HashMap::new();
        sp.insert(
            "__static__".to_string(),
            SessionInfo {
                providers: vec![],
                task_id: None,
            },
        );

        Arc::new(GatewayState {
            session_id: "test-fwd-proxy".to_string(),
            learning_mode: true,
            agent_type: Some("test".to_string()),
            environment: Some("test".to_string()),
            providers: std::sync::RwLock::new(HashMap::new()),
            session_providers: Mutex::new(sp),
            adapter_registry: crate::adapter::Registry::from_config(&HashMap::new()),
            audit: AuditLogger::new(Box::new(std::io::sink())),
            harvester: Harvester::new(),
            profiler: Profiler::new(),
            http_client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            event_sender: events::spawn_event_shipper(EventShipperConfig {
                control_plane_url: String::new(),
                ..Default::default()
            }),
            active_intersection_names: vec![],
            intersection_rules: vec![],
            counter_store: CounterStore::daily(),
            platform: std::sync::RwLock::new(crate::daemon_config::PlatformConfig::default()),
        })
    }

    /// Start a simple upstream HTTP server that echoes the request path as JSON.
    async fn start_upstream() -> (u16, tokio::task::JoinHandle<()>) {
        use axum::Json;
        use axum::routing::get;

        let app = axum::Router::new().fallback(get(|uri: Uri| async move {
            Json(serde_json::json!({
                "path": uri.path(),
                "ok": true,
            }))
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (port, handle)
    }

    /// Start the forward proxy on an ephemeral port.
    async fn start_proxy(state: Arc<GatewayState>) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            run_forward_proxy(state, listener).await.unwrap();
        });
        // Give the listener a moment to start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (port, handle)
    }

    #[tokio::test]
    async fn test_http_forward_proxy_request() {
        // Start an upstream HTTP server.
        let (upstream_port, _upstream) = start_upstream().await;

        // Start the forward proxy.
        let state = make_forward_proxy_state();
        let (proxy_port, _proxy) = start_proxy(state).await;

        // Send an HTTP forward-proxy request (absolute URI) through the proxy.
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy_port)).unwrap())
            .no_proxy() // Don't use system proxy
            .build()
            .unwrap();

        let resp = client
            .get(format!("http://127.0.0.1:{}/test/path", upstream_port))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["path"], "/test/path");
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn test_connect_tunnel_established() {
        // Start a plain TCP server that responds to anything.
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = tcp_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            loop {
                if let Ok((mut stream, _)) = tcp_listener.accept().await {
                    // Just send a greeting and close.
                    let _ = stream.write_all(b"HELLO\n").await;
                }
            }
        });

        // Start the forward proxy.
        let state = make_forward_proxy_state();
        let (proxy_port, _proxy) = start_proxy(state).await;

        // Send a CONNECT request manually via raw TCP.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        // Send CONNECT to the upstream TCP server.
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_port, upstream_port
        );
        stream.write_all(connect_req.as_bytes()).await.unwrap();

        // Read the 200 response.
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("200"),
            "Expected 200 response, got: {}",
            response
        );

        // The tunnel is established — read from the upstream.
        let mut data = vec![0u8; 64];
        let n = stream.read(&mut data).await.unwrap();
        let upstream_msg = String::from_utf8_lossy(&data[..n]);
        assert!(
            upstream_msg.contains("HELLO"),
            "Expected upstream data through tunnel, got: {}",
            upstream_msg
        );
    }

    #[tokio::test]
    async fn test_connect_to_unreachable_host_returns_502() {
        let state = make_forward_proxy_state();
        let (proxy_port, _proxy) = start_proxy(state).await;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        // CONNECT to a port that's definitely not listening.
        stream
            .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("502"),
            "Expected 502 for unreachable host, got: {}",
            response
        );
    }

    #[tokio::test]
    async fn test_path_prefix_request_through_forward_proxy() {
        // Path-prefix requests (relative URI like /github/user) should be handled
        // by the axum router, not the forward proxy. Verify they get routed.
        let state = make_forward_proxy_state();
        let (proxy_port, _proxy) = start_proxy(state).await;

        // Send a normal (non-proxy) HTTP request to the proxy's port.
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let resp = client
            .get(format!(
                "http://127.0.0.1:{}/internal/audit/stats",
                proxy_port
            ))
            .send()
            .await
            .unwrap();

        // Internal endpoints require loopback — since we're connecting from
        // 127.0.0.1, this should succeed (return JSON, not 404).
        assert_eq!(resp.status(), 200);
    }
}
