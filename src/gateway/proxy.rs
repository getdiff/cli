//! HTTP proxy server for the Agent Capability Gateway.
//!
//! Intercepts agent requests, evaluates policy, injects credentials,
//! and forwards to upstream providers. Also serves internal management
//! API endpoints for audit, harvesting, profiling, and session management.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::gateway::adapter::{ParsedOperation, Registry};
use crate::gateway::audit::{AuditEvent, AuditFilter, AuditLogger};
use crate::gateway::config::{GatewayConfig, PolicyConfig};
use crate::gateway::events::{self, EventSender, EventShipperConfig};
use crate::gateway::harvester::Harvester;
use crate::gateway::intersection::{compute_intersections, merge_intersections, rules_from_config};
use crate::gateway::policy::PolicyEvaluator;
use crate::gateway::profiler::Profiler;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Entry for a configured provider in the gateway state.
pub struct ProviderEntry {
    /// Base URL of the upstream provider (e.g. "http://localhost:9999/stripe").
    pub upstream: String,
    /// Managed credential to inject into upstream requests (may be empty).
    pub credential: String,
    /// Policy evaluator for this provider.
    pub evaluator: PolicyEvaluator,
}

/// Shared state available to all axum handlers.
pub struct GatewayState {
    /// Unique identifier for the gateway session.
    pub session_id: String,
    /// When true, requests that would be blocked are forwarded anyway (with logging).
    pub learning_mode: bool,
    /// Agent type for profiling (from config).
    pub agent_type: Option<String>,
    /// Project identifier (from config).
    pub project_id: Option<String>,
    /// Environment label (from config).
    pub environment: Option<String>,
    /// Per-provider configuration: upstream URL, credential, and policy evaluator.
    pub providers: Mutex<HashMap<String, ProviderEntry>>,
    /// Registry of provider adapters for parsing requests.
    pub adapter_registry: Registry,
    /// Structured audit logger.
    pub audit: AuditLogger,
    /// Credential harvester that observes credentials in transit.
    pub harvester: Harvester,
    /// Behavior profiler that tracks request patterns per session.
    pub profiler: Profiler,
    /// HTTP client used to forward requests upstream.
    pub http_client: reqwest::Client,
    /// Event sender for shipping audit events to the control plane.
    pub event_sender: EventSender,
    /// Names of active intersection rules (included in shipped events).
    pub active_intersection_names: Vec<String>,
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Load a config file and run the proxy. Called from the CLI entry point.
pub async fn run_proxy_from_file(config_path: &str, port: u16) -> anyhow::Result<()> {
    let config = crate::gateway::config::load(config_path)?;
    run_proxy(config, port).await
}

/// Build the gateway state from a `GatewayConfig`, then start the axum server
/// on the given port.
///
/// This function blocks until the server shuts down.
pub async fn run_proxy(config: GatewayConfig, port: u16) -> anyhow::Result<()> {
    // Build provider entries from config.
    let mut providers = HashMap::new();
    // Use config-driven adapters if any provider has an `adapter` block,
    // otherwise fall back to built-in adapters.
    let adapter_registry = Registry::from_config(&config.providers);

    // Convert intersection policy configs to rules.
    let intersection_rules = rules_from_config(&config.intersection_policies);

    // Collect provider names for intersection computation.
    let provider_names: Vec<String> = config.providers.keys().cloned().collect();

    // Compute active intersections.
    let active_intersections = compute_intersections(&provider_names, &intersection_rules);

    // Build per-provider base policies, then merge intersections.
    let mut base_policies: HashMap<String, PolicyConfig> = HashMap::new();
    for (name, provider_cfg) in &config.providers {
        base_policies.insert(name.clone(), provider_cfg.policies.clone());
    }
    let merged_policies = merge_intersections(&base_policies, &active_intersections);

    for (name, provider_cfg) in &config.providers {
        // Load credential from environment variable.
        let credential = std::env::var(&provider_cfg.credential.env_var).unwrap_or_default();

        let policy_cfg = merged_policies.get(name).cloned().unwrap_or_default();
        let evaluator = PolicyEvaluator::new(policy_cfg);

        let upstream = provider_cfg.upstream.clone();

        providers.insert(
            name.clone(),
            ProviderEntry {
                upstream,
                credential,
                evaluator,
            },
        );
    }

    // Collect active intersection rule names for event shipping.
    let active_intersection_names: Vec<String> = active_intersections
        .iter()
        .map(|ai| ai.rule.name.clone())
        .collect();

    // Spawn the background event shipper.
    let control_plane_url = std::env::var("GATEWAY_CONTROL_PLANE_URL").unwrap_or_default();
    let event_sender = events::spawn_event_shipper(EventShipperConfig {
        control_plane_url,
        ..Default::default()
    });

    let state = Arc::new(GatewayState {
        session_id: config.session.id.clone(),
        learning_mode: config.session.learning_mode,
        agent_type: config.session.agent_type.clone(),
        project_id: config.session.project_id.clone(),
        environment: config.session.environment.clone(),
        providers: Mutex::new(providers),
        adapter_registry,
        audit: AuditLogger::new(Box::new(std::io::stderr())),
        harvester: Harvester::new(),
        profiler: Profiler::new(),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
        event_sender,
        active_intersection_names,
    });

    let app = build_router(state);

    let addr = format!("0.0.0.0:{}", port);
    eprintln!("gateway proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the axum `Router` with internal management routes and a fallback
/// proxy handler.
pub fn build_router(state: Arc<GatewayState>) -> Router {
    Router::new()
        // Internal management endpoints.
        .route("/internal/audit", get(handle_audit_query))
        .route("/internal/audit/stats", get(handle_audit_stats))
        .route("/internal/harvested", get(handle_harvested))
        .route("/internal/harvested/stats", get(handle_harvested_stats))
        .route("/internal/profile/{session_id}", get(handle_profile))
        .route(
            "/internal/profile/{session_id}/suggest",
            get(handle_suggest),
        )
        .route("/internal/sessions", post(handle_add_session))
        .route("/internal/sessions/{id}", delete(handle_remove_session))
        // Everything else is a provider proxy request.
        .fallback(handle_proxy_request)
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Proxy request handler
// ---------------------------------------------------------------------------

/// Main proxy handler: extracts provider from path, evaluates policy,
/// optionally forwards to upstream, and logs an audit event.
async fn handle_proxy_request(
    State(state): State<Arc<GatewayState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let start = Instant::now();

    // 1. Extract provider name and sub-path from the URI.
    let path = uri.path();
    let trimmed = path.trim_start_matches('/');
    let (provider_name, sub_path) = match trimmed.split_once('/') {
        Some((prov, rest)) => (prov.to_string(), format!("/{}", rest)),
        None => (trimmed.to_string(), "/".to_string()),
    };

    if provider_name.is_empty() {
        return error_json(StatusCode::NOT_FOUND, "no provider specified");
    }

    // 2. Look up provider entry.
    let (upstream, credential, decision) = {
        let providers = state.providers.lock().unwrap();
        let entry = match providers.get(&provider_name) {
            Some(e) => e,
            None => {
                log_audit_event(
                    &state,
                    start,
                    &provider_name,
                    "unknown",
                    method.as_str(),
                    &sub_path,
                    "denied",
                    "unknown provider",
                    404,
                    false,
                    false,
                    "",
                );
                return error_json(
                    StatusCode::NOT_FOUND,
                    &format!("unknown provider: {}", provider_name),
                );
            }
        };

        // 3. Parse the request through the adapter.
        let adapter = state.adapter_registry.find_by_name(&provider_name);
        let parsed = match &adapter {
            Some(a) => a.parse_request(method.as_str(), &sub_path, &body),
            None => ParsedOperation {
                provider: provider_name.clone(),
                operation: "unknown".into(),
                method: method.to_string(),
                path: sub_path.clone(),
                parameters: HashMap::new(),
            },
        };

        // 4. Evaluate policy.
        let decision = entry.evaluator.evaluate(
            method.as_str(),
            &sub_path,
            &parsed.operation,
            &parsed.parameters,
        );

        (entry.upstream.clone(), entry.credential.clone(), decision)
    };

    // 5. Re-parse for harvester/profiler (outside lock).
    let adapter = state.adapter_registry.find_by_name(&provider_name);
    let parsed = match &adapter {
        Some(a) => a.parse_request(method.as_str(), &sub_path, &body),
        None => ParsedOperation {
            provider: provider_name.clone(),
            operation: "unknown".into(),
            method: method.to_string(),
            path: sub_path.clone(),
            parameters: HashMap::new(),
        },
    };

    // 6. Compute body hash and parameters for event shipping.
    let body_hash = events::hash_request_body(&body);
    let params_json = if parsed.parameters.is_empty() {
        None
    } else {
        Some(serde_json::to_value(&parsed.parameters).unwrap_or_default())
    };

    // 7. Observe credentials (harvesting).
    let header_map: HashMap<String, String> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
        .collect();
    state
        .harvester
        .observe(&provider_name, &header_map, uri.query().unwrap_or(""));

    // 8. Handle policy decision.
    if !decision.allowed {
        if state.learning_mode {
            // Learning mode: log would-block but forward anyway.
            state.profiler.record(
                &state.session_id,
                &provider_name,
                &parsed.operation,
                method.as_str(),
                &sub_path,
                "denied",
            );

            let resp = forward_request(
                &state,
                &method,
                &upstream,
                &sub_path,
                &headers,
                &body,
                &credential,
            )
            .await;

            let status_code = resp.as_ref().map(|r| r.status().as_u16()).unwrap_or(502) as i32;

            log_audit_event_with_body(
                &state,
                start,
                &provider_name,
                &parsed.operation,
                method.as_str(),
                &sub_path,
                "allowed",
                "learning mode: forwarded despite policy denial",
                status_code,
                true,
                true,
                &decision.reason,
                body_hash.clone(),
                params_json.clone(),
            );

            return match resp {
                Ok(r) => r,
                Err(msg) => error_json(StatusCode::BAD_GATEWAY, &msg),
            };
        }

        // Blocked.
        state.profiler.record(
            &state.session_id,
            &provider_name,
            &parsed.operation,
            method.as_str(),
            &sub_path,
            "denied",
        );

        log_audit_event_with_body(
            &state,
            start,
            &provider_name,
            &parsed.operation,
            method.as_str(),
            &sub_path,
            "denied",
            &decision.reason,
            403,
            state.learning_mode,
            false,
            "",
            body_hash.clone(),
            params_json.clone(),
        );

        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "blocked by policy",
                "reason": decision.reason,
                "rule": decision.matched_rule,
                "method": method.as_str(),
                "path": sub_path,
                "provider": provider_name,
            })),
        )
            .into_response();
    }

    // 9. Allowed — forward to upstream.
    let resp = forward_request(
        &state,
        &method,
        &upstream,
        &sub_path,
        &headers,
        &body,
        &credential,
    )
    .await;

    match resp {
        Ok(r) => {
            let status_code = r.status().as_u16() as i32;
            state.profiler.record(
                &state.session_id,
                &provider_name,
                &parsed.operation,
                method.as_str(),
                &sub_path,
                "allowed",
            );
            log_audit_event_with_body(
                &state,
                start,
                &provider_name,
                &parsed.operation,
                method.as_str(),
                &sub_path,
                "allowed",
                &decision.reason,
                status_code,
                state.learning_mode,
                false,
                "",
                body_hash,
                params_json,
            );
            r
        }
        Err(msg) => {
            state.profiler.record(
                &state.session_id,
                &provider_name,
                &parsed.operation,
                method.as_str(),
                &sub_path,
                "error",
            );
            log_audit_event_with_body(
                &state,
                start,
                &provider_name,
                &parsed.operation,
                method.as_str(),
                &sub_path,
                "error",
                "upstream error",
                502,
                state.learning_mode,
                false,
                "",
                body_hash,
                params_json,
            );
            error_json(StatusCode::BAD_GATEWAY, &msg)
        }
    }
}

/// Forward an HTTP request to the upstream provider, injecting credentials.
async fn forward_request(
    state: &GatewayState,
    method: &Method,
    upstream: &str,
    sub_path: &str,
    original_headers: &HeaderMap,
    body: &Bytes,
    credential: &str,
) -> Result<Response, String> {
    if upstream.is_empty() {
        return Err("no upstream configured".into());
    }

    let url = format!("{}{}", upstream, sub_path);

    let mut req = state
        .http_client
        .request(method.clone(), &url)
        .body(body.to_vec());

    // Copy relevant headers from the original request.
    for hdr_name in &["content-type", "accept", "user-agent"] {
        if let Some(val) = original_headers.get(*hdr_name) {
            req = req.header(*hdr_name, val.clone());
        }
    }

    // Inject credential.
    if !credential.is_empty() {
        // Use the adapter's inject_credential logic. For a generic approach,
        // set the Authorization header with a Bearer token.
        // The adapter registry can provide provider-specific injection, but
        // the common case is Bearer token in the Authorization header.
        req = req.header("Authorization", format!("Bearer {}", credential));
    } else {
        // No managed credential — pass through agent's credential headers.
        if let Some(auth) = original_headers.get("authorization") {
            req = req.header("Authorization", auth.clone());
        }
        for hdr_name in &["x-api-key", "api-key", "x-auth-token"] {
            if let Some(val) = original_headers.get(*hdr_name) {
                req = req.header(*hdr_name, val.clone());
            }
        }
    }

    let upstream_resp = req
        .send()
        .await
        .map_err(|e| format!("upstream error: {}", e))?;

    // Build axum response from the upstream response.
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = axum::http::Response::builder().status(status);

    // Copy response headers.
    for (key, value) in upstream_resp.headers().iter() {
        builder = builder.header(key.clone(), value.clone());
    }

    let resp_body = upstream_resp
        .bytes()
        .await
        .map_err(|e| format!("failed to read upstream body: {}", e))?;

    builder
        .body(axum::body::Body::from(resp_body))
        .map_err(|e| format!("failed to build response: {}", e))
}

// ---------------------------------------------------------------------------
// Internal API handlers
// ---------------------------------------------------------------------------

/// Query parameters for the audit query endpoint.
#[derive(Debug, Deserialize)]
struct AuditQueryParams {
    session: Option<String>,
    provider: Option<String>,
    decision: Option<String>,
    operation: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// GET /internal/audit — query audit events with optional filters.
async fn handle_audit_query(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<AuditQueryParams>,
) -> impl IntoResponse {
    let filter = AuditFilter {
        session_id: params.session.unwrap_or_default(),
        provider: params.provider.unwrap_or_default(),
        decision: params.decision.unwrap_or_default(),
        operation: params.operation.unwrap_or_default(),
        limit: params.limit.unwrap_or(0),
        offset: params.offset.unwrap_or(0),
    };
    let events = state.audit.query(&filter);
    Json(json!({ "events": events }))
}

/// GET /internal/audit/stats — aggregate audit statistics.
async fn handle_audit_stats(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    Json(state.audit.stats())
}

/// GET /internal/harvested — list observed credentials.
async fn handle_harvested(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    let credentials = state.harvester.list();
    Json(json!({ "credentials": credentials }))
}

/// GET /internal/harvested/stats — harvest statistics.
async fn handle_harvested_stats(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    Json(state.harvester.stats())
}

/// GET /internal/profile/{session_id} — get behavior profile for a session.
async fn handle_profile(
    State(state): State<Arc<GatewayState>>,
    Path(session_id): Path<String>,
) -> Response {
    match state.profiler.get_profile(&session_id) {
        Some(profile) => Json(profile).into_response(),
        None => error_json(StatusCode::NOT_FOUND, "no profile found for session"),
    }
}

/// GET /internal/profile/{session_id}/suggest — get policy suggestions.
async fn handle_suggest(
    State(state): State<Arc<GatewayState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let suggestions = state.profiler.suggest_policies(&session_id);
    Json(json!({
        "session_id": session_id,
        "suggestions": suggestions,
    }))
}

/// POST body for adding a dynamic session.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct AddSessionRequest {
    session_id: String,
    source_ip: Option<String>,
    providers: Option<HashMap<String, SessionProviderConfig>>,
    expires_at: Option<String>,
}

/// Provider configuration within a dynamic session.
#[derive(Debug, Deserialize)]
struct SessionProviderConfig {
    upstream: Option<String>,
    credential: Option<String>,
    policy: Option<PolicyConfig>,
}

/// POST /internal/sessions — add a dynamic session from the control plane.
async fn handle_add_session(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<AddSessionRequest>,
) -> impl IntoResponse {
    // Register each provider from the session into the provider map.
    if let Some(session_providers) = req.providers {
        let mut providers = state.providers.lock().unwrap();
        for (name, pcfg) in session_providers {
            let evaluator = if let Some(policy) = pcfg.policy {
                PolicyEvaluator::new(policy)
            } else {
                PolicyEvaluator::new(PolicyConfig::default())
            };
            providers.insert(
                name,
                ProviderEntry {
                    upstream: pcfg.upstream.unwrap_or_default(),
                    credential: pcfg.credential.unwrap_or_default(),
                    evaluator,
                },
            );
        }
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "session_id": req.session_id })),
    )
}

/// DELETE /internal/sessions/{id} — remove a session.
async fn handle_remove_session(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // In a full implementation we would track which providers belong to which
    // session and remove them. For now, acknowledge the removal.
    let _ = &id;
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a JSON error response with the given status code and message.
fn error_json(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Record an audit event.
fn log_audit_event(
    state: &GatewayState,
    start: Instant,
    provider: &str,
    operation: &str,
    method: &str,
    path: &str,
    decision: &str,
    reason: &str,
    response_status: i32,
    learning_mode: bool,
    would_block: bool,
    would_reason: &str,
) {
    log_audit_event_with_body(
        state,
        start,
        provider,
        operation,
        method,
        path,
        decision,
        reason,
        response_status,
        learning_mode,
        would_block,
        would_reason,
        None,
        None,
    );
}

fn log_audit_event_with_body(
    state: &GatewayState,
    start: Instant,
    provider: &str,
    operation: &str,
    method: &str,
    path: &str,
    decision: &str,
    reason: &str,
    response_status: i32,
    learning_mode: bool,
    would_block: bool,
    would_reason: &str,
    body_hash: Option<String>,
    parameters: Option<serde_json::Value>,
) {
    let latency_ms = start.elapsed().as_millis() as u64;
    let audit_event = AuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: state.session_id.clone(),
        provider: provider.to_string(),
        operation: operation.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        response_status: Some(response_status as u16),
        latency_ms: Some(latency_ms),
        learning_mode,
        would_block,
        would_reason: would_reason.to_string(),
    };

    // Ship to control plane via event sender.
    let intersection_rules = if state.active_intersection_names.is_empty() {
        None
    } else {
        Some(state.active_intersection_names.clone())
    };
    let mut event =
        events::Event::from_audit(&audit_event, body_hash, parameters, intersection_rules);
    event.agent_type = state.agent_type.clone();
    event.project_id = state.project_id.clone();
    event.environment = state.environment.clone();
    state.event_sender.send(event);

    // Log locally.
    state.audit.log(audit_event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_path_extraction() {
        // Simulate the path splitting logic.
        let path = "/github/user/repos";
        let trimmed = path.trim_start_matches('/');
        let (provider, sub_path) = match trimmed.split_once('/') {
            Some((p, rest)) => (p.to_string(), format!("/{}", rest)),
            None => (trimmed.to_string(), "/".to_string()),
        };
        assert_eq!(provider, "github");
        assert_eq!(sub_path, "/user/repos");
    }

    #[test]
    fn test_path_extraction_single_segment() {
        let path = "/stripe";
        let trimmed = path.trim_start_matches('/');
        let (provider, sub_path) = match trimmed.split_once('/') {
            Some((p, rest)) => (p.to_string(), format!("/{}", rest)),
            None => (trimmed.to_string(), "/".to_string()),
        };
        assert_eq!(provider, "stripe");
        assert_eq!(sub_path, "/");
    }

    #[test]
    fn test_path_extraction_empty() {
        let path = "/";
        let trimmed = path.trim_start_matches('/');
        assert!(trimmed.is_empty());
    }
}
