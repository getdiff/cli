//! HTTP proxy server for the Agent Capability Gateway.
//!
//! Intercepts agent requests, evaluates policy, injects credentials,
//! and forwards to upstream providers. Also serves internal management
//! API endpoints for audit, harvesting, profiling, and session management.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::adapter::{ParsedOperation, Registry};
use crate::audit::{AuditEvent, AuditFilter, AuditLogger};
use crate::config::{GatewayConfig, PolicyConfig};
use crate::counter::CounterStore;
use crate::events::{self, EventSender, EventShipperConfig};
use crate::harvester::Harvester;
use crate::intersection::{compute_intersections, merge_intersections, rules_from_config};
use crate::policy::PolicyEvaluator;
use crate::profiler::Profiler;

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
    /// Uses `RwLock` so proxy reads don't block each other — only session
    /// add/remove takes a write lock.
    pub providers: RwLock<HashMap<String, ProviderEntry>>,
    /// Tracks which providers were added by each dynamic session (session_id → provider names).
    /// Providers from the static YAML config are stored under the key `"__static__"`.
    pub session_providers: Mutex<HashMap<String, Vec<String>>>,
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
    /// Intersection rules from config, used to recompute when providers change.
    pub intersection_rules: Vec<crate::intersection::IntersectionRule>,
    /// In-memory counter store for aggregate policy limits (e.g. daily_limit_cents).
    pub counter_store: CounterStore,
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Load a config file and run the proxy. Called from the CLI entry point.
pub async fn run_proxy_from_file(config_path: &str, port: u16) -> anyhow::Result<()> {
    let config = crate::config::load(config_path)?;
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

    // Track which providers came from static config.
    let static_provider_names: Vec<String> = providers.keys().cloned().collect();
    let mut session_providers_map = HashMap::new();
    session_providers_map.insert("__static__".to_string(), static_provider_names);

    // Spawn the background event shipper.
    let control_plane_url = std::env::var("GATEWAY_CONTROL_PLANE_URL").unwrap_or_default();
    let api_token = read_api_token();

    if !control_plane_url.is_empty() && api_token.is_empty() {
        eprintln!(
            "[gateway] WARNING: GATEWAY_CONTROL_PLANE_URL is set but no API token found. \
             Event shipping will fail with 401. Run `getdiff login` or set DIFF_API_KEY."
        );
    }

    let event_sender = events::spawn_event_shipper(EventShipperConfig {
        control_plane_url: control_plane_url.clone(),
        api_token: api_token.clone(),
        ..Default::default()
    });

    // Register with the control plane.
    let daemon_id = events::get_or_create_daemon_id();
    if !control_plane_url.is_empty() && !api_token.is_empty() {
        let capabilities: Vec<String> = providers.keys().cloned().collect();
        let reg_url = control_plane_url.clone();
        let reg_token = api_token.clone();
        let reg_daemon = daemon_id.clone();
        let reg_caps = capabilities.clone();
        tokio::spawn(async move {
            if let Err(e) =
                register_daemon(&reg_url, &reg_token, &reg_daemon, &reg_caps).await
            {
                eprintln!("[gateway] daemon registration failed: {}", e);
            }
        });
    }

    let state = Arc::new(GatewayState {
        session_id: config.session.id.clone(),
        learning_mode: config.session.learning_mode,
        agent_type: config.session.agent_type.clone(),
        project_id: config.session.project_id.clone(),
        environment: config.session.environment.clone(),
        providers: RwLock::new(providers),
        session_providers: Mutex::new(session_providers_map),
        adapter_registry,
        audit: AuditLogger::new(Box::new(std::io::stderr())),
        harvester: Harvester::new(),
        profiler: Profiler::new(),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
        event_sender,
        active_intersection_names,
        intersection_rules,
        counter_store: CounterStore::daily(),
    });

    let app = build_router(state);

    let addr = format!("0.0.0.0:{}", port);
    eprintln!("gateway proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Middleware that restricts access to loopback addresses only.
/// Used for `/internal/*` endpoints that should not be reachable from
/// external clients.
async fn require_loopback(request: axum::extract::Request, next: Next) -> Response {
    let is_loopback = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);

    if !is_loopback {
        return error_json(
            StatusCode::FORBIDDEN,
            "internal endpoints are only accessible from localhost",
        );
    }

    next.run(request).await
}

/// Build the axum `Router` with internal management routes and a fallback
/// proxy handler.
pub fn build_router(state: Arc<GatewayState>) -> Router {
    // Internal management endpoints — restricted to loopback only.
    let internal_routes = Router::new()
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
        .layer(middleware::from_fn(require_loopback));

    Router::new()
        .merge(internal_routes)
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

    // Preserve query string for upstream forwarding.
    let query_string = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

    if provider_name.is_empty() {
        return error_json(StatusCode::NOT_FOUND, "no provider specified");
    }

    // 2. Parse the request through the adapter (outside lock — adapters are immutable).
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

    // 3. Look up provider entry (read lock — concurrent reads don't block).
    let (upstream, credential, decision) = {
        let providers = state.providers.read().unwrap();
        let entry = match providers.get(&provider_name) {
            Some(e) => e,
            None => {
                log_audit(AuditEntry {
                    state: &state,
                    start,
                    provider: &provider_name,
                    operation: "unknown",
                    method: method.as_str(),
                    path: &sub_path,
                    decision: "denied",
                    reason: "unknown provider",
                    matched_rule: "",
                    response_status: 404,
                    learning_mode: false,
                    would_block: false,
                    would_reason: "",
                    body_hash: None,
                    parameters: None,
                });
                return error_json(
                    StatusCode::NOT_FOUND,
                    &format!("unknown provider: {}", provider_name),
                );
            }
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

    // 5. Compute body hash and parameters for event shipping.
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

    // 7b. Check aggregate counter limits (e.g. daily_limit_cents).
    let decision = check_daily_limit(&state, &provider_name, &parsed.parameters, decision);

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

            let full_path = format!("{}{}", sub_path, query_string);
            let resp = forward_request(
                &state,
                &method,
                &upstream,
                &full_path,
                &headers,
                &body,
                &credential,
            )
            .await;

            let status_code = resp.as_ref().map(|r| r.status().as_u16()).unwrap_or(502) as i32;

            log_audit(AuditEntry {
                state: &state,
                start,
                provider: &provider_name,
                operation: &parsed.operation,
                method: method.as_str(),
                path: &sub_path,
                decision: "allowed",
                reason: "learning mode: forwarded despite policy denial",
                matched_rule: &decision.matched_rule,
                response_status: status_code,
                learning_mode: true,
                would_block: true,
                would_reason: &decision.reason,
                body_hash: body_hash.clone(),
                parameters: params_json.clone(),
            });

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

        log_audit(AuditEntry {
            state: &state,
            start,
            provider: &provider_name,
            operation: &parsed.operation,
            method: method.as_str(),
            path: &sub_path,
            decision: "denied",
            reason: &decision.reason,
            matched_rule: &decision.matched_rule,
            response_status: 403,
            learning_mode: state.learning_mode,
            would_block: false,
            would_reason: "",
            body_hash: body_hash.clone(),
            parameters: params_json.clone(),
        });

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
    let full_path = format!("{}{}", sub_path, query_string);
    let resp = forward_request(
        &state,
        &method,
        &upstream,
        &full_path,
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
            log_audit(AuditEntry {
                state: &state,
                start,
                provider: &provider_name,
                operation: &parsed.operation,
                method: method.as_str(),
                path: &sub_path,
                decision: "allowed",
                reason: &decision.reason,
                matched_rule: &decision.matched_rule,
                response_status: status_code,
                learning_mode: state.learning_mode,
                would_block: false,
                would_reason: "",
                body_hash,
                parameters: params_json,
            });
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
            log_audit(AuditEntry {
                state: &state,
                start,
                provider: &provider_name,
                operation: &parsed.operation,
                method: method.as_str(),
                path: &sub_path,
                decision: "error",
                reason: "upstream error",
                matched_rule: "",
                response_status: 502,
                learning_mode: state.learning_mode,
                would_block: false,
                would_reason: "",
                body_hash,
                parameters: params_json,
            });
            error_json(StatusCode::BAD_GATEWAY, &msg)
        }
    }
}

/// Forward an HTTP request to the upstream provider, injecting credentials.
/// `sub_path` should include the query string if present (e.g., "/v1/charges?limit=10").
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
        let mut providers = state.providers.write().unwrap();

        // Collect the raw policies for the new providers.
        let mut new_policies: HashMap<String, PolicyConfig> = HashMap::new();
        let mut new_entries: HashMap<String, (String, String)> = HashMap::new();
        let mut added_names: Vec<String> = Vec::new();

        for (name, pcfg) in session_providers {
            let policy = pcfg.policy.unwrap_or_default();
            new_policies.insert(name.clone(), policy);
            added_names.push(name.clone());
            new_entries.insert(
                name,
                (
                    pcfg.upstream.unwrap_or_default(),
                    pcfg.credential.unwrap_or_default(),
                ),
            );
        }

        // Build the full set of base policies (existing + new) for intersection computation.
        let mut all_policies: HashMap<String, PolicyConfig> = HashMap::new();
        for (name, entry) in providers.iter() {
            all_policies.insert(name.clone(), entry.evaluator.config().clone());
        }
        for (name, policy) in &new_policies {
            all_policies.insert(name.clone(), policy.clone());
        }

        // Recompute intersections across the full provider set.
        let provider_names: Vec<String> = all_policies.keys().cloned().collect();
        let active_intersections =
            compute_intersections(&provider_names, &state.intersection_rules);
        let merged = merge_intersections(&all_policies, &active_intersections);

        // Insert new providers with merged policies.
        for (name, (upstream, credential)) in new_entries {
            let policy = merged.get(&name).cloned().unwrap_or_default();
            let evaluator = PolicyEvaluator::new(policy);
            providers.insert(
                name,
                ProviderEntry {
                    upstream,
                    credential,
                    evaluator,
                },
            );
        }

        // Collect names of newly added providers so we can skip them below.
        let new_names: std::collections::HashSet<String> = new_policies.keys().cloned().collect();

        // Update existing providers whose policies may have changed due to new intersections.
        for (name, entry) in providers.iter_mut() {
            if let Some(merged_policy) = merged.get(name)
                && !new_names.contains(name)
            {
                *entry = ProviderEntry {
                    upstream: entry.upstream.clone(),
                    credential: entry.credential.clone(),
                    evaluator: PolicyEvaluator::new(merged_policy.clone()),
                };
            }
        }

        // Track which providers belong to this session.
        let mut sp = state.session_providers.lock().unwrap();
        sp.insert(req.session_id.clone(), added_names);
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "session_id": req.session_id })),
    )
}

/// DELETE /internal/sessions/{id} — remove a session and its providers.
///
/// Removes all providers that were added by the given session, then
/// recomputes intersection policies across the remaining provider set.
/// Providers from the static YAML config (tracked under `"__static__"`)
/// are never removed.
async fn handle_remove_session(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Look up which providers belong to this session.
    let provider_names = {
        let mut sp = state.session_providers.lock().unwrap();
        sp.remove(&id).unwrap_or_default()
    };

    if provider_names.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "not_found", "session_id": id })),
        );
    }

    // Remove the session's providers and recompute intersections.
    {
        let mut providers = state.providers.write().unwrap();

        for name in &provider_names {
            providers.remove(name);
        }

        // Recompute intersection policies for remaining providers.
        let mut all_policies: HashMap<String, PolicyConfig> = HashMap::new();
        for (name, entry) in providers.iter() {
            all_policies.insert(name.clone(), entry.evaluator.config().clone());
        }

        let remaining_names: Vec<String> = all_policies.keys().cloned().collect();
        let active_intersections =
            compute_intersections(&remaining_names, &state.intersection_rules);
        let merged = merge_intersections(&all_policies, &active_intersections);

        // Update existing providers with recomputed policies.
        for (name, entry) in providers.iter_mut() {
            if let Some(merged_policy) = merged.get(name) {
                *entry = ProviderEntry {
                    upstream: entry.upstream.clone(),
                    credential: entry.credential.clone(),
                    evaluator: PolicyEvaluator::new(merged_policy.clone()),
                };
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "session_id": id, "removed_providers": provider_names })),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a JSON error response with the given status code and message.
fn error_json(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Parameters for recording an audit event.
struct AuditEntry<'a> {
    state: &'a GatewayState,
    start: Instant,
    provider: &'a str,
    operation: &'a str,
    method: &'a str,
    path: &'a str,
    decision: &'a str,
    reason: &'a str,
    matched_rule: &'a str,
    response_status: i32,
    learning_mode: bool,
    would_block: bool,
    would_reason: &'a str,
    body_hash: Option<String>,
    parameters: Option<serde_json::Value>,
}

/// Record an audit event locally and ship to the control plane.
fn log_audit(entry: AuditEntry<'_>) {
    let latency_ms = entry.start.elapsed().as_millis() as u64;
    let audit_event = AuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: entry.state.session_id.clone(),
        provider: entry.provider.to_string(),
        operation: entry.operation.to_string(),
        method: entry.method.to_string(),
        path: entry.path.to_string(),
        decision: entry.decision.to_string(),
        reason: entry.reason.to_string(),
        matched_rule: entry.matched_rule.to_string(),
        response_status: Some(entry.response_status as u16),
        latency_ms: Some(latency_ms),
        learning_mode: entry.learning_mode,
        would_block: entry.would_block,
        would_reason: entry.would_reason.to_string(),
    };

    // Ship to control plane via event sender.
    let intersection_rules = if entry.state.active_intersection_names.is_empty() {
        None
    } else {
        Some(entry.state.active_intersection_names.clone())
    };
    let mut event = events::Event::from_audit(
        &audit_event,
        entry.body_hash,
        entry.parameters,
        intersection_rules,
    );
    event.agent_type = entry.state.agent_type.clone();
    event.project_id = entry.state.project_id.clone();
    event.environment = entry.state.environment.clone();

    // Promote mcp_tool_name from parsed parameters to top-level event field.
    if event.mcp_tool_name.is_none() {
        if let Some(params) = &event.parameters {
            if let Some(tool_name) = params.get("mcp_tool_name").and_then(|v| v.as_str()) {
                event.mcp_tool_name = Some(tool_name.to_string());
            }
        }
    }

    entry.state.event_sender.send(event);

    // Log locally.
    entry.state.audit.log(audit_event);
}

// ---------------------------------------------------------------------------
// Aggregate counter checks
// ---------------------------------------------------------------------------

/// If the provider has `daily_limit_cents` configured and the request contains
/// an `amount` parameter, check whether the daily aggregate would exceed the
/// limit. If so, override the decision to deny. On allowed requests, increment
/// the counter.
fn check_daily_limit(
    state: &GatewayState,
    provider: &str,
    params: &HashMap<String, serde_json::Value>,
    decision: crate::policy::Decision,
) -> crate::policy::Decision {
    // Only check if the request is currently allowed.
    if !decision.allowed {
        return decision;
    }

    // Look up the daily limit for this provider.
    let daily_limit = {
        let providers = state.providers.read().unwrap();
        providers
            .get(provider)
            .and_then(|e| e.evaluator.config().daily_limit_cents)
    };

    let daily_limit = match daily_limit {
        Some(limit) => limit,
        None => return decision, // No daily limit configured.
    };

    // Extract the amount from parameters.
    let amount = params
        .get("amount")
        .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)));

    let amount = match amount {
        Some(a) => a,
        None => return decision, // No amount in this request.
    };

    let counter_key = CounterStore::key(&state.session_id, provider, "daily_spend_cents");

    // Check: would adding this amount exceed the limit?
    let current = state.counter_store.get(&counter_key);
    if current + amount > daily_limit {
        return crate::policy::Decision {
            allowed: false,
            reason: format!(
                "daily spend {} + {} would exceed daily_limit_cents {}",
                current, amount, daily_limit
            ),
            matched_rule: "daily_limit_cents".to_string(),
        };
    }

    // Allowed — increment the counter.
    state.counter_store.increment(&counter_key, amount);
    decision
}

// ---------------------------------------------------------------------------
// API token resolution
// ---------------------------------------------------------------------------

/// Read the API token from the environment or the Diff config file.
/// Prefers `DIFF_API_KEY` env var, then falls back to `~/.config/diff/config.json`.
fn read_api_token() -> String {
    if let Ok(token) = std::env::var("DIFF_API_KEY") {
        if !token.is_empty() {
            return token;
        }
    }

    // Try reading from the config file (same path as auth.rs).
    let config_path = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("diff")
        .join("config.json");

    if let Ok(contents) = std::fs::read_to_string(&config_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(token) = json.get("token").and_then(|v| v.as_str()) {
                return token.to_string();
            }
        }
    }

    String::new()
}

// ---------------------------------------------------------------------------
// Daemon registration
// ---------------------------------------------------------------------------

/// Register this daemon with the control plane on startup.
/// Sends hostname, version, daemon_id, and provider capabilities.
async fn register_daemon(
    control_plane_url: &str,
    api_token: &str,
    daemon_id: &str,
    capabilities: &[String],
) -> Result<(), String> {
    let url = format!(
        "{}/v1/daemons/register",
        control_plane_url.trim_end_matches('/')
    );

    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let version = env!("CARGO_PKG_VERSION");

    let payload = json!({
        "daemon_id": daemon_id,
        "hostname": hostname,
        "version": version,
        "capabilities": capabilities,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client error: {}", e))?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("registration request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("registration failed: HTTP {}", resp.status()));
    }

    eprintln!(
        "[gateway] registered daemon {} (v{}) with {} capabilities",
        daemon_id,
        version,
        capabilities.len()
    );
    Ok(())
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

    // --- Dynamic session management tests ---

    fn make_test_state() -> Arc<GatewayState> {
        make_test_state_with_providers(HashMap::from([(
            "github".to_string(),
            ProviderEntry {
                upstream: "https://api.github.com".to_string(),
                credential: "ghp_test".to_string(),
                evaluator: PolicyEvaluator::new(PolicyConfig {
                    allowed_methods: vec!["GET".to_string()],
                    ..Default::default()
                }),
            },
        )]))
    }

    fn make_test_state_with_providers(
        providers: HashMap<String, ProviderEntry>,
    ) -> Arc<GatewayState> {
        let static_names: Vec<String> = providers.keys().cloned().collect();
        let mut session_providers_map = HashMap::new();
        session_providers_map.insert("__static__".to_string(), static_names);

        Arc::new(GatewayState {
            session_id: "test-session".to_string(),
            learning_mode: false,
            agent_type: None,
            project_id: None,
            environment: None,
            providers: RwLock::new(providers),
            session_providers: Mutex::new(session_providers_map),
            adapter_registry: Registry::from_config(&HashMap::new()),
            audit: AuditLogger::new(Box::new(std::io::sink())),
            harvester: Harvester::new(),
            profiler: Profiler::new(),
            http_client: reqwest::Client::new(),
            event_sender: events::spawn_event_shipper(events::EventShipperConfig {
                control_plane_url: String::new(),
                ..Default::default()
            }),
            active_intersection_names: vec![],
            intersection_rules: vec![],
            counter_store: CounterStore::daily(),
        })
    }

    #[tokio::test]
    async fn test_add_session_inserts_providers() {
        let state = make_test_state();

        let req = AddSessionRequest {
            session_id: "dyn-sess-1".to_string(),
            source_ip: None,
            providers: Some(HashMap::from([(
                "stripe".to_string(),
                SessionProviderConfig {
                    upstream: Some("https://api.stripe.com".to_string()),
                    credential: Some("sk_test".to_string()),
                    policy: Some(PolicyConfig {
                        blocked_methods: vec!["DELETE".to_string()],
                        ..Default::default()
                    }),
                },
            )])),
            expires_at: None,
        };

        let resp = handle_add_session(State(state.clone()), Json(req)).await;
        let (status, _body) = resp.into_response().into_parts();
        assert_eq!(status.status, StatusCode::OK);

        // Verify provider was added.
        let providers = state.providers.read().unwrap();
        assert!(providers.contains_key("stripe"));
        assert!(providers.contains_key("github")); // static still present

        // Verify session tracking.
        let sp = state.session_providers.lock().unwrap();
        assert_eq!(sp.get("dyn-sess-1").unwrap(), &vec!["stripe".to_string()]);
    }

    #[tokio::test]
    async fn test_remove_session_deletes_providers() {
        let state = make_test_state();

        // First add a session with a provider.
        let req = AddSessionRequest {
            session_id: "dyn-sess-2".to_string(),
            source_ip: None,
            providers: Some(HashMap::from([(
                "stripe".to_string(),
                SessionProviderConfig {
                    upstream: Some("https://api.stripe.com".to_string()),
                    credential: Some("sk_test".to_string()),
                    policy: None,
                },
            )])),
            expires_at: None,
        };
        handle_add_session(State(state.clone()), Json(req)).await;

        // Verify stripe is present.
        assert!(state.providers.read().unwrap().contains_key("stripe"));

        // Now remove the session.
        let resp =
            handle_remove_session(State(state.clone()), Path("dyn-sess-2".to_string())).await;
        let (status, _) = resp.into_response().into_parts();
        assert_eq!(status.status, StatusCode::OK);

        // Verify stripe was removed but github remains.
        let providers = state.providers.read().unwrap();
        assert!(!providers.contains_key("stripe"));
        assert!(providers.contains_key("github"));

        // Verify session tracking cleaned up.
        let sp = state.session_providers.lock().unwrap();
        assert!(!sp.contains_key("dyn-sess-2"));
    }

    #[tokio::test]
    async fn test_remove_unknown_session_returns_not_found() {
        let state = make_test_state();

        let resp =
            handle_remove_session(State(state.clone()), Path("nonexistent".to_string())).await;
        let (status, _) = resp.into_response().into_parts();
        assert_eq!(status.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_add_then_remove_multiple_sessions() {
        let state = make_test_state();

        // Add two sessions with different providers.
        let req1 = AddSessionRequest {
            session_id: "sess-a".to_string(),
            source_ip: None,
            providers: Some(HashMap::from([(
                "stripe".to_string(),
                SessionProviderConfig {
                    upstream: Some("https://api.stripe.com".to_string()),
                    credential: Some("sk_a".to_string()),
                    policy: None,
                },
            )])),
            expires_at: None,
        };
        let req2 = AddSessionRequest {
            session_id: "sess-b".to_string(),
            source_ip: None,
            providers: Some(HashMap::from([(
                "gmail".to_string(),
                SessionProviderConfig {
                    upstream: Some("https://gmail.googleapis.com".to_string()),
                    credential: Some("gmail_tok".to_string()),
                    policy: None,
                },
            )])),
            expires_at: None,
        };
        handle_add_session(State(state.clone()), Json(req1)).await;
        handle_add_session(State(state.clone()), Json(req2)).await;

        assert_eq!(state.providers.read().unwrap().len(), 3); // github + stripe + gmail

        // Remove sess-a (stripe).
        handle_remove_session(State(state.clone()), Path("sess-a".to_string())).await;
        {
            let providers = state.providers.read().unwrap();
            assert_eq!(providers.len(), 2);
            assert!(providers.contains_key("github"));
            assert!(providers.contains_key("gmail"));
            assert!(!providers.contains_key("stripe"));
        }

        // Remove sess-b (gmail).
        handle_remove_session(State(state.clone()), Path("sess-b".to_string())).await;
        {
            let providers = state.providers.read().unwrap();
            assert_eq!(providers.len(), 1);
            assert!(providers.contains_key("github"));
        }
    }

    // --- Counter-based daily limit tests ---

    #[tokio::test]
    async fn test_daily_limit_allows_within_budget() {
        let state = make_test_state_with_providers(HashMap::from([(
            "stripe".to_string(),
            ProviderEntry {
                upstream: "https://api.stripe.com".to_string(),
                credential: "sk_test".to_string(),
                evaluator: PolicyEvaluator::new(PolicyConfig {
                    daily_limit_cents: Some(10000),
                    ..Default::default()
                }),
            },
        )]));

        let params = HashMap::from([("amount".to_string(), serde_json::json!(3000))]);
        let allow = crate::policy::Decision {
            allowed: true,
            reason: "default allow".to_string(),
            matched_rule: String::new(),
        };

        let result = check_daily_limit(&state, "stripe", &params, allow);
        assert!(result.allowed);

        // Counter should have been incremented.
        let key = CounterStore::key("test-session", "stripe", "daily_spend_cents");
        assert_eq!(state.counter_store.get(&key), 3000);
    }

    #[tokio::test]
    async fn test_daily_limit_blocks_when_exceeded() {
        let state = make_test_state_with_providers(HashMap::from([(
            "stripe".to_string(),
            ProviderEntry {
                upstream: "https://api.stripe.com".to_string(),
                credential: "sk_test".to_string(),
                evaluator: PolicyEvaluator::new(PolicyConfig {
                    daily_limit_cents: Some(5000),
                    ..Default::default()
                }),
            },
        )]));

        let allow = crate::policy::Decision {
            allowed: true,
            reason: "default allow".to_string(),
            matched_rule: String::new(),
        };

        // First charge: 3000 (under limit)
        let params = HashMap::from([("amount".to_string(), serde_json::json!(3000))]);
        let result = check_daily_limit(&state, "stripe", &params, allow.clone());
        assert!(result.allowed);

        // Second charge: 3000 (would bring total to 6000 > 5000)
        let result = check_daily_limit(&state, "stripe", &params, allow);
        assert!(!result.allowed);
        assert!(result.reason.contains("daily_limit_cents"));
        assert_eq!(result.matched_rule, "daily_limit_cents");
    }

    #[tokio::test]
    async fn test_daily_limit_no_amount_passes_through() {
        let state = make_test_state_with_providers(HashMap::from([(
            "stripe".to_string(),
            ProviderEntry {
                upstream: "https://api.stripe.com".to_string(),
                credential: "sk_test".to_string(),
                evaluator: PolicyEvaluator::new(PolicyConfig {
                    daily_limit_cents: Some(5000),
                    ..Default::default()
                }),
            },
        )]));

        // No amount parameter — should pass through.
        let params = HashMap::new();
        let allow = crate::policy::Decision {
            allowed: true,
            reason: "default allow".to_string(),
            matched_rule: String::new(),
        };

        let result = check_daily_limit(&state, "stripe", &params, allow);
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_daily_limit_skips_already_denied() {
        let state = make_test_state_with_providers(HashMap::from([(
            "stripe".to_string(),
            ProviderEntry {
                upstream: "https://api.stripe.com".to_string(),
                credential: "sk_test".to_string(),
                evaluator: PolicyEvaluator::new(PolicyConfig {
                    daily_limit_cents: Some(5000),
                    ..Default::default()
                }),
            },
        )]));

        let params = HashMap::from([("amount".to_string(), serde_json::json!(100))]);
        let denied = crate::policy::Decision {
            allowed: false,
            reason: "blocked by other rule".to_string(),
            matched_rule: "blocked_methods".to_string(),
        };

        let result = check_daily_limit(&state, "stripe", &params, denied);
        assert!(!result.allowed);
        // Counter should NOT have been incremented.
        let key = CounterStore::key("test-session", "stripe", "daily_spend_cents");
        assert_eq!(state.counter_store.get(&key), 0);
    }
}
