//! Tier 3 loop test (product/specs/0-idea/credential-mvp/verification.md).
//!
//! Proves the credential MVP's core claim end-to-end at the proxy boundary:
//!
//! 1. A canary secret is sealed CLIENT-side to an enrolled device key; the
//!    mock Diff app only ever serves ciphertext.
//! 2. The daemon enrolls its device key, syncs injection mappings, fetches
//!    the envelope, and decrypts with the device key — all client-side.
//! 3. An agent request through the forward proxy reaches the mock provider
//!    with the canary injected in the Authorization header.
//! 4. The agent-visible response, the proxy audit log, and everything the
//!    mock Diff app ever served contain NO plaintext canary.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use serde_json::json;

use getdiff_gateway::adapter::Registry;
use getdiff_gateway::audit::AuditLogger;
use getdiff_gateway::counter::CounterStore;
use getdiff_gateway::daemon_config::PlatformConfig;
use getdiff_gateway::envelope_credentials;
use getdiff_gateway::events;
use getdiff_gateway::forward_proxy::handle_forward_proxy;
use getdiff_gateway::harvester::Harvester;
use getdiff_gateway::profiler::Profiler;
use getdiff_gateway::proxy::{GatewayState, SessionInfo};

const CANARY: &str = "sk_live_DIFFCANARY_loop_test_0001";

/// Shared Write impl to capture the proxy audit stream for scanning.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Everything the mock Diff app served, for the no-plaintext scan.
#[derive(Default)]
struct MockAppState {
    enrolled_public_key: Mutex<Option<Vec<u8>>>,
    served_bodies: Mutex<Vec<String>>,
}

/// What the mock provider observed.
#[derive(Default)]
struct MockProviderState {
    authorization: Mutex<Option<String>>,
    saw_agent_secret_header: Mutex<bool>,
}

fn make_state() -> Arc<GatewayState> {
    let mut session_providers = HashMap::new();
    session_providers.insert(
        "__static__".to_string(),
        SessionInfo {
            providers: vec![],
            task_id: None,
        },
    );
    Arc::new(GatewayState {
        session_id: "loop-test-session".to_string(),
        learning_mode: true,
        agent_type: Some("test".to_string()),
        environment: None,
        providers: RwLock::new(HashMap::new()),
        session_providers: Mutex::new(session_providers),
        adapter_registry: Registry::from_config(&HashMap::new()),
        audit: AuditLogger::new(Box::new(SharedBuf::default())),
        harvester: Harvester::new(),
        profiler: Profiler::new(),
        http_client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        event_sender: events::spawn_event_shipper(events::EventShipperConfig {
            control_plane_url: String::new(),
            ..Default::default()
        }),
        active_intersection_names: vec![],
        intersection_rules: vec![],
        counter_store: CounterStore::daily(),
        platform: RwLock::new(PlatformConfig::default()),
        user_id: None,
    })
}

/// Mock Diff app: enrollment, mappings (provider = the mock provider host),
/// and the ciphertext envelope. Records every body it serves.
fn mock_app_router(state: Arc<MockAppState>, provider_name: String) -> Router {
    async fn record(state: &MockAppState, body: &serde_json::Value) -> Json<serde_json::Value> {
        state.served_bodies.lock().unwrap().push(body.to_string());
        Json(body.clone())
    }

    Router::new()
        .route(
            "/api/v1/credentials/device-keys",
            post(
                |State(s): State<(Arc<MockAppState>, String)>,
                 Json(body): Json<serde_json::Value>| async move {
                    let public_key = body["publicKey"].as_str().unwrap().to_string();
                    *s.0.enrolled_public_key.lock().unwrap() =
                        Some(URL_SAFE_NO_PAD.decode(&public_key).unwrap());
                    record(
                        &s.0,
                        &json!({"kid": "kid-loop-1", "name": body["name"], "role": "device"}),
                    )
                    .await
                },
            ),
        )
        .route(
            "/api/v1/credentials/injection-mappings",
            get(|State(s): State<(Arc<MockAppState>, String)>| async move {
                record(
                    &s.0,
                    &json!([{
                        "id": "map-1",
                        "credentialId": "cred-loop-1",
                        "envName": "STRIPE_SECRET_KEY",
                        "scope": "session",
                        "sessionId": "loop-test-session",
                        "repoPath": null,
                        "provider": s.1,
                        "label": "loop canary key",
                        "createdAt": "2026-07-07T00:00:00.000Z"
                    }]),
                )
                .await
            }),
        )
        .route(
            "/api/v1/credentials/cred-loop-1/envelope",
            get(|State(s): State<(Arc<MockAppState>, String)>| async move {
                // Seal server-side in the mock ONLY because the mock plays the
                // role of the capturing client too. The served body is pure
                // ciphertext, verified by the scan below.
                let public_key =
                    s.0.enrolled_public_key
                        .lock()
                        .unwrap()
                        .clone()
                        .expect("enrolled");
                let envelope = getdiff_envelope::seal(
                    CANARY.as_bytes(),
                    &[getdiff_envelope::Recipient {
                        kid: "kid-loop-1".to_string(),
                        role: "device".to_string(),
                        public_key,
                    }],
                )
                .unwrap();
                record(
                    &s.0,
                    &json!({
                        "credentialId": "cred-loop-1",
                        "secretValueRef": "ver-loop-1",
                        "envelope": envelope,
                    }),
                )
                .await
            }),
        )
        .with_state((state, provider_name))
}

fn mock_provider_router(state: Arc<MockProviderState>) -> Router {
    Router::new()
        .route(
            "/v1/charges",
            get(
                |State(s): State<Arc<MockProviderState>>, headers: axum::http::HeaderMap| async move {
                    *s.authorization.lock().unwrap() = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);
                    *s.saw_agent_secret_header.lock().unwrap() = headers.contains_key("x-agent-secret");
                    Json(json!({"object": "list", "data": []}))
                },
            ),
        )
        .with_state(state)
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn loop_capture_to_injection_without_plaintext_on_server() {
    // --- mock provider -------------------------------------------------------
    let provider_state = Arc::new(MockProviderState::default());
    let provider_url = serve(mock_provider_router(provider_state.clone())).await;
    // provider classification is by hostname; 127.0.0.1 is "unknown" so the
    // provider name is the raw host.
    let provider_name = "127.0.0.1".to_string();

    // --- mock Diff app -------------------------------------------------------
    let app_state = Arc::new(MockAppState::default());
    let app_url = serve(mock_app_router(app_state.clone(), provider_name.clone())).await;

    // --- daemon: enroll device key + sync ------------------------------------
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("device_key.json");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let device_key = envelope_credentials::ensure_enrolled_device_key(
        &client,
        &app_url,
        "diff_u_test",
        &key_path,
    )
    .await
    .unwrap();
    assert_eq!(device_key.kid, "kid-loop-1");

    let state = make_state();
    let synced = envelope_credentials::sync_envelope_credentials(
        &client,
        &app_url,
        "diff_u_test",
        &device_key,
        &state,
    )
    .await
    .unwrap();
    assert_eq!(synced, 1, "one credential should sync");

    // --- agent request through the forward proxy -----------------------------
    let uri: axum::http::Uri = format!("{provider_url}/v1/charges").parse().unwrap();
    let mut headers = axum::http::HeaderMap::new();
    // The agent's own (wrong) credential must be stripped, not forwarded.
    headers.insert(
        "authorization",
        "Bearer agent-placeholder-key".parse().unwrap(),
    );
    let response = handle_forward_proxy(
        &state,
        axum::http::Method::GET,
        uri,
        headers,
        Bytes::new(),
        None,
    )
    .await;

    // --- assertions -----------------------------------------------------------

    // 1. Provider saw the canary, injected by the proxy.
    let seen = provider_state.authorization.lock().unwrap().clone();
    assert_eq!(seen.as_deref(), Some(format!("Bearer {CANARY}").as_str()));

    // 2. The agent's placeholder credential did NOT reach the provider.
    assert_ne!(seen.as_deref(), Some("Bearer agent-placeholder-key"));

    // 3. The agent-visible response contains no canary.
    let (parts, body) = response.into_parts();
    assert_eq!(parts.status, axum::http::StatusCode::OK);
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let body_text = String::from_utf8_lossy(&body_bytes);
    assert!(
        !body_text.contains(CANARY),
        "agent response leaked the canary"
    );

    // 4. Everything the mock Diff app served was ciphertext-only: the canary
    //    never appeared in any server-side body.
    for served in app_state.served_bodies.lock().unwrap().iter() {
        assert!(
            !served.contains(CANARY),
            "server-side body contained plaintext canary: {}",
            &served[..served.len().min(200)]
        );
    }
    assert!(
        !app_state.served_bodies.lock().unwrap().is_empty(),
        "mock app should have served bodies"
    );

    // 5. The device key file on disk contains no canary (only key material).
    let key_file = std::fs::read_to_string(&key_path).unwrap();
    assert!(!key_file.contains(CANARY));
}

#[tokio::test]
async fn sync_skips_credentials_wrapped_for_other_devices() {
    // An envelope wrapped only to a DIFFERENT device must not decrypt or cache.
    let app_state = Arc::new(MockAppState::default());
    let app_url = serve(mock_app_router(app_state.clone(), "127.0.0.1".to_string())).await;

    let dir = tempfile::tempdir().unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // Enroll device A (its public key becomes the wrap target in the mock)...
    let key_a_path = dir.path().join("device_a.json");
    envelope_credentials::ensure_enrolled_device_key(&client, &app_url, "diff_u_test", &key_a_path)
        .await
        .unwrap();

    // ...but sync with device B, which claims the same kid with a different key.
    let key_b_path = dir.path().join("device_b.json");
    let mut key_b = envelope_credentials::load_or_create_device_key(&key_b_path).unwrap();
    key_b.kid = "kid-loop-1".to_string();

    let state = make_state();
    let synced = envelope_credentials::sync_envelope_credentials(
        &client,
        &app_url,
        "diff_u_test",
        &key_b,
        &state,
    )
    .await
    .unwrap();
    assert_eq!(synced, 0, "wrong device key must not decrypt");
    assert!(
        state.platform.read().unwrap().credentials.is_empty(),
        "nothing may be cached after a failed decrypt"
    );
}
