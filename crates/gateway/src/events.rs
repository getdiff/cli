//! Event shipping to the control plane.
//!
//! Buffers audit events and flushes them in batches to
//! `POST /v1/events` on the control plane. Flushes on either
//! a count threshold (100 events) or a time interval (5 seconds),
//! whichever comes first.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Wire types (match server schema)
// ---------------------------------------------------------------------------

/// Batch envelope sent to `POST /v1/events`.
#[derive(Debug, Clone, Serialize)]
pub struct EventBatch {
    pub schema_version: u32,
    pub daemon_id: String,
    pub events: Vec<Event>,
}

/// A single event in the batch. The 6 required fields are non-optional;
/// everything else is optional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    // --- Required fields ---
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub timestamp: String,
    pub session_id: String,
    pub provider: String,
    pub method: String,
    pub path: String,
    pub decision: String, // "allowed" or "denied"

    // --- Optional fields ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub learning_mode: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub would_block: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intersection_rules: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ttl: Option<u64>,
}

fn is_false(v: &bool) -> bool {
    !v
}

/// Current schema version for events. Used in both individual events and batch envelopes.
pub const SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Server response for a batch submission.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    pub accepted: usize,
    pub rejected: usize,
    #[serde(default)]
    pub errors: Vec<BatchError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchError {
    pub index: usize,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Daemon ID
// ---------------------------------------------------------------------------

const DAEMON_ID_FILE: &str = "gateway-daemon-id";

/// Returns a persistent daemon ID. Generated once on first run and stored
/// in `~/.config/diff/gateway-daemon-id`. Unique per daemon instance
/// (not per host), as recommended by the server team.
pub fn get_or_create_daemon_id() -> String {
    let config_dir = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("diff");
    get_or_create_daemon_id_in(&config_dir)
}

/// Implementation that accepts a directory, enabling tests to use a temp dir.
fn get_or_create_daemon_id_in(config_dir: &std::path::Path) -> String {
    let id_path = config_dir.join(DAEMON_ID_FILE);

    // Try to read existing ID.
    if let Ok(id) = std::fs::read_to_string(&id_path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    // Generate a new one: {hostname}-{random_suffix}
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let suffix = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let daemon_id = format!("{}-{}", hostname, suffix);

    // Persist it.
    let _ = std::fs::create_dir_all(config_dir);
    let _ = std::fs::write(&id_path, &daemon_id);

    daemon_id
}

// ---------------------------------------------------------------------------
// Request body hashing
// ---------------------------------------------------------------------------

/// Returns the SHA-256 hex digest of the given bytes.
/// Returns None if the body is empty.
pub fn hash_request_body(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(body);
    Some(format!("{:x}", hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Event sender (channel-based buffer + background flusher)
// ---------------------------------------------------------------------------

/// Handle for sending events from request handlers. Cheap to clone.
#[derive(Clone)]
pub struct EventSender {
    tx: mpsc::Sender<Event>,
}

impl EventSender {
    /// Queue an event for shipping. Non-blocking; drops the event if the
    /// channel buffer is full (back-pressure safety).
    pub fn send(&self, event: Event) {
        let _ = self.tx.try_send(event);
    }
}

/// Configuration for the event shipper.
pub struct EventShipperConfig {
    /// Control plane URL (e.g. "http://localhost:9090").
    pub control_plane_url: String,
    /// API token for authenticating with the control plane (Bearer token).
    pub api_token: String,
    /// Persistent daemon ID.
    pub daemon_id: String,
    /// Flush after this many buffered events.
    pub flush_count: usize,
    /// Flush after this duration even if the buffer isn't full.
    pub flush_interval: std::time::Duration,
}

impl Default for EventShipperConfig {
    fn default() -> Self {
        Self {
            control_plane_url: String::new(),
            api_token: String::new(),
            daemon_id: get_or_create_daemon_id(),
            flush_count: 100,
            flush_interval: std::time::Duration::from_secs(5),
        }
    }
}

/// Spawn the background event shipper. Returns an `EventSender` that
/// request handlers use to enqueue events.
///
/// If `control_plane_url` is empty, events are buffered but never shipped
/// (useful for standalone / demo mode — the events still flow through the
/// channel so the sender never blocks).
pub fn spawn_event_shipper(config: EventShipperConfig) -> EventSender {
    // Channel buffer: 2x flush_count gives headroom.
    let (tx, rx) = mpsc::channel::<Event>(config.flush_count * 2);

    tokio::spawn(shipper_loop(rx, config));

    EventSender { tx }
}

async fn shipper_loop(mut rx: mpsc::Receiver<Event>, config: EventShipperConfig) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let mut buffer: Vec<Event> = Vec::with_capacity(config.flush_count);
    // Deadline tracks the age of the oldest buffered event.
    let mut deadline: Option<tokio::time::Instant> = None;
    // Tracks consecutive flush failures. After 2 failures, drop the failed events.
    let mut consecutive_failures: u32 = 0;

    loop {
        // Determine how long to wait: if we have buffered events, wait until
        // the deadline; otherwise wait indefinitely for the next event.
        let recv_result = if let Some(dl) = deadline {
            tokio::select! {
                biased;
                result = rx.recv() => result,
                _ = tokio::time::sleep_until(dl) => None,
            }
        } else {
            // No deadline — block until an event arrives (or channel closes).
            // We distinguish "channel closed" from "deadline fired" below.
            rx.recv().await
        };

        // Check if the deadline fired (buffer non-empty but recv returned None
        // because the select picked the sleep branch, not because channel closed).
        let deadline_fired = deadline.is_some() && recv_result.is_none() && !rx.is_closed();

        match recv_result {
            Some(ev) => {
                buffer.push(ev);
                // Set deadline when buffer transitions from empty to non-empty.
                if deadline.is_none() {
                    deadline = Some(tokio::time::Instant::now() + config.flush_interval);
                }
                // Drain any additional events that are ready (non-blocking).
                while buffer.len() < config.flush_count {
                    match rx.try_recv() {
                        Ok(ev) => buffer.push(ev),
                        Err(_) => break,
                    }
                }
            }
            None if !deadline_fired => {
                // Channel closed — flush remaining and exit.
                if !buffer.is_empty() {
                    flush(&client, &config, &mut buffer).await;
                }
                return;
            }
            None => {
                // Deadline fired — fall through to flush check.
            }
        }

        // Flush if we hit the count threshold or the deadline fired with data.
        if buffer.len() >= config.flush_count || (deadline_fired && !buffer.is_empty()) {
            let pre_len = buffer.len();
            flush(&client, &config, &mut buffer).await;
            let post_len = buffer.len();
            deadline = None;

            if post_len > 0 && post_len == pre_len {
                // Nothing was sent — count as a failure.
                consecutive_failures += 1;
                if consecutive_failures >= 2 {
                    eprintln!(
                        "[gateway events] dropping {} events after 2 consecutive flush failures",
                        buffer.len()
                    );
                    buffer.clear();
                    consecutive_failures = 0;
                }
            } else {
                consecutive_failures = 0;
            }
        }
    }
}

/// Attempt to send buffered events to the control plane. Mutates `buffer`
/// in-place — successfully acknowledged events are removed. The caller
/// determines success by comparing buffer length before and after.
async fn flush(client: &reqwest::Client, config: &EventShipperConfig, buffer: &mut Vec<Event>) {
    if buffer.is_empty() {
        return;
    }

    // If no control plane URL, just drain the buffer silently.
    if config.control_plane_url.is_empty() {
        buffer.clear();
        return;
    }

    // Send in chunks of 1000 (server max batch size).
    // Only remove events that were successfully acknowledged by the server.
    let url = format!(
        "{}/v1/events",
        config.control_plane_url.trim_end_matches('/')
    );

    let mut sent = 0usize;
    for chunk in buffer.chunks(1000) {
        let batch = EventBatch {
            schema_version: SCHEMA_VERSION,
            daemon_id: config.daemon_id.clone(),
            events: chunk.to_vec(),
        };

        let mut req = client.post(&url).json(&batch);
        if !config.api_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", config.api_token));
        }
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<BatchResponse>().await {
                        Ok(body) => {
                            if body.rejected > 0 {
                                eprintln!(
                                    "[gateway events] batch: {} accepted, {} rejected",
                                    body.accepted, body.rejected
                                );
                                for err in &body.errors {
                                    eprintln!(
                                        "[gateway events]   event {}: {}",
                                        err.index, err.reason
                                    );
                                }
                            }
                            // Only count accepted events as sent.
                            sent += body.accepted;
                        }
                        Err(_) => {
                            // Could not parse response — keep events for retry.
                            break;
                        }
                    }
                } else {
                    eprintln!("[gateway events] flush failed: HTTP {}", resp.status());
                    break; // Stop sending; keep remaining events for retry.
                }
            }
            Err(e) => {
                eprintln!("[gateway events] flush error: {}", e);
                break; // Stop sending; keep remaining events for retry.
            }
        }
    }

    // Remove only the events that were acknowledged.
    if sent >= buffer.len() {
        buffer.clear();
    } else if sent > 0 {
        buffer.drain(..sent);
    }
}

// ---------------------------------------------------------------------------
// Conversion from AuditEvent
// ---------------------------------------------------------------------------

use crate::audit::AuditEvent;

impl Event {
    /// Convert from an internal `AuditEvent` plus additional context.
    pub fn from_audit(
        audit: &AuditEvent,
        body_hash: Option<String>,
        parameters: Option<serde_json::Value>,
        intersection_rules: Option<Vec<String>>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp: audit.timestamp.clone(),
            session_id: audit.session_id.clone(),
            provider: audit.provider.clone(),
            method: audit.method.clone(),
            path: audit.path.clone(),
            decision: audit.decision.clone(),
            operation: if audit.operation.is_empty() {
                None
            } else {
                Some(audit.operation.clone())
            },
            agent_type: None,
            org_id: None,
            task_id: None,
            environment: None,
            learning_mode: audit.learning_mode,
            would_block: audit.would_block,
            would_reason: if audit.would_reason.is_empty() {
                None
            } else {
                Some(audit.would_reason.clone())
            },
            parameters,
            request_body_hash: body_hash,
            mcp_tool_name: None,
            mcp_server: None,
            intersection_rules,
            policy_rule: if audit.matched_rule.is_empty() {
                None
            } else {
                Some(audit.matched_rule.clone())
            },
            response_status: audit.response_status,
            latency_ms: audit.latency_ms,
            credential_id: None,
            credential_ttl: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_id_generation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let id = get_or_create_daemon_id_in(tmp.path());
        assert!(!id.is_empty());
        assert!(id.contains('-'));
    }

    #[test]
    fn test_daemon_id_persistence() {
        let tmp = tempfile::TempDir::new().unwrap();
        let id1 = get_or_create_daemon_id_in(tmp.path());
        let id2 = get_or_create_daemon_id_in(tmp.path());
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_hash_request_body_empty() {
        assert_eq!(hash_request_body(b""), None);
    }

    #[test]
    fn test_hash_request_body() {
        let hash = hash_request_body(b"amount=3000&currency=usd").unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex
        // Same input → same hash
        assert_eq!(
            hash,
            hash_request_body(b"amount=3000&currency=usd").unwrap()
        );
    }

    #[test]
    fn test_hash_request_body_different_inputs() {
        let h1 = hash_request_body(b"hello").unwrap();
        let h2 = hash_request_body(b"world").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_event_batch_serialization() {
        let batch = EventBatch {
            schema_version: SCHEMA_VERSION,
            daemon_id: "test-host-abc123".to_string(),
            events: vec![Event {
                schema_version: SCHEMA_VERSION,
                timestamp: "2026-03-30T14:22:01.123Z".to_string(),
                session_id: "sess-a1b2c3".to_string(),
                provider: "github".to_string(),
                method: "GET".to_string(),
                path: "/user".to_string(),
                decision: "allowed".to_string(),
                operation: Some("get_user".to_string()),
                agent_type: None,
                org_id: None,
                task_id: None,
                environment: None,
                learning_mode: false,
                would_block: false,
                would_reason: None,
                parameters: None,
                request_body_hash: None,
                mcp_tool_name: None,
                mcp_server: None,
                intersection_rules: None,
                policy_rule: None,
                response_status: Some(200),
                latency_ms: Some(42),
                credential_id: None,
                credential_ttl: None,
            }],
        };

        let json = serde_json::to_value(&batch).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["daemon_id"], "test-host-abc123");
        assert_eq!(json["events"].as_array().unwrap().len(), 1);
        assert_eq!(json["events"][0]["provider"], "github");
        // Optional None fields should be absent.
        assert!(json["events"][0].get("agent_type").is_none());
        assert!(json["events"][0].get("mcp_tool_name").is_none());
    }

    #[test]
    fn test_event_from_audit() {
        let audit = AuditEvent {
            timestamp: "2026-03-30T14:22:01Z".to_string(),
            session_id: "sess-1".to_string(),
            provider: "stripe".to_string(),
            operation: "create_charge".to_string(),
            method: "POST".to_string(),
            path: "/v1/charges".to_string(),
            decision: "denied".to_string(),
            reason: "amount 3000 exceeds max_amount_cents 1000".to_string(),
            response_status: Some(403),
            latency_ms: Some(2),
            learning_mode: false,
            would_block: false,
            would_reason: String::new(),
            matched_rule: "max_amount_cents".to_string(),
        };

        let event = Event::from_audit(
            &audit,
            Some("abcdef1234".to_string()),
            Some(serde_json::json!({"amount": 3000, "currency": "usd"})),
            Some(vec!["payment-data-restriction".to_string()]),
        );

        assert_eq!(event.provider, "stripe");
        assert_eq!(event.decision, "denied");
        assert_eq!(event.operation, Some("create_charge".to_string()));
        assert_eq!(event.request_body_hash, Some("abcdef1234".to_string()));
        assert_eq!(event.policy_rule, Some("max_amount_cents".to_string()));
        assert_eq!(
            event.intersection_rules,
            Some(vec!["payment-data-restriction".to_string()])
        );
        assert!(event.parameters.is_some());
    }

    #[test]
    fn test_event_from_audit_learning_mode() {
        let audit = AuditEvent {
            timestamp: "2026-03-30T14:22:01Z".to_string(),
            session_id: "sess-1".to_string(),
            provider: "github".to_string(),
            operation: "create_issue".to_string(),
            method: "POST".to_string(),
            path: "/repos/octocat/test/issues".to_string(),
            decision: "allowed".to_string(),
            reason: String::new(),
            response_status: Some(201),
            latency_ms: Some(5),
            learning_mode: true,
            would_block: true,
            would_reason: "method POST is blocked".to_string(),
            matched_rule: String::new(),
        };

        let event = Event::from_audit(&audit, None, None, None);

        assert_eq!(event.decision, "allowed");
        assert!(event.learning_mode);
        assert!(event.would_block);
        assert_eq!(
            event.would_reason,
            Some("method POST is blocked".to_string())
        );
    }

    #[tokio::test]
    async fn test_event_sender_does_not_block() {
        let config = EventShipperConfig {
            control_plane_url: String::new(), // No server — events silently drained
            api_token: String::new(),
            daemon_id: "test-daemon".to_string(),
            flush_count: 10,
            flush_interval: std::time::Duration::from_millis(100),
        };

        let sender = spawn_event_shipper(config);

        // Send 50 events quickly — should not block or panic.
        for i in 0..50 {
            sender.send(Event {
                schema_version: SCHEMA_VERSION,
                timestamp: chrono::Utc::now().to_rfc3339(),
                session_id: "test".to_string(),
                provider: "github".to_string(),
                method: "GET".to_string(),
                path: format!("/test/{}", i),
                decision: "allowed".to_string(),
                operation: None,
                agent_type: None,
                org_id: None,
                task_id: None,
                environment: None,
                learning_mode: false,
                would_block: false,
                would_reason: None,
                parameters: None,
                request_body_hash: None,
                mcp_tool_name: None,
                mcp_server: None,
                intersection_rules: None,
                policy_rule: None,
                response_status: None,
                latency_ms: None,
                credential_id: None,
                credential_ttl: None,
            });
        }

        // Give the flusher time to drain.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    #[test]
    fn test_batch_response_deserialization() {
        let json = r#"{"accepted": 47, "rejected": 1, "errors": [{"index": 12, "reason": "provider is required"}]}"#;
        let resp: BatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.accepted, 47);
        assert_eq!(resp.rejected, 1);
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].index, 12);
    }
}
