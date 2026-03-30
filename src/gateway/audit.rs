use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Represents a single auditable gateway action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    #[serde(rename = "session")]
    pub session_id: String,
    pub provider: String,
    pub operation: String,
    pub method: String,
    pub path: String,
    pub decision: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub learning_mode: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub would_block: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub would_reason: String,
    /// The matched policy rule identifier (e.g., "blocked_methods: POST").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub matched_rule: String,
}

fn is_false(v: &bool) -> bool {
    !v
}

/// Specifies criteria for querying in-memory audit events.
#[derive(Debug, Default)]
pub struct AuditFilter {
    pub session_id: String,
    pub provider: String,
    pub decision: String,
    pub operation: String,
    pub limit: usize,
    pub offset: usize,
}

/// Contains aggregate statistics about audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_events: usize,
    pub by_provider: HashMap<String, usize>,
    pub by_decision: HashMap<String, usize>,
    pub by_operation: HashMap<String, usize>,
    pub learning_blocks: usize,
}

/// Writes audit events as JSON lines and stores them in memory for querying.
/// Safe for concurrent use via interior mutex.
pub struct AuditLogger {
    inner: Mutex<AuditLoggerInner>,
}

struct AuditLoggerInner {
    writer: Box<dyn std::io::Write + Send>,
    events: Vec<AuditEvent>,
    max_events: usize,
}

impl AuditLogger {
    /// Creates an audit logger that writes JSON lines to the given writer.
    /// Events are also stored in memory (up to 10000) for querying.
    pub fn new(writer: Box<dyn std::io::Write + Send>) -> Self {
        Self {
            inner: Mutex::new(AuditLoggerInner {
                writer,
                events: Vec::new(),
                max_events: 10000,
            }),
        }
    }

    /// Creates an audit logger with a specified max in-memory event count.
    #[allow(dead_code)]
    pub fn with_capacity(writer: Box<dyn std::io::Write + Send>, max_events: usize) -> Self {
        let max_events = if max_events == 0 { 10000 } else { max_events };
        Self {
            inner: Mutex::new(AuditLoggerInner {
                writer,
                events: Vec::new(),
                max_events,
            }),
        }
    }

    /// Serializes the event as a single JSON line and writes it to the output.
    /// The event is also stored in memory for querying.
    pub fn log(&self, event: AuditEvent) {
        let data = match serde_json::to_vec(&event) {
            Ok(d) => d,
            Err(_) => return,
        };

        let mut inner = self.inner.lock().unwrap();

        // Store in memory for querying.
        if inner.events.len() >= inner.max_events {
            // Drop oldest events (shift by 10% to avoid constant shifting).
            let drop = std::cmp::max(inner.max_events / 10, 1);
            inner.events.drain(..drop);
        }
        inner.events.push(event);

        // Write JSON line.
        let _ = inner.writer.write_all(&data);
        let _ = inner.writer.write_all(b"\n");
    }

    /// Returns events matching the filter.
    pub fn query(&self, filter: &AuditFilter) -> Vec<AuditEvent> {
        let inner = self.inner.lock().unwrap();
        let mut results = Vec::new();
        let mut skipped = 0;

        for event in inner.events.iter().rev() {
            if !filter.session_id.is_empty() && event.session_id != filter.session_id {
                continue;
            }
            if !filter.provider.is_empty() && event.provider != filter.provider {
                continue;
            }
            if !filter.decision.is_empty() && event.decision != filter.decision {
                continue;
            }
            if !filter.operation.is_empty() && event.operation != filter.operation {
                continue;
            }
            if filter.offset > 0 && skipped < filter.offset {
                skipped += 1;
                continue;
            }
            results.push(event.clone());
            if filter.limit > 0 && results.len() >= filter.limit {
                break;
            }
        }

        results
    }

    /// Returns aggregate statistics about all in-memory events.
    pub fn stats(&self) -> AuditStats {
        let inner = self.inner.lock().unwrap();
        let mut stats = AuditStats {
            total_events: 0,
            by_provider: HashMap::new(),
            by_decision: HashMap::new(),
            by_operation: HashMap::new(),
            learning_blocks: 0,
        };

        for event in &inner.events {
            stats.total_events += 1;
            if !event.provider.is_empty() {
                *stats.by_provider.entry(event.provider.clone()).or_insert(0) += 1;
            }
            if !event.decision.is_empty() {
                *stats.by_decision.entry(event.decision.clone()).or_insert(0) += 1;
            }
            if !event.operation.is_empty() {
                *stats
                    .by_operation
                    .entry(event.operation.clone())
                    .or_insert(0) += 1;
            }
            if event.learning_mode && event.would_block {
                stats.learning_blocks += 1;
            }
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    fn new_event(session_id: &str, provider: &str, decision: &str, operation: &str) -> AuditEvent {
        AuditEvent {
            timestamp: String::new(),
            session_id: session_id.to_string(),
            provider: provider.to_string(),
            operation: operation.to_string(),
            method: String::new(),
            path: String::new(),
            decision: decision.to_string(),
            reason: String::new(),
            response_status: None,
            latency_ms: None,
            learning_mode: false,
            would_block: false,
            would_reason: String::new(),
            matched_rule: String::new(),
        }
    }

    #[test]
    fn test_log_writes_json_line() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = {
            let buf = Arc::clone(&buf);
            Box::new(WriterProxy(buf)) as Box<dyn std::io::Write + Send>
        };
        let logger = AuditLogger::new(writer);

        logger.log(AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            session_id: "sess-001".to_string(),
            provider: "github".to_string(),
            operation: "get_user".to_string(),
            method: "GET".to_string(),
            path: "/user".to_string(),
            decision: "allowed".to_string(),
            reason: "default allow".to_string(),
            response_status: None,
            latency_ms: None,
            learning_mode: false,
            would_block: false,
            would_reason: String::new(),
            matched_rule: String::new(),
        });

        let output = {
            let data = buf.lock().unwrap();
            String::from_utf8(data.clone()).unwrap()
        };
        assert!(output.ends_with('\n'));

        let event: AuditEvent = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event.provider, "github");
        assert_eq!(event.operation, "get_user");
        assert_eq!(event.session_id, "sess-001");
    }

    #[test]
    fn test_omits_empty_optional_fields() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = Box::new(WriterProxy(Arc::clone(&buf))) as Box<dyn std::io::Write + Send>;
        let logger = AuditLogger::new(writer);

        logger.log(AuditEvent {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            session_id: "sess-001".to_string(),
            provider: "github".to_string(),
            operation: "get_user".to_string(),
            method: "GET".to_string(),
            path: "/user".to_string(),
            decision: "denied".to_string(),
            reason: "blocked".to_string(),
            response_status: None,
            latency_ms: None,
            learning_mode: false,
            would_block: false,
            matched_rule: String::new(),
            would_reason: String::new(),
        });

        let output = {
            let data = buf.lock().unwrap();
            String::from_utf8(data.clone()).unwrap()
        };
        assert!(!output.contains("response_status"));
        assert!(!output.contains("latency_ms"));
    }

    #[test]
    fn test_query_by_session_id() {
        let logger = AuditLogger::new(Box::new(Cursor::new(Vec::new())));

        logger.log(new_event("sess-a", "github", "allowed", "get_user"));
        logger.log(new_event("sess-b", "stripe", "allowed", "list_charges"));
        logger.log(new_event("sess-a", "github", "denied", "create_issue"));

        let results = logger.query(&AuditFilter {
            session_id: "sess-a".to_string(),
            ..Default::default()
        });
        assert_eq!(results.len(), 2);
        for r in &results {
            assert_eq!(r.session_id, "sess-a");
        }
    }

    #[test]
    fn test_query_by_provider() {
        let logger = AuditLogger::new(Box::new(Cursor::new(Vec::new())));

        logger.log(new_event("sess-1", "github", "allowed", "get_user"));
        logger.log(new_event("sess-1", "stripe", "allowed", "list_charges"));
        logger.log(new_event("sess-1", "github", "denied", "create_issue"));

        let results = logger.query(&AuditFilter {
            provider: "stripe".to_string(),
            ..Default::default()
        });
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].provider, "stripe");
    }

    #[test]
    fn test_query_by_decision() {
        let logger = AuditLogger::new(Box::new(Cursor::new(Vec::new())));

        logger.log(new_event("sess-1", "github", "allowed", "get_user"));
        logger.log(new_event("sess-1", "github", "denied", "create_issue"));
        logger.log(new_event("sess-1", "stripe", "denied", "create_transfer"));

        let results = logger.query(&AuditFilter {
            decision: "denied".to_string(),
            ..Default::default()
        });
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_with_limit_and_offset() {
        let logger = AuditLogger::new(Box::new(Cursor::new(Vec::new())));

        for _ in 0..10 {
            logger.log(new_event("sess-1", "github", "allowed", "get_user"));
        }

        // Limit to 3.
        let results = logger.query(&AuditFilter {
            limit: 3,
            ..Default::default()
        });
        assert_eq!(results.len(), 3);

        // Offset 5, no limit (should get 5 remaining).
        let results = logger.query(&AuditFilter {
            offset: 5,
            ..Default::default()
        });
        assert_eq!(results.len(), 5);

        // Offset 8, limit 5 (should get 2 remaining).
        let results = logger.query(&AuditFilter {
            offset: 8,
            limit: 5,
            ..Default::default()
        });
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_stats_returns_correct_aggregates() {
        let logger = AuditLogger::new(Box::new(Cursor::new(Vec::new())));

        logger.log(new_event("", "github", "allowed", "get_user"));
        logger.log(new_event("", "github", "denied", "create_issue"));
        logger.log(new_event("", "stripe", "allowed", "list_charges"));
        logger.log(new_event("", "stripe", "allowed", "get_charge"));

        let stats = logger.stats();
        assert_eq!(stats.total_events, 4);
        assert_eq!(stats.by_provider["github"], 2);
        assert_eq!(stats.by_provider["stripe"], 2);
        assert_eq!(stats.by_decision["allowed"], 3);
        assert_eq!(stats.by_decision["denied"], 1);
    }

    #[test]
    fn test_stats_learning_blocks() {
        let logger = AuditLogger::new(Box::new(Cursor::new(Vec::new())));

        logger.log(AuditEvent {
            provider: "github".to_string(),
            decision: "allowed".to_string(),
            learning_mode: true,
            would_block: true,
            would_reason: "blocked method".to_string(),
            ..new_event("", "github", "allowed", "")
        });
        logger.log(AuditEvent {
            provider: "github".to_string(),
            decision: "allowed".to_string(),
            learning_mode: true,
            ..new_event("", "github", "allowed", "")
        });
        logger.log(new_event("", "stripe", "denied", ""));

        let stats = logger.stats();
        assert_eq!(stats.learning_blocks, 1);
    }

    #[test]
    fn test_thread_safety() {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = Box::new(WriterProxy(Arc::clone(&buf))) as Box<dyn std::io::Write + Send>;
        let logger = Arc::new(AuditLogger::new(writer));

        let mut handles = Vec::new();
        for _ in 0..100 {
            let logger = Arc::clone(&logger);
            handles.push(std::thread::spawn(move || {
                logger.log(AuditEvent {
                    timestamp: "2026-01-01T00:00:00Z".to_string(),
                    session_id: "sess-001".to_string(),
                    provider: "github".to_string(),
                    operation: "get_user".to_string(),
                    method: "GET".to_string(),
                    path: "/user".to_string(),
                    decision: "allowed".to_string(),
                    reason: "test".to_string(),
                    response_status: None,
                    latency_ms: None,
                    learning_mode: false,
                    would_block: false,
                    would_reason: String::new(),
                    matched_rule: String::new(),
                });
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let output = {
            let data = buf.lock().unwrap();
            String::from_utf8(data.clone()).unwrap()
        };
        let lines: Vec<&str> = output.trim().split('\n').collect();
        assert_eq!(lines.len(), 100);

        // Each line should be valid JSON.
        for line in &lines {
            let _: AuditEvent = serde_json::from_str(line).unwrap();
        }
    }

    /// A writer that wraps an Arc<Mutex<Vec<u8>>> for thread-safe testing.
    struct WriterProxy(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for WriterProxy {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut data = self.0.lock().unwrap();
            data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
