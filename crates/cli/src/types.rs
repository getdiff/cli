use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The normalized session payload sent to the Diff API.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiffSession {
    // Identity
    pub session_id: String,
    pub org_id: String,
    pub engineer_id: String,
    pub machine_id: String,

    // Source
    pub tool: String, // "claude_code"
    pub tool_version: String,
    pub diff_cli_version: String,

    // Context
    pub project_path: String,
    pub repo_name: Option<String>,
    pub git_branch: Option<String>,
    pub primary_model: Option<String>,

    // Timeline
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub duration_seconds: Option<u64>,

    // Conversation
    pub messages: Vec<DiffMessage>,
    pub message_count: u32,
    pub user_message_count: u32,
    pub assistant_message_count: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_detector_version: Option<String>,

    // Tool Usage
    pub tool_calls: Vec<ToolCallSummary>,
    pub total_tool_calls: u32,

    // Runtime reliability telemetry (transport-agnostic; CLI now, OTEL later)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability_telemetry: Option<ReliabilityTelemetry>,

    // Economics
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_creation_tokens: u64,
    pub estimated_cost_usd: f64,

    // Claude Code's own classification (from usage-data/facets/)
    pub auto_classification: Option<AutoClassification>,

    // Files touched during session
    pub files_modified: Vec<String>,
    pub files_read: Vec<String>,

    // Optional configuration snapshot captured at session start
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_snapshot: Option<ConfigSnapshotPayload>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigSnapshotPayload {
    provider: String,
    snapshot: RedactedConfigSnapshot,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactedConfigSnapshot(serde_json::Value);

impl RedactedConfigSnapshot {
    pub fn new(redacted_json: serde_json::Value) -> Result<Self, &'static str> {
        if !redacted_json.is_object() {
            return Err("redacted snapshot must be a JSON object");
        }
        Ok(Self(redacted_json))
    }

    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    pub fn as_object_mut(&mut self) -> Option<&mut serde_json::Map<String, serde_json::Value>> {
        self.0.as_object_mut()
    }
}

impl ConfigSnapshotPayload {
    pub fn from_redacted(
        provider: impl Into<String>,
        redacted_json: serde_json::Value,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            provider: provider.into(),
            snapshot: RedactedConfigSnapshot::new(redacted_json)?,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn snapshot(&self) -> &serde_json::Value {
        self.snapshot.as_value()
    }

    pub fn snapshot_object_mut(
        &mut self,
    ) -> Option<&mut serde_json::Map<String, serde_json::Value>> {
        self.snapshot.as_object_mut()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiffMessage {
    pub index: u32,
    pub role: String, // "user" or "assistant"
    pub timestamp: Option<String>,

    // Content
    pub text: Option<String>,
    pub has_thinking: bool,

    // Tool calls (assistant messages)
    pub tool_calls: Vec<ToolCall>,

    // Tool results (user messages containing results)
    pub tool_results: Vec<ToolResult>,

    // Token economics (assistant only)
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub model: Option<String>,
    pub stop_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub tool_use_id: String,
    pub input_summary: String, // redacted, truncated
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub is_error: bool,
    pub output_summary: String, // redacted, truncated
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolCallSummary {
    pub tool_name: String,
    pub count: u32,
    pub error_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReliabilityTelemetry {
    pub api_error_count: u32,
    pub tool_error_count: u32,
    pub tool_success_count: u32,
    pub retry_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_api_latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_api_latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_tool_latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_tool_latency_ms: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutoClassification {
    pub underlying_goal: Option<String>,
    pub goal_categories: Option<HashMap<String, serde_json::Value>>,
    pub outcome: Option<String>,
    pub session_type: Option<String>,
    pub claude_helpfulness: Option<String>,
    pub brief_summary: Option<String>,
    pub friction_detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_session() -> DiffSession {
        DiffSession {
            session_id: "session_1".to_string(),
            org_id: "org_1".to_string(),
            engineer_id: "eng_1".to_string(),
            machine_id: "mac_1".to_string(),
            tool: "claude_code".to_string(),
            tool_version: "1.0.0".to_string(),
            diff_cli_version: "0.1.0".to_string(),
            project_path: "/tmp/repo".to_string(),
            repo_name: Some("repo".to_string()),
            git_branch: Some("main".to_string()),
            primary_model: Some("claude-sonnet".to_string()),
            started_at: Some("2026-03-01T00:00:00Z".to_string()),
            ended_at: Some("2026-03-01T00:01:00Z".to_string()),
            duration_seconds: Some(60),
            messages: vec![],
            message_count: 0,
            user_message_count: 0,
            assistant_message_count: 0,
            security_detector_version: None,
            tool_calls: vec![],
            total_tool_calls: 0,
            reliability_telemetry: None,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cache_read_tokens: 0,
            total_cache_creation_tokens: 0,
            estimated_cost_usd: 0.0,
            auto_classification: None,
            files_modified: vec![],
            files_read: vec![],
            config_snapshot: None,
        }
    }

    #[test]
    fn omits_config_snapshot_when_none() {
        let session = base_session();
        let json = serde_json::to_value(&session).expect("serialize session");

        assert!(json.get("config_snapshot").is_none());
    }

    #[test]
    fn serializes_config_snapshot_when_present() {
        let mut session = base_session();
        session.config_snapshot = Some(
            ConfigSnapshotPayload::from_redacted(
                "claude",
                serde_json::json!({
                    "system_prompt_hash": "sha256:abc",
                    "permission_mode": "allowlist"
                }),
            )
            .expect("valid redacted snapshot"),
        );

        let json = serde_json::to_value(&session).expect("serialize session");
        assert_eq!(json["config_snapshot"]["provider"], "claude");
        assert_eq!(
            json["config_snapshot"]["snapshot"]["permission_mode"],
            "allowlist"
        );
    }
}
