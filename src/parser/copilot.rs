use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::redact::Redactor;
use crate::types::*;

const INPUT_SUMMARY_MAX: usize = 500;
const OUTPUT_SUMMARY_MAX: usize = 1000;
const TEXT_MAX: usize = 5000;

// ---------------------------------------------------------------------------
// Raw JSONL line types (what Copilot writes to events.jsonl)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLine {
    #[serde(rename = "type")]
    line_type: String,
    #[allow(dead_code)]
    id: Option<String>,
    timestamp: Option<String>,
    #[allow(dead_code)]
    parent_id: Option<String>,
    data: Option<Value>,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

pub fn default_session_state_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".copilot")
        .join("session-state"))
}

pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_session_state_dir()?,
    };

    if !root.exists() {
        anyhow::bail!(
            "Copilot session-state directory not found at {}",
            root.display()
        );
    }

    let candidate = root.join(session_id).join("events.jsonl");
    if candidate.exists() {
        return Ok(candidate);
    }

    anyhow::bail!("Session {} not found under {}", session_id, root.display())
}

pub fn discover_sessions(root_override: Option<&Path>) -> Result<Vec<(String, PathBuf)>> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_session_state_dir()?,
    };

    let mut sessions = Vec::new();
    if !root.exists() {
        return Ok(sessions);
    }

    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let events_path = entry.path().join("events.jsonl");
        if events_path.exists() {
            if let Some(session_id) = entry.file_name().to_str() {
                sessions.push((session_id.to_string(), events_path));
            }
        }
    }

    sessions.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(sessions)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse_session(
    session_path: &Path,
    org_id: &str,
    engineer_id: &str,
    machine_id: &str,
    redactor: &Redactor,
) -> Result<DiffSession> {
    let content = std::fs::read_to_string(session_path)
        .with_context(|| format!("Failed to read {}", session_path.display()))?;

    let mut messages: Vec<DiffMessage> = Vec::new();
    let mut tool_counts: HashMap<String, (u32, u32)> = HashMap::new();
    let mut tool_use_id_to_name: HashMap<String, String> = HashMap::new();
    let mut tool_use_id_to_ts: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut files_modified: Vec<String> = Vec::new();
    let mut files_read: Vec<String> = Vec::new();
    let mut first_timestamp: Option<String> = None;
    let mut last_timestamp: Option<String> = None;
    let mut session_id = String::new();
    let mut project_path: Option<String> = None;
    let mut repo_name: Option<String> = None;
    let mut tool_version: Option<String> = None;
    let mut primary_model: Option<String> = None;
    let mut model_counts: HashMap<String, u32> = HashMap::new();
    let mut message_index: u32 = 0;
    let mut previous_user_timestamp: Option<DateTime<Utc>> = None;
    let mut api_latencies_ms: Vec<u32> = Vec::new();
    let mut tool_latencies_ms: Vec<u32> = Vec::new();
    let mut tool_error_count: u32 = 0;
    let mut tool_success_count: u32 = 0;
    let mut pending_has_thinking = false;

    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let raw: RawLine = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "Warning: skipping malformed JSONL at line {}: {}",
                    line_idx + 1,
                    e
                );
                continue;
            }
        };

        // Track timestamps
        if let Some(ref ts) = raw.timestamp {
            if first_timestamp.is_none() {
                first_timestamp = Some(ts.clone());
            }
            last_timestamp = Some(ts.clone());
        }

        let data = match raw.data.as_ref() {
            Some(d) => d,
            None => continue,
        };

        match raw.line_type.as_str() {
            "session.start" => {
                if let Some(id) = data.get("sessionId").and_then(|v| v.as_str()) {
                    session_id = id.to_string();
                }
                if let Some(cwd) = data
                    .get("context")
                    .and_then(|c| c.get("cwd"))
                    .and_then(|v| v.as_str())
                {
                    project_path = Some(cwd.to_string());
                    repo_name = Path::new(cwd)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string());
                }
                if let Some(version) = data.get("copilotVersion").and_then(|v| v.as_str()) {
                    tool_version = Some(version.to_string());
                }
            }
            "user.message" => {
                let text = data
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|t| redactor.redact(t))
                    .map(|t| truncate(&t, TEXT_MAX));

                if let Some(ref ts) = raw.timestamp {
                    previous_user_timestamp = DateTime::parse_from_rfc3339(ts)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc));
                }

                messages.push(DiffMessage {
                    index: message_index,
                    role: "user".to_string(),
                    timestamp: raw.timestamp.clone(),
                    text,
                    has_thinking: false,
                    tool_calls: vec![],
                    tool_results: vec![],
                    input_tokens: None,
                    output_tokens: None,
                    cache_read_tokens: None,
                    model: None,
                    stop_reason: None,
                });
                message_index += 1;
            }
            "assistant.message" => {
                let content_text = data.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let text = if content_text.is_empty() {
                    None
                } else {
                    Some(truncate(&redactor.redact(content_text), TEXT_MAX))
                };

                // Check for reasoning/thinking
                let has_thinking = pending_has_thinking
                    || data.get("reasoningText").is_some()
                    || data.get("reasoningOpaque").is_some();
                pending_has_thinking = false;

                // Extract tool calls from toolRequests
                let mut tool_calls_vec: Vec<ToolCall> = Vec::new();
                if let Some(requests) = data.get("toolRequests") {
                    let requests_arr = match requests {
                        Value::Array(arr) => Some(arr.clone()),
                        Value::String(s) => {
                            // Sometimes serialized as a Python-repr string; try JSON parse
                            serde_json::from_str::<Vec<Value>>(s).ok()
                        }
                        _ => None,
                    };

                    if let Some(arr) = requests_arr {
                        for req in &arr {
                            let tool_name = req
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown")
                                .to_string();

                            // Skip internal report_intent calls
                            if tool_name == "report_intent" {
                                continue;
                            }

                            let tool_call_id = req
                                .get("toolCallId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();

                            let args = req.get("arguments").cloned().unwrap_or(Value::Null);
                            let input_summary = redactor.redact(&truncate(
                                &summarize_tool_input(&tool_name, &args),
                                INPUT_SUMMARY_MAX,
                            ));

                            track_file_access(
                                &tool_name,
                                &args,
                                &mut files_modified,
                                &mut files_read,
                            );

                            let entry = tool_counts.entry(tool_name.clone()).or_insert((0, 0));
                            entry.0 += 1;
                            tool_use_id_to_name.insert(tool_call_id.clone(), tool_name.clone());
                            if let Some(ref ts) = raw.timestamp
                                && let Ok(tool_ts) = DateTime::parse_from_rfc3339(ts)
                                    .map(|dt| dt.with_timezone(&Utc))
                            {
                                tool_use_id_to_ts.insert(tool_call_id.clone(), tool_ts);
                            }

                            tool_calls_vec.push(ToolCall {
                                tool_name,
                                tool_use_id: tool_call_id,
                                input_summary,
                            });
                        }
                    }
                }

                // API latency (first assistant message after user)
                if let Some(ref ts) = raw.timestamp
                    && let Ok(assistant_ts) =
                        DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                    && let Some(user_ts) = previous_user_timestamp
                {
                    let latency_ms = (assistant_ts - user_ts).num_milliseconds();
                    if latency_ms >= 0 {
                        api_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                    }
                    // Only count the first assistant message per user message
                    previous_user_timestamp = None;
                }

                let stop_reason = if tool_calls_vec.is_empty() {
                    Some("end_turn".to_string())
                } else {
                    Some("tool_use".to_string())
                };

                messages.push(DiffMessage {
                    index: message_index,
                    role: "assistant".to_string(),
                    timestamp: raw.timestamp.clone(),
                    text,
                    has_thinking,
                    tool_calls: tool_calls_vec,
                    tool_results: vec![],
                    input_tokens: None,
                    output_tokens: data.get("outputTokens").and_then(|v| v.as_u64()),
                    cache_read_tokens: None,
                    model: None,
                    stop_reason,
                });
                message_index += 1;
            }
            "tool.execution_complete" => {
                let tool_call_id = data
                    .get("toolCallId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Skip report_intent results
                if tool_use_id_to_name
                    .get(&tool_call_id)
                    .map(|n| n == "report_intent")
                    .unwrap_or(false)
                {
                    continue;
                }

                let success = data
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let is_error = !success;

                // Track model
                if let Some(model) = data.get("model").and_then(|v| v.as_str()) {
                    *model_counts.entry(model.to_string()).or_insert(0) += 1;
                }

                // Extract result text
                let output = extract_result_text(data);
                let output_summary = redactor.redact(&truncate(&output, OUTPUT_SUMMARY_MAX));

                if is_error {
                    if let Some(name) = tool_use_id_to_name.get(&tool_call_id) {
                        let entry = tool_counts.entry(name.clone()).or_insert((0, 0));
                        entry.1 += 1;
                    }
                    tool_error_count += 1;
                } else {
                    tool_success_count += 1;
                }

                // Tool latency
                if let Some(ref ts) = raw.timestamp
                    && let Ok(result_ts) =
                        DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                    && let Some(start_ts) = tool_use_id_to_ts.get(&tool_call_id)
                {
                    let latency_ms = (result_ts - *start_ts).num_milliseconds();
                    if latency_ms >= 0 {
                        tool_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                    }
                }

                messages.push(DiffMessage {
                    index: message_index,
                    role: "user".to_string(),
                    timestamp: raw.timestamp.clone(),
                    text: None,
                    has_thinking: false,
                    tool_calls: vec![],
                    tool_results: vec![ToolResult {
                        tool_use_id: tool_call_id,
                        is_error,
                        output_summary,
                    }],
                    input_tokens: None,
                    output_tokens: None,
                    cache_read_tokens: None,
                    model: None,
                    stop_reason: None,
                });
                message_index += 1;
            }
            "tool.execution_start" => {
                let tool_call_id = data
                    .get("toolCallId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let tool_name = data
                    .get("toolName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                // Register the mapping even for start events (in case assistant.message
                // serialized toolRequests as a string and we couldn't parse it)
                if !tool_call_id.is_empty() {
                    tool_use_id_to_name
                        .entry(tool_call_id.to_string())
                        .or_insert_with(|| tool_name.to_string());
                    if let Some(ref ts) = raw.timestamp
                        && let Ok(tool_ts) =
                            DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                    {
                        tool_use_id_to_ts
                            .entry(tool_call_id.to_string())
                            .or_insert(tool_ts);
                    }
                }
            }
            // Skip: assistant.turn_start, assistant.turn_end
            _ => continue,
        }
    }

    // Determine primary model
    if !model_counts.is_empty() {
        primary_model = model_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(model, _)| model);
    }

    // If session_id is still empty, derive from path
    if session_id.is_empty() {
        session_id = session_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
    }

    let duration_seconds = compute_duration(&first_timestamp, &last_timestamp);

    let tool_call_summaries: Vec<ToolCallSummary> = tool_counts
        .into_iter()
        .filter(|(name, _)| name != "report_intent")
        .map(|(name, (count, error_count))| ToolCallSummary {
            tool_name: name,
            count,
            error_count,
        })
        .collect();

    let total_tool_calls: u32 = tool_call_summaries.iter().map(|t| t.count).sum();
    let user_count = messages.iter().filter(|m| m.role == "user").count() as u32;
    let assistant_count = messages.iter().filter(|m| m.role == "assistant").count() as u32;

    files_modified.sort();
    files_modified.dedup();
    files_read.sort();
    files_read.dedup();

    let reliability_telemetry = if tool_error_count == 0
        && tool_success_count == 0
        && api_latencies_ms.is_empty()
        && tool_latencies_ms.is_empty()
    {
        None
    } else {
        Some(ReliabilityTelemetry {
            api_error_count: 0,
            tool_error_count,
            tool_success_count,
            retry_count: 0,
            avg_api_latency_ms: summarize_mean(&api_latencies_ms),
            p95_api_latency_ms: summarize_p95(&api_latencies_ms),
            avg_tool_latency_ms: summarize_mean(&tool_latencies_ms),
            p95_tool_latency_ms: summarize_p95(&tool_latencies_ms),
        })
    };

    Ok(DiffSession {
        session_id,
        org_id: org_id.to_string(),
        engineer_id: engineer_id.to_string(),
        machine_id: machine_id.to_string(),
        tool: "copilot".to_string(),
        tool_version: tool_version.unwrap_or_else(|| "unknown".to_string()),
        diff_cli_version: env!("CARGO_PKG_VERSION").to_string(),
        project_path: project_path.unwrap_or_default(),
        repo_name,
        git_branch: None,
        primary_model,
        started_at: first_timestamp,
        ended_at: last_timestamp,
        duration_seconds,
        messages,
        message_count: message_index,
        user_message_count: user_count,
        assistant_message_count: assistant_count,
        security_detector_version: None,
        tool_calls: tool_call_summaries,
        total_tool_calls,
        reliability_telemetry,
        total_input_tokens: 0,
        total_output_tokens: 0,
        total_cache_read_tokens: 0,
        total_cache_creation_tokens: 0,
        estimated_cost_usd: 0.0,
        auto_classification: None,
        files_modified,
        files_read,
        config_snapshot: None,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_result_text(data: &Value) -> String {
    let result = match data.get("result") {
        Some(r) => r,
        None => return String::new(),
    };

    match result {
        Value::Object(obj) => obj
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        Value::String(s) => {
            // Sometimes result is a Python-repr string; try to extract content
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                parsed
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or(s)
                    .to_string()
            } else {
                s.clone()
            }
        }
        _ => String::new(),
    }
}

fn summarize_tool_input(tool_name: &str, args: &Value) -> String {
    match tool_name {
        "bash" => {
            let cmd = args
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("(no command)");
            let desc = args.get("description").and_then(|d| d.as_str());
            match desc {
                Some(d) => format!("{}: {}", cmd, d),
                None => cmd.to_string(),
            }
        }
        "view" => {
            let path = args.get("path").and_then(|p| p.as_str()).unwrap_or("?");
            format!("View {}", path)
        }
        "edit" | "insert" | "str_replace_editor" => {
            let path = args.get("path").and_then(|p| p.as_str()).unwrap_or("?");
            format!("Edit {}", path)
        }
        "web_fetch" => {
            let url = args.get("url").and_then(|u| u.as_str()).unwrap_or("?");
            format!("WebFetch: {}", url)
        }
        "web_search" => {
            let queries = args.get("search_queries");
            let objective = args
                .get("objective")
                .and_then(|o| o.as_str())
                .unwrap_or("?");
            if let Some(Value::Array(arr)) = queries {
                let q: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                format!("WebSearch: {}", q.join(", "))
            } else {
                format!("WebSearch: {}", objective)
            }
        }
        "grep" | "grep_search" => {
            let pattern = args.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
            format!("Grep {}", pattern)
        }
        _ => serde_json::to_string(args).unwrap_or_else(|_| "(unparseable)".to_string()),
    }
}

fn track_file_access(
    tool_name: &str,
    args: &Value,
    modified: &mut Vec<String>,
    read: &mut Vec<String>,
) {
    let file_path = args.get("path").and_then(|p| p.as_str());

    match tool_name {
        "edit" | "insert" | "str_replace_editor" => {
            if let Some(path) = file_path {
                modified.push(path.to_string());
            }
        }
        "view" => {
            if let Some(path) = file_path {
                read.push(path.to_string());
            }
        }
        _ => {}
    }
}

fn compute_duration(start: &Option<String>, end: &Option<String>) -> Option<u64> {
    let s = start.as_ref()?;
    let e = end.as_ref()?;
    let start_dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    let end_dt = chrono::DateTime::parse_from_rfc3339(e).ok()?;
    let dur = end_dt.signed_duration_since(start_dt);
    Some(dur.num_seconds().max(0) as u64)
}

fn summarize_mean(values: &[u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    let sum: u64 = values.iter().map(|v| *v as u64).sum();
    Some((sum / values.len() as u64) as u32)
}

fn summarize_p95(values: &[u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() as f64) * 0.95).ceil() as usize;
    let clamped = index.saturating_sub(1).min(sorted.len() - 1);
    sorted.get(clamped).copied()
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
