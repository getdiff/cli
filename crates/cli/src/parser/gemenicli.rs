use anyhow::{Context, Result};
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
// Raw JSON types (what Gemini CLI writes to disk)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSession {
    session_id: Option<String>,
    #[allow(dead_code)]
    project_hash: Option<String>,
    #[allow(dead_code)]
    start_time: Option<String>,
    #[allow(dead_code)]
    last_updated: Option<String>,
    messages: Vec<RawMessage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMessage {
    #[allow(dead_code)]
    id: Option<String>,
    timestamp: Option<String>,
    #[serde(rename = "type")]
    msg_type: String,
    content: Option<Value>,
    thoughts: Option<Vec<RawThought>>,
    tokens: Option<RawTokens>,
    model: Option<String>,
    tool_calls: Option<Vec<RawToolCall>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawThought {
    subject: Option<String>,
    description: Option<String>,
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawTokens {
    input: Option<u64>,
    output: Option<u64>,
    cached: Option<u64>,
    thoughts: Option<u64>,
    tool: Option<u64>,
    total: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawToolCall {
    id: Option<String>,
    name: Option<String>,
    args: Option<Value>,
    #[allow(dead_code)]
    result: Option<Value>,
    status: Option<String>,
    timestamp: Option<String>,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

pub fn default_sessions_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".gemini")
        .join("tmp"))
}

pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_sessions_dir()?,
    };

    if !root.exists() {
        anyhow::bail!("Gemini CLI tmp directory not found at {}", root.display());
    }

    let filename = format!("session-{}.json", session_id);

    // Search through ~/.gemini/tmp/*/chats/
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let chats_dir = entry.path().join("chats");
        if chats_dir.is_dir() {
            let candidate = chats_dir.join(&filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    anyhow::bail!("Session {} not found under {}", session_id, root.display())
}

pub fn discover_sessions(root_override: Option<&Path>) -> Result<Vec<(String, PathBuf)>> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_sessions_dir()?,
    };

    let mut sessions = Vec::new();
    if !root.exists() {
        return Ok(sessions);
    }

    // Walk ~/.gemini/tmp/*/chats/session-*.json
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let chats_dir = entry.path().join("chats");
        if !chats_dir.is_dir() {
            continue;
        }
        for file_entry in std::fs::read_dir(&chats_dir)? {
            let file_entry = file_entry?;
            let path = file_entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && let Some(id) = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|stem| stem.strip_prefix("session-"))
            {
                sessions.push((id.to_string(), path));
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

    let raw_session: RawSession = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from {}", session_path.display()))?;

    let mut messages: Vec<DiffMessage> = Vec::new();
    let mut tool_counts: HashMap<String, (u32, u32)> = HashMap::new();
    let mut files_modified: Vec<String> = Vec::new();
    let mut files_read: Vec<String> = Vec::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;
    let mut total_cache_read: u64 = 0;
    let total_cache_creation: u64 = 0;
    let mut first_timestamp: Option<String> = None;
    let mut last_timestamp: Option<String> = None;
    let mut primary_model: Option<String> = None;
    let mut model_counts: HashMap<String, u32> = HashMap::new();
    let mut message_index: u32 = 0;
    let mut api_latencies_ms: Vec<u32> = Vec::new();
    let mut tool_latencies_ms: Vec<u32> = Vec::new();
    let api_error_count: u32 = 0;
    let mut tool_error_count: u32 = 0;
    let mut tool_success_count: u32 = 0;
    let retry_count: u32 = 0;
    let mut previous_user_timestamp: Option<chrono::DateTime<chrono::Utc>> = None;

    let session_id = raw_session.session_id.unwrap_or_else(|| {
        session_path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("session-"))
            .unwrap_or_else(|| {
                session_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
            })
            .to_string()
    });

    for raw_msg in &raw_session.messages {
        // Track timestamps
        if let Some(ref ts) = raw_msg.timestamp {
            if first_timestamp.is_none() {
                first_timestamp = Some(ts.clone());
            }
            last_timestamp = Some(ts.clone());
        }

        match raw_msg.msg_type.as_str() {
            "user" => {
                let text = extract_user_text(&raw_msg.content, redactor);

                if let Some(ref ts) = raw_msg.timestamp {
                    previous_user_timestamp = chrono::DateTime::parse_from_rfc3339(ts)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc));
                }

                messages.push(DiffMessage {
                    index: message_index,
                    role: "user".to_string(),
                    timestamp: raw_msg.timestamp.clone(),
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
            "gemini" => {
                // Token economics
                if let Some(ref tokens) = raw_msg.tokens {
                    let inp = tokens.input.unwrap_or(0);
                    let out = tokens.output.unwrap_or(0);
                    let cr = tokens.cached.unwrap_or(0);
                    total_input_tokens += inp;
                    total_output_tokens += out;
                    total_cache_read += cr;
                }

                // Track model
                if let Some(ref model) = raw_msg.model {
                    *model_counts.entry(model.clone()).or_insert(0) += 1;
                }

                // API latency
                if let Some(ref ts) = raw_msg.timestamp
                    && let Ok(assistant_ts) = chrono::DateTime::parse_from_rfc3339(ts)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                    && let Some(user_ts) = previous_user_timestamp
                {
                    let latency_ms = (assistant_ts - user_ts).num_milliseconds();
                    if latency_ms >= 0 {
                        api_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                    }
                    previous_user_timestamp = None;
                }

                // Detect thinking
                let has_thinking = raw_msg
                    .thoughts
                    .as_ref()
                    .map(|t| !t.is_empty())
                    .unwrap_or(false);

                // Extract text content
                let text = extract_gemini_text(&raw_msg.content, redactor);

                // Extract tool calls
                let mut msg_tool_calls: Vec<ToolCall> = Vec::new();
                let mut msg_tool_results: Vec<ToolResult> = Vec::new();

                if let Some(ref tool_calls) = raw_msg.tool_calls {
                    for tc in tool_calls {
                        let tool_name = tc.name.as_deref().unwrap_or("unknown").to_string();
                        let tool_use_id = tc.id.as_deref().unwrap_or("").to_string();
                        let args = tc.args.clone().unwrap_or(Value::Null);

                        let input_summary = redactor.redact(&truncate(
                            &summarize_tool_input(&tool_name, &args),
                            INPUT_SUMMARY_MAX,
                        ));

                        track_file_access(&tool_name, &args, &mut files_modified, &mut files_read);

                        let entry = tool_counts.entry(tool_name.clone()).or_insert((0, 0));
                        entry.0 += 1;

                        let is_error = tc
                            .status
                            .as_deref()
                            .map(|s| s != "success")
                            .unwrap_or(false);

                        if is_error {
                            entry.1 += 1;
                            tool_error_count += 1;
                        } else {
                            tool_success_count += 1;
                        }

                        // Tool latency: from message timestamp to tool completion timestamp
                        if let Some(msg_ts) = &raw_msg.timestamp
                            && let Some(tool_ts_str) = &tc.timestamp
                            && let Ok(start) = chrono::DateTime::parse_from_rfc3339(msg_ts)
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                            && let Ok(end) = chrono::DateTime::parse_from_rfc3339(tool_ts_str)
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                        {
                            let latency_ms = (end - start).num_milliseconds();
                            if latency_ms >= 0 {
                                tool_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                            }
                        }

                        // Update last_timestamp from tool timestamp
                        if let Some(ref tool_ts) = tc.timestamp {
                            last_timestamp = Some(tool_ts.clone());
                        }

                        // Extract result summary for tool result
                        let output_summary = extract_tool_result_summary(tc, redactor);

                        msg_tool_calls.push(ToolCall {
                            tool_name: tool_name.clone(),
                            tool_use_id: tool_use_id.clone(),
                            input_summary,
                        });

                        msg_tool_results.push(ToolResult {
                            tool_use_id,
                            is_error,
                            output_summary,
                        });
                    }
                }

                let stop_reason = if !msg_tool_calls.is_empty() {
                    Some("tool_use".to_string())
                } else {
                    Some("end_turn".to_string())
                };

                messages.push(DiffMessage {
                    index: message_index,
                    role: "assistant".to_string(),
                    timestamp: raw_msg.timestamp.clone(),
                    text,
                    has_thinking,
                    tool_calls: msg_tool_calls,
                    tool_results: msg_tool_results,
                    input_tokens: raw_msg.tokens.as_ref().and_then(|t| t.input),
                    output_tokens: raw_msg.tokens.as_ref().and_then(|t| t.output),
                    cache_read_tokens: raw_msg.tokens.as_ref().and_then(|t| t.cached),
                    model: raw_msg.model.clone(),
                    stop_reason,
                });
                message_index += 1;
            }
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

    let duration_seconds = compute_duration(&first_timestamp, &last_timestamp);

    let tool_call_summaries: Vec<ToolCallSummary> = tool_counts
        .into_iter()
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

    let reliability_telemetry = if api_error_count == 0
        && tool_error_count == 0
        && tool_success_count == 0
        && retry_count == 0
        && api_latencies_ms.is_empty()
        && tool_latencies_ms.is_empty()
    {
        None
    } else {
        Some(ReliabilityTelemetry {
            api_error_count,
            tool_error_count,
            tool_success_count,
            retry_count,
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
        tool: "gemini".to_string(),
        tool_version: "unknown".to_string(),
        diff_cli_version: env!("CARGO_PKG_VERSION").to_string(),
        project_path: String::new(),
        repo_name: None,
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
        total_input_tokens,
        total_output_tokens,
        total_cache_read_tokens: total_cache_read,
        total_cache_creation_tokens: total_cache_creation,
        estimated_cost_usd: 0.0,
        auto_classification: None,
        files_modified,
        files_read,
        config_snapshot: None,
    })
}

// ---------------------------------------------------------------------------
// Content extraction helpers
// ---------------------------------------------------------------------------

/// Extract text from user messages: content is [{text: "..."}]
fn extract_user_text(content: &Option<Value>, redactor: &Redactor) -> Option<String> {
    let content = content.as_ref()?;
    let blocks = content.as_array()?;

    let text_parts: Vec<String> = blocks
        .iter()
        .filter_map(|block| {
            block
                .get("text")
                .and_then(|t| t.as_str())
                .map(|t| redactor.redact(t))
        })
        .collect();

    if text_parts.is_empty() {
        None
    } else {
        Some(truncate(&text_parts.join("\n"), TEXT_MAX))
    }
}

/// Extract text from gemini messages: content is a string
fn extract_gemini_text(content: &Option<Value>, redactor: &Redactor) -> Option<String> {
    let content = content.as_ref()?;
    let text = content.as_str()?;
    if text.is_empty() {
        return None;
    }
    Some(truncate(&redactor.redact(text), TEXT_MAX))
}

fn extract_tool_result_summary(tc: &RawToolCall, redactor: &Redactor) -> String {
    let Some(ref result) = tc.result else {
        return String::new();
    };

    let results = match result.as_array() {
        Some(arr) => arr,
        None => return String::new(),
    };

    let output_parts: Vec<String> = results
        .iter()
        .filter_map(|r| {
            r.get("functionResponse")
                .and_then(|fr| fr.get("response"))
                .and_then(|resp| resp.get("output"))
                .and_then(|o| o.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    let output = output_parts.join("\n");
    redactor.redact(&truncate(&output, OUTPUT_SUMMARY_MAX))
}

fn summarize_tool_input(tool_name: &str, args: &Value) -> String {
    match tool_name {
        "run_command" => args
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("(no command)")
            .to_string(),
        "read_file" => {
            let path = args
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Read {}", path)
        }
        "write_new_file" => {
            let path = args
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Write {}", path)
        }
        "edit_file" => {
            let path = args
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Edit {}", path)
        }
        "delete_file" => {
            let path = args
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Delete {}", path)
        }
        "grep_search" => {
            let pattern = args.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
            format!("Grep {}", pattern)
        }
        "list_directory" => {
            let dir = args.get("dir_path").and_then(|p| p.as_str()).unwrap_or("?");
            format!("List {}", dir)
        }
        "google_web_search" => {
            let query = args.get("query").and_then(|q| q.as_str()).unwrap_or("?");
            format!("Search {}", query)
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
    match tool_name {
        "edit_file" | "write_new_file" | "delete_file" => {
            if let Some(path) = args.get("file_path").and_then(|p| p.as_str()) {
                modified.push(path.to_string());
            }
        }
        "read_file" => {
            if let Some(path) = args.get("file_path").and_then(|p| p.as_str()) {
                read.push(path.to_string());
            }
        }
        "grep_search" | "list_directory" => {
            if let Some(path) = args.get("dir_path").and_then(|p| p.as_str()) {
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
