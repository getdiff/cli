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
// Raw JSONL line types (what OpenClaw writes to disk)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawLine {
    #[serde(rename = "type")]
    line_type: String,
    id: Option<String>,
    timestamp: Option<String>,
    // Session header fields
    #[allow(dead_code)]
    version: Option<u32>,
    cwd: Option<String>,
    // Message envelope
    message: Option<RawMessage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMessage {
    role: Option<String>,
    content: Option<Value>, // array of content blocks
    // Assistant-only fields
    model: Option<String>,
    usage: Option<RawUsage>,
    stop_reason: Option<String>,
    // Tool result fields
    tool_call_id: Option<String>,
    #[allow(dead_code)]
    tool_name: Option<String>,
    is_error: Option<bool>,
    details: Option<RawToolDetails>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUsage {
    input: Option<u64>,
    output: Option<u64>,
    cache_read: Option<u64>,
    cache_write: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawToolDetails {
    exit_code: Option<i32>,
    #[allow(dead_code)]
    duration_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

pub fn default_sessions_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".openclaw")
        .join("agents"))
}

pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_sessions_dir()?,
    };

    if !root.exists() {
        anyhow::bail!("OpenClaw agents directory not found at {}", root.display());
    }

    let filename = format!("{}.jsonl", session_id);

    // Search through ~/.openclaw/agents/*/sessions/
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let sessions_dir = entry.path().join("sessions");
        if sessions_dir.is_dir() {
            let candidate = sessions_dir.join(&filename);
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

    // Walk ~/.openclaw/agents/*/sessions/*.jsonl
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let sessions_dir = entry.path().join("sessions");
        if !sessions_dir.is_dir() {
            continue;
        }
        for file_entry in std::fs::read_dir(&sessions_dir)? {
            let file_entry = file_entry?;
            let path = file_entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    // Skip sessions.json(l) index files
                    if stem == "sessions" {
                        continue;
                    }
                    sessions.push((stem.to_string(), path));
                }
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
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;
    let mut total_cache_read: u64 = 0;
    let mut total_cache_creation: u64 = 0;
    let mut first_timestamp: Option<String> = None;
    let mut last_timestamp: Option<String> = None;
    let mut project_path: Option<String> = None;
    let mut repo_name: Option<String> = None;
    let mut session_id = session_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut primary_model: Option<String> = None;
    let mut model_counts: HashMap<String, u32> = HashMap::new();
    let mut message_index: u32 = 0;
    let mut previous_user_timestamp: Option<DateTime<Utc>> = None;
    let mut api_latencies_ms: Vec<u32> = Vec::new();
    let mut tool_latencies_ms: Vec<u32> = Vec::new();
    let mut api_error_count: u32 = 0;
    let mut tool_error_count: u32 = 0;
    let mut tool_success_count: u32 = 0;
    let mut pending_retry_tool: Option<String> = None;
    let mut retry_count: u32 = 0;
    let mut estimated_cost: f64 = 0.0;

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

        match raw.line_type.as_str() {
            "session" => {
                if let Some(ref id) = raw.id {
                    session_id = id.clone();
                }
                if let Some(ref cwd) = raw.cwd {
                    project_path = Some(cwd.clone());
                    repo_name = Path::new(cwd)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string());
                }
            }
            "message" => {
                let msg = match raw.message {
                    Some(m) => m,
                    None => continue,
                };

                let role = msg.role.as_deref().unwrap_or("unknown");

                match role {
                    "user" => {
                        let text = extract_text_content(&msg, redactor);

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
                    "assistant" => {
                        // Token economics
                        if let Some(ref usage) = msg.usage {
                            let inp = usage.input.unwrap_or(0);
                            let out = usage.output.unwrap_or(0);
                            let cr = usage.cache_read.unwrap_or(0);
                            let cw = usage.cache_write.unwrap_or(0);
                            total_input_tokens += inp;
                            total_output_tokens += out;
                            total_cache_read += cr;
                            total_cache_creation += cw;
                        }

                        // Track model
                        if let Some(ref model) = msg.model {
                            *model_counts.entry(model.clone()).or_insert(0) += 1;
                        }

                        // API latency
                        if let Some(ref ts) = raw.timestamp
                            && let Ok(assistant_ts) =
                                DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                            && let Some(user_ts) = previous_user_timestamp
                        {
                            let latency_ms = (assistant_ts - user_ts).num_milliseconds();
                            if latency_ms >= 0 {
                                api_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                            }
                        }

                        if matches!(
                            msg.stop_reason.as_deref(),
                            Some("error") | Some("max_tokens")
                        ) {
                            api_error_count += 1;
                        }

                        let (text, has_thinking, tool_calls_vec) = extract_assistant_content(
                            &msg,
                            redactor,
                            &mut files_modified,
                            &mut files_read,
                        );

                        // Track tool call counts
                        for tc in &tool_calls_vec {
                            let entry = tool_counts.entry(tc.tool_name.clone()).or_insert((0, 0));
                            entry.0 += 1;
                            tool_use_id_to_name
                                .insert(tc.tool_use_id.clone(), tc.tool_name.clone());
                            if let Some(ref ts) = raw.timestamp
                                && let Ok(tool_ts) = DateTime::parse_from_rfc3339(ts)
                                    .map(|dt| dt.with_timezone(&Utc))
                            {
                                tool_use_id_to_ts.insert(tc.tool_use_id.clone(), tool_ts);
                            }
                            if pending_retry_tool.as_deref() == Some(tc.tool_name.as_str()) {
                                retry_count += 1;
                                pending_retry_tool = None;
                            }
                        }

                        let stop_reason = msg
                            .stop_reason
                            .as_deref()
                            .map(normalize_stop_reason)
                            .map(String::from);

                        messages.push(DiffMessage {
                            index: message_index,
                            role: "assistant".to_string(),
                            timestamp: raw.timestamp.clone(),
                            text,
                            has_thinking,
                            tool_calls: tool_calls_vec,
                            tool_results: vec![],
                            input_tokens: msg.usage.as_ref().and_then(|u| u.input),
                            output_tokens: msg.usage.as_ref().and_then(|u| u.output),
                            cache_read_tokens: msg.usage.as_ref().and_then(|u| u.cache_read),
                            model: msg.model.clone(),
                            stop_reason,
                        });
                        message_index += 1;
                    }
                    "toolResult" => {
                        let tool_call_id = msg.tool_call_id.clone().unwrap_or_default();
                        let is_error = msg.is_error.unwrap_or(false)
                            || msg
                                .details
                                .as_ref()
                                .and_then(|d| d.exit_code)
                                .map(|c| c != 0)
                                .unwrap_or(false);

                        let output = extract_tool_result_text(&msg);
                        let output_summary =
                            redactor.redact(&truncate(&output, OUTPUT_SUMMARY_MAX));

                        if is_error {
                            if let Some(name) = tool_use_id_to_name.get(&tool_call_id) {
                                let entry = tool_counts.entry(name.clone()).or_insert((0, 0));
                                entry.1 += 1;
                                pending_retry_tool = Some(name.clone());
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
                    _ => continue,
                }
            }
            // Skip: thinking_level_change, custom, compaction, branch_summary
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

    // Accumulate cost from usage (OpenClaw provides cost per-message)
    // Re-parse to sum costs since we didn't track them in the main loop
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if let Some(cost) = v
                .get("message")
                .and_then(|m| m.get("usage"))
                .and_then(|u| u.get("cost"))
                .and_then(|c| c.get("total"))
                .and_then(|t| t.as_f64())
            {
                estimated_cost += cost;
            }
        }
    }
    estimated_cost = (estimated_cost * 100.0).round() / 100.0;

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
        tool: "openclaw".to_string(),
        tool_version: "unknown".to_string(),
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
        total_input_tokens,
        total_output_tokens,
        total_cache_read_tokens: total_cache_read,
        total_cache_creation_tokens: total_cache_creation,
        estimated_cost_usd: estimated_cost,
        auto_classification: None,
        files_modified,
        files_read,
        config_snapshot: None,
    })
}

// ---------------------------------------------------------------------------
// Content extraction helpers
// ---------------------------------------------------------------------------

fn extract_text_content(msg: &RawMessage, redactor: &Redactor) -> Option<String> {
    let content = msg.content.as_ref()?;
    let blocks = content.as_array()?;

    let text_parts: Vec<String> = blocks
        .iter()
        .filter_map(|block| {
            let block_type = block.get("type").and_then(|t| t.as_str())?;
            if block_type == "text" {
                block
                    .get("text")
                    .and_then(|t| t.as_str())
                    .map(|t| redactor.redact(t))
            } else {
                None
            }
        })
        .collect();

    if text_parts.is_empty() {
        None
    } else {
        Some(truncate(&text_parts.join("\n"), TEXT_MAX))
    }
}

fn extract_assistant_content(
    msg: &RawMessage,
    redactor: &Redactor,
    files_modified: &mut Vec<String>,
    files_read: &mut Vec<String>,
) -> (Option<String>, bool, Vec<ToolCall>) {
    let mut text_parts: Vec<String> = Vec::new();
    let mut has_thinking = false;
    let mut tool_calls: Vec<ToolCall> = Vec::new();

    let content = match &msg.content {
        Some(c) => c,
        None => return (None, false, vec![]),
    };

    if let Value::Array(blocks) = content {
        for block in blocks {
            let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match block_type {
                "thinking" => {
                    has_thinking = true;
                }
                "text" => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        text_parts.push(redactor.redact(t));
                    }
                }
                "toolCall" => {
                    let tool_name = block
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let tool_use_id = block
                        .get("id")
                        .and_then(|id| id.as_str())
                        .unwrap_or("")
                        .to_string();

                    let args = block.get("arguments").cloned().unwrap_or(Value::Null);
                    let input_summary = redactor.redact(&truncate(
                        &summarize_tool_input(&tool_name, &args),
                        INPUT_SUMMARY_MAX,
                    ));

                    track_file_access(&tool_name, &args, files_modified, files_read);

                    tool_calls.push(ToolCall {
                        tool_name,
                        tool_use_id,
                        input_summary,
                    });
                }
                _ => {}
            }
        }
    }

    let text = if text_parts.is_empty() {
        None
    } else {
        Some(truncate(&text_parts.join("\n"), TEXT_MAX))
    };

    (text, has_thinking, tool_calls)
}

fn extract_tool_result_text(msg: &RawMessage) -> String {
    let Some(content) = &msg.content else {
        return String::new();
    };
    let Some(blocks) = content.as_array() else {
        return String::new();
    };

    blocks
        .iter()
        .filter_map(|block| block.get("text").and_then(|t| t.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn summarize_tool_input(tool_name: &str, args: &Value) -> String {
    match tool_name {
        "exec" => args
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("(no command)")
            .to_string(),
        "read" => {
            let path = args
                .get("path")
                .or_else(|| args.get("filePath"))
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Read {}", path)
        }
        "write" => {
            let path = args
                .get("path")
                .or_else(|| args.get("filePath"))
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Write {}", path)
        }
        "edit" => {
            let path = args
                .get("path")
                .or_else(|| args.get("filePath"))
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Edit {}", path)
        }
        "glob" => {
            let pattern = args.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
            format!("Glob {}", pattern)
        }
        "grep" => {
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
    let file_path = args
        .get("path")
        .or_else(|| args.get("filePath"))
        .and_then(|p| p.as_str());

    match tool_name {
        "write" | "edit" => {
            if let Some(path) = file_path {
                modified.push(path.to_string());
            }
        }
        "read" => {
            if let Some(path) = file_path {
                read.push(path.to_string());
            }
        }
        _ => {}
    }
}

/// Normalize OpenClaw's camelCase stop reasons to snake_case.
fn normalize_stop_reason(reason: &str) -> &str {
    match reason {
        "toolUse" => "tool_use",
        "endTurn" | "stop" => "end_turn",
        other => other,
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
