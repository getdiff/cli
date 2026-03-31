use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::redact::Redactor;
use crate::types::*;

// ---------------------------------------------------------------------------
// Raw JSONL line types (what Claude Code actually writes to disk)
// ---------------------------------------------------------------------------

/// Every line in the JSONL shares these common fields.
#[derive(Debug, Deserialize)]
struct RawLine {
    #[serde(rename = "type")]
    line_type: String,
    #[serde(rename = "sessionId")]
    #[allow(dead_code)]
    session_id: Option<String>,
    timestamp: Option<String>,
    version: Option<String>,
    #[serde(rename = "gitBranch")]
    git_branch: Option<String>,
    #[allow(dead_code)]
    cwd: Option<String>,
    message: Option<RawMessage>,
    #[allow(dead_code)]
    uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[allow(dead_code)]
    role: Option<String>,
    content: Option<Value>, // string or array of content blocks
    model: Option<String>,
    usage: Option<RawUsage>,
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

const INPUT_SUMMARY_MAX: usize = 500;
const OUTPUT_SUMMARY_MAX: usize = 1000;
const TEXT_MAX: usize = 5000;

pub fn default_projects_dir() -> Result<PathBuf> {
    let claude_dir = dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".claude")
        .join("projects");

    Ok(claude_dir)
}

/// Find the session JSONL file by scanning ~/.claude/projects/*/
pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let claude_dir = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_projects_dir()?,
    };

    if !claude_dir.exists() {
        anyhow::bail!(
            "Claude Code projects directory not found at {}",
            claude_dir.display()
        );
    }

    let filename = format!("{}.jsonl", session_id);

    for entry in std::fs::read_dir(&claude_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let candidate = entry.path().join(&filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    anyhow::bail!(
        "Session {} not found in any project under {}",
        session_id,
        claude_dir.display()
    )
}

/// Discovers all session JSONL files under the Claude Code projects directory.
/// Returns a vec of (session_id, file_path) tuples.
pub fn discover_sessions(root_override: Option<&Path>) -> Result<Vec<(String, PathBuf)>> {
    let claude_dir = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_projects_dir()?,
    };

    let mut sessions = Vec::new();

    if !claude_dir.exists() {
        return Ok(sessions);
    }

    for entry in std::fs::read_dir(&claude_dir)? {
        let entry = entry?;
        let project_dir = entry.path();
        if !project_dir.is_dir() {
            continue;
        }

        for file_entry in std::fs::read_dir(&project_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();

            if file_path.extension().and_then(|e| e.to_str()) == Some("jsonl")
                && let Some(stem) = file_path.file_stem().and_then(|s| s.to_str())
                && uuid::Uuid::parse_str(stem).is_ok()
            {
                sessions.push((stem.to_string(), file_path));
            }
        }
    }

    Ok(sessions)
}

/// Derive the project path from the Claude Code directory name.
/// e.g. "-Users-jane-work-api-service" -> "/Users/jane/work/api-service"
fn project_path_from_dir(dir_name: &str) -> String {
    dir_name.replacen('-', "/", 1).replace('-', "/")
}

/// Extract repo name from the project path (last path component).
fn repo_name_from_path(project_path: &str) -> Option<String> {
    Path::new(project_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
}

/// Try to load the auto-classification from usage-data/facets/{session_id}.json
fn load_auto_classification(session_id: &str) -> Option<AutoClassification> {
    let facets_path = dirs::home_dir()?
        .join(".claude")
        .join("usage-data")
        .join("facets")
        .join(format!("{}.json", session_id));

    if !facets_path.exists() {
        return None;
    }

    let data = std::fs::read_to_string(&facets_path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Parse a Claude Code session JSONL file into a normalized DiffSession.
pub fn parse_session(
    session_path: &Path,
    org_id: &str,
    engineer_id: &str,
    machine_id: &str,
    redactor: &Redactor,
) -> Result<DiffSession> {
    let content = std::fs::read_to_string(session_path)
        .with_context(|| format!("Failed to read {}", session_path.display()))?;

    // Derive project path from parent directory name
    let parent_dir = session_path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let project_path = project_path_from_dir(&parent_dir);
    let repo_name = repo_name_from_path(&project_path);

    // Extract session_id from filename
    let session_id = session_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut messages: Vec<DiffMessage> = Vec::new();
    let mut tool_counts: HashMap<String, (u32, u32)> = HashMap::new(); // name -> (count, errors)
    let mut tool_use_id_to_name: HashMap<String, String> = HashMap::new(); // tool_use_id -> name
    let mut tool_use_id_to_ts: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut files_modified: Vec<String> = Vec::new();
    let mut files_read: Vec<String> = Vec::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;
    let mut total_cache_read: u64 = 0;
    let mut total_cache_creation: u64 = 0;
    let mut first_timestamp: Option<String> = None;
    let mut last_timestamp: Option<String> = None;
    let mut git_branch: Option<String> = None;
    let mut tool_version: Option<String> = None;
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

        // Track metadata from any line
        if git_branch.is_none()
            && let Some(ref b) = raw.git_branch
            && b != "HEAD"
        {
            git_branch = Some(b.clone());
        }
        if tool_version.is_none() {
            tool_version = raw.version.clone();
        }

        // Track timestamps
        if let Some(ref ts) = raw.timestamp {
            if first_timestamp.is_none() {
                first_timestamp = Some(ts.clone());
            }
            last_timestamp = Some(ts.clone());
        }

        match raw.line_type.as_str() {
            "user" => {
                let msg = match raw.message {
                    Some(m) => m,
                    None => continue,
                };

                let (text, tool_results) = extract_user_content(&msg, redactor);

                // Track tool result errors by mapping tool_use_id back to tool name
                for tr in &tool_results {
                    if tr.is_error
                        && let Some(name) = tool_use_id_to_name.get(&tr.tool_use_id)
                    {
                        let entry = tool_counts.entry(name.clone()).or_insert((0, 0));
                        entry.1 += 1;
                        tool_error_count += 1;
                        pending_retry_tool = Some(name.clone());
                    } else {
                        tool_success_count += 1;
                    }

                    if let Some(ref ts) = raw.timestamp
                        && let Ok(result_ts) =
                            DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                        && let Some(start_ts) = tool_use_id_to_ts.get(&tr.tool_use_id)
                    {
                        let latency_ms = (result_ts - *start_ts).num_milliseconds();
                        if latency_ms >= 0 {
                            tool_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                        }
                    }
                }

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
                    tool_results,
                    input_tokens: None,
                    output_tokens: None,
                    cache_read_tokens: None,
                    model: None,
                    stop_reason: None,
                });
                message_index += 1;
            }
            "assistant" => {
                let msg = match raw.message {
                    Some(m) => m,
                    None => continue,
                };

                // Token economics
                if let Some(ref usage) = msg.usage {
                    let inp = usage.input_tokens.unwrap_or(0);
                    let out = usage.output_tokens.unwrap_or(0);
                    let cr = usage.cache_read_input_tokens.unwrap_or(0);
                    let cc = usage.cache_creation_input_tokens.unwrap_or(0);
                    total_input_tokens += inp;
                    total_output_tokens += out;
                    total_cache_read += cr;
                    total_cache_creation += cc;
                }

                // Track model
                if let Some(ref model) = msg.model {
                    *model_counts.entry(model.clone()).or_insert(0) += 1;
                }

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

                let (text, has_thinking, tool_calls_vec) =
                    extract_assistant_content(&msg, redactor, &mut files_modified, &mut files_read);

                // Track tool call counts and build tool_use_id -> name mapping
                for tc in &tool_calls_vec {
                    let entry = tool_counts.entry(tc.tool_name.clone()).or_insert((0, 0));
                    entry.0 += 1;
                    tool_use_id_to_name.insert(tc.tool_use_id.clone(), tc.tool_name.clone());
                    if let Some(ref ts) = raw.timestamp
                        && let Ok(tool_ts) =
                            DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                    {
                        tool_use_id_to_ts.insert(tc.tool_use_id.clone(), tool_ts);
                    }
                    if pending_retry_tool.as_deref() == Some(tc.tool_name.as_str()) {
                        retry_count += 1;
                        pending_retry_tool = None;
                    }
                }

                messages.push(DiffMessage {
                    index: message_index,
                    role: "assistant".to_string(),
                    timestamp: raw.timestamp.clone(),
                    text,
                    has_thinking,
                    tool_calls: tool_calls_vec,
                    tool_results: vec![],
                    input_tokens: msg.usage.as_ref().and_then(|u| u.input_tokens),
                    output_tokens: msg.usage.as_ref().and_then(|u| u.output_tokens),
                    cache_read_tokens: msg.usage.as_ref().and_then(|u| u.cache_read_input_tokens),
                    model: msg.model.clone(),
                    stop_reason: msg.stop_reason.clone(),
                });
                message_index += 1;
            }
            // Skip: "queue-operation", "file-history-snapshot", "progress"
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

    // Compute duration
    let duration_seconds = compute_duration(&first_timestamp, &last_timestamp);

    // Build tool call summary
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

    // Estimate cost (rough: opus=$15/M input, $75/M output; sonnet=$3/$15; haiku=$0.25/$1.25)
    let estimated_cost = estimate_cost(&primary_model, total_input_tokens, total_output_tokens);

    // Deduplicate file lists
    files_modified.sort();
    files_modified.dedup();
    files_read.sort();
    files_read.dedup();

    // Load auto-classification
    let auto_classification = load_auto_classification(&session_id);

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
        tool: "claude_code".to_string(),
        tool_version: tool_version.unwrap_or_else(|| "unknown".to_string()),
        diff_cli_version: env!("CARGO_PKG_VERSION").to_string(),
        project_path,
        repo_name,
        git_branch,
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
        auto_classification,
        files_modified,
        files_read,
        config_snapshot: None,
    })
}

// ---------------------------------------------------------------------------
// Content extraction helpers
// ---------------------------------------------------------------------------

/// Extract text and tool results from a user message.
fn extract_user_content(
    msg: &RawMessage,
    redactor: &Redactor,
) -> (Option<String>, Vec<ToolResult>) {
    let mut text_parts: Vec<String> = Vec::new();
    let mut tool_results: Vec<ToolResult> = Vec::new();

    let content = match &msg.content {
        Some(c) => c,
        None => return (None, vec![]),
    };

    match content {
        Value::String(s) => {
            text_parts.push(redactor.redact(s));
        }
        Value::Array(blocks) => {
            for block in blocks {
                let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match block_type {
                    "text" => {
                        if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                            text_parts.push(redactor.redact(t));
                        }
                    }
                    "tool_result" => {
                        let tool_use_id = block
                            .get("tool_use_id")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();
                        let is_error = block
                            .get("is_error")
                            .and_then(|e| e.as_bool())
                            .unwrap_or(false);

                        let output = extract_tool_result_content(block);
                        let output_summary =
                            redactor.redact(&truncate(&output, OUTPUT_SUMMARY_MAX));

                        tool_results.push(ToolResult {
                            tool_use_id,
                            is_error,
                            output_summary,
                        });
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    let text = if text_parts.is_empty() {
        None
    } else {
        Some(truncate(&text_parts.join("\n"), TEXT_MAX))
    };

    (text, tool_results)
}

/// Extract text content from a tool_result block (which can be string or array).
fn extract_tool_result_content(block: &Value) -> String {
    match block.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|item| {
                if item.get("type").and_then(|t| t.as_str()) == Some("text") {
                    item.get("text").and_then(|t| t.as_str()).map(String::from)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Extract text, thinking flag, and tool calls from an assistant message.
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
                    // Don't capture thinking content -- too large and sensitive
                }
                "text" => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        text_parts.push(redactor.redact(t));
                    }
                }
                "tool_use" => {
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

                    let input = block.get("input").cloned().unwrap_or(Value::Null);
                    let input_summary = redactor.redact(&truncate(
                        &summarize_tool_input(&tool_name, &input),
                        INPUT_SUMMARY_MAX,
                    ));

                    // Track file modifications
                    track_file_access(&tool_name, &input, files_modified, files_read);

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

/// Create a human-readable summary of a tool call's input.
fn summarize_tool_input(tool_name: &str, input: &Value) -> String {
    match tool_name {
        "Bash" => {
            let cmd = input
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("(no command)");
            let desc = input.get("description").and_then(|d| d.as_str());
            match desc {
                Some(d) => format!("{}: {}", cmd, d),
                None => cmd.to_string(),
            }
        }
        "Read" => {
            let path = input
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Read {}", path)
        }
        "Write" => {
            let path = input
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            // Don't include content -- too large and sensitive
            format!("Write {}", path)
        }
        "Edit" => {
            let path = input
                .get("file_path")
                .and_then(|p| p.as_str())
                .unwrap_or("?");
            format!("Edit {}", path)
        }
        "Glob" => {
            let pattern = input.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
            format!("Glob {}", pattern)
        }
        "Grep" => {
            let pattern = input.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
            format!("Grep {}", pattern)
        }
        "Agent" => {
            let desc = input
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("(agent task)");
            format!("Agent: {}", desc)
        }
        "WebSearch" => {
            let query = input.get("query").and_then(|q| q.as_str()).unwrap_or("?");
            format!("WebSearch: {}", query)
        }
        "WebFetch" => {
            let url = input.get("url").and_then(|u| u.as_str()).unwrap_or("?");
            format!("WebFetch: {}", url)
        }
        _ => {
            // Generic: serialize input, truncated
            serde_json::to_string(input).unwrap_or_else(|_| "(unparseable)".to_string())
        }
    }
}

/// Track which files were read or modified based on tool calls.
fn track_file_access(
    tool_name: &str,
    input: &Value,
    modified: &mut Vec<String>,
    read: &mut Vec<String>,
) {
    let file_path = input.get("file_path").and_then(|p| p.as_str());

    match tool_name {
        "Write" | "Edit" | "NotebookEdit" => {
            if let Some(path) = file_path {
                modified.push(path.to_string());
            }
        }
        "Read" => {
            if let Some(path) = file_path {
                read.push(path.to_string());
            }
        }
        _ => {}
    }
}

/// Compute duration in seconds between two ISO8601 timestamps.
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
    let sum: u64 = values.iter().map(|value| *value as u64).sum();
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

/// Estimate cost based on model and token counts.
/// Prices per 1M tokens, last updated 2025-05. Falls back to sonnet pricing for unknown models.
fn estimate_cost(model: &Option<String>, input_tokens: u64, output_tokens: u64) -> f64 {
    let (input_price, output_price) = match model.as_deref() {
        Some(m) if m.contains("opus") => (15.0, 75.0),
        Some(m) if m.contains("sonnet") => (3.0, 15.0),
        Some(m) if m.contains("haiku") => (0.25, 1.25),
        _ => (3.0, 15.0), // default to sonnet pricing
    };

    let input_cost = (input_tokens as f64 / 1_000_000.0) * input_price;
    let output_cost = (output_tokens as f64 / 1_000_000.0) * output_price;
    ((input_cost + output_cost) * 100.0).round() / 100.0 // round to cents
}

/// Truncate a string to approximately max_len bytes, respecting UTF-8 char boundaries.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find the largest char boundary <= max_len
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}
