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

#[derive(Debug, Deserialize)]
struct RawLine {
    timestamp: Option<String>,
    #[serde(rename = "type")]
    line_type: String,
    payload: Option<Value>,
}

pub fn default_sessions_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".codex")
        .join("sessions"))
}

pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_sessions_dir()?,
    };

    if !root.exists() {
        anyhow::bail!("Codex sessions directory not found at {}", root.display());
    }

    for (_, path) in discover_sessions(Some(&root))? {
        if session_id_from_path(&path).as_deref() == Some(session_id) {
            return Ok(path);
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

    collect_jsonl_files(&root, &mut sessions)?;
    sessions.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(sessions)
}

fn collect_jsonl_files(dir: &Path, sessions: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_jsonl_files(&path, sessions)?;
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }

        if let Some(session_id) = session_id_from_path(&path) {
            sessions.push((session_id, path));
        }
    }

    Ok(())
}

fn session_id_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    stem.rsplit_once('-')
        .map(|(_, session_id)| session_id.to_string())
}

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
    let mut tool_use_id_to_command: HashMap<String, String> = HashMap::new();
    let mut files_modified: Vec<String> = Vec::new();
    let mut files_read: Vec<String> = Vec::new();
    let mut total_input_tokens: u64 = 0;
    let mut total_output_tokens: u64 = 0;
    let mut total_cache_read: u64 = 0;
    let total_cache_creation: u64 = 0;
    let mut first_timestamp: Option<String> = None;
    let mut last_timestamp: Option<String> = None;
    let mut project_path: Option<String> = None;
    let mut repo_name: Option<String> = None;
    let mut git_branch: Option<String> = None;
    let mut tool_version: Option<String> = None;
    let mut primary_model: Option<String> = None;
    let mut model_counts: HashMap<String, u32> = HashMap::new();
    let mut message_index: u32 = 0;
    let mut previous_user_timestamp: Option<DateTime<Utc>> = None;
    let mut api_latencies_ms: Vec<u32> = Vec::new();
    let mut tool_latencies_ms: Vec<u32> = Vec::new();
    let api_error_count: u32 = 0;
    let mut tool_error_count: u32 = 0;
    let mut tool_success_count: u32 = 0;
    let retry_count: u32 = 0;
    let mut pending_has_thinking = false;

    let mut session_id = session_id_from_path(session_path).unwrap_or_default();

    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let raw: RawLine = match serde_json::from_str(line) {
            Ok(raw) => raw,
            Err(error) => {
                eprintln!(
                    "Warning: skipping malformed JSONL at line {}: {}",
                    line_idx + 1,
                    error
                );
                continue;
            }
        };

        if let Some(ref ts) = raw.timestamp {
            if first_timestamp.is_none() {
                first_timestamp = Some(ts.clone());
            }
            last_timestamp = Some(ts.clone());
        }

        match raw.line_type.as_str() {
            "session_meta" => {
                let Some(payload) = raw.payload.as_ref() else {
                    continue;
                };

                if let Some(id) = payload.get("id").and_then(|value| value.as_str()) {
                    session_id = id.to_string();
                }
                if let Some(cwd) = payload.get("cwd").and_then(|value| value.as_str()) {
                    project_path = Some(cwd.to_string());
                    repo_name = repo_name_from_path(cwd);
                }
                if let Some(version) = payload.get("cli_version").and_then(|value| value.as_str()) {
                    tool_version = Some(version.to_string());
                }
                if let Some(branch) = payload
                    .get("git")
                    .and_then(|git| git.get("branch"))
                    .and_then(|value| value.as_str())
                {
                    git_branch = Some(branch.to_string());
                }
            }
            "turn_context" => {
                let Some(payload) = raw.payload.as_ref() else {
                    continue;
                };

                if project_path.is_none()
                    && let Some(cwd) = payload.get("cwd").and_then(|value| value.as_str())
                {
                    project_path = Some(cwd.to_string());
                    repo_name = repo_name_from_path(cwd);
                }

                if let Some(model) = payload.get("model").and_then(|value| value.as_str()) {
                    *model_counts.entry(model.to_string()).or_insert(0) += 1;
                }
            }
            "event_msg" => {
                let Some(payload) = raw.payload.as_ref() else {
                    continue;
                };

                match payload.get("type").and_then(|value| value.as_str()) {
                    Some("token_count") => {
                        if let Some(info) = payload.get("info")
                            && let Some(total_usage) = info.get("total_token_usage")
                        {
                            total_input_tokens = total_input_tokens.max(
                                total_usage
                                    .get("input_tokens")
                                    .and_then(|value| value.as_u64())
                                    .unwrap_or(0),
                            );
                            total_output_tokens = total_output_tokens.max(
                                total_usage
                                    .get("output_tokens")
                                    .and_then(|value| value.as_u64())
                                    .unwrap_or(0),
                            );
                            total_cache_read = total_cache_read.max(
                                total_usage
                                    .get("cached_input_tokens")
                                    .and_then(|value| value.as_u64())
                                    .unwrap_or(0),
                            );
                        }
                    }
                    Some("agent_reasoning") => {
                        pending_has_thinking = true;
                    }
                    _ => {}
                }
            }
            "response_item" => {
                let Some(payload) = raw.payload.as_ref() else {
                    continue;
                };

                match payload.get("type").and_then(|value| value.as_str()) {
                    Some("message") => {
                        let role = payload
                            .get("role")
                            .and_then(|value| value.as_str())
                            .unwrap_or("assistant");
                        if role != "user" && role != "assistant" {
                            continue;
                        }
                        let text = extract_message_text(payload, redactor);

                        if role == "user"
                            && let Some(ref ts) = raw.timestamp
                        {
                            previous_user_timestamp = DateTime::parse_from_rfc3339(ts)
                                .ok()
                                .map(|dt| dt.with_timezone(&Utc));
                        }

                        if role == "assistant"
                            && let Some(ref ts) = raw.timestamp
                            && let Ok(assistant_ts) =
                                DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                            && let Some(user_ts) = previous_user_timestamp
                        {
                            let latency_ms = (assistant_ts - user_ts).num_milliseconds();
                            if latency_ms >= 0 {
                                api_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                            }
                        }

                        messages.push(DiffMessage {
                            index: message_index,
                            role: role.to_string(),
                            timestamp: raw.timestamp.clone(),
                            text,
                            has_thinking: role == "assistant"
                                && std::mem::take(&mut pending_has_thinking),
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
                    Some("reasoning") => {
                        pending_has_thinking = true;
                    }
                    Some("function_call") => {
                        let call_id = payload
                            .get("call_id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .to_string();
                        let raw_name = payload
                            .get("name")
                            .and_then(|value| value.as_str())
                            .unwrap_or("shell_command");
                        let tool_name = normalize_tool_name(raw_name).to_string();
                        let arguments = payload
                            .get("arguments")
                            .and_then(|value| value.as_str())
                            .unwrap_or("{}");
                        let args_json: Value =
                            serde_json::from_str(arguments).unwrap_or(Value::Null);
                        let command = args_json
                            .get("command")
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .to_string();
                        let input_summary = redactor.redact(&truncate(
                            &summarize_tool_input(raw_name, &args_json),
                            INPUT_SUMMARY_MAX,
                        ));

                        track_file_access(
                            raw_name,
                            &args_json,
                            &mut files_modified,
                            &mut files_read,
                        );

                        let entry = tool_counts.entry(tool_name.clone()).or_insert((0, 0));
                        entry.0 += 1;
                        tool_use_id_to_name.insert(call_id.clone(), tool_name.clone());
                        if !command.is_empty() {
                            tool_use_id_to_command.insert(call_id.clone(), command);
                        }

                        if let Some(ref ts) = raw.timestamp
                            && let Ok(tool_ts) =
                                DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                        {
                            tool_use_id_to_ts.insert(call_id.clone(), tool_ts);
                        }

                        messages.push(DiffMessage {
                            index: message_index,
                            role: "assistant".to_string(),
                            timestamp: raw.timestamp.clone(),
                            text: None,
                            has_thinking: std::mem::take(&mut pending_has_thinking),
                            tool_calls: vec![ToolCall {
                                tool_name,
                                tool_use_id: call_id,
                                input_summary,
                            }],
                            tool_results: vec![],
                            input_tokens: None,
                            output_tokens: None,
                            cache_read_tokens: None,
                            model: None,
                            stop_reason: Some("tool_call".to_string()),
                        });
                        message_index += 1;
                    }
                    Some("custom_tool_call") => {
                        let call_id = payload
                            .get("call_id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .to_string();
                        let raw_name = payload
                            .get("name")
                            .and_then(|value| value.as_str())
                            .unwrap_or("custom_tool");
                        let tool_name = normalize_tool_name(raw_name).to_string();
                        let input = payload
                            .get("input")
                            .and_then(|value| value.as_str())
                            .unwrap_or("");
                        let input_summary = redactor.redact(&truncate(input, INPUT_SUMMARY_MAX));

                        track_patch_files(input, &mut files_modified);

                        let entry = tool_counts.entry(tool_name.clone()).or_insert((0, 0));
                        entry.0 += 1;
                        tool_use_id_to_name.insert(call_id.clone(), tool_name.clone());

                        if let Some(ref ts) = raw.timestamp
                            && let Ok(tool_ts) =
                                DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                        {
                            tool_use_id_to_ts.insert(call_id.clone(), tool_ts);
                        }

                        messages.push(DiffMessage {
                            index: message_index,
                            role: "assistant".to_string(),
                            timestamp: raw.timestamp.clone(),
                            text: None,
                            has_thinking: std::mem::take(&mut pending_has_thinking),
                            tool_calls: vec![ToolCall {
                                tool_name,
                                tool_use_id: call_id,
                                input_summary,
                            }],
                            tool_results: vec![],
                            input_tokens: None,
                            output_tokens: None,
                            cache_read_tokens: None,
                            model: None,
                            stop_reason: Some("tool_call".to_string()),
                        });
                        message_index += 1;
                    }
                    Some("function_call_output") | Some("custom_tool_call_output") => {
                        let call_id = payload
                            .get("call_id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .to_string();
                        let output = payload
                            .get("output")
                            .and_then(|value| value.as_str())
                            .unwrap_or("");
                        let is_error = tool_result_is_error(output);

                        if is_error {
                            if let Some(name) = tool_use_id_to_name.get(&call_id) {
                                let entry = tool_counts.entry(name.clone()).or_insert((0, 0));
                                entry.1 += 1;
                            }
                            tool_error_count += 1;
                        } else {
                            tool_success_count += 1;
                        }

                        if let Some(ref ts) = raw.timestamp
                            && let Ok(result_ts) =
                                DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&Utc))
                            && let Some(start_ts) = tool_use_id_to_ts.get(&call_id)
                        {
                            let latency_ms = (result_ts - *start_ts).num_milliseconds();
                            if latency_ms >= 0 {
                                tool_latencies_ms.push(latency_ms.min(u32::MAX as i64) as u32);
                            }
                        }

                        if let Some(command) = tool_use_id_to_command.get(&call_id) {
                            track_shell_output_files(
                                command,
                                output,
                                &mut files_modified,
                                &mut files_read,
                            );
                        }

                        messages.push(DiffMessage {
                            index: message_index,
                            role: "user".to_string(),
                            timestamp: raw.timestamp.clone(),
                            text: None,
                            has_thinking: false,
                            tool_calls: vec![],
                            tool_results: vec![ToolResult {
                                tool_use_id: call_id,
                                is_error,
                                output_summary: redactor
                                    .redact(&truncate(output, OUTPUT_SUMMARY_MAX)),
                            }],
                            input_tokens: None,
                            output_tokens: None,
                            cache_read_tokens: None,
                            model: None,
                            stop_reason: None,
                        });
                        message_index += 1;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

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
    let total_tool_calls = tool_call_summaries.iter().map(|tool| tool.count).sum();
    let user_count = messages
        .iter()
        .filter(|message| message.role == "user")
        .count() as u32;
    let assistant_count = messages
        .iter()
        .filter(|message| message.role == "assistant")
        .count() as u32;

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
        tool: "codex".to_string(),
        tool_version: tool_version.unwrap_or_else(|| "unknown".to_string()),
        diff_cli_version: env!("CARGO_PKG_VERSION").to_string(),
        project_path: project_path.unwrap_or_default(),
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
        estimated_cost_usd: 0.0,
        auto_classification: None,
        files_modified,
        files_read,
        config_snapshot: None,
    })
}

fn extract_message_text(payload: &Value, redactor: &Redactor) -> Option<String> {
    let content = payload.get("content")?.as_array()?;
    let text_parts: Vec<String> = content
        .iter()
        .filter_map(|item| item.get("text").and_then(|value| value.as_str()))
        .map(|text| redactor.redact(text))
        .collect();

    if text_parts.is_empty() {
        None
    } else {
        Some(truncate(&text_parts.join("\n"), TEXT_MAX))
    }
}

fn normalize_tool_name(name: &str) -> &str {
    match name {
        "shell_command" => "Bash",
        "apply_patch" => "apply_patch",
        _ => name,
    }
}

fn summarize_tool_input(raw_name: &str, input: &Value) -> String {
    match raw_name {
        "shell_command" => input
            .get("command")
            .and_then(|value| value.as_str())
            .unwrap_or("(no command)")
            .to_string(),
        _ => serde_json::to_string(input).unwrap_or_else(|_| "(unparseable)".to_string()),
    }
}

fn track_file_access(
    raw_name: &str,
    input: &Value,
    files_modified: &mut Vec<String>,
    files_read: &mut Vec<String>,
) {
    if raw_name != "shell_command" {
        return;
    }

    let Some(command) = input.get("command").and_then(|value| value.as_str()) else {
        return;
    };

    let normalized = command.trim();
    if normalized.is_empty() {
        return;
    }

    let tokens = shell_like_tokens(normalized);
    if tokens.is_empty() {
        return;
    }

    match tokens[0].as_str() {
        "cat" | "less" | "more" | "head" | "tail" => {
            for token in tokens.iter().skip(1) {
                if let Some(path) = normalize_path_token(token) {
                    files_read.push(path);
                }
            }
        }
        "rg" | "grep" => {
            for token in tokens.iter().skip(1) {
                if let Some(path) = normalize_search_target(token) {
                    files_read.push(path);
                }
            }
        }
        "sed" => {
            for token in tokens.iter().skip(1) {
                if let Some(path) = normalize_path_token(token) {
                    files_modified.push(path);
                }
            }
        }
        _ => {}
    }
}

fn track_shell_output_files(
    command: &str,
    output: &str,
    _files_modified: &mut Vec<String>,
    files_read: &mut Vec<String>,
) {
    let tokens = shell_like_tokens(command);
    if tokens.is_empty() {
        return;
    }

    if matches!(tokens[0].as_str(), "rg" | "grep") {
        for line in output.lines() {
            let candidate = line
                .split_once(':')
                .map(|(path, _)| path)
                .unwrap_or(line)
                .trim();
            if let Some(path) = normalize_output_path(candidate) {
                files_read.push(path);
            }
        }
    }
}

fn track_patch_files(patch: &str, files_modified: &mut Vec<String>) {
    for line in patch.lines() {
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            files_modified.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Add File: ") {
            files_modified.push(path.trim().to_string());
        }
    }
}

fn shell_like_tokens(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in command.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn normalize_search_target(token: &str) -> Option<String> {
    if token.starts_with('-') || token == "." || token == ".." {
        return None;
    }
    normalize_path_token(token)
}

fn normalize_path_token(token: &str) -> Option<String> {
    let trimmed = token.trim_matches(|ch| matches!(ch, '"' | '\'' | ',' | ';' | ')'));
    if trimmed.is_empty()
        || trimmed.contains('*')
        || trimmed.contains('|')
        || trimmed.contains('=')
        || trimmed.starts_with("http")
    {
        return None;
    }

    if trimmed.contains('/') || trimmed.contains('.') {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn normalize_output_path(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("Exit code")
        || trimmed.starts_with("Wall time")
        || trimmed.starts_with("Output")
        || trimmed.starts_with("Found ")
        || trimmed.starts_with("Success.")
    {
        return None;
    }

    normalize_path_token(trimmed)
}

fn tool_result_is_error(output: &str) -> bool {
    if output.trim().is_empty() {
        return false;
    }

    if let Some(code) = output
        .lines()
        .find_map(|line| line.strip_prefix("Exit code: "))
        .and_then(|value| value.trim().parse::<i32>().ok())
    {
        return code != 0;
    }

    if let Ok(json) = serde_json::from_str::<Value>(output)
        && let Some(code) = json
            .get("metadata")
            .and_then(|value| value.get("exit_code"))
            .and_then(|value| value.as_i64())
    {
        return code != 0;
    }

    false
}

fn repo_name_from_path(project_path: &str) -> Option<String> {
    Path::new(project_path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
}

fn compute_duration(start: &Option<String>, end: &Option<String>) -> Option<u64> {
    let start = start.as_ref()?;
    let end = end.as_ref()?;
    let start_dt = chrono::DateTime::parse_from_rfc3339(start).ok()?;
    let end_dt = chrono::DateTime::parse_from_rfc3339(end).ok()?;
    let duration = end_dt.signed_duration_since(start_dt);
    Some(duration.num_seconds().max(0) as u64)
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

fn truncate(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &text[..end])
    }
}
