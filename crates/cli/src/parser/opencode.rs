use anyhow::{Context, Result, bail};
use chrono::{TimeZone, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::redact::Redactor;
use crate::types::*;

const INPUT_SUMMARY_MAX: usize = 500;
const OUTPUT_SUMMARY_MAX: usize = 1000;
const TEXT_MAX: usize = 5000;

type PartMap = HashMap<String, Vec<Value>>;

struct ParsedOpenCodeSession {
    session: Value,
    messages: Vec<Value>,
    part_map: PartMap,
    diff_files: Vec<String>,
}

pub fn default_data_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".local")
        .join("share")
        .join("opencode"))
}

pub fn discover_sessions(root_override: Option<&Path>) -> Result<Vec<(String, PathBuf)>> {
    let root = root_override
        .map(Path::to_path_buf)
        .unwrap_or(default_data_dir()?);
    let session_root = root.join("storage").join("session");
    let mut sessions = Vec::new();

    if !session_root.exists() {
        return Ok(sessions);
    }

    collect_session_files(&session_root, &mut sessions)?;
    sessions.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(sessions)
}

pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let root = root_override
        .map(Path::to_path_buf)
        .unwrap_or(default_data_dir()?);

    for (id, path) in discover_sessions(Some(&root))? {
        if id == session_id {
            return Ok(path);
        }
    }

    bail!(
        "OpenCode session {} not found under {}",
        session_id,
        root.display()
    )
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

    let ParsedOpenCodeSession {
        session,
        mut messages,
        part_map,
        mut diff_files,
    } = if looks_like_exported_sample(&content) {
        parse_exported_sample(&content)?
    } else {
        parse_storage_session(session_path, &content)?
    };

    messages.sort_by_key(message_time_created);

    let session_id = string_field(&session, &["id"]).unwrap_or_default();
    let project_path = string_field(&session, &["directory"]).unwrap_or_default();
    let tool_version =
        string_field(&session, &["version"]).unwrap_or_else(|| "unknown".to_string());
    let started_ms = int_field(&session, &["time_created"])
        .or_else(|| int_field(&session, &["time", "created"]));
    let ended_ms = int_field(&session, &["time_updated"])
        .or_else(|| int_field(&session, &["time", "updated"]));

    let mut diff_messages = Vec::new();
    let mut tool_counts: HashMap<String, (u32, u32)> = HashMap::new();
    let mut files_modified = Vec::new();
    let mut files_read = Vec::new();
    let mut total_input_tokens = 0_u64;
    let mut total_output_tokens = 0_u64;
    let mut total_cache_read_tokens = 0_u64;
    let mut total_cache_creation_tokens = 0_u64;
    let mut model_counts: HashMap<String, u32> = HashMap::new();
    let mut tool_error_count = 0_u32;
    let mut tool_success_count = 0_u32;
    let mut tool_latencies_ms = Vec::new();

    for (index, message) in messages.iter().enumerate() {
        let role = string_field(message, &["role"]).unwrap_or_else(|| "assistant".to_string());
        let timestamp_ms = int_field(message, &["time_created"])
            .or_else(|| int_field(message, &["time", "created"]));
        let model = string_field(message, &["modelID"])
            .or_else(|| string_field(message, &["data", "modelID"]));
        let finish = string_field(message, &["finish"])
            .or_else(|| string_field(message, &["data", "finish"]));
        if let Some(model) = &model {
            *model_counts.entry(model.clone()).or_insert(0) += 1;
        }

        let tokens = object_field(message, &["tokens"])
            .or_else(|| object_field(message, &["data", "tokens"]));
        if role == "assistant" {
            total_input_tokens += int_field_from(tokens, &["input"]).unwrap_or(0) as u64;
            total_output_tokens += int_field_from(tokens, &["output"]).unwrap_or(0) as u64;
            total_cache_read_tokens +=
                int_field_from(tokens, &["cache", "read"]).unwrap_or(0) as u64;
            total_cache_creation_tokens +=
                int_field_from(tokens, &["cache", "write"]).unwrap_or(0) as u64;
        }

        let parts = part_map.get(string_field(message, &["id"]).as_deref().unwrap_or(""));
        let mut text_parts = Vec::new();
        let mut has_thinking = false;
        let mut tool_calls = Vec::new();
        let mut tool_results = Vec::new();

        if let Some(parts) = parts {
            for part in parts {
                let part_type =
                    string_field(part, &["type"]).or_else(|| string_field(part, &["data", "type"]));
                match part_type.as_deref() {
                    Some("text") => {
                        if let Some(text) = string_field(part, &["text"])
                            .or_else(|| string_field(part, &["data", "text"]))
                            && !text.trim().is_empty()
                        {
                            text_parts.push(redactor.redact(&text));
                        }
                    }
                    Some("reasoning") => {
                        has_thinking = true;
                    }
                    Some("patch") => {
                        for path in string_array_field(part, &["files"])
                            .into_iter()
                            .chain(string_array_field(part, &["data", "files"]))
                        {
                            files_modified.push(path);
                        }
                    }
                    Some("tool") => {
                        let raw_tool = string_field(part, &["tool"])
                            .or_else(|| string_field(part, &["data", "tool"]))
                            .unwrap_or_else(|| "unknown".to_string());
                        let tool_name = normalize_tool_name(&raw_tool).to_string();
                        let call_id = string_field(part, &["callID"])
                            .or_else(|| string_field(part, &["data", "callID"]))
                            .unwrap_or_default();
                        let input = value_field(part, &["state", "input"])
                            .or_else(|| value_field(part, &["data", "state", "input"]))
                            .unwrap_or(Value::Null);
                        let output = value_field(part, &["state", "output"])
                            .or_else(|| value_field(part, &["data", "state", "output"]));
                        let metadata = object_field(part, &["state", "metadata"])
                            .or_else(|| object_field(part, &["data", "state", "metadata"]));
                        let status = string_field(part, &["state", "status"])
                            .or_else(|| string_field(part, &["data", "state", "status"]))
                            .unwrap_or_else(|| "completed".to_string());

                        let entry = tool_counts.entry(tool_name.clone()).or_insert((0, 0));
                        entry.0 += 1;

                        let input_summary = redactor.redact(&truncate(
                            &summarize_tool_input(&raw_tool, &input),
                            INPUT_SUMMARY_MAX,
                        ));
                        track_tool_files(&raw_tool, &input, &mut files_modified, &mut files_read);

                        let is_error = tool_status_is_error(&status, metadata)
                            || tool_output_is_error(output.as_ref(), metadata);
                        if is_error {
                            entry.1 += 1;
                            tool_error_count += 1;
                        } else {
                            tool_success_count += 1;
                        }

                        if let Some((start, end)) = part_time_range_ms(part)
                            && end >= start
                        {
                            tool_latencies_ms.push((end - start).min(u32::MAX as i64) as u32);
                        }

                        if let Some(output) = output.as_ref() {
                            track_tool_output_files(
                                &raw_tool,
                                output,
                                &mut files_modified,
                                &mut files_read,
                            );
                        }

                        let output_summary = redactor.redact(&truncate(
                            &summarize_tool_output(output.as_ref(), metadata),
                            OUTPUT_SUMMARY_MAX,
                        ));

                        tool_calls.push(ToolCall {
                            tool_name,
                            tool_use_id: call_id.clone(),
                            input_summary,
                        });

                        if !output_summary.is_empty() {
                            tool_results.push(ToolResult {
                                tool_use_id: call_id,
                                is_error,
                                output_summary,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        diff_messages.push(DiffMessage {
            index: index as u32,
            role,
            timestamp: timestamp_ms.map(timestamp_ms_to_rfc3339),
            text: if text_parts.is_empty() {
                None
            } else {
                Some(truncate(&text_parts.join("\n"), TEXT_MAX))
            },
            has_thinking,
            tool_calls,
            tool_results,
            input_tokens: int_field_from(tokens, &["input"]).map(|v| v as u64),
            output_tokens: int_field_from(tokens, &["output"]).map(|v| v as u64),
            cache_read_tokens: int_field_from(tokens, &["cache", "read"]).map(|v| v as u64),
            model,
            stop_reason: finish,
        });
    }

    files_modified.append(&mut diff_files);
    files_modified.sort();
    files_modified.dedup();
    files_read.sort();
    files_read.dedup();

    let tool_calls = tool_counts
        .into_iter()
        .map(|(tool_name, (count, error_count))| ToolCallSummary {
            tool_name,
            count,
            error_count,
        })
        .collect::<Vec<_>>();
    let total_tool_calls = tool_calls.iter().map(|tool| tool.count).sum();
    let user_message_count = diff_messages.iter().filter(|m| m.role == "user").count() as u32;
    let assistant_message_count = diff_messages
        .iter()
        .filter(|m| m.role == "assistant")
        .count() as u32;

    Ok(DiffSession {
        session_id,
        org_id: org_id.to_string(),
        engineer_id: engineer_id.to_string(),
        machine_id: machine_id.to_string(),
        tool: "opencode".to_string(),
        tool_version,
        diff_cli_version: env!("CARGO_PKG_VERSION").to_string(),
        project_path: project_path.clone(),
        repo_name: repo_name_from_path(&project_path),
        git_branch: None,
        primary_model: model_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(m, _)| m),
        started_at: started_ms.map(timestamp_ms_to_rfc3339),
        ended_at: ended_ms.map(timestamp_ms_to_rfc3339),
        duration_seconds: match (started_ms, ended_ms) {
            (Some(start), Some(end)) if end >= start => Some(((end - start) / 1000) as u64),
            _ => None,
        },
        message_count: diff_messages.len() as u32,
        user_message_count,
        assistant_message_count,
        messages: diff_messages,
        security_detector_version: None,
        tool_calls,
        total_tool_calls,
        reliability_telemetry: if tool_success_count == 0
            && tool_error_count == 0
            && tool_latencies_ms.is_empty()
        {
            None
        } else {
            Some(ReliabilityTelemetry {
                api_error_count: 0,
                tool_error_count,
                tool_success_count,
                retry_count: 0,
                avg_api_latency_ms: None,
                p95_api_latency_ms: None,
                avg_tool_latency_ms: summarize_mean(&tool_latencies_ms),
                p95_tool_latency_ms: summarize_p95(&tool_latencies_ms),
            })
        },
        total_input_tokens,
        total_output_tokens,
        total_cache_read_tokens,
        total_cache_creation_tokens,
        estimated_cost_usd: 0.0,
        auto_classification: None,
        files_modified,
        files_read,
        config_snapshot: None,
    })
}

pub fn session_update_marker(session_path: &Path) -> Result<Option<String>> {
    let content = std::fs::read_to_string(session_path)
        .with_context(|| format!("Failed to read {}", session_path.display()))?;

    if looks_like_exported_sample(&content) {
        let sections = split_exported_sections(&content)?;
        return Ok(int_field(&sections.session, &["time_updated"])
            .or_else(|| int_field(&sections.session, &["time", "updated"]))
            .map(|value| value.to_string()));
    }

    let value: Value = serde_json::from_str(&content).with_context(|| {
        format!(
            "Failed to parse session JSON from {}",
            session_path.display()
        )
    })?;
    Ok(int_field(&value, &["time_updated"])
        .or_else(|| int_field(&value, &["time", "updated"]))
        .map(|value| value.to_string()))
}

fn collect_session_files(dir: &Path, sessions: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_session_files(&path, sessions)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        let value: Value = match serde_json::from_str(&content) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(id) = string_field(&value, &["id"]) {
            sessions.push((id, path));
        }
    }
    Ok(())
}

fn looks_like_exported_sample(content: &str) -> bool {
    content.starts_with("=== SESSION ===")
}

fn parse_exported_sample(content: &str) -> Result<ParsedOpenCodeSession> {
    let sections = split_exported_sections(content)?;
    let session = sections.session;
    let messages = sections.messages;
    let mut parts_by_message: PartMap = HashMap::new();
    for part in sections.parts {
        if let Some(message_id) =
            string_field(&part, &["message_id"]).or_else(|| string_field(&part, &["messageID"]))
        {
            parts_by_message.entry(message_id).or_default().push(part);
        }
    }
    Ok(ParsedOpenCodeSession {
        session,
        messages,
        part_map: parts_by_message,
        diff_files: vec![],
    })
}

fn parse_storage_session(session_path: &Path, content: &str) -> Result<ParsedOpenCodeSession> {
    let session: Value = serde_json::from_str(content).with_context(|| {
        format!(
            "Failed to parse session JSON from {}",
            session_path.display()
        )
    })?;
    let data_root = infer_data_root(session_path)?;
    let session_id = string_field(&session, &["id"]).context("OpenCode session missing id")?;
    let message_dir = data_root.join("storage").join("message").join(&session_id);
    let part_root = data_root.join("storage").join("part");
    let diff_path = data_root
        .join("storage")
        .join("session_diff")
        .join(format!("{}.json", session_id));

    let mut messages = read_json_values(&message_dir)?;
    messages.sort_by_key(message_time_created);

    let mut parts_by_message: PartMap = HashMap::new();
    for message in &messages {
        if let Some(message_id) = string_field(message, &["id"]) {
            let mut parts = read_json_values(&part_root.join(&message_id))?;
            parts.sort_by_key(part_time_created);
            parts_by_message.insert(message_id, parts);
        }
    }

    let diff_files = if diff_path.exists() {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&diff_path)?)?;
        match value {
            Value::Array(rows) => rows
                .into_iter()
                .filter_map(|row| string_field(&row, &["file"]))
                .collect(),
            _ => vec![],
        }
    } else {
        vec![]
    };

    Ok(ParsedOpenCodeSession {
        session,
        messages,
        part_map: parts_by_message,
        diff_files,
    })
}

struct ExportedSections {
    session: Value,
    messages: Vec<Value>,
    parts: Vec<Value>,
}

fn split_exported_sections(content: &str) -> Result<ExportedSections> {
    let mut section = "";
    let mut buf = String::new();
    let mut session = None;
    let mut messages = Vec::new();
    let mut parts = Vec::new();

    let mut flush = |section: &str, buf: &mut String| -> Result<()> {
        let chunk = buf.trim();
        if chunk.is_empty() {
            return Ok(());
        }
        let value: Value = serde_json::from_str(chunk)?;
        match section {
            "session" => session = Some(value),
            "messages" => messages.push(value),
            "parts" => parts.push(value),
            _ => {}
        }
        buf.clear();
        Ok(())
    };

    for line in content.lines() {
        match line.trim() {
            "=== SESSION ===" => {
                flush(section, &mut buf)?;
                section = "session";
            }
            "=== MESSAGES ===" => {
                flush(section, &mut buf)?;
                section = "messages";
            }
            line if line.starts_with("=== PARTS") => {
                flush(section, &mut buf)?;
                section = "parts";
            }
            _ => {
                if line.trim().is_empty()
                    && buf.trim().starts_with('{')
                    && buf.trim().ends_with('}')
                {
                    flush(section, &mut buf)?;
                } else {
                    if !buf.is_empty() {
                        buf.push('\n');
                    }
                    buf.push_str(line);
                }
            }
        }
    }
    flush(section, &mut buf)?;

    Ok(ExportedSections {
        session: session.context("exported OpenCode sample missing session section")?,
        messages,
        parts,
    })
}

fn infer_data_root(session_path: &Path) -> Result<PathBuf> {
    let parent = session_path
        .parent()
        .context("session path has no parent")?;
    if parent.file_name().and_then(|name| name.to_str()) == Some("session")
        && parent
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("storage")
    {
        return parent
            .parent()
            .and_then(|p| p.parent())
            .context("invalid storage tree")
            .map(Path::to_path_buf);
    }
    if parent
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        == Some("session")
        && parent
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("storage")
    {
        return parent
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .context("invalid storage tree")
            .map(Path::to_path_buf);
    }
    bail!(
        "Unsupported OpenCode session path layout: {}",
        session_path.display()
    )
}

fn read_json_values(dir: &Path) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    if !dir.exists() {
        return Ok(values);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file()
            || path.extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        if let Ok(value) = serde_json::from_str::<Value>(&content) {
            values.push(value);
        }
    }
    Ok(values)
}

fn message_time_created(message: &Value) -> i64 {
    int_field(message, &["time_created"])
        .or_else(|| int_field(message, &["time", "created"]))
        .unwrap_or(0)
}

fn part_time_created(part: &Value) -> i64 {
    int_field(part, &["time_created"])
        .or_else(|| int_field(part, &["data", "time_created"]))
        .or_else(|| int_field(part, &["time", "start"]))
        .or_else(|| int_field(part, &["data", "time", "start"]))
        .unwrap_or(0)
}

fn part_time_range_ms(part: &Value) -> Option<(i64, i64)> {
    let start = int_field(part, &["state", "time", "start"])
        .or_else(|| int_field(part, &["data", "state", "time", "start"]))
        .or_else(|| int_field(part, &["time", "start"]))
        .or_else(|| int_field(part, &["data", "time", "start"]));
    let end = int_field(part, &["state", "time", "end"])
        .or_else(|| int_field(part, &["data", "state", "time", "end"]))
        .or_else(|| int_field(part, &["time", "end"]))
        .or_else(|| int_field(part, &["data", "time", "end"]));
    Some((start?, end?))
}

fn string_field(value: &Value, path: &[&str]) -> Option<String> {
    value
        .pointer(&pointer(path))?
        .as_str()
        .map(ToString::to_string)
}

fn int_field(value: &Value, path: &[&str]) -> Option<i64> {
    value.pointer(&pointer(path))?.as_i64()
}

fn object_field<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let value = value.pointer(&pointer(path))?;
    value.is_object().then_some(value)
}

fn value_field(value: &Value, path: &[&str]) -> Option<Value> {
    value.pointer(&pointer(path)).cloned()
}

fn int_field_from(value: Option<&Value>, path: &[&str]) -> Option<i64> {
    value?.pointer(&pointer(path))?.as_i64()
}

fn string_array_field(value: &Value, path: &[&str]) -> Vec<String> {
    value
        .pointer(&pointer(path))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn pointer(path: &[&str]) -> String {
    format!("/{}", path.join("/"))
}

fn normalize_tool_name(name: &str) -> &str {
    match name {
        "read" => "Read",
        "write" => "Write",
        "edit" => "Edit",
        "bash" => "Bash",
        "grep" => "Grep",
        "glob" => "Glob",
        "apply_patch" => "apply_patch",
        other => other,
    }
}

fn summarize_tool_input(tool: &str, input: &Value) -> String {
    match tool {
        "read" | "write" | "edit" => input
            .pointer("/filePath")
            .or_else(|| input.pointer("/path"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                serde_json::to_string(input).unwrap_or_else(|_| "(unparseable)".to_string())
            }),
        "bash" => input
            .pointer("/command")
            .and_then(Value::as_str)
            .unwrap_or("(no command)")
            .to_string(),
        "grep" | "glob" => {
            serde_json::to_string(input).unwrap_or_else(|_| "(unparseable)".to_string())
        }
        _ => serde_json::to_string(input).unwrap_or_else(|_| "(unparseable)".to_string()),
    }
}

fn summarize_tool_output(output: Option<&Value>, metadata: Option<&Value>) -> String {
    if let Some(path) = metadata
        .and_then(|m| m.pointer("/outputPath"))
        .and_then(Value::as_str)
        && let Ok(content) = std::fs::read_to_string(path)
    {
        return content;
    }

    match output {
        Some(Value::String(s)) => s.clone(),
        Some(value) if !value.is_null() => serde_json::to_string(value).unwrap_or_default(),
        _ => metadata
            .and_then(|m| m.pointer("/output"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    }
}

fn track_tool_files(
    tool: &str,
    input: &Value,
    files_modified: &mut Vec<String>,
    files_read: &mut Vec<String>,
) {
    match tool {
        "read" => {
            if let Some(path) = input.pointer("/filePath").and_then(Value::as_str) {
                files_read.push(path.to_string());
            }
        }
        "write" | "edit" => {
            if let Some(path) = input.pointer("/filePath").and_then(Value::as_str) {
                files_modified.push(path.to_string());
            }
        }
        "glob" | "grep" => {
            if let Some(path) = input.pointer("/path").and_then(Value::as_str) {
                files_read.push(path.to_string());
            }
        }
        "apply_patch" => {
            if let Some(text) = input.pointer("/input").and_then(Value::as_str) {
                track_patch_files(text, files_modified);
            }
        }
        _ => {}
    }
}

fn track_tool_output_files(
    tool: &str,
    output: &Value,
    files_modified: &mut Vec<String>,
    files_read: &mut Vec<String>,
) {
    match tool {
        "glob" | "grep" => {
            if let Some(text) = output.as_str() {
                for line in text.lines() {
                    let candidate = line.split_once(':').map(|(p, _)| p).unwrap_or(line).trim();
                    if candidate.starts_with('/') || candidate.starts_with("src/") {
                        files_read.push(candidate.to_string());
                    }
                }
            }
        }
        "apply_patch" => {
            if let Some(text) = output.as_str() {
                track_patch_files(text, files_modified);
            }
        }
        _ => {}
    }
}

fn track_patch_files(text: &str, files_modified: &mut Vec<String>) {
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            files_modified.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Add File: ") {
            files_modified.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
            files_modified.push(path.trim().to_string());
        }
    }
}

fn tool_status_is_error(status: &str, metadata: Option<&Value>) -> bool {
    if status != "completed" {
        return true;
    }
    metadata
        .and_then(|m| m.pointer("/exit"))
        .and_then(Value::as_i64)
        .is_some_and(|exit| exit != 0)
}

fn tool_output_is_error(output: Option<&Value>, metadata: Option<&Value>) -> bool {
    if metadata
        .and_then(|m| m.pointer("/exit_code"))
        .and_then(Value::as_i64)
        .is_some_and(|exit| exit != 0)
    {
        return true;
    }
    match output {
        Some(Value::String(text)) => text
            .lines()
            .any(|line| line.starts_with("Exit code: ") && !line.ends_with('0')),
        _ => false,
    }
}

fn repo_name_from_path(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
}

fn timestamp_ms_to_rfc3339(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

fn summarize_mean(values: &[u32]) -> Option<u32> {
    if values.is_empty() {
        None
    } else {
        Some((values.iter().map(|v| *v as u64).sum::<u64>() / values.len() as u64) as u32)
    }
}

fn summarize_p95(values: &[u32]) -> Option<u32> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64) * 0.95).ceil() as usize;
    sorted
        .get(idx.saturating_sub(1).min(sorted.len() - 1))
        .copied()
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
