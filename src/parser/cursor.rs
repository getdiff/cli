use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::redact::Redactor;
use crate::types::*;

const TEXT_MAX: usize = 5000;

// ---------------------------------------------------------------------------
// Raw JSONL line types (what Cursor writes to agent-transcripts/)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawLine {
    role: Option<String>,
    message: Option<RawMessage>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    content: Option<Value>,
}

// ---------------------------------------------------------------------------
// AI-tracking DB enrichment
// ---------------------------------------------------------------------------

struct TrackingHint {
    file_name: String,
    timestamp: DateTime<Utc>,
    model: Option<String>,
}

/// Best-effort: query ~/.cursor/ai-tracking/ai-code-tracking.db for file edits
/// linked to this conversation.
fn load_tracking_hints(conversation_id: &str) -> Vec<TrackingHint> {
    let db_path = match dirs::home_dir() {
        Some(h) => h
            .join(".cursor")
            .join("ai-tracking")
            .join("ai-code-tracking.db"),
        None => return vec![],
    };

    if !db_path.exists() {
        return vec![];
    }

    let Ok(db_str) = db_path.to_str().ok_or(()) else {
        return vec![];
    };

    // Shell out to sqlite3 rather than adding a native SQLite dependency.
    let output = std::process::Command::new("sqlite3")
        .arg(db_str)
        .arg(format!(
            "SELECT fileName, timestamp, model FROM ai_code_hashes WHERE conversationId = '{}' ORDER BY timestamp;",
            conversation_id.replace('\'', "''")
        ))
        .output();

    let Ok(output) = output else {
        return vec![];
    };

    if !output.status.success() {
        return vec![];
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() < 2 {
                return None;
            }
            let file_name = parts[0].to_string();
            let ts_millis: i64 = parts[1].parse().ok()?;
            let timestamp = Utc.timestamp_millis_opt(ts_millis).single()?;
            let model = parts.get(2).and_then(|m| {
                let m = m.trim();
                if m.is_empty() || m == "default" {
                    None
                } else {
                    Some(m.to_string())
                }
            });
            Some(TrackingHint {
                file_name,
                timestamp,
                model,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

pub fn default_projects_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("Could not determine home directory")?
        .join(".cursor")
        .join("projects"))
}

pub fn find_session_file(session_id: &str, root_override: Option<&Path>) -> Result<PathBuf> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_projects_dir()?,
    };

    if !root.exists() {
        anyhow::bail!("Cursor projects directory not found at {}", root.display());
    }

    // Walk <root>/*/agent-transcripts/<session_id>/<session_id>.jsonl
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let transcripts_dir = entry.path().join("agent-transcripts").join(session_id);
        let candidate = transcripts_dir.join(format!("{}.jsonl", session_id));
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    anyhow::bail!("Session {} not found under {}", session_id, root.display())
}

pub fn discover_sessions(root_override: Option<&Path>) -> Result<Vec<(String, PathBuf)>> {
    let root = match root_override {
        Some(path) => path.to_path_buf(),
        None => default_projects_dir()?,
    };

    let mut sessions = Vec::new();
    if !root.exists() {
        return Ok(sessions);
    }

    // Walk <root>/*/agent-transcripts/*/*.jsonl
    for project_entry in std::fs::read_dir(&root)? {
        let project_entry = project_entry?;
        if !project_entry.file_type()?.is_dir() {
            continue;
        }
        let transcripts_dir = project_entry.path().join("agent-transcripts");
        if !transcripts_dir.is_dir() {
            continue;
        }
        for session_entry in std::fs::read_dir(&transcripts_dir)? {
            let session_entry = session_entry?;
            if !session_entry.file_type()?.is_dir() {
                continue;
            }
            let session_dir = session_entry.path();
            if let Some(session_id) = session_dir.file_name().and_then(|n| n.to_str()) {
                let jsonl_path = session_dir.join(format!("{}.jsonl", session_id));
                if jsonl_path.exists() {
                    sessions.push((session_id.to_string(), jsonl_path));
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

/// Derive the project path from the Cursor project directory name.
/// e.g. "Users-ericand-openclaw" -> "/Users/ericand/openclaw"
fn project_path_from_dir(dir_name: &str) -> Option<String> {
    // Skip temp directories (var-folders-...)
    if dir_name.starts_with("var-folders") {
        return None;
    }
    Some(dir_name.replacen('-', "/", 1).replace('-', "/"))
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

    // Session ID from path: .../agent-transcripts/<uuid>/<uuid>.jsonl
    let session_id = session_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    // Project path from the project directory name
    // Path structure: <root>/<project-dir>/agent-transcripts/<uuid>/<uuid>.jsonl
    let project_dir_name = session_path
        .parent() // <uuid>/
        .and_then(|p| p.parent()) // agent-transcripts/
        .and_then(|p| p.parent()) // <project-dir>/
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let project_path = project_path_from_dir(project_dir_name).unwrap_or_default();
    let repo_name = Path::new(&project_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string());

    // Best-effort timestamps from file metadata
    let file_meta = std::fs::metadata(session_path).ok();
    let started_at = file_meta
        .as_ref()
        .and_then(|m| m.created().ok())
        .map(|t| DateTime::<Utc>::from(t).to_rfc3339());
    let ended_at = file_meta
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(|t| DateTime::<Utc>::from(t).to_rfc3339());
    let duration_seconds = match (&started_at, &ended_at) {
        (Some(s), Some(e)) => {
            let s = DateTime::parse_from_rfc3339(s).ok();
            let e = DateTime::parse_from_rfc3339(e).ok();
            match (s, e) {
                (Some(s), Some(e)) => Some(e.signed_duration_since(s).num_seconds().max(0) as u64),
                _ => None,
            }
        }
        _ => None,
    };

    // Load tracking hints from AI tracking DB
    let hints = load_tracking_hints(&session_id);
    let mut files_modified: Vec<String> = hints.iter().map(|h| h.file_name.clone()).collect();
    let primary_model = hints.iter().find_map(|h| h.model.clone());

    // Build a map of hint timestamps to enrich assistant messages
    // We'll assign hint timestamps to assistant messages that follow user messages
    let hint_timestamps: Vec<DateTime<Utc>> = hints.iter().map(|h| h.timestamp).collect();

    let mut messages: Vec<DiffMessage> = Vec::new();
    let mut message_index: u32 = 0;

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

        let role = raw.role.as_deref().unwrap_or("unknown");
        if role != "user" && role != "assistant" {
            continue;
        }

        let text = extract_text_content(&raw, redactor);

        messages.push(DiffMessage {
            index: message_index,
            role: role.to_string(),
            timestamp: None,
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

    // Best-effort: stamp assistant messages with tracking hint timestamps.
    // Assign each hint timestamp to the next assistant message that doesn't have one yet,
    // working backwards from the end (edits tend to correspond to later assistant messages).
    let mut hint_idx = hint_timestamps.len();
    for msg in messages.iter_mut().rev() {
        if msg.role == "assistant" && msg.timestamp.is_none() && hint_idx > 0 {
            hint_idx -= 1;
            msg.timestamp = Some(hint_timestamps[hint_idx].to_rfc3339());
        }
    }

    let user_count = messages.iter().filter(|m| m.role == "user").count() as u32;
    let assistant_count = messages.iter().filter(|m| m.role == "assistant").count() as u32;

    files_modified.sort();
    files_modified.dedup();

    Ok(DiffSession {
        session_id,
        org_id: org_id.to_string(),
        engineer_id: engineer_id.to_string(),
        machine_id: machine_id.to_string(),
        tool: "cursor".to_string(),
        tool_version: "unknown".to_string(),
        diff_cli_version: env!("CARGO_PKG_VERSION").to_string(),
        project_path,
        repo_name,
        git_branch: None,
        primary_model,
        started_at,
        ended_at,
        duration_seconds,
        messages,
        message_count: message_index,
        user_message_count: user_count,
        assistant_message_count: assistant_count,
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
        files_modified,
        files_read: vec![],
        config_snapshot: None,
    })
}

// ---------------------------------------------------------------------------
// Content extraction
// ---------------------------------------------------------------------------

fn extract_text_content(raw: &RawLine, redactor: &Redactor) -> Option<String> {
    let msg = raw.message.as_ref()?;
    let content = msg.content.as_ref()?;
    let blocks = content.as_array()?;

    let text_parts: Vec<String> = blocks
        .iter()
        .filter_map(|block| {
            let block_type = block.get("type").and_then(|t| t.as_str())?;
            if block_type == "text" {
                let text = block.get("text").and_then(|t| t.as_str())?;
                // Strip the <user_query> wrapper that Cursor adds
                let text = strip_user_query_wrapper(text);
                Some(redactor.redact(&text))
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

/// Strip the `<user_query>...</user_query>` wrapper Cursor adds around user input.
fn strip_user_query_wrapper(text: &str) -> String {
    let trimmed = text.trim();
    if let Some(inner) = trimmed
        .strip_prefix("<user_query>")
        .and_then(|s| s.strip_suffix("</user_query>"))
    {
        inner.trim().to_string()
    } else {
        trimmed.to_string()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_user_query_removes_wrapper() {
        let input = "<user_query>\nwhat is the weather\n</user_query>";
        assert_eq!(strip_user_query_wrapper(input), "what is the weather");
    }

    #[test]
    fn strip_user_query_preserves_plain_text() {
        let input = "just a normal message";
        assert_eq!(strip_user_query_wrapper(input), "just a normal message");
    }
}
