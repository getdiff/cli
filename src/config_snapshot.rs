use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::types::ConfigSnapshotPayload;

pub fn capture_claude_snapshot(project_path: &str) -> Result<ConfigSnapshotPayload> {
    let project_root = PathBuf::from(project_path);

    let system_prompt_path = project_root.join("CLAUDE.md");
    let settings_path = project_root.join(".claude").join("settings.json");
    let settings_local_path = project_root.join(".claude").join("settings.local.json");
    let agents_dir = project_root.join(".claude").join("agents");

    let system_prompt_hash = hash_file_if_exists(&system_prompt_path);
    let settings_hash = hash_file_if_exists(&settings_path);
    let settings_local_hash = hash_file_if_exists(&settings_local_path);

    let (active_hooks_count, active_mcps_count, permission_mode) =
        summarize_settings(&settings_path, &settings_local_path);

    let active_agents_count = count_agent_markdown_files(&agents_dir);

    let fingerprint = stable_snapshot_fingerprint(
        system_prompt_hash.as_deref(),
        settings_hash.as_deref(),
        settings_local_hash.as_deref(),
        active_agents_count,
        active_hooks_count,
        active_mcps_count,
        &permission_mode,
    );

    let project_id = stable_project_id(project_path);

    let snapshot = ConfigSnapshotPayload::from_redacted(
        "claude",
        serde_json::json!({
            "project_id": project_id,
            "system_prompt_hash": system_prompt_hash,
            "settings_hash": settings_hash,
            "settings_local_hash": settings_local_hash,
            "active_agents_count": active_agents_count,
            "active_hooks_count": active_hooks_count,
            "active_mcps_count": active_mcps_count,
            "permission_mode": permission_mode,
            "config_fingerprint": fingerprint,
        }),
    )
    .map_err(|error| anyhow::anyhow!(error))?;

    Ok(snapshot)
}

fn stable_project_id(project_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(project_path.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_file_if_exists(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Some(format!("sha256:{:x}", hasher.finalize()))
}

fn count_agent_markdown_files(agents_dir: &Path) -> u64 {
    let entries = match std::fs::read_dir(agents_dir) {
        Ok(entries) => entries,
        Err(_) => return 0,
    };

    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        })
        .count() as u64
}

fn summarize_settings(settings_path: &Path, settings_local_path: &Path) -> (u64, u64, String) {
    let settings = read_json_map(settings_path);
    let local = read_json_map(settings_local_path);

    let hooks_count = count_hooks(&settings) + count_hooks(&local);
    let mcps_count = count_mcps(&settings) + count_mcps(&local);

    let permission_mode = permission_mode(&local)
        .or_else(|| permission_mode(&settings))
        .unwrap_or_else(|| "default".to_string());

    (hooks_count, mcps_count, permission_mode)
}

fn read_json_map(path: &Path) -> Option<serde_json::Map<String, serde_json::Value>> {
    let content = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    value.as_object().cloned()
}

fn count_hooks(map: &Option<serde_json::Map<String, serde_json::Value>>) -> u64 {
    let hooks = map
        .as_ref()
        .and_then(|m| m.get("hooks"))
        .and_then(|v| v.as_object());

    hooks
        .map(|hooks_obj| {
            hooks_obj
                .values()
                .map(|value| value.as_array().map_or(0, |arr| arr.len() as u64))
                .sum()
        })
        .unwrap_or(0)
}

fn count_mcps(map: &Option<serde_json::Map<String, serde_json::Value>>) -> u64 {
    map.as_ref()
        .and_then(|m| m.get("mcpServers"))
        .and_then(|v| v.as_object())
        .map_or(0, |obj| obj.len() as u64)
}

fn permission_mode(map: &Option<serde_json::Map<String, serde_json::Value>>) -> Option<String> {
    let permissions = map
        .as_ref()
        .and_then(|m| m.get("permissions"))
        .and_then(|v| v.as_object())?;

    if permissions.contains_key("allow") {
        return Some("allowlist".to_string());
    }
    if permissions.contains_key("deny") {
        return Some("denylist".to_string());
    }
    Some("custom".to_string())
}

fn stable_snapshot_fingerprint(
    system_prompt_hash: Option<&str>,
    settings_hash: Option<&str>,
    settings_local_hash: Option<&str>,
    active_agents_count: u64,
    active_hooks_count: u64,
    active_mcps_count: u64,
    permission_mode: &str,
) -> String {
    let mut payload = BTreeMap::new();
    payload.insert(
        "active_agents_count",
        serde_json::Value::from(active_agents_count),
    );
    payload.insert(
        "active_hooks_count",
        serde_json::Value::from(active_hooks_count),
    );
    payload.insert(
        "active_mcps_count",
        serde_json::Value::from(active_mcps_count),
    );
    payload.insert(
        "permission_mode",
        serde_json::Value::String(permission_mode.to_string()),
    );
    payload.insert("settings_hash", optional_string_or_null(settings_hash));
    payload.insert(
        "settings_local_hash",
        optional_string_or_null(settings_local_hash),
    );
    payload.insert(
        "system_prompt_hash",
        optional_string_or_null(system_prompt_hash),
    );

    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let mut hasher = Sha256::new();
    hasher.update(payload_bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn optional_string_or_null(value: Option<&str>) -> serde_json::Value {
    match value {
        Some(v) => serde_json::Value::String(v.to_string()),
        None => serde_json::Value::Null,
    }
}
