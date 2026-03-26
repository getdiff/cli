use anyhow::{Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::parser::{self, ProviderKind, SessionLocator};

/// How long a file must be idle (no writes) before we check for changes.
#[allow(dead_code)]
const IDLE_THRESHOLD: Duration = Duration::from_secs(60);

/// How long between scan cycles when running in poll mode.
#[allow(dead_code)]
const SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// State file tracking uploaded session sizes.
const STATE_FILE: &str = "state.json";

/// Legacy upload log (for migration).
const LEGACY_UPLOAD_LOG: &str = "uploaded.log";

// ---------------------------------------------------------------
// Upload state: tracks session sizes for incremental re-upload
// ---------------------------------------------------------------

/// Per-session upload state.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SessionState {
    /// File size in bytes at last upload.
    pub uploaded_size: u64,
    /// Timestamp of last upload.
    pub uploaded_at: String,
    /// Provider-specific progress marker for incremental uploads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_marker: Option<String>,
}

/// Full upload state: map of session_id -> SessionState.
pub type UploadState = HashMap<String, SessionState>;

fn state_key(provider: ProviderKind, session_id: &str) -> String {
    format!("{}:{}", provider.as_str(), session_id)
}

fn normalize_state_keys(state: UploadState) -> UploadState {
    state
        .into_iter()
        .map(|(key, value)| {
            if key.contains(':') {
                (key, value)
            } else {
                (state_key(ProviderKind::ClaudeCode, &key), value)
            }
        })
        .collect()
}

/// Reads the upload state from state.json. If it doesn't exist, migrates
/// from the legacy uploaded.log (marking those sessions as uploaded with
/// size 0 so they'll get re-uploaded with the full data on next change).
pub fn read_state(diff_dir: &Path) -> Result<UploadState> {
    let state_path = diff_dir.join(STATE_FILE);

    if state_path.exists() {
        let contents = std::fs::read_to_string(&state_path)?;
        match serde_json::from_str::<UploadState>(&contents) {
            Ok(state) => return Ok(normalize_state_keys(state)),
            Err(e) => {
                eprintln!(
                    "Warning: corrupt state file {}, resetting upload state: {}",
                    state_path.display(),
                    e
                );
                return Ok(UploadState::new());
            }
        }
    }

    // Migrate from legacy uploaded.log
    let mut state = UploadState::new();
    for log_name in [LEGACY_UPLOAD_LOG] {
        let log_path = diff_dir.join(log_name);
        if log_path.exists() {
            let contents = std::fs::read_to_string(&log_path)?;
            for line in contents.lines() {
                let id = line.trim();
                if !id.is_empty() {
                    state.insert(
                        state_key(ProviderKind::ClaudeCode, id),
                        SessionState {
                            uploaded_size: 0, // Will trigger re-upload
                            uploaded_at: chrono::Utc::now().to_rfc3339(),
                            uploaded_marker: None,
                        },
                    );
                }
            }
        }
    }

    if !state.is_empty() {
        write_state(diff_dir, &state)?;
    }

    Ok(state)
}

/// Writes the full upload state to state.json.
pub fn write_state(diff_dir: &Path, state: &UploadState) -> Result<()> {
    std::fs::create_dir_all(diff_dir)?;
    let state_path = diff_dir.join(STATE_FILE);
    let contents = serde_json::to_string_pretty(state)?;
    std::fs::write(&state_path, contents)?;
    Ok(())
}

/// Updates the state for a single session after successful upload.
pub fn update_session_state(
    diff_dir: &Path,
    state: &mut UploadState,
    provider: ProviderKind,
    session_id: &str,
    file_size: u64,
    uploaded_marker: Option<String>,
) -> Result<()> {
    state.insert(
        state_key(provider, session_id),
        SessionState {
            uploaded_size: file_size,
            uploaded_at: chrono::Utc::now().to_rfc3339(),
            uploaded_marker,
        },
    );
    write_state(diff_dir, state)
}

// ---------------------------------------------------------------
// Session discovery: find all .jsonl session files
// ---------------------------------------------------------------

pub fn discover_sessions(
    provider: ProviderKind,
    source_root: &Path,
) -> Result<Vec<SessionLocator>> {
    provider.discover_sessions(Some(source_root))
}

/// Returns the last modification time of a file.
pub fn file_modified_time(path: &Path) -> Result<SystemTime> {
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.modified()?)
}

/// Returns the file size in bytes.
pub fn file_size(path: &Path) -> Result<u64> {
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.len())
}

/// Checks if a file has been idle (not modified) for at least the threshold duration.
pub fn is_session_idle(path: &Path, threshold: Duration) -> Result<bool> {
    let modified = file_modified_time(path)?;
    let elapsed = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    Ok(elapsed >= threshold)
}

/// Returns sessions that have changed since last upload:
/// - File is idle (not modified in >threshold)
/// - File size has grown since last upload (or never uploaded)
pub fn find_changed_sessions(
    provider: ProviderKind,
    source_root: &Path,
    state: &UploadState,
    threshold: Duration,
) -> Result<Vec<SessionLocator>> {
    let all_sessions = discover_sessions(provider, source_root)?;
    let mut changed = Vec::new();

    for locator in all_sessions {
        if provider_uses_idle_threshold(locator.provider)
            && !is_session_idle(&locator.path, threshold)?
        {
            continue;
        }
        let current_size = file_size(&locator.path)?;
        let current_marker = session_progress_marker(&locator)?;
        let needs_upload = match state.get(&state_key(locator.provider, &locator.session_id)) {
            Some(prev) => session_needs_upload(
                locator.provider,
                prev,
                current_size,
                current_marker.as_deref(),
            ),
            None => true, // Never uploaded
        };
        if needs_upload {
            changed.push(locator);
        }
    }

    Ok(changed)
}

fn provider_uses_idle_threshold(provider: ProviderKind) -> bool {
    !matches!(provider, ProviderKind::OpenCode)
}

fn session_progress_marker(locator: &SessionLocator) -> Result<Option<String>> {
    match locator.provider {
        ProviderKind::OpenCode => parser::opencode::session_update_marker(&locator.path),
        _ => Ok(None),
    }
}

fn session_needs_upload(
    provider: ProviderKind,
    previous: &SessionState,
    current_size: u64,
    current_marker: Option<&str>,
) -> bool {
    match provider {
        ProviderKind::OpenCode => match (previous.uploaded_marker.as_deref(), current_marker) {
            (Some(prev), Some(curr)) => curr != prev,
            (None, Some(_)) => true,
            _ => current_size > previous.uploaded_size,
        },
        _ => current_size > previous.uploaded_size,
    }
}

// ---------------------------------------------------------------
// Watch loop: the main daemon logic
// ---------------------------------------------------------------

/// Configuration for the watch daemon.
pub struct WatchConfig {
    pub providers: Vec<ProviderKind>,
    pub diff_dir: PathBuf,
    pub server: String,
    pub api_key: String,
    pub org_id: String,
    pub engineer_id: String,
    pub machine_id: String,
    pub idle_threshold: Duration,
    pub scan_interval: Duration,
}

impl WatchConfig {
    pub fn default_source_root(provider: ProviderKind) -> Result<PathBuf> {
        match provider {
            ProviderKind::ClaudeCode => parser::claude_code::default_projects_dir(),
            ProviderKind::Codex => parser::codex::default_sessions_dir(),
            ProviderKind::OpenCode => parser::opencode::default_data_dir(),
            ProviderKind::OpenClaw => parser::openclaw::default_sessions_dir(),
            ProviderKind::Cursor => parser::cursor::default_projects_dir(),
            ProviderKind::Copilot => parser::copilot::default_session_state_dir(),
            ProviderKind::GeminiCli => parser::gemenicli::default_sessions_dir(),
        }
    }

    pub fn default_diff_dir() -> PathBuf {
        dirs::home_dir()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".diff")
    }
}

/// Runs the watch loop. This function runs forever (until killed).
pub async fn run_watch_loop(config: WatchConfig) -> Result<()> {
    let provider_names: Vec<&str> = config.providers.iter().map(|p| p.as_str()).collect();
    eprintln!(
        "Diff daemon starting. Watching providers: {}",
        provider_names.join(", ")
    );
    eprintln!("  Server: {}", config.server);
    eprintln!("  Idle threshold: {}s", config.idle_threshold.as_secs());
    eprintln!("  Scan interval: {}s", config.scan_interval.as_secs());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    // Load state (migrates from legacy uploaded.log if needed)
    let mut state = read_state(&config.diff_dir)?;

    // Initial scan: upload all changed sessions
    eprintln!("\nRunning initial scan...");
    let initial_count = process_changed_sessions(&config, &client, &mut state).await?;
    if initial_count > 0 {
        eprintln!("Initial scan: {} session(s) uploaded.", initial_count);
    } else {
        eprintln!("No sessions to upload.");
    }

    // Initial artifact sync
    if let Err(e) = crate::artifact_sync::run_sync_cycle(&config.server, &config.api_key, &config.diff_dir).await {
        eprintln!("Artifact sync error: {}", e);
    }

    // Main watch loop
    // Artifact sync runs every ARTIFACT_SYNC_INTERVAL cycles (~2.5 min at 30s scan)
    // since config files change infrequently compared to sessions.
    const ARTIFACT_SYNC_INTERVAL: u64 = 5;
    let mut cycle: u64 = 0;

    eprintln!("\nWatching for new and updated sessions...");
    loop {
        tokio::time::sleep(config.scan_interval).await;
        cycle += 1;

        let count = process_changed_sessions(&config, &client, &mut state).await?;
        if count > 0 {
            eprintln!(
                "[{}] Uploaded {} session(s).",
                chrono::Local::now().format("%H:%M:%S"),
                count
            );
        }

        if cycle.is_multiple_of(ARTIFACT_SYNC_INTERVAL)
            && let Err(e) = crate::artifact_sync::run_sync_cycle(&config.server, &config.api_key, &config.diff_dir).await
        {
            eprintln!("Artifact sync error: {}", e);
        }
    }
}

/// Scans for changed sessions and uploads them. Returns the number uploaded.
async fn process_changed_sessions(
    config: &WatchConfig,
    client: &reqwest::Client,
    state: &mut UploadState,
) -> Result<usize> {
    let (redactor, detector_version) =
        crate::detectors::load_redactor(&config.server, &config.api_key).await?;

    let mut changed = Vec::new();
    for &provider in &config.providers {
        let source_root = match WatchConfig::default_source_root(provider) {
            Ok(root) => root,
            Err(_) => continue, // Provider dir doesn't exist, skip
        };
        match find_changed_sessions(provider, &source_root, state, config.idle_threshold) {
            Ok(sessions) => changed.extend(sessions),
            Err(e) => {
                eprintln!("  Error scanning {}: {}", provider, e);
                continue;
            }
        }
    }

    let mut count = 0;
    for locator in &changed {
        let current_size = match file_size(&locator.path) {
            Ok(size) => size,
            Err(e) => {
                eprintln!(
                    "  Skipping {}:{}: could not read file size: {}",
                    locator.provider, locator.session_id, e
                );
                continue;
            }
        };
        match upload_single_session(
            config,
            client,
            &redactor,
            detector_version.as_deref(),
            locator,
        )
        .await
        {
            Ok(()) => {
                let current_marker = match session_progress_marker(locator) {
                    Ok(marker) => marker,
                    Err(e) => {
                        eprintln!(
                            "  Skipping state update for {}:{}: could not read progress marker: {}",
                            locator.provider, locator.session_id, e
                        );
                        None
                    }
                };
                update_session_state(
                    &config.diff_dir,
                    state,
                    locator.provider,
                    &locator.session_id,
                    current_size,
                    current_marker,
                )?;
                count += 1;
            }
            Err(e) => {
                eprintln!(
                    "  Error uploading {}:{}: {}",
                    locator.provider, locator.session_id, e
                );
            }
        }
    }

    Ok(count)
}

/// Parses and uploads a single session.
async fn upload_single_session(
    config: &WatchConfig,
    client: &reqwest::Client,
    redactor: &crate::redact::Redactor,
    detector_version: Option<&str>,
    locator: &SessionLocator,
) -> Result<()> {
    eprintln!(
        "  Uploading {}:{} ...",
        locator.provider, locator.session_id
    );

    let parsed = locator.provider.parse_locator(
        locator,
        &crate::parser::ParseContext {
            org_id: &config.org_id,
            engineer_id: &config.engineer_id,
            machine_id: &config.machine_id,
            redactor,
        },
    )?;
    let mut parsed = parsed;
    parsed.security_detector_version = detector_version.map(ToOwned::to_owned);
    if let Some(mut snapshot) = locator
        .provider
        .capture_config_snapshot(&parsed.project_path)?
    {
        if let Some(obj) = snapshot.snapshot_object_mut()
            && let Some(model) = &parsed.primary_model
        {
            obj.insert(
                "primary_model".to_string(),
                serde_json::Value::String(model.clone()),
            );
        }
        crate::config_history::annotate_snapshot_change(
            &config.diff_dir,
            &parsed.project_path,
            &mut snapshot,
        )?;
        parsed.config_snapshot = Some(snapshot);
    }

    upload_session_payload(client, &config.server, &config.api_key, &parsed).await?;

    if let Some(snapshot) = &parsed.config_snapshot {
        upload_config_snapshot(
            client,
            &config.server,
            &config.api_key,
            &parsed.session_id,
            parsed.primary_model.as_deref(),
            snapshot,
        )
        .await?;
    }

    Ok(())
}

async fn upload_session_payload(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    parsed: &crate::types::DiffSession,
) -> Result<()> {
    let url = format!("{}/api/v1/sessions", server.trim_end_matches('/'));
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(parsed)
        .send()
        .await?;

    let status = response.status();

    match status.as_u16() {
        200 => eprintln!("    Updated on server."),
        201 => eprintln!("    Uploaded successfully."),
        _ => {
            let body_text = response.text().await.unwrap_or_default();
            let body: serde_json::Value = serde_json::from_str(&body_text)
                .unwrap_or_else(|_| serde_json::json!({"raw": body_text}));
            if status == 401 {
                bail!(
                    "Authentication failed: {}",
                    body["error"].as_str().unwrap_or("invalid API key")
                );
            }
            bail!("Upload failed (HTTP {}): {}", status, body_text);
        }
    }

    Ok(())
}

async fn upload_config_snapshot(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    session_id: &str,
    primary_model: Option<&str>,
    snapshot: &crate::types::ConfigSnapshotPayload,
) -> Result<()> {
    let url = format!("{}/api/v1/config/snapshots", server.trim_end_matches('/'));
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "session_id": session_id,
            "config_snapshot": {
                "provider": snapshot.provider(),
                "primary_model": primary_model,
                "system_prompt_hash": snapshot.snapshot()["system_prompt_hash"],
                "settings_hash": snapshot.snapshot()["settings_hash"],
                "settings_local_hash": snapshot.snapshot()["settings_local_hash"],
                "active_agents_count": snapshot.snapshot()["active_agents_count"],
                "active_hooks_count": snapshot.snapshot()["active_hooks_count"],
                "active_mcps_count": snapshot.snapshot()["active_mcps_count"],
                "permission_mode": snapshot.snapshot()["permission_mode"],
                "config_changed": snapshot.snapshot()["config_changed"],
                "previous_config_fingerprint": snapshot.snapshot()["previous_config_fingerprint"],
                "config_fingerprint": snapshot.snapshot()["config_fingerprint"],
            },
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Config snapshot upload failed (HTTP {}): {}", status, body);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ProviderKind;
    use std::fs;
    use std::io::Write;

    fn setup_test_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::TempDir::new().unwrap();
        let projects_dir = tmp.path().join("projects");
        let diff_dir = tmp.path().join("diff");
        fs::create_dir_all(&projects_dir).unwrap();
        fs::create_dir_all(&diff_dir).unwrap();
        (tmp, projects_dir, diff_dir)
    }

    fn create_session_file(projects_dir: &Path, project: &str, session_id: &str) -> PathBuf {
        let project_dir = projects_dir.join(project);
        fs::create_dir_all(&project_dir).unwrap();
        let file_path = project_dir.join(format!("{}.jsonl", session_id));
        let mut f = fs::File::create(&file_path).unwrap();
        // Write a minimal valid JSONL line
        writeln!(f, r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"text","text":"hello"}}]}},"timestamp":"2025-03-01T10:00:00Z"}}"#).unwrap();
        file_path
    }

    // ---------------------------------------------------------------
    // State management tests
    // ---------------------------------------------------------------

    #[test]
    fn test_read_empty_state() {
        let (_tmp, _projects, diff_dir) = setup_test_dir();
        let state = read_state(&diff_dir).unwrap();
        assert!(state.is_empty());
    }

    #[test]
    fn test_update_and_read_state() {
        let (_tmp, _projects, diff_dir) = setup_test_dir();
        let mut state = UploadState::new();
        update_session_state(
            &diff_dir,
            &mut state,
            ProviderKind::ClaudeCode,
            "session-aaa",
            1234,
            None,
        )
        .unwrap();
        update_session_state(
            &diff_dir,
            &mut state,
            ProviderKind::ClaudeCode,
            "session-bbb",
            5678,
            None,
        )
        .unwrap();

        let loaded = read_state(&diff_dir).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["claude_code:session-aaa"].uploaded_size, 1234);
        assert_eq!(loaded["claude_code:session-bbb"].uploaded_size, 5678);
    }

    #[test]
    fn test_migrate_from_legacy_log() {
        let (_tmp, _projects, diff_dir) = setup_test_dir();
        // Write a legacy uploaded.log
        let log_path = diff_dir.join("uploaded.log");
        fs::write(&log_path, "session-aaa\nsession-bbb\n").unwrap();

        let state = read_state(&diff_dir).unwrap();
        assert_eq!(state.len(), 2);
        // Migrated entries have size 0 (will trigger re-upload)
        assert_eq!(state["claude_code:session-aaa"].uploaded_size, 0);
        assert_eq!(state["claude_code:session-bbb"].uploaded_size, 0);

        // State file should have been written
        assert!(diff_dir.join(STATE_FILE).exists());
    }

    // ---------------------------------------------------------------
    // Session discovery tests
    // ---------------------------------------------------------------

    #[test]
    fn test_discover_sessions_empty() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        let sessions = discover_sessions(ProviderKind::ClaudeCode, &projects_dir).unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_discover_sessions_finds_jsonl_files() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );
        create_session_file(
            &projects_dir,
            "-Users-jane-other",
            "bbb222cc-dddd-eeee-ffff-aaaaaaaaaaaa",
        );

        let sessions = discover_sessions(ProviderKind::ClaudeCode, &projects_dir).unwrap();
        assert_eq!(sessions.len(), 2);

        let ids: std::collections::HashSet<String> = sessions
            .iter()
            .map(|locator| locator.session_id.clone())
            .collect();
        assert!(ids.contains("aaa111bb-cccc-dddd-eeee-ffffffffffff"));
        assert!(ids.contains("bbb222cc-dddd-eeee-ffff-aaaaaaaaaaaa"));
    }

    #[test]
    fn test_discover_ignores_non_uuid_jsonl() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );
        let project_dir = projects_dir.join("-Users-jane-project");
        fs::write(project_dir.join("short.jsonl"), "{}").unwrap();
        fs::write(project_dir.join("sessions-index.json"), "{}").unwrap();

        let sessions = discover_sessions(ProviderKind::ClaudeCode, &projects_dir).unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_discover_nonexistent_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sessions =
            discover_sessions(ProviderKind::ClaudeCode, &tmp.path().join("nope")).unwrap();
        assert!(sessions.is_empty());
    }

    // ---------------------------------------------------------------
    // Idle detection tests
    // ---------------------------------------------------------------

    #[test]
    fn test_freshly_created_file_is_not_idle() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        let path = create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );
        assert!(!is_session_idle(&path, Duration::from_secs(60)).unwrap());
    }

    #[test]
    fn test_file_is_idle_with_zero_threshold() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        let path = create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );
        assert!(is_session_idle(&path, Duration::ZERO).unwrap());
    }

    // ---------------------------------------------------------------
    // find_changed_sessions tests
    // ---------------------------------------------------------------

    #[test]
    fn test_find_changed_new_session() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );

        let state = UploadState::new();
        let changed = find_changed_sessions(
            ProviderKind::ClaudeCode,
            &projects_dir,
            &state,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn test_find_changed_skips_unchanged() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        let path = create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );

        let current_size = fs::metadata(&path).unwrap().len();
        let mut state = UploadState::new();
        state.insert(
            "claude_code:aaa111bb-cccc-dddd-eeee-ffffffffffff".to_string(),
            SessionState {
                uploaded_size: current_size,
                uploaded_at: "2025-01-01T00:00:00Z".to_string(),
                uploaded_marker: None,
            },
        );

        let changed = find_changed_sessions(
            ProviderKind::ClaudeCode,
            &projects_dir,
            &state,
            Duration::ZERO,
        )
        .unwrap();
        assert!(changed.is_empty());
    }

    #[test]
    fn test_find_changed_detects_growth() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        let path = create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );

        // Record a smaller size than current
        let mut state = UploadState::new();
        state.insert(
            "claude_code:aaa111bb-cccc-dddd-eeee-ffffffffffff".to_string(),
            SessionState {
                uploaded_size: 10, // Much smaller than actual file
                uploaded_at: "2025-01-01T00:00:00Z".to_string(),
                uploaded_marker: None,
            },
        );

        let current_size = fs::metadata(&path).unwrap().len();
        assert!(current_size > 10);

        let changed = find_changed_sessions(
            ProviderKind::ClaudeCode,
            &projects_dir,
            &state,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn test_find_changed_excludes_active_sessions() {
        let (_tmp, projects_dir, _diff) = setup_test_dir();
        create_session_file(
            &projects_dir,
            "-Users-jane-project",
            "aaa111bb-cccc-dddd-eeee-ffffffffffff",
        );

        let state = UploadState::new();
        // With 60s threshold, freshly created file should NOT be ready
        let changed = find_changed_sessions(
            ProviderKind::ClaudeCode,
            &projects_dir,
            &state,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(changed.is_empty());
    }

    #[test]
    fn test_read_state_migrates_legacy_state_json_keys() {
        let (_tmp, _projects, diff_dir) = setup_test_dir();
        fs::write(
            diff_dir.join(STATE_FILE),
            serde_json::json!({
                "session-legacy": {
                    "uploaded_size": 42,
                    "uploaded_at": "2025-01-01T00:00:00Z"
                }
            })
            .to_string(),
        )
        .unwrap();

        let state = read_state(&diff_dir).unwrap();
        assert_eq!(state["claude_code:session-legacy"].uploaded_size, 42);
    }

    #[test]
    fn test_find_changed_opencode_uses_update_marker() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("opencode");
        let session_dir = root.join("storage").join("session").join("workspace");
        fs::create_dir_all(&session_dir).unwrap();
        let session_path = session_dir.join("ses_test.json");
        fs::write(
            &session_path,
            serde_json::json!({
                "id": "ses_test",
                "directory": "/tmp/project",
                "version": "1.0.0",
                "time_created": 100,
                "time_updated": 200
            })
            .to_string(),
        )
        .unwrap();

        let mut state = UploadState::new();
        state.insert(
            "opencode:ses_test".to_string(),
            SessionState {
                uploaded_size: fs::metadata(&session_path).unwrap().len(),
                uploaded_at: "2025-01-01T00:00:00Z".to_string(),
                uploaded_marker: Some("200".to_string()),
            },
        );

        let changed = find_changed_sessions(
            ProviderKind::OpenCode,
            &root,
            &state,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(changed.is_empty());

        fs::write(
            &session_path,
            serde_json::json!({
                "id": "ses_test",
                "directory": "/tmp/project",
                "version": "1.0.0",
                "time_created": 100,
                "time_updated": 300
            })
            .to_string(),
        )
        .unwrap();

        let changed = find_changed_sessions(
            ProviderKind::OpenCode,
            &root,
            &state,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(changed.len(), 1);
    }
}
