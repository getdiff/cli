use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::artifact_scanner::{self, ArtifactProvider, ScannedArtifact};

/// Hash cache file within ~/.diff/
const HASH_CACHE_FILE: &str = "artifact-hashes.json";

/// Lock file for advisory locking of the hash cache.
const HASH_CACHE_LOCK: &str = "artifact-hashes.lock";

/// Maximum artifacts per sync request.
const MAX_ARTIFACTS_PER_REQUEST: usize = 100;

// ---------------------------------------------------------------------------
// Hash cache: tracks what we've already uploaded
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CachedHash {
    pub content_hash: String,
    pub synced_at: String,
}

/// Map of "provider:origin_path" -> CachedHash
pub type HashCache = HashMap<String, CachedHash>;

fn cache_key(provider: ArtifactProvider, origin_path: &str) -> String {
    format!("{}:{}", provider.as_str(), origin_path)
}

fn read_hash_cache(diff_dir: &Path) -> HashCache {
    let path = diff_dir.join(HASH_CACHE_FILE);
    if !path.exists() {
        return HashCache::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => HashCache::new(),
    }
}

/// Write the hash cache atomically: write to a temp file then rename.
/// Uses an advisory lock to prevent concurrent writers from losing data.
fn write_hash_cache(diff_dir: &Path, cache: &HashCache) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(diff_dir)?;

    let lock_path = diff_dir.join(HASH_CACHE_LOCK);
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)?;

    // Advisory lock — blocks if another process holds it
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX);
        }
    }

    // Re-read the cache under the lock to merge any writes from another process
    let mut merged = read_hash_cache(diff_dir);
    for (key, value) in cache {
        merged.insert(key.clone(), value.clone());
    }

    // Write to temp file then rename for atomicity
    let cache_path = diff_dir.join(HASH_CACHE_FILE);
    let temp_path = diff_dir.join(format!(".{}.tmp-{}", HASH_CACHE_FILE, uuid::Uuid::new_v4()));
    let contents = serde_json::to_string_pretty(&merged)?;
    {
        let mut f = std::fs::File::create(&temp_path)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&temp_path, &cache_path)?;

    // Lock is released when lock_file is dropped
    drop(lock_file);
    // Clean up lock file (best-effort)
    let _ = std::fs::remove_file(&lock_path);

    Ok(())
}

// ---------------------------------------------------------------------------
// Sync cycle: scan -> upload changed -> poll pending -> write -> confirm
// ---------------------------------------------------------------------------

/// Run a full artifact sync cycle. Called from the watch loop.
pub async fn run_sync_cycle(server: &str, api_key: &str, diff_dir: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // Phase 1: Scan and upload
    let cache = read_hash_cache(diff_dir);
    let project_roots = artifact_scanner::discover_project_roots();
    let all_artifacts = artifact_scanner::scan_all(&project_roots);

    let changed: Vec<&ScannedArtifact> = all_artifacts
        .iter()
        .filter(|a| {
            let key = cache_key(a.provider, &a.origin_path);
            match cache.get(&key) {
                Some(cached) => cached.content_hash != a.content_hash,
                None => true,
            }
        })
        .collect();

    if !changed.is_empty() {
        eprintln!(
            "  Artifact sync: {} changed artifact(s) to upload",
            changed.len()
        );

        // Track which artifacts were successfully synced vs rejected
        let mut synced_cache = HashCache::new();

        // Upload in batches of MAX_ARTIFACTS_PER_REQUEST
        for chunk in changed.chunks(MAX_ARTIFACTS_PER_REQUEST) {
            match upload_artifacts(&client, server, api_key, chunk).await {
                Ok(result) => {
                    eprintln!(
                        "    Synced: {} created, {} updated, {} skipped",
                        result.created, result.updated, result.skipped
                    );

                    // Build set of rejected origin_paths so we don't cache them
                    let rejected_paths: HashSet<&str> = result
                        .rejected
                        .iter()
                        .map(|r| r.origin_path.as_str())
                        .collect();

                    if !result.rejected.is_empty() {
                        for rejection in &result.rejected {
                            eprintln!(
                                "    Rejected: {} ({})",
                                rejection.origin_path, rejection.reason
                            );
                        }
                    }

                    // Only cache artifacts that were NOT rejected
                    let now = chrono::Utc::now().to_rfc3339();
                    for artifact in chunk {
                        if !rejected_paths.contains(artifact.origin_path.as_str()) {
                            let key = cache_key(artifact.provider, &artifact.origin_path);
                            synced_cache.insert(
                                key,
                                CachedHash {
                                    content_hash: artifact.content_hash.clone(),
                                    synced_at: now.clone(),
                                },
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("    Upload error: {}", e);
                }
            }
        }

        if !synced_cache.is_empty() {
            write_hash_cache(diff_dir, &synced_cache)?;
        }
    }

    // Phase 2: Poll for pending installs and apply them
    match poll_pending(&client, server, api_key).await {
        Ok(pending) => {
            if !pending.is_empty() {
                eprintln!(
                    "  Artifact sync: {} pending update(s) to install",
                    pending.len()
                );
                for item in &pending {
                    match install_pending_artifact(&client, server, api_key, item).await {
                        Ok(local_hash) => {
                            eprintln!("    Installed: {} (v{})", item.name, item.version);
                            if let Err(e) = confirm_install(
                                &client,
                                server,
                                api_key,
                                &item.artifact_id,
                                &local_hash,
                            )
                            .await
                            {
                                eprintln!("    Confirm error for {}: {}", item.name, e);
                            }
                        }
                        Err(e) => {
                            eprintln!("    Install error for {}: {}", item.name, e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("  Pending poll error: {}", e);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct SyncResponse {
    #[serde(default)]
    created: u64,
    #[serde(default)]
    updated: u64,
    #[serde(default)]
    skipped: u64,
    #[serde(default)]
    rejected: Vec<RejectedArtifact>,
}

#[derive(Debug, serde::Deserialize)]
struct RejectedArtifact {
    #[serde(default)]
    origin_path: String,
    #[serde(default)]
    reason: String,
}

async fn upload_artifacts(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    artifacts: &[&ScannedArtifact],
) -> Result<SyncResponse> {
    let url = format!("{}/api/v1/artifacts/sync", server.trim_end_matches('/'));

    let payload: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "type": a.artifact_type.as_str(),
                "name": a.name,
                "origin_provider": a.provider.as_str(),
                "origin_path": a.origin_path,
                "origin_project": a.origin_project,
                "raw_content": a.raw_content,
                "content_hash": a.content_hash,
            })
        })
        .collect();

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "artifacts": payload }))
        .send()
        .await?;

    let status = response.status();
    if status == 401 {
        bail!(
            "Authentication failed. Your token may have expired. Run `getdiff login` to re-authenticate."
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Artifact sync failed (HTTP {}): {}", status, body);
    }

    let result: SyncResponse = response.json().await?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Poll pending
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct PendingItem {
    /// Deserialized from API but not currently used by CLI logic.
    #[serde(rename = "installation_id")]
    _installation_id: String,
    artifact_id: String,
    name: String,
    #[serde(rename = "type")]
    artifact_type: String,
    version: u64,
    target_provider: String,
    raw_content: String,
    /// Deserialized from API but not currently used by CLI logic.
    #[serde(rename = "origin_provider")]
    _origin_provider: String,
    origin_path: String,
    #[serde(default)]
    ucir: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct PendingResponse {
    #[serde(default)]
    pending: Vec<PendingItem>,
}

#[derive(Debug, Clone)]
struct ArtifactRecord {
    id: String,
    name: String,
    artifact_type: String,
    origin_provider: String,
    origin_path: String,
    raw_content: String,
    version: u64,
}

#[derive(Debug, Clone)]
struct PluginChildRef {
    artifact_id: Option<String>,
    origin_path: Option<String>,
    name: Option<String>,
    artifact_type: Option<String>,
}

async fn poll_pending(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
) -> Result<Vec<PendingItem>> {
    let url = format!("{}/api/v1/artifacts/pending", server.trim_end_matches('/'));

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    let status = response.status();
    if status == 401 {
        bail!(
            "Authentication failed. Your token may have expired. Run `getdiff login` to re-authenticate."
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Pending poll failed (HTTP {}): {}", status, body);
    }

    let result: PendingResponse = response.json().await?;
    Ok(result.pending)
}

fn extract_plugin_child_refs(value: Option<&serde_json::Value>) -> Result<Vec<PluginChildRef>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let ucir = match value {
        serde_json::Value::Object(map) => map,
        serde_json::Value::String(text) => {
            let parsed: serde_json::Value = serde_json::from_str(text)?;
            return extract_plugin_child_refs(Some(&parsed));
        }
        _ => return Ok(Vec::new()),
    };

    let candidates = ucir
        .get("contents")
        .or_else(|| ucir.get("children"))
        .or_else(|| ucir.get("artifacts"));
    let Some(serde_json::Value::Array(entries)) = candidates else {
        return Ok(Vec::new());
    };

    Ok(entries
        .iter()
        .filter_map(|entry| match entry {
            serde_json::Value::String(path) => Some(PluginChildRef {
                artifact_id: None,
                origin_path: Some(path.clone()),
                name: None,
                artifact_type: None,
            }),
            serde_json::Value::Object(obj) => {
                let artifact_id = obj
                    .get("artifactId")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string);
                let origin_path = obj
                    .get("originPath")
                    .or_else(|| obj.get("path"))
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string);
                let name = obj
                    .get("name")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string);
                let artifact_type = obj
                    .get("type")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string);
                if artifact_id.is_none()
                    && origin_path.is_none()
                    && name.is_none()
                    && artifact_type.is_none()
                {
                    None
                } else {
                    Some(PluginChildRef {
                        artifact_id,
                        origin_path,
                        name,
                        artifact_type,
                    })
                }
            }
            _ => None,
        })
        .collect())
}

async fn fetch_artifact_record(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    artifact_id: &str,
) -> Result<ArtifactRecord> {
    let detail_url = format!(
        "{}/api/v1/artifacts/{}",
        server.trim_end_matches('/'),
        artifact_id
    );
    let response = client
        .get(&detail_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!(
            "Failed to fetch artifact details for {} (HTTP {}): {}",
            artifact_id,
            status,
            body
        );
    }

    let detail: serde_json::Value = response.json().await?;
    let artifact = &detail["artifact"];
    Ok(ArtifactRecord {
        id: artifact["id"].as_str().unwrap_or(artifact_id).to_string(),
        name: artifact["name"].as_str().unwrap_or("unknown").to_string(),
        artifact_type: artifact["type"].as_str().unwrap_or("agent").to_string(),
        origin_provider: artifact["originProvider"]
            .as_str()
            .unwrap_or("claude")
            .to_string(),
        origin_path: artifact["originPath"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        raw_content: artifact["rawContent"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        version: artifact["version"].as_u64().unwrap_or(1),
    })
}

async fn search_artifact_candidates(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    query: Option<&str>,
    artifact_type: Option<&str>,
) -> Result<Vec<String>> {
    let mut url = format!("{}/api/v1/artifacts", server.trim_end_matches('/'));
    let mut first = true;
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push(if first { '?' } else { '&' });
        first = false;
        url.push_str(&format!("q={}", urlencoding::encode(q)));
    }
    if let Some(t) = artifact_type.filter(|t| !t.is_empty()) {
        url.push(if first { '?' } else { '&' });
        url.push_str(&format!("type={}", urlencoding::encode(t)));
    }

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Artifact search failed (HTTP {}): {}", status, body);
    }

    let body: serde_json::Value = response.json().await?;
    Ok(body["artifacts"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|artifact| artifact["id"].as_str().map(ToString::to_string))
        .collect())
}

async fn resolve_plugin_child_artifact(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    plugin_name: &str,
    plugin_provider: &str,
    child: &PluginChildRef,
) -> Result<ArtifactRecord> {
    if let Some(artifact_id) = &child.artifact_id {
        return fetch_artifact_record(client, server, api_key, artifact_id).await;
    }

    let candidate_ids = search_artifact_candidates(
        client,
        server,
        api_key,
        child.name.as_deref(),
        child.artifact_type.as_deref(),
    )
    .await?;

    let mut exact_matches = Vec::new();
    for candidate_id in candidate_ids {
        let record = fetch_artifact_record(client, server, api_key, &candidate_id).await?;
        if let Some(expected_type) = &child.artifact_type
            && record.artifact_type != *expected_type
        {
            continue;
        }
        if let Some(expected_path) = &child.origin_path
            && record.origin_path != *expected_path
        {
            continue;
        }
        if let Some(expected_name) = &child.name
            && record.name != *expected_name
        {
            continue;
        }
        if !plugin_provider.is_empty() && record.origin_provider != plugin_provider {
            continue;
        }
        exact_matches.push(record);
    }

    match exact_matches.len() {
        1 => Ok(exact_matches.remove(0)),
        0 => bail!(
            "Could not resolve plugin child for {}: origin_path={:?} name={:?} type={:?}",
            plugin_name,
            child.origin_path,
            child.name,
            child.artifact_type
        ),
        _ => bail!(
            "Ambiguous plugin child for {}: origin_path={:?} name={:?} type={:?}",
            plugin_name,
            child.origin_path,
            child.name,
            child.artifact_type
        ),
    }
}

async fn install_plugin_bundle(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    item: &PendingItem,
) -> Result<String> {
    let plugin_ucir_value = item
        .ucir
        .as_ref()
        .cloned()
        .unwrap_or(serde_json::Value::String(item.raw_content.clone()));
    let child_refs = extract_plugin_child_refs(Some(&plugin_ucir_value))?;
    if child_refs.is_empty() {
        bail!(
            "Plugin bundle {} does not contain any installable child refs",
            item.name
        );
    }

    let plugin_record = fetch_artifact_record(client, server, api_key, &item.artifact_id).await?;
    let mut installed_children = 0usize;
    for child_ref in child_refs {
        if child_ref.artifact_type.as_deref() == Some("plugin") {
            bail!("Nested plugin bundles are not supported for {}", item.name);
        }
        let child = resolve_plugin_child_artifact(
            client,
            server,
            api_key,
            &item.name,
            &plugin_record.origin_provider,
            &child_ref,
        )
        .await?;

        let child_pending = PendingItem {
            _installation_id: String::new(),
            artifact_id: child.id,
            name: child.name.clone(),
            artifact_type: child.artifact_type.clone(),
            version: child.version,
            target_provider: item.target_provider.clone(),
            raw_content: child.raw_content,
            _origin_provider: child.origin_provider,
            origin_path: child.origin_path,
            ucir: None,
        };
        let _ = install_leaf_pending_artifact(&child_pending)?;
        installed_children += 1;
    }

    eprintln!(
        "      Materialized plugin bundle {} into {} child artifact(s)",
        item.name, installed_children
    );
    Ok(artifact_scanner::sha256_hex(&item.raw_content))
}

// ---------------------------------------------------------------------------
// Install pending artifact to local filesystem
// ---------------------------------------------------------------------------

async fn install_pending_artifact(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    item: &PendingItem,
) -> Result<String> {
    if item.artifact_type == "plugin" {
        return install_plugin_bundle(client, server, api_key, item).await;
    }

    install_leaf_pending_artifact(item)
}

fn install_leaf_pending_artifact(item: &PendingItem) -> Result<String> {
    let target_path = resolve_install_path(
        &item.target_provider,
        &item.origin_path,
        &item.artifact_type,
    )?;

    // Ensure parent directory exists
    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&target_path, &item.raw_content)?;

    let hash = artifact_scanner::sha256_hex(&item.raw_content);

    eprintln!("      Wrote: {}", target_path.display());
    Ok(hash)
}

/// Resolve where to write an artifact based on target provider and origin path.
fn resolve_install_path(
    target_provider: &str,
    origin_path: &str,
    artifact_type: &str,
) -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

    // If origin_path is absolute, use it directly
    if Path::new(origin_path).is_absolute() {
        return Ok(PathBuf::from(origin_path));
    }

    // If origin_path starts with ~/, expand it
    if let Some(stripped) = origin_path.strip_prefix("~/") {
        if target_provider == "claude"
            && artifact_type == "skill"
            && stripped.contains(".claude/commands/")
        {
            let stem = Path::new(stripped)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            return sanitize_home_join(&home, &format!(".claude/skills/{}/SKILL.md", stem));
        }
        return sanitize_home_join(&home, stripped);
    }

    // Root-level files that should NOT be remapped to a subdirectory.
    // These live at the project root, not inside a provider-specific folder.
    const ROOT_LEVEL_FILES: &[&str] = &[
        "CLAUDE.md",
        "AGENTS.md",
        "CONVENTIONS.md",
        ".cursorrules",
        ".windsurfrules",
    ];
    if ROOT_LEVEL_FILES.contains(&origin_path) {
        // Project-relative: return as-is (relative to CWD / project root)
        return Ok(PathBuf::from(origin_path));
    }

    // Provider-specific path mapping for files inside subdirectories
    if origin_path.starts_with('.') || origin_path.contains('/') {
        let path = match target_provider {
            "claude" => resolve_claude_path(origin_path, artifact_type, &home)?,
            "codex" => resolve_codex_path(origin_path, artifact_type, &home)?,
            "cursor" => resolve_cursor_path(origin_path, artifact_type)?,
            "copilot" => resolve_copilot_path(origin_path, artifact_type)?,
            "windsurf" => resolve_windsurf_path(origin_path, artifact_type, &home)?,
            "amazonq" => resolve_amazonq_path(origin_path, artifact_type)?,
            "aider" => sanitize_project_relative_path(origin_path)?,
            _ => sanitize_project_relative_path(origin_path)?,
        };
        return Ok(path);
    }

    // Fallback: use origin_path as-is
    Ok(PathBuf::from(origin_path))
}

fn resolve_claude_path(origin_path: &str, artifact_type: &str, home: &Path) -> Result<PathBuf> {
    // Project-scoped artifacts have relative paths (e.g., ".claude/agents/review.md").
    // Global artifacts have tilde-prefixed paths (e.g., "~/.claude/agents/review.md")
    // which are expanded before reaching this function. If we get here with a
    // ".claude/" prefix, it's project-scoped — keep it relative to the project root.
    let is_project_scoped =
        origin_path.starts_with(".claude/") && !origin_path.starts_with(".claude/projects/");

    Ok(match artifact_type {
        "agent" => {
            if is_project_scoped {
                sanitize_project_relative_path(origin_path)?
            } else {
                let filename = Path::new(origin_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                sanitize_home_join(home, &format!(".claude/agents/{}", filename))?
            }
        }
        "skill" => {
            if is_project_scoped {
                sanitize_project_relative_path(origin_path)?
            } else if origin_path.contains("/commands/") {
                let stem = Path::new(origin_path)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();
                sanitize_home_join(home, &format!(".claude/skills/{}/SKILL.md", stem))?
            } else {
                sanitize_home_join(home, origin_path)?
            }
        }
        "rule" => {
            if is_project_scoped {
                sanitize_project_relative_path(origin_path)?
            } else {
                sanitize_home_join(home, origin_path)?
            }
        }
        "hook" | "mcp" => sanitize_home_join(home, ".claude/settings.json")?,
        "memory" => sanitize_home_join(home, origin_path)?,
        _ => sanitize_project_relative_path(origin_path)?,
    })
}

fn sanitize_project_relative_path(origin_path: &str) -> Result<PathBuf> {
    use std::path::Component;

    let path = Path::new(origin_path);
    if path.is_absolute() {
        bail!(
            "absolute project-relative path is not allowed: {}",
            origin_path
        );
    }

    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => sanitized.push(component.as_os_str()),
            Component::Normal(part) => sanitized.push(part),
            Component::ParentDir => {
                bail!("parent directory traversal is not allowed: {}", origin_path)
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "invalid path component in project-relative path: {}",
                    origin_path
                )
            }
        }
    }
    Ok(sanitized)
}

fn sanitize_home_join(home: &Path, relative_path: &str) -> Result<PathBuf> {
    let sanitized = sanitize_project_relative_path(relative_path)?;
    let joined = home.join(&sanitized);
    if !joined.starts_with(home) {
        bail!("resolved path escapes home directory: {}", relative_path);
    }
    Ok(joined)
}

fn resolve_codex_path(origin_path: &str, artifact_type: &str, home: &Path) -> Result<PathBuf> {
    Ok(match artifact_type {
        "agent" => {
            let filename = Path::new(origin_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            sanitize_home_join(home, &format!(".codex/skills/{}", filename))?
        }
        "hook" => sanitize_home_join(home, ".codex/config.toml")?,
        _ => sanitize_project_relative_path(origin_path)?,
    })
}

fn resolve_cursor_path(origin_path: &str, artifact_type: &str) -> Result<PathBuf> {
    Ok(match artifact_type {
        "system_prompt" => {
            // Preserve the origin_path for files inside .cursor/rules/
            sanitize_project_relative_path(origin_path)?
        }
        "mcp" => sanitize_project_relative_path(".cursor/mcp.json")?,
        _ => sanitize_project_relative_path(origin_path)?,
    })
}

fn resolve_copilot_path(origin_path: &str, artifact_type: &str) -> Result<PathBuf> {
    Ok(match artifact_type {
        "agent" => {
            let filename = Path::new(origin_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            sanitize_project_relative_path(&format!(".github/agents/{}", filename))?
        }
        "system_prompt" => sanitize_project_relative_path(".github/copilot-instructions.md")?,
        _ => sanitize_project_relative_path(origin_path)?,
    })
}

fn resolve_windsurf_path(origin_path: &str, _artifact_type: &str, home: &Path) -> Result<PathBuf> {
    // Only subdirectory file for windsurf is the MCP config
    if origin_path.contains("mcp_config") {
        return sanitize_home_join(home, ".codeium/windsurf/mcp_config.json");
    }
    sanitize_project_relative_path(origin_path)
}

fn resolve_amazonq_path(origin_path: &str, _artifact_type: &str) -> Result<PathBuf> {
    // Preserve the origin path — it already includes the correct subdirectory
    sanitize_project_relative_path(origin_path)
}

// ---------------------------------------------------------------------------
// Confirm install
// ---------------------------------------------------------------------------

async fn confirm_install(
    client: &reqwest::Client,
    server: &str,
    api_key: &str,
    artifact_id: &str,
    local_hash: &str,
) -> Result<()> {
    let url = format!(
        "{}/api/v1/artifacts/{}/confirm",
        server.trim_end_matches('/'),
        artifact_id
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "local_hash": local_hash }))
        .send()
        .await?;

    let status = response.status();
    if status == 401 {
        bail!(
            "Authentication failed. Your token may have expired. Run `getdiff login` to re-authenticate."
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Confirm failed (HTTP {}): {}", status, body);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Manual install by artifact ID
// ---------------------------------------------------------------------------

/// Fetch a specific artifact and install it locally.
pub async fn install_artifact(
    server: &str,
    api_key: &str,
    artifact_id: &str,
    target_provider: &str,
    subscribe: bool,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // First, subscribe or add
    let action = if subscribe { "subscribe" } else { "add" };
    let url = format!(
        "{}/api/v1/artifacts/{}/{}",
        server.trim_end_matches('/'),
        artifact_id,
        action
    );

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "target_provider": target_provider }))
        .send()
        .await?;

    let status = response.status();
    if status == 401 {
        bail!(
            "Authentication failed. Your token may have expired. Run `getdiff login` to re-authenticate."
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Install failed (HTTP {}): {}", status, body);
    }

    let body: serde_json::Value = response.json().await?;
    eprintln!(
        "Artifact {} ({}), version {}",
        artifact_id,
        body["status"].as_str().unwrap_or("ok"),
        body["version"].as_u64().unwrap_or(0),
    );

    let artifact = fetch_artifact_record(&client, server, api_key, artifact_id).await?;

    let pending_item = PendingItem {
        _installation_id: String::new(),
        artifact_id: artifact_id.to_string(),
        name: artifact.name.clone(),
        artifact_type: artifact.artifact_type.clone(),
        version: artifact.version,
        target_provider: target_provider.to_string(),
        raw_content: artifact.raw_content.clone(),
        _origin_provider: artifact.origin_provider,
        origin_path: artifact.origin_path,
        ucir: if artifact.artifact_type == "plugin" {
            serde_json::from_str(&artifact.raw_content).ok()
        } else {
            None
        },
    };

    let local_hash = install_pending_artifact(&client, server, api_key, &pending_item).await?;
    confirm_install(&client, server, api_key, artifact_id, &local_hash).await?;

    eprintln!("Installed {} successfully.", artifact.name);
    Ok(())
}

/// List artifacts visible to the user.
pub async fn list_artifacts(
    server: &str,
    api_key: &str,
    query: Option<&str>,
    artifact_type: Option<&str>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut url = format!("{}/api/v1/artifacts", server.trim_end_matches('/'));
    let mut first = true;
    if let Some(q) = query {
        url.push(if first { '?' } else { '&' });
        first = false;
        url.push_str(&format!("q={}", urlencoding::encode(q)));
    }
    if let Some(t) = artifact_type {
        url.push(if first { '?' } else { '&' });
        url.push_str(&format!("type={}", urlencoding::encode(t)));
    }

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    let status = response.status();
    if status == 401 {
        bail!(
            "Authentication failed. Your token may have expired. Run `getdiff login` to re-authenticate."
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Search failed (HTTP {}): {}", status, body);
    }

    let body: serde_json::Value = response.json().await?;
    let artifacts = body["artifacts"].as_array().cloned().unwrap_or_default();
    if artifacts.is_empty() {
        println!("No artifacts found");
        return Ok(());
    }

    for artifact in artifacts {
        println!(
            "{}\t{}\t{}\tv{}\t{}",
            artifact["id"].as_str().unwrap_or("?"),
            artifact["type"].as_str().unwrap_or("?"),
            artifact["name"].as_str().unwrap_or("?"),
            artifact["version"].as_i64().unwrap_or(1),
            artifact["originProvider"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// Share an artifact with the org or specific users.
pub async fn share_artifact(
    server: &str,
    api_key: &str,
    artifact_id: &str,
    org_wide: bool,
    user_ids: Option<Vec<String>>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!(
        "{}/api/v1/artifacts/{}/share",
        server.trim_end_matches('/'),
        artifact_id
    );

    let payload = if org_wide {
        serde_json::json!({ "org_wide": true })
    } else if let Some(ids) = user_ids {
        serde_json::json!({ "shared_with": ids })
    } else {
        bail!("Must specify --org-wide or --user-ids for sharing");
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    let status = response.status();
    if status == 401 {
        bail!(
            "Authentication failed. Your token may have expired. Run `getdiff login` to re-authenticate."
        );
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Share failed (HTTP {}): {}", status, body);
    }

    eprintln!("Shared artifact {} successfully.", artifact_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_hash_cache_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let diff_dir = tmp.path();

        let mut cache = HashCache::new();
        cache.insert(
            "claude:agents/review.md".to_string(),
            CachedHash {
                content_hash: "sha256-abc123".to_string(),
                synced_at: "2026-03-25T00:00:00Z".to_string(),
            },
        );

        write_hash_cache(diff_dir, &cache).unwrap();
        let loaded = read_hash_cache(diff_dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded["claude:agents/review.md"].content_hash,
            "sha256-abc123"
        );
    }

    #[test]
    fn test_atomic_write_no_temp_files_left() {
        let tmp = tempfile::TempDir::new().unwrap();
        let diff_dir = tmp.path();

        let mut cache = HashCache::new();
        cache.insert(
            "claude:test".to_string(),
            CachedHash {
                content_hash: "sha256-abc".to_string(),
                synced_at: "2026-01-01T00:00:00Z".to_string(),
            },
        );

        write_hash_cache(diff_dir, &cache).unwrap();

        // Verify no temp files or lock files remain
        let entries: Vec<_> = fs::read_dir(diff_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec![HASH_CACHE_FILE]);
    }

    #[test]
    fn test_write_merges_with_existing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let diff_dir = tmp.path();

        // Write first entry
        let mut cache1 = HashCache::new();
        cache1.insert(
            "claude:first".to_string(),
            CachedHash {
                content_hash: "sha256-111".to_string(),
                synced_at: "2026-01-01T00:00:00Z".to_string(),
            },
        );
        write_hash_cache(diff_dir, &cache1).unwrap();

        // Write second entry — should merge
        let mut cache2 = HashCache::new();
        cache2.insert(
            "claude:second".to_string(),
            CachedHash {
                content_hash: "sha256-222".to_string(),
                synced_at: "2026-01-02T00:00:00Z".to_string(),
            },
        );
        write_hash_cache(diff_dir, &cache2).unwrap();

        let loaded = read_hash_cache(diff_dir);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains_key("claude:first"));
        assert!(loaded.contains_key("claude:second"));
    }

    #[test]
    fn test_read_empty_cache() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = read_hash_cache(tmp.path());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_resolve_claude_agent_path_project_scoped() {
        // Project-scoped agents (.claude/ prefix) stay relative to project root
        let path = resolve_install_path("claude", ".claude/agents/review.md", "agent").unwrap();
        assert_eq!(path, PathBuf::from(".claude/agents/review.md"));
    }

    #[test]
    fn test_resolve_claude_agent_path_global() {
        // Global agents (~/.claude/ prefix) expand to home directory
        let home = dirs::home_dir().unwrap();
        let path = resolve_install_path("claude", "~/.claude/agents/review.md", "agent").unwrap();
        assert_eq!(path, home.join(".claude/agents/review.md"));
    }

    #[test]
    fn test_resolve_claude_skill_path_project_scoped() {
        let path =
            resolve_install_path("claude", ".claude/skills/review/SKILL.md", "skill").unwrap();
        assert_eq!(path, PathBuf::from(".claude/skills/review/SKILL.md"));
    }

    #[test]
    fn test_resolve_claude_skill_path_global() {
        let home = dirs::home_dir().unwrap();
        let path =
            resolve_install_path("claude", "~/.claude/skills/review/SKILL.md", "skill").unwrap();
        assert_eq!(path, home.join(".claude/skills/review/SKILL.md"));
    }

    #[test]
    fn test_resolve_claude_rule_path_project_scoped() {
        let path = resolve_install_path("claude", ".claude/rules/security.md", "rule").unwrap();
        assert_eq!(path, PathBuf::from(".claude/rules/security.md"));
    }

    #[test]
    fn test_resolve_claude_rule_path_global() {
        let home = dirs::home_dir().unwrap();
        let path = resolve_install_path("claude", "~/.claude/rules/security.md", "rule").unwrap();
        assert_eq!(path, home.join(".claude/rules/security.md"));
    }

    #[test]
    fn test_resolve_claude_command_skill_project_scoped_stays_relative() {
        let path = resolve_install_path("claude", ".claude/commands/foo.md", "skill").unwrap();
        assert_eq!(path, PathBuf::from(".claude/commands/foo.md"));
    }

    #[test]
    fn test_resolve_claude_command_skill_global_remaps_to_skill_dir() {
        let home = dirs::home_dir().unwrap();
        let path = resolve_install_path("claude", "~/.claude/commands/foo.md", "skill").unwrap();
        assert_eq!(path, home.join(".claude/skills/foo/SKILL.md"));
    }

    #[test]
    fn test_resolve_copilot_agent_path() {
        let path =
            resolve_install_path("copilot", ".github/agents/review.agent.md", "agent").unwrap();
        assert_eq!(path, PathBuf::from(".github/agents/review.agent.md"));
    }

    #[test]
    fn test_resolve_home_expanded_path() {
        let home = dirs::home_dir().unwrap();
        let path = resolve_install_path("codex", "~/.codex/skills/review.md", "agent").unwrap();
        assert_eq!(path, home.join(".codex/skills/review.md"));
    }

    #[test]
    fn test_rejects_parent_dir_in_home_scoped_path() {
        let err = resolve_install_path("claude", "~/.claude/rules/../../secret.md", "rule")
            .unwrap_err()
            .to_string();
        assert!(err.contains("parent directory traversal"));
    }

    #[test]
    fn test_rejects_parent_dir_in_project_scoped_path() {
        let err = resolve_install_path("claude", ".claude/rules/../../secret.md", "rule")
            .unwrap_err()
            .to_string();
        assert!(err.contains("parent directory traversal"));
    }

    #[test]
    fn test_resolve_root_level_files_not_remapped() {
        // .cursorrules should stay as-is, NOT become .cursor/rules/.cursorrules
        let path = resolve_install_path("cursor", ".cursorrules", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from(".cursorrules"));

        // CLAUDE.md should stay as-is, NOT go to ~/CLAUDE.md
        let path = resolve_install_path("claude", "CLAUDE.md", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from("CLAUDE.md"));

        // AGENTS.md
        let path = resolve_install_path("codex", "AGENTS.md", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from("AGENTS.md"));

        // CONVENTIONS.md
        let path = resolve_install_path("aider", "CONVENTIONS.md", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from("CONVENTIONS.md"));

        // .windsurfrules
        let path = resolve_install_path("windsurf", ".windsurfrules", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from(".windsurfrules"));
    }

    #[test]
    fn test_resolve_amazonq_rules_not_remapped() {
        // .amazonq/rules/security.md should stay as-is
        let path =
            resolve_install_path("amazonq", ".amazonq/rules/security.md", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from(".amazonq/rules/security.md"));
    }

    #[test]
    fn test_resolve_cursor_rules_in_subdir_not_remapped() {
        // .cursor/rules/my-rule.mdc should stay as-is
        let path =
            resolve_install_path("cursor", ".cursor/rules/my-rule.mdc", "system_prompt").unwrap();
        assert_eq!(path, PathBuf::from(".cursor/rules/my-rule.mdc"));
    }

    #[test]
    fn test_extract_plugin_child_refs_reads_contents_shape() {
        let value = serde_json::json!({
            "kind": "plugin",
            "contents": [
                {
                    "artifactId": "art-1",
                    "originPath": ".claude/plugins/team/skills/review/SKILL.md",
                    "name": "Review",
                    "type": "skill"
                },
                ".claude/plugins/team/hooks/hooks.json"
            ]
        });

        let refs = extract_plugin_child_refs(Some(&value)).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].artifact_id.as_deref(), Some("art-1"));
        assert_eq!(
            refs[0].origin_path.as_deref(),
            Some(".claude/plugins/team/skills/review/SKILL.md")
        );
        assert_eq!(refs[0].name.as_deref(), Some("Review"));
        assert_eq!(refs[0].artifact_type.as_deref(), Some("skill"));
        assert_eq!(
            refs[1].origin_path.as_deref(),
            Some(".claude/plugins/team/hooks/hooks.json")
        );
    }

    #[tokio::test]
    async fn test_install_pending_artifact_writes_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target_dir = tmp.path().join("sub");
        fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("test-artifact.md");
        let client = reqwest::Client::builder().build().unwrap();

        // Use an absolute path as origin_path so resolve_install_path returns it as-is
        let item = PendingItem {
            _installation_id: "inst-1".to_string(),
            artifact_id: "art-1".to_string(),
            name: "Test".to_string(),
            artifact_type: "agent".to_string(),
            version: 1,
            target_provider: "claude".to_string(),
            raw_content: "You are a test agent".to_string(),
            _origin_provider: "claude".to_string(),
            origin_path: target.to_string_lossy().to_string(),
            ucir: None,
        };

        let hash = install_pending_artifact(&client, "https://example.test", "token", &item)
            .await
            .unwrap();
        assert!(hash.starts_with("sha256-"));
        assert_eq!(fs::read_to_string(&target).unwrap(), "You are a test agent");
    }

    #[test]
    fn test_cache_key_format() {
        let key = cache_key(ArtifactProvider::Claude, ".claude/agents/review.md");
        assert_eq!(key, "claude:.claude/agents/review.md");
    }
}
