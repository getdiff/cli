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
                    match install_pending_artifact(item) {
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
}

#[derive(Debug, serde::Deserialize)]
struct PendingResponse {
    #[serde(default)]
    pending: Vec<PendingItem>,
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

// ---------------------------------------------------------------------------
// Install pending artifact to local filesystem
// ---------------------------------------------------------------------------

fn install_pending_artifact(item: &PendingItem) -> Result<String> {
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
        return Ok(home.join(stripped));
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
            "claude" => resolve_claude_path(origin_path, artifact_type, &home),
            "codex" => resolve_codex_path(origin_path, artifact_type, &home),
            "cursor" => resolve_cursor_path(origin_path, artifact_type),
            "copilot" => resolve_copilot_path(origin_path, artifact_type),
            "windsurf" => resolve_windsurf_path(origin_path, artifact_type, &home),
            "amazonq" => resolve_amazonq_path(origin_path, artifact_type),
            "aider" => PathBuf::from(origin_path),
            _ => PathBuf::from(origin_path),
        };
        return Ok(path);
    }

    // Fallback: use origin_path as-is
    Ok(PathBuf::from(origin_path))
}

fn resolve_claude_path(origin_path: &str, artifact_type: &str, home: &Path) -> PathBuf {
    // Project-scoped artifacts have relative paths (e.g., ".claude/agents/review.md").
    // Global artifacts have tilde-prefixed paths (e.g., "~/.claude/agents/review.md")
    // which are expanded before reaching this function. If we get here with a
    // ".claude/" prefix, it's project-scoped — keep it relative to the project root.
    let is_project_scoped =
        origin_path.starts_with(".claude/") && !origin_path.starts_with(".claude/projects/");

    match artifact_type {
        "agent" => {
            if is_project_scoped {
                PathBuf::from(origin_path)
            } else {
                let filename = Path::new(origin_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                home.join(".claude/agents").join(filename.as_ref())
            }
        }
        "skill" => {
            if is_project_scoped {
                PathBuf::from(origin_path)
            } else if origin_path.contains("/commands/") {
                // Legacy command: resolve to skills directory
                let stem = Path::new(origin_path)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();
                home.join(".claude/skills")
                    .join(stem.as_ref())
                    .join("SKILL.md")
            } else {
                home.join(origin_path)
            }
        }
        "rule" => {
            if is_project_scoped {
                PathBuf::from(origin_path)
            } else {
                home.join(origin_path)
            }
        }
        "hook" | "mcp" => home.join(".claude/settings.json"),
        "memory" => home.join(origin_path),
        _ => PathBuf::from(origin_path),
    }
}

fn resolve_codex_path(origin_path: &str, artifact_type: &str, home: &Path) -> PathBuf {
    match artifact_type {
        "agent" => {
            let filename = Path::new(origin_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            home.join(".codex/skills").join(filename.as_ref())
        }
        "hook" => home.join(".codex/config.toml"),
        _ => PathBuf::from(origin_path),
    }
}

fn resolve_cursor_path(origin_path: &str, artifact_type: &str) -> PathBuf {
    match artifact_type {
        "system_prompt" => {
            // Preserve the origin_path for files inside .cursor/rules/
            PathBuf::from(origin_path)
        }
        "mcp" => PathBuf::from(".cursor/mcp.json"),
        _ => PathBuf::from(origin_path),
    }
}

fn resolve_copilot_path(origin_path: &str, artifact_type: &str) -> PathBuf {
    match artifact_type {
        "agent" => {
            let filename = Path::new(origin_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            PathBuf::from(".github/agents").join(filename.as_ref())
        }
        "system_prompt" => PathBuf::from(".github/copilot-instructions.md"),
        _ => PathBuf::from(origin_path),
    }
}

fn resolve_windsurf_path(origin_path: &str, _artifact_type: &str, home: &Path) -> PathBuf {
    // Only subdirectory file for windsurf is the MCP config
    if origin_path.contains("mcp_config") {
        return home.join(".codeium/windsurf/mcp_config.json");
    }
    PathBuf::from(origin_path)
}

fn resolve_amazonq_path(origin_path: &str, _artifact_type: &str) -> PathBuf {
    // Preserve the origin path — it already includes the correct subdirectory
    PathBuf::from(origin_path)
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

    // Now fetch the artifact details to get content
    let detail_url = format!(
        "{}/api/v1/artifacts/{}",
        server.trim_end_matches('/'),
        artifact_id
    );
    let detail_response = client
        .get(&detail_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    if !detail_response.status().is_success() {
        let status = detail_response.status();
        let body = detail_response.text().await.unwrap_or_default();
        bail!(
            "Failed to fetch artifact details (HTTP {}): {}",
            status,
            body
        );
    }

    let detail: serde_json::Value = detail_response.json().await?;
    let artifact = &detail["artifact"];

    let raw_content = artifact["rawContent"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let origin_path = artifact["originPath"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let artifact_type = artifact["type"].as_str().unwrap_or("agent").to_string();
    let name = artifact["name"].as_str().unwrap_or("unknown").to_string();

    let pending_item = PendingItem {
        _installation_id: String::new(),
        artifact_id: artifact_id.to_string(),
        name: name.clone(),
        artifact_type: artifact_type.clone(),
        version: artifact["version"].as_u64().unwrap_or(1),
        target_provider: target_provider.to_string(),
        raw_content,
        _origin_provider: artifact["originProvider"]
            .as_str()
            .unwrap_or("claude")
            .to_string(),
        origin_path,
    };

    let local_hash = install_pending_artifact(&pending_item)?;
    confirm_install(&client, server, api_key, artifact_id, &local_hash).await?;

    eprintln!("Installed {} successfully.", name);
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
    fn test_install_pending_artifact_writes_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target_dir = tmp.path().join("sub");
        fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("test-artifact.md");

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
        };

        let hash = install_pending_artifact(&item).unwrap();
        assert!(hash.starts_with("sha256-"));
        assert_eq!(fs::read_to_string(&target).unwrap(), "You are a test agent");
    }

    #[test]
    fn test_cache_key_format() {
        let key = cache_key(ArtifactProvider::Claude, ".claude/agents/review.md");
        assert_eq!(key, "claude:.claude/agents/review.md");
    }
}
