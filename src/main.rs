mod auth;
mod config_history;
mod config_snapshot;
mod detectors;
mod parser;
mod redact;
mod types;
mod watcher;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::time::Duration;

const DEFAULT_SERVER: &str = "https://getdiff.now";

#[derive(Parser)]
#[command(
    name = "getdiff",
    version,
    about = "Capture and upload agentic coding sessions"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Upload a Claude Code session by session ID
    Upload {
        /// The provider session ID
        #[arg(long)]
        session: String,

        /// Session provider
        #[arg(long, value_enum, default_value_t = parser::ProviderKind::ClaudeCode)]
        provider: parser::ProviderKind,

        /// Output normalized JSON to stdout instead of uploading
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
        server: String,
    },

    /// Parse a session JSONL file directly (for testing)
    Parse {
        /// Session provider
        #[arg(long, value_enum, default_value_t = parser::ProviderKind::ClaudeCode)]
        provider: parser::ProviderKind,

        /// Path to a session artifact file
        #[arg(long)]
        file: String,
    },

    /// Watch for completed sessions and upload them automatically
    Watch {
        /// Session provider
        #[arg(long, value_enum, default_value_t = parser::ProviderKind::ClaudeCode)]
        provider: parser::ProviderKind,

        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
        server: String,

        /// Idle threshold in seconds (session must be idle this long before upload)
        #[arg(long, default_value_t = 60)]
        idle_seconds: u64,

        /// Scan interval in seconds
        #[arg(long, default_value_t = 30)]
        scan_seconds: u64,
    },

    /// Log in to Diff via your browser
    Login {
        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
        server: String,

        /// Use a pre-existing token instead of browser flow
        #[arg(long)]
        token: Option<String>,
    },

    /// Log out and remove stored credentials
    Logout,

    /// Show current login status
    Status,

    /// Publish a configuration artifact to the registry
    Publish {
        /// Artifact type (agent, hook, mcp, plugin, prompt)
        #[arg(long)]
        r#type: String,

        /// Human-readable artifact name
        #[arg(long)]
        name: String,

        /// Path to UCIR JSON file
        #[arg(long)]
        path: String,

        /// Optional description
        #[arg(long)]
        description: Option<String>,

        /// Visibility scope
        #[arg(long, default_value = "org")]
        visibility: String,

        /// Project key (required when visibility=project)
        #[arg(long)]
        project_key: Option<String>,

        /// Origin provider
        #[arg(long)]
        provider: Option<String>,

        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER")]
        server: String,
    },

    /// Browse and install registry artifacts
    Registry {
        #[command(subcommand)]
        command: RegistryCommands,
    },
}

#[derive(Subcommand)]
enum RegistryCommands {
    /// Search artifacts in registry
    Search {
        #[arg(long)]
        query: Option<String>,

        #[arg(long)]
        r#type: Option<String>,

        #[arg(long, env = "DIFF_SERVER")]
        server: String,
    },

    /// Install artifact by id
    Install {
        #[arg(long)]
        artifact_id: String,

        #[arg(long, default_value = "claude")]
        target_provider: String,

        #[arg(long, env = "DIFF_SERVER")]
        server: String,
    },

    /// Translate an artifact between providers and show fidelity report
    Translate {
        #[arg(long)]
        artifact_id: String,

        #[arg(long)]
        target_provider: String,

        #[arg(long, env = "DIFF_SERVER")]
        server: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Upload {
            session,
            provider,
            dry_run,
            server,
        } => {
            let locator = provider.find_session(&session, None)?;
            eprintln!("Found session at: {}", locator.path.display());

            let machine_id = get_machine_id();
            let engineer_id = get_engineer_id();
            let org_id = get_org_id()?;
            let api_key = get_api_key()?;
            let (redactor, detector_version) = detectors::load_redactor(&server, &api_key).await?;

            let parsed = provider.parse_locator(
                &locator,
                &parser::ParseContext {
                    org_id: &org_id,
                    engineer_id: &engineer_id,
                    machine_id: &machine_id,
                    redactor: &redactor,
                },
            )?;
            let mut parsed = parsed;
            parsed.security_detector_version = detector_version;
            attach_config_snapshot_if_enabled(&mut parsed)?;

            if dry_run {
                println!("{}", serde_json::to_string_pretty(&parsed)?);
            } else {
                upload_session(&server, &api_key, &parsed).await?;
            }
        }
        Commands::Parse { provider, file } => {
            let path = std::path::Path::new(&file);
            let redactor = redact::Redactor::new();

            let parsed = provider.parse_file(
                path,
                "org_test",
                "engineer_test",
                "machine_test",
                &redactor,
            )?;
            let mut parsed = parsed;
            attach_config_snapshot_if_enabled(&mut parsed)?;

            println!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        Commands::Watch {
            provider,
            server,
            idle_seconds,
            scan_seconds,
        } => {
            let api_key = get_api_key()?;
            let config = watcher::WatchConfig {
                provider,
                source_root: watcher::WatchConfig::default_source_root(provider)?,
                diff_dir: watcher::WatchConfig::default_diff_dir(),
                server,
                api_key,
                org_id: get_org_id()?,
                engineer_id: get_engineer_id(),
                machine_id: get_machine_id(),
                idle_threshold: std::time::Duration::from_secs(idle_seconds),
                scan_interval: std::time::Duration::from_secs(scan_seconds),
            };
            watcher::run_watch_loop(config).await?;
        }
        Commands::Login { server, token } => {
            if let Some(token) = token {
                auth::login_with_token(&server, &token).await?;
            } else {
                auth::login(&server).await?;
            }
        }
        Commands::Logout => {
            auth::logout()?;
        }
        Commands::Status => match auth::read_config() {
            Some(config) => {
                eprintln!("Logged in as: {}", config.email);
                eprintln!("Server:       {}", config.server);
                eprintln!("Config:       {}", auth::config_path().display());
            }
            None => {
                eprintln!("Not logged in. Run `getdiff login` to authenticate.");
            }
        },
        Commands::Publish {
            r#type,
            name,
            path,
            description,
            visibility,
            project_key,
            provider,
            server,
        } => {
            ensure_publish_visibility_project_key(&visibility, project_key.as_deref())?;
            let api_key = get_required_diff_api_key()?;
            let opts = PublishArtifactOptions {
                server,
                api_key,
                artifact_type: r#type,
                name,
                path,
                description,
                visibility,
                project_key,
                provider,
            };
            publish_artifact(&opts).await?;
        }
        Commands::Registry { command } => match command {
            RegistryCommands::Search {
                query,
                r#type,
                server,
            } => {
                let api_key = get_required_diff_api_key()?;
                registry_search(&server, &api_key, query.as_deref(), r#type.as_deref()).await?;
            }
            RegistryCommands::Install {
                artifact_id,
                target_provider,
                server,
            } => {
                let api_key = get_required_diff_api_key()?;
                registry_install(&server, &api_key, &artifact_id, &target_provider).await?;
            }
            RegistryCommands::Translate {
                artifact_id,
                target_provider,
                server,
            } => {
                let api_key = get_required_diff_api_key()?;
                registry_translate(&server, &api_key, &artifact_id, &target_provider).await?;
            }
        },
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct PublishArtifactOptions {
    server: String,
    api_key: String,
    artifact_type: String,
    name: String,
    path: String,
    description: Option<String>,
    visibility: String,
    project_key: Option<String>,
    provider: Option<String>,
}

async fn publish_artifact(opts: &PublishArtifactOptions) -> Result<()> {
    ensure_publish_visibility_project_key(&opts.visibility, opts.project_key.as_deref())?;

    let ucir_path = std::path::Path::new(&opts.path);
    let content = std::fs::read_to_string(ucir_path)?;
    let ucir: serde_json::Value = serde_json::from_str(&content)?;
    let redactor = redact::Redactor::new();
    let sanitized_ucir = sanitize_ucir_for_publish(ucir, &redactor)?;

    let url = format!(
        "{}/api/v1/config/artifacts",
        opts.server.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", opts.api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "type": opts.artifact_type.as_str(),
            "name": opts.name.as_str(),
            "description": opts.description.as_deref(),
            "origin_provider": opts.provider.as_deref(),
            "visibility": opts.visibility.as_str(),
            "project_key": opts.project_key.as_deref(),
            "ucir": sanitized_ucir,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Publish failed (HTTP {}): {}", status, body);
    }

    let body: serde_json::Value = response.json().await?;
    eprintln!(
        "Published artifact {} ({})",
        body["id"].as_str().unwrap_or("unknown"),
        body["status"].as_str().unwrap_or("ok")
    );
    Ok(())
}

fn sanitize_ucir_for_publish(
    ucir: serde_json::Value,
    redactor: &redact::Redactor,
) -> Result<serde_json::Value> {
    let raw = serde_json::to_string(&ucir)?;
    let redacted = redactor.redact(&raw);
    Ok(serde_json::from_str(&redacted)?)
}

fn ensure_publish_visibility_project_key(
    visibility: &str,
    project_key: Option<&str>,
) -> Result<()> {
    if visibility == "project"
        && project_key
            .map(str::trim)
            .map(str::is_empty)
            .unwrap_or(true)
    {
        bail!("--project-key is required when --visibility=project");
    }
    Ok(())
}

async fn registry_search(
    server: &str,
    api_key: &str,
    query: Option<&str>,
    artifact_type: Option<&str>,
) -> Result<()> {
    let mut url = format!("{}/api/v1/config/artifacts", server.trim_end_matches('/'));
    let mut first = true;
    if let Some(query) = query {
        url.push(if first { '?' } else { '&' });
        first = false;
        url.push_str(&format!("q={}", urlencoding::encode(query)));
    }
    if let Some(artifact_type) = artifact_type {
        url.push(if first { '?' } else { '&' });
        url.push_str(&format!("type={}", urlencoding::encode(artifact_type)));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
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
            "{}\t{}\t{}\tv{}",
            artifact["id"].as_str().unwrap_or("?"),
            artifact["type"].as_str().unwrap_or("?"),
            artifact["name"].as_str().unwrap_or("?"),
            artifact["version"].as_i64().unwrap_or(1),
        );
    }
    Ok(())
}

async fn registry_install(
    server: &str,
    api_key: &str,
    artifact_id: &str,
    target_provider: &str,
) -> Result<()> {
    let url = format!(
        "{}/api/v1/config/artifacts/{}/install",
        server.trim_end_matches('/'),
        artifact_id
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "target_provider": target_provider,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Install failed (HTTP {}): {}", status, body);
    }

    let body: serde_json::Value = response.json().await?;
    eprintln!(
        "Installed artifact {} ({})",
        body["id"].as_str().unwrap_or("unknown"),
        body["status"].as_str().unwrap_or("ok")
    );
    Ok(())
}

async fn registry_translate(
    server: &str,
    api_key: &str,
    artifact_id: &str,
    target_provider: &str,
) -> Result<()> {
    let url = format!("{}/api/v1/config/translate", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "artifact_id": artifact_id,
            "target_provider": target_provider,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Translate failed (HTTP {}): {}", status, body);
    }

    let body: serde_json::Value = response.json().await?;
    println!(
        "{} -> {} | fidelity={} ({:.2})",
        body["source_provider"].as_str().unwrap_or("unknown"),
        body["targetProvider"].as_str().unwrap_or("unknown"),
        body["report"]["label"].as_str().unwrap_or("unknown"),
        body["report"]["score"].as_f64().unwrap_or(0.0)
    );
    let unsupported = body["report"]["unsupportedFields"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !unsupported.is_empty() {
        let fields: Vec<String> = unsupported
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        println!("Unsupported fields: {}", fields.join(", "));
    }
    println!(
        "Translated:\n{}",
        serde_json::to_string_pretty(&body["translated"]).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

async fn upload_session(server: &str, api_key: &str, session: &types::DiffSession) -> Result<()> {
    let url = format!("{}/api/v1/sessions", server.trim_end_matches('/'));
    eprintln!("Uploading to {}...", url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(session)
        .send()
        .await?;

    let status = response.status();
    let body_text = response.text().await?;
    let body: serde_json::Value =
        serde_json::from_str(&body_text).unwrap_or_else(|_| serde_json::json!({"raw": body_text}));

    match status.as_u16() {
        200 => {
            let s = body["status"].as_str().unwrap_or("already_exists");
            eprintln!("Session {}: {}", session.session_id, s);
        }
        201 => {
            eprintln!("Uploaded successfully.");
            eprintln!(
                "  Session ID: {}",
                body["session_id"].as_str().unwrap_or("?")
            );
            eprintln!(
                "  Analysis:   {}",
                body["analysis_status"].as_str().unwrap_or("?")
            );
        }
        401 => {
            bail!(
                "Authentication failed: {}",
                body["error"].as_str().unwrap_or("invalid API key")
            );
        }
        _ => {
            bail!("Upload failed (HTTP {}): {}", status, body_text);
        }
    }

    if let Some(snapshot) = &session.config_snapshot {
        upload_config_snapshot(
            server,
            api_key,
            &session.session_id,
            session.primary_model.as_deref(),
            snapshot,
        )
        .await?;
    }

    Ok(())
}

async fn upload_config_snapshot(
    server: &str,
    api_key: &str,
    session_id: &str,
    primary_model: Option<&str>,
    snapshot: &types::ConfigSnapshotPayload,
) -> Result<()> {
    let url = format!("{}/api/v1/config/snapshots", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

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

fn get_machine_id() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

fn get_engineer_id() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Returns the server URL, preferring config file, then env vars, then default.
fn default_server() -> String {
    if let Some(config) = auth::read_config() {
        return config.server;
    }
    std::env::var("DIFF_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string())
}

fn get_org_id() -> Result<String> {
    if let Some(config) = auth::read_config()
        && !config.org_id.trim().is_empty()
    {
        return Ok(config.org_id);
    }
    std::env::var("DIFF_ORG_ID").map_err(|_| {
        anyhow::anyhow!("Not logged in. Run `getdiff login` first or set DIFF_ORG_ID.")
    })
}

fn get_api_key() -> Result<String> {
    if let Some(config) = auth::read_config()
        && !config.token.trim().is_empty()
    {
        return Ok(config.token);
    }
    std::env::var("DIFF_API_KEY").map_err(|_| {
        anyhow::anyhow!("Not logged in. Run `getdiff login` first or set DIFF_API_KEY.")
    })
}

fn get_required_diff_api_key() -> Result<String> {
    get_api_key().map_err(|_| {
        anyhow::anyhow!(
            "Not logged in. Run `getdiff login` first or set DIFF_API_KEY before using registry or publish commands."
        )
    })
}

fn attach_config_snapshot_if_enabled(session: &mut types::DiffSession) -> Result<()> {
    let Some(provider) = parser::provider_from_tool(&session.tool) else {
        return Ok(());
    };

    let Some(mut snapshot) = provider.capture_config_snapshot(&session.project_path)? else {
        return Ok(());
    };

    if let Some(obj) = snapshot.snapshot_object_mut()
        && let Some(model) = &session.primary_model
    {
        obj.insert(
            "primary_model".to_string(),
            serde_json::Value::String(model.clone()),
        );
    }
    config_history::annotate_snapshot_change(
        &default_diff_dir(),
        &session.project_path,
        &mut snapshot,
    )?;
    session.config_snapshot = Some(snapshot);
    Ok(())
}

fn default_diff_dir() -> std::path::PathBuf {
    dirs::home_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".diff")
}

#[cfg(test)]
mod tests {
    use super::{
        attach_config_snapshot_if_enabled, ensure_publish_visibility_project_key,
        sanitize_ucir_for_publish,
    };
    use crate::types::DiffSession;

    fn base_session(project_path: String) -> DiffSession {
        DiffSession {
            session_id: "session_1".to_string(),
            org_id: "org_1".to_string(),
            engineer_id: "eng_1".to_string(),
            machine_id: "mac_1".to_string(),
            tool: "claude_code".to_string(),
            tool_version: "1.0.0".to_string(),
            diff_cli_version: "0.1.0".to_string(),
            project_path,
            repo_name: Some("repo".to_string()),
            git_branch: Some("main".to_string()),
            primary_model: Some("claude-sonnet".to_string()),
            started_at: None,
            ended_at: None,
            duration_seconds: None,
            messages: vec![],
            message_count: 0,
            user_message_count: 0,
            assistant_message_count: 0,
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
            files_modified: vec![],
            files_read: vec![],
            config_snapshot: None,
        }
    }

    #[test]
    fn attaches_real_config_metadata() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let project_root = temp.path();
        std::fs::create_dir_all(project_root.join(".claude/agents")).expect("agents dir");

        std::fs::write(project_root.join("CLAUDE.md"), "# project instructions")
            .expect("write claude md");
        std::fs::write(project_root.join(".claude/agents/reviewer.md"), "agent")
            .expect("write agent");
        std::fs::write(
            project_root.join(".claude/settings.local.json"),
            r#"{"hooks":{"PostToolUse":[{"matcher":"Edit"}]},"mcpServers":{"postgres":{}},"permissions":{"allow":["Bash(git status:*)"]}}"#,
        )
        .expect("write settings");

        let mut session = base_session(project_root.to_string_lossy().to_string());
        attach_config_snapshot_if_enabled(&mut session).expect("attach config snapshot");

        let snapshot = session
            .config_snapshot
            .expect("snapshot should be attached when enabled");

        assert_eq!(snapshot.provider(), "claude");
        assert!(snapshot.snapshot()["system_prompt_hash"].as_str().is_some());
        assert_eq!(snapshot.snapshot()["active_agents_count"].as_u64(), Some(1));
        assert_eq!(snapshot.snapshot()["active_hooks_count"].as_u64(), Some(1));
        assert_eq!(snapshot.snapshot()["active_mcps_count"].as_u64(), Some(1));
        assert_eq!(snapshot.snapshot()["permission_mode"], "allowlist");
    }

    #[test]
    fn sanitize_ucir_rejects_secret_like_content() {
        let redactor = crate::redact::Redactor::new();
        let result = sanitize_ucir_for_publish(
            serde_json::json!({
                "env": {
                    "OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz123456"
                }
            }),
            &redactor,
        );

        assert!(result.is_ok());
        let sanitized = result.expect("redaction should succeed");
        assert_ne!(
            sanitized["env"]["OPENAI_API_KEY"].as_str(),
            Some("sk-abcdefghijklmnopqrstuvwxyz123456")
        );
    }

    #[test]
    fn requires_project_key_for_project_visibility() {
        let result = ensure_publish_visibility_project_key("project", None);
        assert!(result.is_err());

        let ok = ensure_publish_visibility_project_key("project", Some("repo-a"));
        assert!(ok.is_ok());
    }
}
