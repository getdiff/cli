mod artifact_scanner;
mod artifact_sync;
mod auth;
mod config_history;
mod config_snapshot;
mod detectors;
mod parser;
mod redact;
mod types;
mod watcher;

use getdiff_gateway as gateway;

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
        /// Session provider(s) to watch (default: all)
        #[arg(long, value_enum, default_value_t = parser::ProviderSelection::All)]
        provider: parser::ProviderSelection,

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

    /// Run artifact sync manually (scan, upload, install pending)
    Sync {
        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
        server: String,
    },

    /// Artifact registry commands
    Artifacts {
        #[command(subcommand)]
        command: ArtifactCommands,
    },

    /// Run the agent capability gateway proxy
    Gateway {
        /// Path to gateway config YAML file (optional — runs with built-in defaults if omitted)
        #[arg(long, short)]
        config: Option<String>,

        /// Port to listen on
        #[arg(long, short, default_value_t = 19090)]
        port: u16,

        /// Agent type label (default: "default")
        #[arg(long, env = "GATEWAY_AGENT_TYPE")]
        agent_type: Option<String>,

        /// Environment label (auto-detected: "ci" if CI=true, else "local")
        #[arg(long, env = "GATEWAY_ENVIRONMENT")]
        environment: Option<String>,
    },

    /// Run the mock API server (for gateway testing/demos)
    MockApi {
        /// Port to listen on
        #[arg(long, short, default_value_t = 9999)]
        port: u16,
    },

    /// Configure an agent to route traffic through the gateway proxy
    Init {
        /// Agent to configure: claude-code, copilot, codex, gemini, opencode, cursor, or --env
        agent: String,

        /// Gateway proxy port (default: 19090)
        #[arg(long, default_value_t = 19090)]
        port: u16,
    },

    /// Remove gateway proxy configuration from an agent
    Uninit {
        /// Agent to unconfigure: claude-code, copilot, codex, gemini, opencode, cursor
        agent: String,
    },
}

#[derive(Subcommand)]
enum ArtifactCommands {
    /// List artifacts visible to you
    List {
        /// Search query
        #[arg(long)]
        query: Option<String>,

        /// Filter by type (agent, skill, rule, system_prompt, mcp, memory, hook, plugin)
        #[arg(long)]
        r#type: Option<String>,

        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
        server: String,
    },

    /// Install an artifact by ID (one-time, no auto-updates)
    Install {
        /// Artifact ID
        artifact_id: String,

        /// Target provider to install for
        #[arg(long, default_value = "claude")]
        target_provider: String,

        /// Subscribe for auto-updates instead of one-time install
        #[arg(long, default_value_t = false)]
        subscribe: bool,

        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
        server: String,
    },

    /// Share an artifact with your org or specific users
    Share {
        /// Artifact ID
        artifact_id: String,

        /// Share with the entire org
        #[arg(long, default_value_t = false)]
        org_wide: bool,

        /// Share with specific user IDs (comma-separated)
        #[arg(long, value_delimiter = ',')]
        user_ids: Option<Vec<String>>,

        /// Diff server URL
        #[arg(long, env = "DIFF_SERVER", default_value_t = default_server())]
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
            let providers = provider.providers().to_vec();
            let config = watcher::WatchConfig {
                providers: providers.clone(),
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
        Commands::Sync { server } => {
            let api_key = get_api_key()?;
            let diff_dir = default_diff_dir();
            artifact_sync::run_sync_cycle(&server, &api_key, &diff_dir).await?;
        }
        Commands::Gateway {
            config,
            port,
            agent_type,
            environment,
        } => {
            // Configure all detected agents to route through the gateway on startup.
            eprintln!("[gateway] configuring agents...");
            let _ = init_agent("all", port);

            // Install a Ctrl+C / SIGTERM handler that uninits agents on shutdown.
            // Waits briefly after uninit to let the event shipper flush buffered events.
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("\n[gateway] shutting down — removing agent proxy configuration...");
                let _ = uninit_agent("all");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                std::process::exit(0);
            });

            // Also handle SIGTERM (what brew services stop sends).
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                tokio::spawn(async move {
                    sigterm.recv().await;
                    eprintln!(
                        "\n[gateway] received SIGTERM — removing agent proxy configuration..."
                    );
                    let _ = uninit_agent("all");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    std::process::exit(0);
                });
            }

            let agent_ports: Vec<(String, u16)> = AGENT_PORTS
                .iter()
                .map(|(name, p)| (name.to_string(), *p))
                .collect();
            gateway::proxy::run_gateway(
                config.as_deref(),
                port,
                agent_type,
                environment,
                agent_ports,
            )
            .await?;
        }
        Commands::MockApi { port } => {
            gateway::mockapi::run_mock_api(port).await?;
        }
        Commands::Init { agent, port } => {
            init_agent(&agent, port)?;
        }
        Commands::Uninit { agent } => {
            uninit_agent(&agent)?;
        }
        Commands::Artifacts { command } => match command {
            ArtifactCommands::List {
                query,
                r#type,
                server,
            } => {
                let api_key = get_api_key()?;
                artifact_sync::list_artifacts(
                    &server,
                    &api_key,
                    query.as_deref(),
                    r#type.as_deref(),
                )
                .await?;
            }
            ArtifactCommands::Install {
                artifact_id,
                target_provider,
                subscribe,
                server,
            } => {
                let api_key = get_api_key()?;
                artifact_sync::install_artifact(
                    &server,
                    &api_key,
                    &artifact_id,
                    &target_provider,
                    subscribe,
                )
                .await?;
            }
            ArtifactCommands::Share {
                artifact_id,
                org_wide,
                user_ids,
                server,
            } => {
                let api_key = get_api_key()?;
                artifact_sync::share_artifact(&server, &api_key, &artifact_id, org_wide, user_ids)
                    .await?;
            }
        },
    }

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

// ---------------------------------------------------------------------------
// Agent init / uninit
// ---------------------------------------------------------------------------

/// Supported agents and how they accept proxy configuration:
///
/// | Agent        | Mechanism                          | Config path                    |
/// |--------------|------------------------------------|--------------------------------|
/// | claude-code  | `env` field in settings.json       | ~/.claude/settings.json        |
/// | copilot      | `env` field in config.json         | ~/.copilot/config.json         |
/// | codex        | env vars only (Node.js)            | shell environment              |
/// | gemini       | env vars only (Node.js)            | shell environment              |
/// | opencode     | env vars only (Go binary)          | shell environment              |
/// | cursor       | `http.proxy` in VS Code settings   | Cursor settings.json           |
///
/// Claude Code and Copilot support env injection in their settings files.
/// Codex, Gemini, and OpenCode are CLI tools that read HTTP_PROXY/HTTPS_PROXY
/// from the process environment — `getdiff init` prints the required exports.
/// Cursor uses VS Code's `http.proxy` setting.
const SUPPORTED_AGENTS: &[&str] = &[
    "claude-code",
    "copilot",
    "codex",
    "gemini",
    "opencode",
    "cursor",
];

/// Per-agent proxy port assignments. Each agent gets its own port so events
/// can be attributed to a specific agent. The default port (19090) is used
/// as a fallback for unrecognized traffic.
const AGENT_PORTS: &[(&str, u16)] = &[
    ("claude-code", 19091),
    ("cursor", 19092),
    ("codex", 19093),
    ("gemini", 19094),
    ("opencode", 19095),
    ("copilot", 19096),
];

/// Look up the per-agent port, falling back to the given default port.
fn agent_port(agent: &str, default_port: u16) -> u16 {
    AGENT_PORTS
        .iter()
        .find(|(name, _)| *name == agent)
        .map(|(_, port)| *port)
        .unwrap_or(default_port)
}

/// Configure an agent to route traffic through the gateway proxy.
fn init_agent(agent: &str, port: u16) -> Result<()> {
    let agent_port = agent_port(agent, port);
    let proxy_url = format!("http://localhost:{}", agent_port);

    match agent {
        "all" => init_all(port),
        "claude-code" => init_json_env(
            "Claude Code",
            "~/.claude/settings.json",
            &home_join(".claude"),
            &proxy_url,
            Some(format!("http://localhost:{}/anthropic", agent_port)),
        ),
        // Copilot: no BASE_URL override — GitHub Copilot uses its own endpoint
        // and does not support a standard base URL env var.
        "copilot" => init_json_env(
            "Copilot",
            "~/.copilot/config.json",
            &home_join(".copilot"),
            &proxy_url,
            None,
        ),
        // Cursor: no BASE_URL override — Cursor uses api2.cursor.sh/api3.cursor.sh
        // which are proprietary endpoints, not standard OpenAI-compatible.
        "cursor" => init_cursor(&proxy_url),
        // Agents that don't have config-file env injection — install wrapper script.
        "codex" => init_wrapper(
            agent,
            &proxy_url,
            Some(format!("http://localhost:{}/openai", agent_port)),
        ),
        // Gemini: no confirmed BASE_URL env var for Google's Gemini CLI.
        // OpenCode: supports multiple providers; no single BASE_URL to set.
        // Both fall back to CONNECT tunneling (hostname + timing visibility).
        "gemini" | "opencode" => init_wrapper(agent, &proxy_url, None),
        "--env" | "env" => {
            eprintln!("Set these environment variables before launching your agent:");
            eprintln!();
            eprintln!("  export HTTP_PROXY={}", proxy_url);
            eprintln!("  export HTTPS_PROXY={}", proxy_url);
            eprintln!();
            eprintln!("Or run: getdiff init <agent-name>");
            Ok(())
        }
        other => {
            bail!(
                "Unknown agent: \"{}\". Supported: {}, all. Use `--env` for manual setup.",
                other,
                SUPPORTED_AGENTS.join(", ")
            );
        }
    }
}

/// Remove gateway proxy configuration from an agent.
fn uninit_agent(agent: &str) -> Result<()> {
    match agent {
        "all" => uninit_all(),
        "claude-code" => {
            uninit_json_env("Claude Code", &home_join(".claude").join("settings.json"))
        }
        "copilot" => uninit_json_env("Copilot", &home_join(".copilot").join("config.json")),
        "cursor" => uninit_cursor(),
        "codex" | "gemini" | "opencode" => uninit_wrapper(agent),
        other => {
            bail!(
                "Unknown agent: \"{}\". Supported: {}, all",
                other,
                SUPPORTED_AGENTS.join(", ")
            );
        }
    }
}

/// Returns true if the given agent appears to be installed.
fn is_agent_installed(agent: &str) -> bool {
    match agent {
        "claude-code" => home_join(".claude").exists(),
        "copilot" => home_join(".copilot").exists(),
        "cursor" => cursor_settings_path()
            .ok()
            .map(|p| {
                // Check if the Cursor app data dir exists, not the settings file itself.
                p.parent().map(|d| d.exists()).unwrap_or(false)
            })
            .unwrap_or(false),
        "codex" | "gemini" | "opencode" => which_binary(agent).is_ok(),
        _ => false,
    }
}

/// Configure all detected agents.
fn init_all(port: u16) -> Result<()> {
    let mut configured = 0u32;

    for &agent in SUPPORTED_AGENTS {
        if is_agent_installed(agent) {
            eprintln!("--- {} ---", agent);
            match init_agent(agent, port) {
                Ok(()) => {
                    configured += 1;
                    eprintln!();
                }
                Err(e) => {
                    eprintln!("  skipped: {}", e);
                    eprintln!();
                }
            }
        }
    }

    if configured == 0 {
        eprintln!(
            "No supported agents detected. Supported: {}",
            SUPPORTED_AGENTS.join(", ")
        );
    } else {
        eprintln!(
            "{} agent(s) configured. Run `getdiff gateway` to start observing.",
            configured
        );
    }
    Ok(())
}

/// Remove gateway configuration from all agents that have it.
fn uninit_all() -> Result<()> {
    for &agent in SUPPORTED_AGENTS {
        // Try uninit — it's safe even if the agent wasn't configured.
        let _ = uninit_agent(agent);
    }
    eprintln!("All agent proxy configurations removed.");
    Ok(())
}

/// Helper: resolve ~/.<dir> path.
fn home_join(relative: &str) -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(relative)
}

/// Configure an agent that stores env vars in a JSON settings file.
/// Works for Claude Code (~/.claude/settings.json) and Copilot (~/.copilot/config.json).
/// If `base_url` is provided, sets the appropriate BASE_URL env var for direct
/// HTTP routing (full request visibility instead of CONNECT tunnels).
fn init_json_env(
    agent_name: &str,
    display_path: &str,
    config_dir: &std::path::Path,
    proxy_url: &str,
    base_url: Option<String>,
) -> Result<()> {
    if !config_dir.exists() {
        bail!(
            "{} config directory not found at {}. Is {} installed?",
            agent_name,
            config_dir.display(),
            agent_name
        );
    }

    let settings_path = config_dir.join(if config_dir.ends_with(".copilot") {
        "config.json"
    } else {
        "settings.json"
    });
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Merge env vars into settings.
    let env = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a JSON object", display_path))?
        .entry("env")
        .or_insert_with(|| serde_json::json!({}));
    let env_obj = env
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("env field in {} is not an object", display_path))?;
    env_obj.insert("HTTP_PROXY".to_string(), serde_json::json!(proxy_url));
    env_obj.insert("HTTPS_PROXY".to_string(), serde_json::json!(proxy_url));
    if let Some(ref url) = base_url {
        // Determine the env var name based on the URL path prefix.
        let var_name = if url.contains("/anthropic") {
            "ANTHROPIC_BASE_URL"
        } else if url.contains("/openai") {
            "OPENAI_BASE_URL"
        } else {
            "ANTHROPIC_BASE_URL"
        };
        env_obj.insert(var_name.to_string(), serde_json::json!(url));
    }

    let json_str = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, json_str)?;

    eprintln!(
        "{} configured to route through getDiff gateway.",
        agent_name
    );
    eprintln!("  Config: {}", settings_path.display());
    eprintln!();
    eprintln!("Run `getdiff gateway` to start observing agent traffic.");
    Ok(())
}

/// Remove proxy env vars from a JSON settings file.
fn uninit_json_env(agent_name: &str, settings_path: &std::path::Path) -> Result<()> {
    if !settings_path.exists() {
        eprintln!(
            "No {} settings found at {}",
            agent_name,
            settings_path.display()
        );
        return Ok(());
    }

    let content = std::fs::read_to_string(settings_path)?;
    let mut settings: serde_json::Value =
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}));

    if let Some(env) = settings.get_mut("env").and_then(|e| e.as_object_mut()) {
        env.remove("HTTP_PROXY");
        env.remove("HTTPS_PROXY");
        env.remove("ANTHROPIC_BASE_URL");
        env.remove("OPENAI_BASE_URL");
        if env.is_empty() {
            settings.as_object_mut().unwrap().remove("env");
        }
    }

    let json_str = serde_json::to_string_pretty(&settings)?;
    std::fs::write(settings_path, json_str)?;

    eprintln!("Gateway proxy configuration removed from {}.", agent_name);
    eprintln!("  Config: {}", settings_path.display());
    Ok(())
}

/// Configure Cursor via VS Code-style http.proxy setting.
fn init_cursor(proxy_url: &str) -> Result<()> {
    // Cursor settings path varies by platform.
    let settings_path = cursor_settings_path()?;

    // Ensure parent directory exists.
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let obj = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Cursor settings is not a JSON object"))?;
    obj.insert("http.proxy".to_string(), serde_json::json!(proxy_url));
    obj.insert("http.proxyStrictSSL".to_string(), serde_json::json!(false));

    let json_str = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, json_str)?;

    eprintln!("Cursor configured to route through getDiff gateway.");
    eprintln!("  Config: {}", settings_path.display());
    eprintln!();
    eprintln!("Run `getdiff gateway` to start observing agent traffic.");
    Ok(())
}

/// Remove proxy settings from Cursor.
fn uninit_cursor() -> Result<()> {
    let settings_path = cursor_settings_path()?;
    if !settings_path.exists() {
        eprintln!("No Cursor settings found at {}", settings_path.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value =
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}));

    if let Some(obj) = settings.as_object_mut() {
        obj.remove("http.proxy");
        obj.remove("http.proxyStrictSSL");
    }

    let json_str = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, json_str)?;

    eprintln!("Gateway proxy configuration removed from Cursor.");
    eprintln!("  Config: {}", settings_path.display());
    Ok(())
}

/// Resolve Cursor's settings.json path (platform-dependent).
fn cursor_settings_path() -> Result<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
            .join("Library/Application Support/Cursor/User/settings.json");
        Ok(path)
    }
    #[cfg(target_os = "linux")]
    {
        let path = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine config directory"))?
            .join("Cursor/User/settings.json");
        Ok(path)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        bail!("Cursor init is not supported on this platform. Use `getdiff init --env` instead.");
    }
}

/// Install a wrapper script that sets proxy env vars and exec's the real binary.
///
/// Creates `~/.getdiff/bin/<agent>` and ensures `~/.getdiff/bin` is on PATH
/// by adding a source line to the user's shell profile.
fn init_wrapper(agent: &str, proxy_url: &str, base_url: Option<String>) -> Result<()> {
    // Find the real binary.
    let real_path = which_binary(agent)?;
    let wrapper_dir = home_join(".getdiff/bin");
    let wrapper_path = wrapper_dir.join(agent);

    // Don't wrap our own wrapper.
    if real_path.starts_with(&wrapper_dir) {
        eprintln!(
            "{} is already configured (wrapper at {}).",
            agent,
            wrapper_path.display()
        );
        return Ok(());
    }

    std::fs::create_dir_all(&wrapper_dir)?;

    // Write the wrapper script.
    // Resolve the real binary at runtime via PATH (skipping our wrapper dir)
    // so the script doesn't break if the binary moves or is updated.
    let base_url_line = if let Some(ref url) = base_url {
        let var_name = if url.contains("/openai") {
            "OPENAI_BASE_URL"
        } else if url.contains("/anthropic") {
            "ANTHROPIC_BASE_URL"
        } else {
            "OPENAI_BASE_URL"
        };
        format!(" {}=\"{}\"", var_name, url)
    } else {
        String::new()
    };
    let script = format!(
        "#!/bin/sh\n\
         # Resolve the real binary by removing our wrapper dir from PATH.\n\
         _GETDIFF_PATH=$(echo \"$PATH\" | tr ':' '\\n' | grep -v '{wrapper}' | tr '\\n' ':')\n\
         _GETDIFF_BIN=$(PATH=\"$_GETDIFF_PATH\" command -v {agent})\n\
         exec env HTTP_PROXY=\"{proxy}\" HTTPS_PROXY=\"{proxy}\"{base_url} \"$_GETDIFF_BIN\" \"$@\"\n",
        wrapper = wrapper_dir.display(),
        agent = agent,
        proxy = proxy_url,
        base_url = base_url_line,
    );
    std::fs::write(&wrapper_path, &script)?;

    // Make it executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // Ensure ~/.getdiff/bin is on PATH via the shell profile.
    ensure_path_entry(&wrapper_dir)?;

    eprintln!("{} configured to route through getDiff gateway.", agent);
    eprintln!("  Wrapper: {}", wrapper_path.display());
    eprintln!("  Wraps:   {}", real_path.display());
    eprintln!();
    eprintln!("Open a new shell, then run `getdiff gateway` to start observing.");
    Ok(())
}

/// Remove a wrapper script installed by `init_wrapper`.
fn uninit_wrapper(agent: &str) -> Result<()> {
    let wrapper_path = home_join(".getdiff/bin").join(agent);
    if wrapper_path.exists() {
        std::fs::remove_file(&wrapper_path)?;
        eprintln!("Removed {} wrapper at {}", agent, wrapper_path.display());
    } else {
        eprintln!(
            "No wrapper found for {} at {}",
            agent,
            wrapper_path.display()
        );
    }

    // Clean up the bin directory if empty.
    let wrapper_dir = home_join(".getdiff/bin");
    if wrapper_dir.exists() && std::fs::read_dir(&wrapper_dir)?.next().is_none() {
        let _ = std::fs::remove_dir(&wrapper_dir);
    }
    Ok(())
}

/// Find the real binary path for an agent, skipping our own wrappers.
fn which_binary(name: &str) -> Result<std::path::PathBuf> {
    let wrapper_dir = home_join(".getdiff/bin");

    // Search PATH for the binary, skipping our wrapper directory.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if dir == wrapper_dir {
                continue;
            }
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    bail!("Could not find `{}` on PATH. Is it installed?", name)
}

/// Ensure `~/.getdiff/bin` is on PATH by adding a line to the shell profile.
/// Idempotent — won't add the line if it's already present.
fn ensure_path_entry(bin_dir: &std::path::Path) -> Result<()> {
    let source_line = format!("export PATH=\"{}:$PATH\"", bin_dir.display());

    // Detect the user's shell profile.
    let shell = std::env::var("SHELL").unwrap_or_default();
    let profile = if shell.contains("zsh") {
        home_join(".zshrc")
    } else {
        home_join(".bashrc")
    };

    // Check if the line is already present.
    if profile.exists() {
        let content = std::fs::read_to_string(&profile)?;
        if content.contains(&bin_dir.display().to_string()) {
            return Ok(());
        }
    }

    // Append the PATH entry with a comment.
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&profile)?;
    writeln!(f)?;
    writeln!(f, "# Added by getdiff — agent proxy wrappers")?;
    writeln!(f, "{}", source_line)?;

    eprintln!(
        "  Added {} to PATH in {}",
        bin_dir.display(),
        profile.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::attach_config_snapshot_if_enabled;
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
}
