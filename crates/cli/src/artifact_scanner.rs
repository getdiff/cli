use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Artifact types matching the server-side enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Agent,
    Skill,
    Rule,
    SystemPrompt,
    Mcp,
    Memory,
    Hook,
    Plugin,
}

impl ArtifactType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Skill => "skill",
            Self::Rule => "rule",
            Self::SystemPrompt => "system_prompt",
            Self::Mcp => "mcp",
            Self::Memory => "memory",
            Self::Hook => "hook",
            Self::Plugin => "plugin",
        }
    }
}

/// Provider names for artifact origin (matches server-side enum, distinct from session ProviderKind).
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProvider {
    Claude,
    Codex,
    Cursor,
    Copilot,
    Windsurf,
    Amazonq,
    Aider,
}

impl ArtifactProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::Windsurf => "windsurf",
            Self::Amazonq => "amazonq",
            Self::Aider => "aider",
        }
    }
}

/// All artifact providers to scan.
pub const ALL_ARTIFACT_PROVIDERS: &[ArtifactProvider] = &[
    ArtifactProvider::Claude,
    ArtifactProvider::Codex,
    ArtifactProvider::Cursor,
    ArtifactProvider::Copilot,
    ArtifactProvider::Windsurf,
    ArtifactProvider::Amazonq,
    ArtifactProvider::Aider,
];

/// A scanned artifact ready for upload.
#[derive(Clone, Debug)]
pub struct ScannedArtifact {
    pub artifact_type: ArtifactType,
    pub provider: ArtifactProvider,
    pub origin_path: String,
    pub origin_project: Option<String>,
    pub name: String,
    pub raw_content: String,
    pub content_hash: String,
}

#[derive(serde::Serialize)]
struct PluginUcir<'a> {
    kind: &'static str,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    contents: Vec<PluginChildRef<'a>>,
}

#[derive(serde::Serialize)]
struct PluginChildRef<'a> {
    #[serde(rename = "originPath")]
    origin_path: &'a str,
    name: &'a str,
    #[serde(rename = "type")]
    artifact_type: &'static str,
}

/// Scan all providers and return discovered artifacts.
///
/// `project_roots` specifies directories to scan for project-relative artifacts
/// (e.g., CLAUDE.md, .cursorrules). If empty, only home-relative (global) artifacts
/// are scanned. The daemon discovers project roots from `~/.claude/projects/`.
pub fn scan_all(project_roots: &[PathBuf]) -> Vec<ScannedArtifact> {
    let mut artifacts = Vec::new();
    for &provider in ALL_ARTIFACT_PROVIDERS {
        match scan_provider_global(provider) {
            Ok(found) => artifacts.extend(found),
            Err(e) => {
                eprintln!("  Artifact scan warning ({}): {}", provider.as_str(), e);
            }
        }
        for root in project_roots {
            match scan_provider_project(provider, root) {
                Ok(found) => artifacts.extend(found),
                Err(e) => {
                    eprintln!(
                        "  Artifact scan warning ({}, {}): {}",
                        provider.as_str(),
                        root.display(),
                        e
                    );
                }
            }
        }
    }
    artifacts
}

/// Discover project roots from `~/.claude/projects/` directory names.
/// Directory names are path-encoded: `/Users/jane/repo` → `-Users-jane-repo`.
pub fn discover_project_roots() -> Vec<PathBuf> {
    let home = match home_dir() {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };
    let projects_dir = home.join(".claude/projects");
    let entries = match std::fs::read_dir(&projects_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut roots = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // Decode: leading `-` represents `/`, internal `-` stay as `-`
        // Claude encodes `/Users/jane/repo` as `-Users-jane-repo`
        // We reconstruct by replacing the leading `-` with `/`
        if name.starts_with('-') {
            let decoded = name.replacen('-', "/", 1).replace('-', "/");
            let path = PathBuf::from(&decoded);
            if path.is_dir() {
                roots.push(path);
            }
        }
    }
    roots
}

fn scan_provider_global(provider: ArtifactProvider) -> Result<Vec<ScannedArtifact>> {
    match provider {
        ArtifactProvider::Claude => scan_claude_global(),
        ArtifactProvider::Codex => scan_codex_global(),
        ArtifactProvider::Cursor => Ok(Vec::new()), // All cursor artifacts are project-relative
        ArtifactProvider::Copilot => Ok(Vec::new()), // All copilot artifacts are project-relative
        ArtifactProvider::Windsurf => scan_windsurf_global(),
        ArtifactProvider::Amazonq => Ok(Vec::new()), // All amazonq artifacts are project-relative
        ArtifactProvider::Aider => Ok(Vec::new()),   // All aider artifacts are project-relative
    }
}

fn scan_provider_project(
    provider: ArtifactProvider,
    project_root: &Path,
) -> Result<Vec<ScannedArtifact>> {
    match provider {
        ArtifactProvider::Claude => scan_claude_project(project_root),
        ArtifactProvider::Codex => scan_codex_project(project_root),
        ArtifactProvider::Cursor => scan_cursor_project(project_root),
        ArtifactProvider::Copilot => scan_copilot_project(project_root),
        ArtifactProvider::Windsurf => scan_windsurf_project(project_root),
        ArtifactProvider::Amazonq => scan_amazonq_project(project_root),
        ArtifactProvider::Aider => scan_aider_project(project_root),
    }
}

// ---------------------------------------------------------------------------
// Claude
// ---------------------------------------------------------------------------

fn scan_claude_global() -> Result<Vec<ScannedArtifact>> {
    let home = home_dir()?;
    let mut artifacts = Vec::new();

    // Agents (subagents): ~/.claude/agents/*.md
    scan_glob_files(
        &home.join(".claude/agents/*.md"),
        ArtifactType::Agent,
        ArtifactProvider::Claude,
        |p| format!("~/.claude/agents/{}", file_name(p)),
        None,
        None,
        &mut artifacts,
    );

    // Skills: ~/.claude/skills/*/SKILL.md
    let skill_start = artifacts.len();
    scan_glob_files(
        &home.join(".claude/skills/*/SKILL.md"),
        ArtifactType::Skill,
        ArtifactProvider::Claude,
        |p| {
            let parent = p.parent().and_then(|d| d.file_name()).unwrap_or_default();
            format!("~/.claude/skills/{}/SKILL.md", parent.to_string_lossy())
        },
        None,
        None,
        &mut artifacts,
    );
    // Use parent directory name for skill display name instead of "SKILL"
    for a in &mut artifacts[skill_start..] {
        let parent_name = Path::new(&a.origin_path)
            .parent()
            .and_then(|d| d.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !parent_name.is_empty() {
            a.name = name_from_path(Path::new(&parent_name));
        }
    }

    // Commands (legacy, ingest as skills): ~/.claude/commands/*.md
    scan_glob_files(
        &home.join(".claude/commands/*.md"),
        ArtifactType::Skill,
        ArtifactProvider::Claude,
        |p| format!("~/.claude/commands/{}", file_name(p)),
        None,
        None,
        &mut artifacts,
    );

    // Rules: ~/.claude/rules/**/*.md (recursive)
    scan_glob_files(
        &home.join(".claude/rules/**/*.md"),
        ArtifactType::Rule,
        ArtifactProvider::Claude,
        |p| {
            let rules_dir = home.join(".claude/rules");
            let rel = p.strip_prefix(&rules_dir).unwrap_or(p);
            format!("~/.claude/rules/{}", rel.to_string_lossy())
        },
        None,
        Some(&home.join(".claude/rules")),
        &mut artifacts,
    );

    // User-level system prompt: ~/.claude/CLAUDE.md
    if let Some(a) = scan_single_file(
        &home.join(".claude/CLAUDE.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Claude,
        "~/.claude/CLAUDE.md",
    ) {
        artifacts.push(a);
    }

    // Settings (hooks + MCP): ~/.claude/settings.json
    scan_claude_settings(&home.join(".claude/settings.json"), &mut artifacts);

    // Memory: ~/.claude/projects/*/memory/**
    scan_claude_memory(&home, &mut artifacts);

    // Global plugins: ~/.claude/plugins/*/.claude-plugin/plugin.json
    scan_claude_plugins(&home, &home.join(".claude/plugins"), None, &mut artifacts);

    Ok(artifacts)
}

fn scan_claude_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_root
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // System prompt: {project}/CLAUDE.md
    if let Some(mut a) = scan_single_file(
        &project_root.join("CLAUDE.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Claude,
        "CLAUDE.md",
    ) {
        a.origin_project = Some(project_name.clone());
        artifacts.push(a);
    }

    // Project-level agents: {project}/.claude/agents/*.md
    scan_glob_files(
        &project_root.join(".claude/agents/*.md"),
        ArtifactType::Agent,
        ArtifactProvider::Claude,
        |p| format!(".claude/agents/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Project-level skills: {project}/.claude/skills/*/SKILL.md
    let skill_start = artifacts.len();
    scan_glob_files(
        &project_root.join(".claude/skills/*/SKILL.md"),
        ArtifactType::Skill,
        ArtifactProvider::Claude,
        |p| {
            let parent = p.parent().and_then(|d| d.file_name()).unwrap_or_default();
            format!(".claude/skills/{}/SKILL.md", parent.to_string_lossy())
        },
        Some(&project_name),
        None,
        &mut artifacts,
    );
    // Use parent directory name for skill display name instead of "SKILL"
    for a in &mut artifacts[skill_start..] {
        let parent_name = Path::new(&a.origin_path)
            .parent()
            .and_then(|d| d.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if !parent_name.is_empty() {
            a.name = name_from_path(Path::new(&parent_name));
        }
    }

    // Project-level commands (legacy, ingest as skills): {project}/.claude/commands/*.md
    scan_glob_files(
        &project_root.join(".claude/commands/*.md"),
        ArtifactType::Skill,
        ArtifactProvider::Claude,
        |p| format!(".claude/commands/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Project-level rules: {project}/.claude/rules/**/*.md
    scan_glob_files(
        &project_root.join(".claude/rules/**/*.md"),
        ArtifactType::Rule,
        ArtifactProvider::Claude,
        |p| {
            let rules_dir = project_root.join(".claude/rules");
            let rel = p.strip_prefix(&rules_dir).unwrap_or(p);
            format!(".claude/rules/{}", rel.to_string_lossy())
        },
        Some(&project_name),
        Some(&project_root.join(".claude/rules")),
        &mut artifacts,
    );

    // Project-level settings: {project}/.claude/settings.local.json
    scan_claude_settings_project(
        &project_root.join(".claude/settings.local.json"),
        &project_name,
        &mut artifacts,
    );

    // Project-level plugins: {project}/.claude/plugins/*/.claude-plugin/plugin.json
    scan_claude_plugins(
        project_root,
        &project_root.join(".claude/plugins"),
        Some(&project_name),
        &mut artifacts,
    );

    Ok(artifacts)
}

fn scan_claude_settings(settings_path: &Path, artifacts: &mut Vec<ScannedArtifact>) {
    let content = match std::fs::read_to_string(settings_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    extract_hooks_and_mcps(&json, None, artifacts);
}

fn scan_claude_settings_project(
    settings_path: &Path,
    project_name: &str,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let content = match std::fs::read_to_string(settings_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    extract_hooks_and_mcps(&json, Some(project_name), artifacts);
}

fn extract_hooks_and_mcps(
    json: &serde_json::Value,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    // Extract hooks
    if let Some(hooks) = json.get("hooks")
        && !hooks.is_null()
    {
        let hooks_str = serde_json::to_string_pretty(hooks).unwrap_or_default();
        if !hooks_str.is_empty() && hooks_str != "null" {
            let hash = sha256_hex(&hooks_str);
            artifacts.push(ScannedArtifact {
                artifact_type: ArtifactType::Hook,
                provider: ArtifactProvider::Claude,
                origin_path: "settings.json#hooks".to_string(),
                origin_project: project.map(ToString::to_string),
                name: "Claude Hooks".to_string(),
                raw_content: hooks_str,
                content_hash: hash,
            });
        }
    }

    // Extract MCP servers (with credential redaction)
    if let Some(mcps) = json.get("mcpServers")
        && !mcps.is_null()
    {
        let redacted = redact_credentials(mcps);
        let mcp_str = serde_json::to_string_pretty(&redacted).unwrap_or_default();
        if !mcp_str.is_empty() && mcp_str != "null" {
            let hash = sha256_hex(&mcp_str);
            artifacts.push(ScannedArtifact {
                artifact_type: ArtifactType::Mcp,
                provider: ArtifactProvider::Claude,
                origin_path: "settings.json#mcpServers".to_string(),
                origin_project: project.map(ToString::to_string),
                name: "Claude MCP Servers".to_string(),
                raw_content: mcp_str,
                content_hash: hash,
            });
        }
    }
}

fn scan_claude_memory(home: &Path, artifacts: &mut Vec<ScannedArtifact>) {
    let projects_dir = home.join(".claude/projects");
    let pattern = projects_dir.join("*/memory/**/*.md");
    let pattern_str = pattern.to_string_lossy().to_string();
    let entries = match glob::glob(&pattern_str) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if let Ok(content) = std::fs::read_to_string(&entry) {
            if content.trim().is_empty() {
                continue;
            }
            // origin_path relative to home
            let rel = entry
                .strip_prefix(home)
                .unwrap_or(&entry)
                .to_string_lossy()
                .to_string();
            let hash = sha256_hex(&content);
            artifacts.push(ScannedArtifact {
                artifact_type: ArtifactType::Memory,
                provider: ArtifactProvider::Claude,
                origin_path: rel.clone(),
                origin_project: extract_claude_project(&rel),
                name: format!("Memory: {}", file_stem(&entry)),
                raw_content: content,
                content_hash: hash,
            });
        }
    }
}

fn extract_claude_project(rel_path: &str) -> Option<String> {
    // .claude/projects/{project-hash}/memory/...
    let parts: Vec<&str> = rel_path.split('/').collect();
    if parts.len() >= 4 && parts[0] == ".claude" && parts[1] == "projects" {
        Some(parts[2].to_string())
    } else {
        None
    }
}

fn scan_claude_plugins(
    scan_root: &Path,
    plugins_root: &Path,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let pattern = plugins_root.join("**/.claude-plugin/plugin.json");
    let pattern_str = pattern.to_string_lossy().to_string();
    let entries = match glob::glob(&pattern_str) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let canonical_scan_root = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let canonical_boundary = match plugins_root.canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };

    for plugin_manifest in entries.flatten() {
        let canonical_manifest = match plugin_manifest.canonicalize() {
            Ok(path) if path.starts_with(&canonical_boundary) => path,
            Ok(_) => {
                eprintln!(
                    "  Skipping plugin manifest outside boundary: {}",
                    plugin_manifest.display()
                );
                continue;
            }
            Err(_) => continue,
        };

        let plugin_root = match canonical_manifest.parent().and_then(Path::parent) {
            Some(path) => path.to_path_buf(),
            None => continue,
        };
        let plugin_name = file_name(&plugin_root);
        let plugin_origin_root =
            origin_path_from_root(&plugin_root, &canonical_scan_root, project.is_none());
        let plugin_origin_path = format!("{}/.claude-plugin/plugin.json", plugin_origin_root);
        let plugin_project = project.map(ToString::to_string);

        let plugin_json = match std::fs::read_to_string(&canonical_manifest) {
            Ok(content) => content,
            Err(_) => continue,
        };
        let plugin_meta: serde_json::Value = match serde_json::from_str(&plugin_json) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let mut plugin_children = Vec::new();
        scan_claude_plugin_child_markdown_dir(
            &plugin_root.join("agents"),
            ArtifactType::Agent,
            ArtifactProvider::Claude,
            &format!("{}/agents", plugin_origin_root),
            project,
            &mut plugin_children,
        );
        scan_claude_plugin_skills(
            &plugin_root.join("skills"),
            &format!("{}/skills", plugin_origin_root),
            project,
            &mut plugin_children,
        );
        scan_claude_plugin_child_markdown_dir(
            &plugin_root.join("commands"),
            ArtifactType::Skill,
            ArtifactProvider::Claude,
            &format!("{}/commands", plugin_origin_root),
            project,
            &mut plugin_children,
        );
        scan_claude_plugin_hook_file(
            &plugin_root.join("hooks/hooks.json"),
            &format!("{}/hooks/hooks.json", plugin_origin_root),
            project,
            &mut plugin_children,
        );
        scan_json_mcp_file(
            &plugin_root.join(".mcp.json"),
            ArtifactProvider::Claude,
            &format!("{}/.mcp.json", plugin_origin_root),
            project,
            &mut plugin_children,
        );

        let plugin_display_name = plugin_meta
            .get("name")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| plugin_name.clone());
        let plugin_description = plugin_meta
            .get("description")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        let plugin_ucir = build_plugin_ucir(
            &plugin_display_name,
            plugin_description.as_deref(),
            &plugin_children,
        );
        let plugin_hash = sha256_hex(&plugin_ucir);

        artifacts.push(ScannedArtifact {
            artifact_type: ArtifactType::Plugin,
            provider: ArtifactProvider::Claude,
            origin_path: plugin_origin_path,
            origin_project: plugin_project,
            name: plugin_display_name,
            raw_content: plugin_ucir,
            content_hash: plugin_hash,
        });
        artifacts.extend(plugin_children);
    }
}

fn scan_claude_plugin_child_markdown_dir(
    dir: &Path,
    artifact_type: ArtifactType,
    provider: ArtifactProvider,
    origin_prefix: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    scan_glob_files(
        &dir.join("*.md"),
        artifact_type,
        provider,
        |p| format!("{}/{}", origin_prefix, file_name(p)),
        project,
        Some(dir),
        artifacts,
    );
}

fn scan_claude_plugin_skills(
    skills_dir: &Path,
    origin_prefix: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let skill_start = artifacts.len();
    scan_glob_files(
        &skills_dir.join("*/SKILL.md"),
        ArtifactType::Skill,
        ArtifactProvider::Claude,
        |p| {
            let parent = p.parent().and_then(|d| d.file_name()).unwrap_or_default();
            format!("{}/{}/SKILL.md", origin_prefix, parent.to_string_lossy())
        },
        project,
        Some(skills_dir),
        artifacts,
    );
    for artifact in &mut artifacts[skill_start..] {
        let parent_name = Path::new(&artifact.origin_path)
            .parent()
            .and_then(|d| d.file_name())
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if !parent_name.is_empty() {
            artifact.name = name_from_path(Path::new(&parent_name));
        }
    }
}

fn scan_claude_plugin_hook_file(
    path: &Path,
    origin_path: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let content = match std::fs::read_to_string(path) {
        Ok(content) if !content.trim().is_empty() => content,
        _ => return,
    };
    artifacts.push(ScannedArtifact {
        artifact_type: ArtifactType::Hook,
        provider: ArtifactProvider::Claude,
        origin_path: origin_path.to_string(),
        origin_project: project.map(ToString::to_string),
        name: "Plugin Hooks".to_string(),
        content_hash: sha256_hex(&content),
        raw_content: content,
    });
}

fn build_plugin_ucir(
    plugin_name: &str,
    plugin_description: Option<&str>,
    plugin_children: &[ScannedArtifact],
) -> String {
    let contents = plugin_children
        .iter()
        .map(|child| PluginChildRef {
            origin_path: &child.origin_path,
            name: &child.name,
            artifact_type: child.artifact_type.as_str(),
        })
        .collect();
    serde_json::to_string_pretty(&PluginUcir {
        kind: "plugin",
        name: plugin_name,
        description: plugin_description,
        contents,
    })
    .unwrap_or_else(|_| "{\"kind\":\"plugin\"}".to_string())
}

// ---------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------

fn scan_codex_global() -> Result<Vec<ScannedArtifact>> {
    let home = home_dir()?;
    let mut artifacts = Vec::new();

    // Skills: ~/.codex/skills/*.md
    scan_glob_files(
        &home.join(".codex/skills/*.md"),
        ArtifactType::Skill,
        ArtifactProvider::Codex,
        |p| format!("~/.codex/skills/{}", file_name(p)),
        None,
        None,
        &mut artifacts,
    );

    // Hooks: ~/.codex/config.toml
    if let Some(a) = scan_single_file(
        &home.join(".codex/config.toml"),
        ArtifactType::Hook,
        ArtifactProvider::Codex,
        "~/.codex/config.toml",
    ) {
        artifacts.push(a);
    }

    // Home-local Codex plugins: ~/plugins/*/.codex-plugin/plugin.json
    scan_codex_plugins(&home, &home.join("plugins"), None, &mut artifacts);

    Ok(artifacts)
}

fn scan_codex_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_dir_name(project_root);

    // System prompt: {project}/AGENTS.md
    if let Some(mut a) = scan_single_file(
        &project_root.join("AGENTS.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Codex,
        "AGENTS.md",
    ) {
        a.origin_project = Some(project_name.clone());
        artifacts.push(a);
    }

    // Repo-local Codex plugins: {project}/plugins/*/.codex-plugin/plugin.json
    scan_codex_plugins(
        project_root,
        &project_root.join("plugins"),
        Some(&project_name),
        &mut artifacts,
    );

    Ok(artifacts)
}

fn scan_codex_plugins(
    scan_root: &Path,
    plugins_root: &Path,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let pattern = plugins_root.join("**/.codex-plugin/plugin.json");
    let pattern_str = pattern.to_string_lossy().to_string();
    let entries = match glob::glob(&pattern_str) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let canonical_scan_root = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let canonical_boundary = match plugins_root.canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };

    for plugin_manifest in entries.flatten() {
        let canonical_manifest = match plugin_manifest.canonicalize() {
            Ok(path) if path.starts_with(&canonical_boundary) => path,
            Ok(_) => {
                eprintln!(
                    "  Skipping plugin manifest outside boundary: {}",
                    plugin_manifest.display()
                );
                continue;
            }
            Err(_) => continue,
        };

        let plugin_root = match canonical_manifest.parent().and_then(Path::parent) {
            Some(path) => path.to_path_buf(),
            None => continue,
        };
        let plugin_origin_root =
            origin_path_from_root(&plugin_root, &canonical_scan_root, project.is_none());
        let plugin_origin_path = format!("{}/.codex-plugin/plugin.json", plugin_origin_root);
        let plugin_project = project.map(ToString::to_string);

        let plugin_json = match std::fs::read_to_string(&canonical_manifest) {
            Ok(content) => content,
            Err(_) => continue,
        };
        let plugin_meta: serde_json::Value = match serde_json::from_str(&plugin_json) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let plugin_name = plugin_meta
            .get("name")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| file_name(&plugin_root));
        let plugin_description = plugin_meta
            .get("description")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty());

        let mut plugin_children = Vec::new();
        if let Some(skills_path) = plugin_meta.get("skills").and_then(|value| value.as_str()) {
            scan_codex_plugin_skills_path(
                &plugin_root,
                &canonical_scan_root,
                project.is_none(),
                skills_path,
                project,
                &mut plugin_children,
                &canonical_manifest,
            );
        } else {
            scan_codex_plugin_skills_dir(
                &plugin_root.join("skills"),
                &origin_path_from_root(
                    &plugin_root.join("skills"),
                    &canonical_scan_root,
                    project.is_none(),
                ),
                project,
                &mut plugin_children,
            );
        }
        if let Some(hooks_path) = plugin_meta.get("hooks").and_then(|value| value.as_str()) {
            scan_codex_plugin_hook_path(
                &plugin_root,
                &canonical_scan_root,
                project.is_none(),
                hooks_path,
                project,
                &mut plugin_children,
                &canonical_manifest,
            );
        }
        if let Some(mcp_path) = plugin_meta
            .get("mcpServers")
            .and_then(|value| value.as_str())
        {
            scan_codex_plugin_mcp_path(
                &plugin_root,
                &canonical_scan_root,
                project.is_none(),
                mcp_path,
                project,
                &mut plugin_children,
                &canonical_manifest,
            );
        }

        let plugin_ucir = build_plugin_ucir(&plugin_name, plugin_description, &plugin_children);
        let plugin_hash = sha256_hex(&plugin_ucir);

        artifacts.push(ScannedArtifact {
            artifact_type: ArtifactType::Plugin,
            provider: ArtifactProvider::Codex,
            origin_path: plugin_origin_path,
            origin_project: plugin_project,
            name: plugin_name,
            raw_content: plugin_ucir,
            content_hash: plugin_hash,
        });
        artifacts.extend(plugin_children);
    }
}

fn scan_codex_plugin_skills_path(
    plugin_root: &Path,
    scan_root: &Path,
    global_scope: bool,
    skills_path: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
    manifest_path: &Path,
) {
    let resolved = match resolve_plugin_relative_path(plugin_root, skills_path) {
        Some(path) => path,
        None => return,
    };
    let canonical_root = match plugin_root.canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };
    match resolved.canonicalize() {
        Ok(path) if !path.starts_with(&canonical_root) => {
            eprintln!(
                "  Skipping Codex plugin skill path outside plugin boundary: {}",
                manifest_path.display()
            );
            return;
        }
        Err(_) => return,
        _ => {}
    }

    if resolved.is_dir() {
        let origin_prefix = origin_path_from_root(&resolved, scan_root, global_scope);
        scan_codex_plugin_skills_dir(&resolved, &origin_prefix, project, artifacts);
    } else if let Some(mut skill) = scan_single_file(
        &resolved,
        ArtifactType::Skill,
        ArtifactProvider::Codex,
        &origin_path_from_root(&resolved, scan_root, global_scope),
    ) {
        skill.origin_project = project.map(ToString::to_string);
        artifacts.push(skill);
    }
}

fn scan_codex_plugin_skills_dir(
    skills_dir: &Path,
    origin_prefix: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let skill_start = artifacts.len();
    scan_glob_files(
        &skills_dir.join("*/SKILL.md"),
        ArtifactType::Skill,
        ArtifactProvider::Codex,
        |p| {
            let parent = p.parent().and_then(|d| d.file_name()).unwrap_or_default();
            format!("{}/{}/SKILL.md", origin_prefix, parent.to_string_lossy())
        },
        project,
        Some(skills_dir),
        artifacts,
    );
    for artifact in &mut artifacts[skill_start..] {
        let parent_name = Path::new(&artifact.origin_path)
            .parent()
            .and_then(|d| d.file_name())
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if !parent_name.is_empty() {
            artifact.name = name_from_path(Path::new(&parent_name));
        }
    }

    scan_glob_files(
        &skills_dir.join("*.md"),
        ArtifactType::Skill,
        ArtifactProvider::Codex,
        |p| format!("{}/{}", origin_prefix, file_name(p)),
        project,
        Some(skills_dir),
        artifacts,
    );
}

fn scan_codex_plugin_hook_path(
    plugin_root: &Path,
    scan_root: &Path,
    global_scope: bool,
    hooks_path: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
    manifest_path: &Path,
) {
    let resolved = match resolve_plugin_relative_path(plugin_root, hooks_path) {
        Some(path) => path,
        None => return,
    };
    let canonical_root = match plugin_root.canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };
    match resolved.canonicalize() {
        Ok(path) if !path.starts_with(&canonical_root) => {
            eprintln!(
                "  Skipping Codex plugin hook path outside plugin boundary: {}",
                manifest_path.display()
            );
            return;
        }
        Err(_) => return,
        _ => {}
    }

    let content = match std::fs::read_to_string(&resolved) {
        Ok(content) if !content.trim().is_empty() => content,
        _ => return,
    };
    artifacts.push(ScannedArtifact {
        artifact_type: ArtifactType::Hook,
        provider: ArtifactProvider::Codex,
        origin_path: origin_path_from_root(&resolved, scan_root, global_scope),
        origin_project: project.map(ToString::to_string),
        name: "Plugin Hooks".to_string(),
        raw_content: content.clone(),
        content_hash: sha256_hex(&content),
    });
}

fn scan_codex_plugin_mcp_path(
    plugin_root: &Path,
    scan_root: &Path,
    global_scope: bool,
    mcp_path: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
    manifest_path: &Path,
) {
    let resolved = match resolve_plugin_relative_path(plugin_root, mcp_path) {
        Some(path) => path,
        None => return,
    };
    let canonical_root = match plugin_root.canonicalize() {
        Ok(path) => path,
        Err(_) => return,
    };
    match resolved.canonicalize() {
        Ok(path) if !path.starts_with(&canonical_root) => {
            eprintln!(
                "  Skipping Codex plugin MCP path outside plugin boundary: {}",
                manifest_path.display()
            );
            return;
        }
        Err(_) => return,
        _ => {}
    }

    scan_json_mcp_file(
        &resolved,
        ArtifactProvider::Codex,
        &origin_path_from_root(&resolved, scan_root, global_scope),
        project,
        artifacts,
    );
}

fn resolve_plugin_relative_path(plugin_root: &Path, plugin_path: &str) -> Option<PathBuf> {
    if plugin_path.trim().is_empty() {
        return None;
    }
    let path = Path::new(plugin_path);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    Some(plugin_root.join(path))
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

fn scan_cursor_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_dir_name(project_root);

    // Rules (modern): {project}/.cursor/rules/*.mdc and *.md
    scan_glob_files(
        &project_root.join(".cursor/rules/*.mdc"),
        ArtifactType::Rule,
        ArtifactProvider::Cursor,
        |p| format!(".cursor/rules/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );
    scan_glob_files(
        &project_root.join(".cursor/rules/*.md"),
        ArtifactType::Rule,
        ArtifactProvider::Cursor,
        |p| format!(".cursor/rules/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Legacy system prompt: {project}/.cursorrules
    if let Some(mut a) = scan_single_file(
        &project_root.join(".cursorrules"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Cursor,
        ".cursorrules",
    ) {
        a.origin_project = Some(project_name.clone());
        artifacts.push(a);
    }

    // Commands (ingest as skills): {project}/.cursor/commands/*.md
    scan_glob_files(
        &project_root.join(".cursor/commands/*.md"),
        ArtifactType::Skill,
        ArtifactProvider::Cursor,
        |p| format!(".cursor/commands/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // MCP: {project}/.cursor/mcp.json (with credential redaction)
    scan_json_mcp_file(
        &project_root.join(".cursor/mcp.json"),
        ArtifactProvider::Cursor,
        ".cursor/mcp.json",
        Some(&project_name),
        &mut artifacts,
    );

    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// Copilot
// ---------------------------------------------------------------------------

fn scan_copilot_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_dir_name(project_root);

    // Agents: {project}/.github/agents/*.agent.md
    scan_glob_files(
        &project_root.join(".github/agents/*.agent.md"),
        ArtifactType::Agent,
        ArtifactProvider::Copilot,
        |p| format!(".github/agents/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Path-scoped instructions (rules): {project}/.github/instructions/*.instructions.md
    scan_glob_files(
        &project_root.join(".github/instructions/*.instructions.md"),
        ArtifactType::Rule,
        ArtifactProvider::Copilot,
        |p| format!(".github/instructions/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Prompt files (skills): {project}/.github/prompts/*.prompt.md
    scan_glob_files(
        &project_root.join(".github/prompts/*.prompt.md"),
        ArtifactType::Skill,
        ArtifactProvider::Copilot,
        |p| format!(".github/prompts/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // System prompt: {project}/.github/copilot-instructions.md
    if let Some(mut a) = scan_single_file(
        &project_root.join(".github/copilot-instructions.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Copilot,
        ".github/copilot-instructions.md",
    ) {
        a.origin_project = Some(project_name.clone());
        artifacts.push(a);
    }

    // Cross-tool: {project}/AGENTS.md
    if let Some(mut a) = scan_single_file(
        &project_root.join("AGENTS.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Copilot,
        "AGENTS.md",
    ) {
        a.origin_project = Some(project_name);
        artifacts.push(a);
    }

    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// Windsurf
// ---------------------------------------------------------------------------

fn scan_windsurf_global() -> Result<Vec<ScannedArtifact>> {
    let home = home_dir()?;
    let mut artifacts = Vec::new();

    // MCP: ~/.codeium/windsurf/mcp_config.json
    scan_json_mcp_file(
        &home.join(".codeium/windsurf/mcp_config.json"),
        ArtifactProvider::Windsurf,
        "~/.codeium/windsurf/mcp_config.json",
        None,
        &mut artifacts,
    );

    Ok(artifacts)
}

fn scan_windsurf_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_dir_name(project_root);

    // Rules (modern): {project}/.windsurf/rules/*.md
    scan_glob_files(
        &project_root.join(".windsurf/rules/*.md"),
        ArtifactType::Rule,
        ArtifactProvider::Windsurf,
        |p| format!(".windsurf/rules/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Legacy system prompt: {project}/.windsurfrules (root-level file)
    if let Some(mut a) = scan_single_file(
        &project_root.join(".windsurfrules"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Windsurf,
        ".windsurfrules",
    ) {
        a.origin_project = Some(project_name.clone());
        artifacts.push(a);
    }

    // Cross-tool: {project}/AGENTS.md
    if let Some(mut a) = scan_single_file(
        &project_root.join("AGENTS.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Windsurf,
        "AGENTS.md",
    ) {
        a.origin_project = Some(project_name);
        artifacts.push(a);
    }

    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// Amazon Q
// ---------------------------------------------------------------------------

fn scan_amazonq_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_dir_name(project_root);

    // Agents: {project}/.amazonq/agents/*.json
    scan_glob_files(
        &project_root.join(".amazonq/agents/*.json"),
        ArtifactType::Agent,
        ArtifactProvider::Amazonq,
        |p| format!(".amazonq/agents/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    // Rules: {project}/.amazonq/rules/*.md
    scan_glob_files(
        &project_root.join(".amazonq/rules/*.md"),
        ArtifactType::Rule,
        ArtifactProvider::Amazonq,
        |p| format!(".amazonq/rules/{}", file_name(p)),
        Some(&project_name),
        None,
        &mut artifacts,
    );

    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// Aider
// ---------------------------------------------------------------------------

fn scan_aider_project(project_root: &Path) -> Result<Vec<ScannedArtifact>> {
    let mut artifacts = Vec::new();
    let project_name = project_dir_name(project_root);

    // System prompt: {project}/CONVENTIONS.md
    if let Some(mut a) = scan_single_file(
        &project_root.join("CONVENTIONS.md"),
        ArtifactType::SystemPrompt,
        ArtifactProvider::Aider,
        "CONVENTIONS.md",
    ) {
        a.origin_project = Some(project_name);
        artifacts.push(a);
    }

    Ok(artifacts)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))
}

fn project_dir_name(project_root: &Path) -> String {
    project_root
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn origin_path_from_root(path: &Path, root: &Path, global_scope: bool) -> String {
    use std::path::Component;

    let rel_path = path.strip_prefix(root).unwrap_or(path);
    let normalized_rel = rel_path
        .components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            other => Some(other.as_os_str().to_string_lossy().to_string()),
        })
        .collect::<Vec<_>>()
        .join("/");
    if global_scope {
        format!("~/{}", normalized_rel)
    } else {
        normalized_rel
    }
}

pub fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("sha256-{:x}", hasher.finalize())
}

fn name_from_path(path: &Path) -> String {
    file_stem(path)
        .replace(['-', '_'], " ")
        .split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn scan_single_file(
    path: &Path,
    artifact_type: ArtifactType,
    provider: ArtifactProvider,
    origin_path: &str,
) -> Option<ScannedArtifact> {
    // Resolve symlinks and verify the canonical path is under the original parent
    // to prevent symlink-based directory traversal
    let canonical = path.canonicalize().ok()?;
    if let Some(parent) = path.parent()
        && let Ok(canonical_parent) = parent.canonicalize()
        && !canonical.starts_with(&canonical_parent)
    {
        eprintln!(
            "  Skipping symlink outside project boundary: {}",
            path.display()
        );
        return None;
    }

    let content = std::fs::read_to_string(&canonical).ok()?;
    if content.trim().is_empty() {
        return None;
    }
    let hash = sha256_hex(&content);
    Some(ScannedArtifact {
        artifact_type,
        provider,
        origin_path: origin_path.to_string(),
        origin_project: None,
        name: name_from_path(path),
        raw_content: content,
        content_hash: hash,
    })
}

fn scan_glob_files(
    pattern: &Path,
    artifact_type: ArtifactType,
    provider: ArtifactProvider,
    origin_path_fn: impl Fn(&Path) -> String,
    project: Option<&str>,
    boundary: Option<&Path>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let pattern_str = pattern.to_string_lossy().to_string();
    let entries = match glob::glob(&pattern_str) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Compute canonical boundary once: prefer explicit boundary, fall back to pattern parent
    let canonical_boundary = boundary
        .and_then(|b| b.canonicalize().ok())
        .or_else(|| pattern.parent().and_then(|p| p.canonicalize().ok()));

    for entry in entries.flatten() {
        // Validate entry is within the boundary (prevents symlink escapes)
        if let Some(ref cb) = canonical_boundary {
            match entry.canonicalize() {
                Ok(canonical_entry) if !canonical_entry.starts_with(cb) => {
                    eprintln!("  Skipping file outside boundary: {}", entry.display());
                    continue;
                }
                Err(_) => continue,
                _ => {}
            }
        }
        if let Ok(content) = std::fs::read_to_string(&entry) {
            if content.trim().is_empty() {
                continue;
            }
            let hash = sha256_hex(&content);
            artifacts.push(ScannedArtifact {
                artifact_type,
                provider,
                origin_path: origin_path_fn(&entry),
                origin_project: project.map(ToString::to_string),
                name: name_from_path(&entry),
                raw_content: content,
                content_hash: hash,
            });
        }
    }
}

fn scan_json_mcp_file(
    path: &Path,
    provider: ArtifactProvider,
    origin_path: &str,
    project: Option<&str>,
    artifacts: &mut Vec<ScannedArtifact>,
) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };
    let redacted = redact_credentials(&json);
    let redacted_str = serde_json::to_string_pretty(&redacted).unwrap_or_default();
    if redacted_str.trim().is_empty() || redacted_str == "null" {
        return;
    }
    let hash = sha256_hex(&redacted_str);
    artifacts.push(ScannedArtifact {
        artifact_type: ArtifactType::Mcp,
        provider,
        origin_path: origin_path.to_string(),
        origin_project: project.map(ToString::to_string),
        name: format!("{} MCP Config", capitalize(provider.as_str())),
        raw_content: redacted_str,
        content_hash: hash,
    });
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

/// Keys whose values must be redacted before upload.
const SENSITIVE_KEYS: &[&str] = &[
    "apikey",
    "api_key",
    "token",
    "password",
    "secret",
    "connectionstring",
    "database_url",
];

/// Recursively redact sensitive credential values from JSON.
pub fn redact_credentials(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, val) in map {
                let lower = key.to_lowercase();
                if SENSITIVE_KEYS.iter().any(|&s| lower.contains(s)) {
                    // Only redact string values (not nested objects that happen to have "token" in key)
                    match val {
                        serde_json::Value::String(_) => {
                            out.insert(
                                key.clone(),
                                serde_json::Value::String("<redacted>".to_string()),
                            );
                        }
                        _ => {
                            out.insert(key.clone(), redact_credentials(val));
                        }
                    }
                } else {
                    out.insert(key.clone(), redact_credentials(val));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_credentials).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex("hello");
        assert!(hash.starts_with("sha256-"));
        assert_eq!(hash.len(), 7 + 64); // "sha256-" + 64 hex chars
    }

    #[test]
    fn test_redact_credentials() {
        let input = serde_json::json!({
            "name": "postgres",
            "apiKey": "sk-secret-123",
            "config": {
                "token": "tok_abc",
                "host": "localhost",
                "PASSWORD": "hunter2",
                "nested": {
                    "connectionString": "postgres://user:pass@host/db"
                }
            },
            "items": [
                {"api_key": "key123", "label": "test"}
            ]
        });

        let redacted = redact_credentials(&input);

        assert_eq!(redacted["name"], "postgres");
        assert_eq!(redacted["apiKey"], "<redacted>");
        assert_eq!(redacted["config"]["token"], "<redacted>");
        assert_eq!(redacted["config"]["host"], "localhost");
        assert_eq!(redacted["config"]["PASSWORD"], "<redacted>");
        assert_eq!(
            redacted["config"]["nested"]["connectionString"],
            "<redacted>"
        );
        assert_eq!(redacted["items"][0]["api_key"], "<redacted>");
        assert_eq!(redacted["items"][0]["label"], "test");
    }

    #[test]
    fn test_name_from_path() {
        assert_eq!(name_from_path(Path::new("code-review.md")), "Code Review");
        assert_eq!(name_from_path(Path::new("my_agent.md")), "My Agent");
    }

    #[test]
    fn test_scan_single_file_nonexistent() {
        let result = scan_single_file(
            Path::new("/nonexistent/file.md"),
            ArtifactType::Agent,
            ArtifactProvider::Claude,
            "test.md",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_single_file_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "   \n  ").unwrap();
        let result = scan_single_file(
            tmp.path(),
            ArtifactType::Agent,
            ArtifactProvider::Claude,
            "test.md",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_single_file_with_content() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "You are a code reviewer").unwrap();
        let result = scan_single_file(
            tmp.path(),
            ArtifactType::Agent,
            ArtifactProvider::Claude,
            ".claude/agents/reviewer.md",
        );
        assert!(result.is_some());
        let artifact = result.unwrap();
        assert_eq!(artifact.artifact_type, ArtifactType::Agent);
        assert_eq!(artifact.provider, ArtifactProvider::Claude);
        assert!(artifact.content_hash.starts_with("sha256-"));
        assert_eq!(artifact.raw_content, "You are a code reviewer");
    }

    #[test]
    fn test_extract_claude_project() {
        assert_eq!(
            extract_claude_project(".claude/projects/abc123/memory/notes.md"),
            Some("abc123".to_string())
        );
        assert_eq!(extract_claude_project("some/other/path.md"), None);
    }

    #[test]
    fn test_scan_claude_settings_extracts_hooks_and_mcps() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"{
                "hooks": {"PostToolUse": [{"matcher": "Edit"}]},
                "mcpServers": {"pg": {"command": "pg", "apiKey": "secret"}}
            }"#,
        )
        .unwrap();

        let mut artifacts = Vec::new();
        scan_claude_settings(tmp.path(), &mut artifacts);

        assert_eq!(artifacts.len(), 2);
        let hook = artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::Hook)
            .unwrap();
        assert!(hook.raw_content.contains("PostToolUse"));

        let mcp = artifacts
            .iter()
            .find(|a| a.artifact_type == ArtifactType::Mcp)
            .unwrap();
        assert!(mcp.raw_content.contains("<redacted>"));
        assert!(!mcp.raw_content.contains("secret"));
    }

    #[test]
    fn test_scan_claude_project_finds_plugin_and_children() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plugin_root = tmp.path().join(".claude/plugins/team-pack");
        std::fs::create_dir_all(plugin_root.join(".claude-plugin")).unwrap();
        std::fs::create_dir_all(plugin_root.join("agents")).unwrap();
        std::fs::create_dir_all(plugin_root.join("skills/review-flow")).unwrap();
        std::fs::create_dir_all(plugin_root.join("commands")).unwrap();
        std::fs::create_dir_all(plugin_root.join("hooks")).unwrap();

        std::fs::write(
            plugin_root.join(".claude-plugin/plugin.json"),
            r#"{"name":"team-pack","description":"Team workflow bundle"}"#,
        )
        .unwrap();
        std::fs::write(plugin_root.join("agents/reviewer.md"), "Review code").unwrap();
        std::fs::write(
            plugin_root.join("skills/review-flow/SKILL.md"),
            "Run review flow",
        )
        .unwrap();
        std::fs::write(plugin_root.join("commands/review.md"), "Review command").unwrap();
        std::fs::write(
            plugin_root.join("hooks/hooks.json"),
            r#"{"PostToolUse":[{"matcher":"Edit"}]}"#,
        )
        .unwrap();
        std::fs::write(
            plugin_root.join(".mcp.json"),
            r#"{"review":{"command":"review","apiKey":"secret"}}"#,
        )
        .unwrap();

        let artifacts = scan_claude_project(tmp.path()).unwrap();

        let plugin = artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == ArtifactType::Plugin)
            .unwrap();
        assert_eq!(
            plugin.origin_path,
            ".claude/plugins/team-pack/.claude-plugin/plugin.json"
        );
        assert_eq!(plugin.name, "team-pack");
        let plugin_ucir: serde_json::Value = serde_json::from_str(&plugin.raw_content).unwrap();
        assert_eq!(plugin_ucir["kind"], "plugin");
        assert_eq!(plugin_ucir["description"], "Team workflow bundle");
        let contents = plugin_ucir["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 5);
        assert!(contents.iter().any(|child| {
            child["originPath"] == ".claude/plugins/team-pack/agents/reviewer.md"
                && child["type"] == "agent"
        }));
        assert!(contents.iter().any(|child| {
            child["originPath"] == ".claude/plugins/team-pack/skills/review-flow/SKILL.md"
                && child["type"] == "skill"
        }));
        assert!(contents.iter().any(|child| {
            child["originPath"] == ".claude/plugins/team-pack/commands/review.md"
                && child["type"] == "skill"
        }));
        assert!(contents.iter().any(|child| {
            child["originPath"] == ".claude/plugins/team-pack/hooks/hooks.json"
                && child["type"] == "hook"
        }));
        assert!(contents.iter().any(|child| {
            child["originPath"] == ".claude/plugins/team-pack/.mcp.json" && child["type"] == "mcp"
        }));

        assert!(artifacts.iter().any(|artifact| {
            artifact.artifact_type == ArtifactType::Agent
                && artifact.origin_path == ".claude/plugins/team-pack/agents/reviewer.md"
        }));
        assert!(artifacts.iter().any(|artifact| {
            artifact.artifact_type == ArtifactType::Skill
                && artifact.origin_path == ".claude/plugins/team-pack/skills/review-flow/SKILL.md"
                && artifact.name == "Review Flow"
        }));
        assert!(artifacts.iter().any(|artifact| {
            artifact.artifact_type == ArtifactType::Hook
                && artifact.origin_path == ".claude/plugins/team-pack/hooks/hooks.json"
        }));
        let mcp = artifacts
            .iter()
            .find(|artifact| artifact.origin_path == ".claude/plugins/team-pack/.mcp.json")
            .unwrap();
        assert_eq!(mcp.artifact_type, ArtifactType::Mcp);
        assert!(mcp.raw_content.contains("<redacted>"));
        assert!(!mcp.raw_content.contains("secret"));
    }

    #[test]
    fn test_scan_claude_plugins_finds_marketplace_plugins_recursively() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plugin_root = tmp
            .path()
            .join(".claude/plugins/marketplaces/official/plugins/feature-dev");
        std::fs::create_dir_all(plugin_root.join(".claude-plugin")).unwrap();
        std::fs::create_dir_all(plugin_root.join("commands")).unwrap();
        std::fs::write(
            plugin_root.join(".claude-plugin/plugin.json"),
            r#"{"name":"feature-dev","description":"Workflow"}"#,
        )
        .unwrap();
        std::fs::write(plugin_root.join("commands/review.md"), "Review command").unwrap();

        let mut artifacts = Vec::new();
        scan_claude_plugins(
            tmp.path(),
            &tmp.path().join(".claude/plugins"),
            None,
            &mut artifacts,
        );

        let plugin = artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == ArtifactType::Plugin)
            .unwrap();
        assert_eq!(
            plugin.origin_path,
            "~/.claude/plugins/marketplaces/official/plugins/feature-dev/.claude-plugin/plugin.json"
        );
        let plugin_ucir: serde_json::Value = serde_json::from_str(&plugin.raw_content).unwrap();
        assert_eq!(
            plugin_ucir["contents"][0]["originPath"],
            "~/.claude/plugins/marketplaces/official/plugins/feature-dev/commands/review.md"
        );
    }

    #[test]
    fn test_scan_codex_project_finds_plugin_and_children() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plugin_root = tmp.path().join("plugins/linear");
        std::fs::create_dir_all(plugin_root.join(".codex-plugin")).unwrap();
        std::fs::create_dir_all(plugin_root.join("skills/release-helper")).unwrap();
        std::fs::write(
            plugin_root.join(".codex-plugin/plugin.json"),
            r#"{
                "name":"linear",
                "description":"Linear workflow tools",
                "skills":"./skills",
                "hooks":"./hooks.json",
                "mcpServers":"./.mcp.json"
            }"#,
        )
        .unwrap();
        std::fs::write(
            plugin_root.join("skills/release-helper/SKILL.md"),
            "Release helper skill",
        )
        .unwrap();
        std::fs::write(plugin_root.join("hooks.json"), r#"{"event":"on_use"}"#).unwrap();
        std::fs::write(
            plugin_root.join(".mcp.json"),
            r#"{"linear":{"command":"linear","apiKey":"secret"}}"#,
        )
        .unwrap();

        let artifacts = scan_codex_project(tmp.path()).unwrap();

        let plugin = artifacts
            .iter()
            .find(|artifact| {
                artifact.artifact_type == ArtifactType::Plugin
                    && artifact.provider == ArtifactProvider::Codex
            })
            .unwrap();
        assert_eq!(
            plugin.origin_path,
            "plugins/linear/.codex-plugin/plugin.json"
        );
        let plugin_ucir: serde_json::Value = serde_json::from_str(&plugin.raw_content).unwrap();
        assert_eq!(plugin_ucir["kind"], "plugin");
        assert_eq!(plugin_ucir["description"], "Linear workflow tools");
        assert!(
            plugin_ucir["contents"]
                .as_array()
                .unwrap()
                .iter()
                .any(|child| {
                    child["originPath"] == "plugins/linear/skills/release-helper/SKILL.md"
                        && child["type"] == "skill"
                })
        );
        assert!(
            plugin_ucir["contents"]
                .as_array()
                .unwrap()
                .iter()
                .any(|child| {
                    child["originPath"] == "plugins/linear/hooks.json" && child["type"] == "hook"
                })
        );
        assert!(
            plugin_ucir["contents"]
                .as_array()
                .unwrap()
                .iter()
                .any(|child| {
                    child["originPath"] == "plugins/linear/.mcp.json" && child["type"] == "mcp"
                })
        );
        assert!(artifacts.iter().any(|artifact| {
            artifact.artifact_type == ArtifactType::Skill
                && artifact.origin_path == "plugins/linear/skills/release-helper/SKILL.md"
                && artifact.name == "Release Helper"
        }));
    }

    #[test]
    fn test_scan_codex_plugins_finds_home_local_plugins() {
        let tmp = tempfile::TempDir::new().unwrap();
        let plugin_root = tmp.path().join("plugins/github");
        std::fs::create_dir_all(plugin_root.join(".codex-plugin")).unwrap();
        std::fs::create_dir_all(plugin_root.join("skills")).unwrap();
        std::fs::write(
            plugin_root.join(".codex-plugin/plugin.json"),
            r#"{"name":"github","skills":"./skills/review.md"}"#,
        )
        .unwrap();
        std::fs::write(plugin_root.join("skills/review.md"), "Review skill").unwrap();

        let mut artifacts = Vec::new();
        scan_codex_plugins(
            tmp.path(),
            &tmp.path().join("plugins"),
            None,
            &mut artifacts,
        );

        let plugin = artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == ArtifactType::Plugin)
            .unwrap();
        assert_eq!(
            plugin.origin_path,
            "~/plugins/github/.codex-plugin/plugin.json"
        );
        let plugin_ucir: serde_json::Value = serde_json::from_str(&plugin.raw_content).unwrap();
        assert_eq!(
            plugin_ucir["contents"][0]["originPath"],
            "~/plugins/github/skills/review.md"
        );
    }

    #[test]
    fn test_build_plugin_ucir_includes_strong_child_refs() {
        let plugin_ucir = build_plugin_ucir(
            "bundle",
            Some("desc"),
            &[ScannedArtifact {
                artifact_type: ArtifactType::Skill,
                provider: ArtifactProvider::Claude,
                origin_path: ".claude/plugins/bundle/skills/review/SKILL.md".to_string(),
                origin_project: Some("repo".to_string()),
                name: "Review".to_string(),
                raw_content: "content".to_string(),
                content_hash: "sha256-test".to_string(),
            }],
        );

        let json: serde_json::Value = serde_json::from_str(&plugin_ucir).unwrap();
        assert_eq!(json["kind"], "plugin");
        assert_eq!(json["name"], "bundle");
        assert_eq!(json["description"], "desc");
        assert_eq!(
            json["contents"][0]["originPath"],
            ".claude/plugins/bundle/skills/review/SKILL.md"
        );
        assert_eq!(json["contents"][0]["name"], "Review");
        assert_eq!(json["contents"][0]["type"], "skill");
        assert!(json["contents"][0].get("artifactId").is_none());
    }

    #[test]
    fn test_project_scan_finds_claude_md() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("CLAUDE.md"), "# Project instructions").unwrap();

        let artifacts = scan_claude_project(tmp.path()).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ArtifactType::SystemPrompt);
        assert_eq!(artifacts[0].origin_path, "CLAUDE.md");
        assert!(artifacts[0].origin_project.is_some());
    }

    #[test]
    fn test_project_scan_finds_cursorrules() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".cursorrules"), "rules content").unwrap();

        let artifacts = scan_cursor_project(tmp.path()).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].origin_path, ".cursorrules");
        assert!(artifacts[0].origin_project.is_some());
    }

    #[test]
    fn test_project_scan_finds_amazonq_rules() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rules_dir = tmp.path().join(".amazonq/rules");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::write(rules_dir.join("security.md"), "# Security rules").unwrap();

        let artifacts = scan_amazonq_project(tmp.path()).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].origin_path, ".amazonq/rules/security.md");
    }

    #[test]
    fn test_scan_all_with_no_project_roots_only_returns_globals() {
        // With no project roots, project-relative files should not be found
        let artifacts = scan_all(&[]);
        // All artifacts should have origin paths that are home-relative or absolute
        for a in &artifacts {
            assert!(
                !a.origin_path.starts_with("CLAUDE.md")
                    || a.provider != ArtifactProvider::Claude
                    || a.origin_project.is_some(),
                "Found project-relative CLAUDE.md without project root: {:?}",
                a.origin_path
            );
        }
    }

    #[test]
    fn test_symlink_outside_boundary_skipped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();

        // Create a file outside the project
        let outside = tmp.path().join("secret.md");
        std::fs::write(&outside, "secret content").unwrap();

        // Symlink into the project
        let link = project.join("CLAUDE.md");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        #[cfg(not(unix))]
        {
            // On non-unix, just skip this test
            return;
        }

        let artifacts = scan_claude_project(&project).unwrap();
        // The symlink points outside the project dir, so it should be skipped
        assert!(
            artifacts.is_empty(),
            "Symlink outside project boundary should be skipped"
        );
    }
}
