pub mod claude_code;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod gemenicli;
pub mod openclaw;
pub mod opencode;

use anyhow::{Result, bail};
use clap::ValueEnum;
use std::path::{Path, PathBuf};

use crate::config_snapshot;
use crate::redact::Redactor;
use crate::types::{ConfigSnapshotPayload, DiffSession};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProviderKind {
    #[value(alias = "claude")]
    ClaudeCode,
    Codex,
    #[value(alias = "open-code", alias = "opencode")]
    OpenCode,
    #[value(alias = "open-claw")]
    OpenClaw,
    Cursor,
    #[value(alias = "github-copilot")]
    Copilot,
    #[value(alias = "gemini")]
    GeminiCli,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::OpenCode => "opencode",
            Self::OpenClaw => "openclaw",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::GeminiCli => "gemenicli",
        }
    }

    pub fn discover_sessions(self, root_override: Option<&Path>) -> Result<Vec<SessionLocator>> {
        let map_locators = |sessions: Vec<(String, PathBuf)>| {
            sessions
                .into_iter()
                .map(|(session_id, path)| SessionLocator {
                    provider: self,
                    session_id,
                    path,
                })
                .collect()
        };

        match self {
            Self::ClaudeCode => claude_code::discover_sessions(root_override).map(map_locators),
            Self::Codex => codex::discover_sessions(root_override).map(map_locators),
            Self::OpenCode => opencode::discover_sessions(root_override).map(map_locators),
            Self::OpenClaw => openclaw::discover_sessions(root_override).map(map_locators),
            Self::Cursor => cursor::discover_sessions(root_override).map(map_locators),
            Self::Copilot => copilot::discover_sessions(root_override).map(map_locators),
            Self::GeminiCli => gemenicli::discover_sessions(root_override).map(map_locators),
        }
    }

    pub fn find_session(
        self,
        session_id: &str,
        root_override: Option<&Path>,
    ) -> Result<SessionLocator> {
        let path = match self {
            Self::ClaudeCode => claude_code::find_session_file(session_id, root_override)?,
            Self::Codex => codex::find_session_file(session_id, root_override)?,
            Self::OpenCode => opencode::find_session_file(session_id, root_override)?,
            Self::OpenClaw => openclaw::find_session_file(session_id, root_override)?,
            Self::Cursor => cursor::find_session_file(session_id, root_override)?,
            Self::Copilot => copilot::find_session_file(session_id, root_override)?,
            Self::GeminiCli => gemenicli::find_session_file(session_id, root_override)?,
        };

        Ok(SessionLocator {
            provider: self,
            session_id: session_id.to_string(),
            path,
        })
    }

    pub fn parse_file(
        self,
        path: &Path,
        org_id: &str,
        engineer_id: &str,
        machine_id: &str,
        redactor: &Redactor,
    ) -> Result<DiffSession> {
        match self {
            Self::ClaudeCode => {
                claude_code::parse_session(path, org_id, engineer_id, machine_id, redactor)
            }
            Self::Codex => codex::parse_session(path, org_id, engineer_id, machine_id, redactor),
            Self::OpenCode => {
                opencode::parse_session(path, org_id, engineer_id, machine_id, redactor)
            }
            Self::OpenClaw => {
                openclaw::parse_session(path, org_id, engineer_id, machine_id, redactor)
            }
            Self::Cursor => cursor::parse_session(path, org_id, engineer_id, machine_id, redactor),
            Self::Copilot => {
                copilot::parse_session(path, org_id, engineer_id, machine_id, redactor)
            }
            Self::GeminiCli => {
                gemenicli::parse_session(path, org_id, engineer_id, machine_id, redactor)
            }
        }
    }

    pub fn parse_locator(
        self,
        locator: &SessionLocator,
        ctx: &ParseContext<'_>,
    ) -> Result<DiffSession> {
        if locator.provider != self {
            bail!(
                "session locator provider mismatch: expected {}, got {}",
                self.as_str(),
                locator.provider.as_str()
            );
        }

        self.parse_file(
            &locator.path,
            ctx.org_id,
            ctx.engineer_id,
            ctx.machine_id,
            ctx.redactor,
        )
    }

    pub fn capture_config_snapshot(
        self,
        project_path: &str,
    ) -> Result<Option<ConfigSnapshotPayload>> {
        match self {
            Self::ClaudeCode => config_snapshot::capture_claude_snapshot(project_path).map(Some),
            Self::Codex => Ok(None),
            Self::OpenCode => Ok(None),
            Self::OpenClaw => Ok(None),
            Self::Cursor => Ok(None),
            Self::Copilot => Ok(None),
            Self::GeminiCli => Ok(None),
        }
    }
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLocator {
    pub provider: ProviderKind,
    pub session_id: String,
    pub path: PathBuf,
}

pub struct ParseContext<'a> {
    pub org_id: &'a str,
    pub engineer_id: &'a str,
    pub machine_id: &'a str,
    pub redactor: &'a Redactor,
}

pub fn provider_from_tool(tool: &str) -> Option<ProviderKind> {
    match tool {
        "claude_code" => Some(ProviderKind::ClaudeCode),
        "codex" => Some(ProviderKind::Codex),
        "opencode" => Some(ProviderKind::OpenCode),
        "openclaw" => Some(ProviderKind::OpenClaw),
        "cursor" => Some(ProviderKind::Cursor),
        "copilot" => Some(ProviderKind::Copilot),
        "gemenicli" => Some(ProviderKind::GeminiCli),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderKind;
    use clap::ValueEnum;

    #[test]
    fn provider_accepts_claude_alias() {
        let provider = ProviderKind::from_str("claude", true).expect("provider alias");
        assert_eq!(provider, ProviderKind::ClaudeCode);
    }

    #[test]
    fn provider_string_matches_session_tool() {
        assert_eq!(ProviderKind::ClaudeCode.as_str(), "claude_code");
    }

    #[test]
    fn provider_from_tool_roundtrips() {
        for provider in [
            ProviderKind::ClaudeCode,
            ProviderKind::Codex,
            ProviderKind::OpenCode,
            ProviderKind::OpenClaw,
            ProviderKind::Cursor,
            ProviderKind::Copilot,
            ProviderKind::GeminiCli,
        ] {
            assert_eq!(super::provider_from_tool(provider.as_str()), Some(provider));
        }
    }
}
