// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::integration::{
    cline_settings_path, codex_config_exists, codex_config_path, codex_hooks_path,
    gemini_settings_exists, gemini_settings_path, opencode_config_exists, opencode_config_path,
};

use super::probe::ProbeResult;

pub trait AgentDescriptor {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn is_installed(&self) -> bool;
    fn probe(&self) -> ProbeResult;
    fn managed_paths(&self) -> Vec<PathBuf>;
    fn kyris_content_markers(&self) -> &'static [&'static str];
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)>;
}

pub fn all_agents() -> Vec<Box<dyn AgentDescriptor>> {
    vec![
        Box::new(ClaudeCode),
        Box::new(CodexCli),
        Box::new(GeminiCli),
        Box::new(Cline),
        Box::new(OpenCode),
    ]
}

pub fn agent_by_id(id: &str) -> Option<Box<dyn AgentDescriptor>> {
    match id {
        "claude-code" => Some(Box::new(ClaudeCode)),
        "codex-cli" => Some(Box::new(CodexCli)),
        "gemini-cli" => Some(Box::new(GeminiCli)),
        "cline" => Some(Box::new(Cline)),
        "opencode" => Some(Box::new(OpenCode)),
        _ => None,
    }
}

pub struct ClaudeCode;
pub struct CodexCli;
pub struct GeminiCli;
pub struct Cline;
pub struct OpenCode;

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
}

pub fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|output| output.status.success())
}

pub fn cline_extension_installed() -> bool {
    let ext_dir = home_dir().join(".vscode").join("extensions");
    ext_dir.is_dir()
        && std::fs::read_dir(&ext_dir).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("saoudrizwan.claude-dev")
            })
        })
}

impl AgentDescriptor for ClaudeCode {
    fn id(&self) -> &'static str {
        "claude-code"
    }
    fn display_name(&self) -> &'static str {
        "Claude Code"
    }
    fn is_installed(&self) -> bool {
        home_dir().join(".claude").is_dir()
    }
    fn probe(&self) -> ProbeResult {
        super::probe::probe_claude_code()
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = crate::integration::claude_settings_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["agentpact_pretooluse"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        vec![
            ("ANTHROPIC_BASE_URL".to_string(), format!("http://{listen}")),
            ("ANTHROPIC_API_KEY".to_string(), inbound_key.to_string()),
        ]
    }
}

impl AgentDescriptor for CodexCli {
    fn id(&self) -> &'static str {
        "codex-cli"
    }
    fn display_name(&self) -> &'static str {
        "Codex CLI"
    }
    fn is_installed(&self) -> bool {
        codex_config_exists()
    }
    fn probe(&self) -> ProbeResult {
        super::probe::probe_codex_cli()
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = codex_config_path() {
            paths.push(path);
        }
        if let Ok(path) = codex_hooks_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["kyris-mcp", "kyris_pretooluse"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        vec![
            ("OPENAI_BASE_URL".to_string(), format!("http://{listen}/v1")),
            ("OPENAI_API_KEY".to_string(), inbound_key.to_string()),
        ]
    }
}

impl AgentDescriptor for GeminiCli {
    fn id(&self) -> &'static str {
        "gemini-cli"
    }
    fn display_name(&self) -> &'static str {
        "Gemini CLI"
    }
    fn is_installed(&self) -> bool {
        which_exists("gemini") || gemini_settings_exists()
    }
    fn probe(&self) -> ProbeResult {
        super::probe::probe_gemini_cli()
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = gemini_settings_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["agentpact_beforetool"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        vec![
            (
                "GOOGLE_GEMINI_BASE_URL".to_string(),
                format!("http://{listen}"),
            ),
            ("GEMINI_API_KEY".to_string(), inbound_key.to_string()),
        ]
    }
}

impl AgentDescriptor for Cline {
    fn id(&self) -> &'static str {
        "cline"
    }
    fn display_name(&self) -> &'static str {
        "Cline"
    }
    fn is_installed(&self) -> bool {
        cline_extension_installed()
    }
    fn probe(&self) -> ProbeResult {
        super::probe::probe_cline()
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = cline_settings_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["CLINE_COMMAND_PERMISSIONS"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        vec![
            ("ANTHROPIC_BASE_URL".to_string(), format!("http://{listen}")),
            ("ANTHROPIC_API_KEY".to_string(), inbound_key.to_string()),
        ]
    }
}

impl AgentDescriptor for OpenCode {
    fn id(&self) -> &'static str {
        "opencode"
    }
    fn display_name(&self) -> &'static str {
        "OpenCode"
    }
    fn is_installed(&self) -> bool {
        which_exists("opencode") || opencode_config_exists()
    }
    fn probe(&self) -> ProbeResult {
        super::probe::probe_opencode()
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = opencode_config_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &[]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        vec![
            ("ANTHROPIC_BASE_URL".to_string(), format!("http://{listen}")),
            ("ANTHROPIC_API_KEY".to_string(), inbound_key.to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testAllAgentsReturnsFive() {
        assert_eq!(all_agents().len(), 5);
    }

    #[test]
    fn testAgentByIdKnown() {
        assert!(agent_by_id("claude-code").is_some());
        assert!(agent_by_id("codex-cli").is_some());
        assert!(agent_by_id("gemini-cli").is_some());
        assert!(agent_by_id("cline").is_some());
        assert!(agent_by_id("opencode").is_some());
    }

    #[test]
    fn testAgentByIdUnknown() {
        assert!(agent_by_id("nonexistent").is_none());
    }

    #[test]
    fn testAllAgentsHaveUniqueIds() {
        let agents = all_agents();
        let mut ids: Vec<&str> = agents.iter().map(|a| a.id()).collect();
        let len_before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), len_before);
    }
}
