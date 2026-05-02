// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::integration::{read_json_value, remove_json_command_hook, write_json_value};

use super::probe::{ProbeResult, probe_live_hook_agent};
use super::registry::{
    AgentDescriptor, HookProtocol, McpConfigFormat, McpConfigLocation, ResponseFormat, ToolMapping,
};

pub struct ClaudeCode;

pub fn claude_settings_path() -> Result<PathBuf, String> {
    let home = crate::integration::home_dir()?;
    Ok(home.join(".claude").join("settings.json"))
}

pub fn claude_hooks_dir() -> Result<PathBuf, String> {
    let home = crate::integration::home_dir()?;
    Ok(home.join(".claude").join("hooks"))
}

fn claude_code_env_exports(listen: &str, inbound_key: &str) -> Vec<(String, String)> {
    let base_url = format!("http://{listen}");
    vec![
        ("ANTHROPIC_BASE_URL".to_string(), base_url.clone()),
        ("ANTHROPIC_API_KEY".to_string(), inbound_key.to_string()),
        ("ANTHROPIC_AUTH_TOKEN".to_string(), inbound_key.to_string()),
        ("ANTHROPIC_BEDROCK_BASE_URL".to_string(), base_url.clone()),
        ("CLAUDE_CODE_SKIP_BEDROCK_AUTH".to_string(), "1".to_string()),
        ("ANTHROPIC_VERTEX_BASE_URL".to_string(), base_url.clone()),
        ("CLAUDE_CODE_SKIP_VERTEX_AUTH".to_string(), "1".to_string()),
        ("ANTHROPIC_FOUNDRY_BASE_URL".to_string(), base_url.clone()),
        (
            "ANTHROPIC_BEDROCK_MANTLE_BASE_URL".to_string(),
            base_url.clone(),
        ),
    ]
}

impl AgentDescriptor for ClaudeCode {
    fn id(&self) -> &'static str {
        "claude-code"
    }
    fn display_name(&self) -> &'static str {
        "Claude Code"
    }
    fn is_installed(&self) -> bool {
        crate::integration::home_dir().is_ok_and(|h| h.join(".claude").is_dir())
    }
    fn probe(&self) -> ProbeResult {
        let home = std::env::var("HOME").unwrap_or_default();
        let detected = std::path::Path::new(&format!("{home}/.claude")).is_dir();
        let settings_path = claude_settings_path().ok();
        probe_live_hook_agent(
            detected,
            settings_path.as_deref(),
            "PreToolUse",
            "agentpact_pretooluse",
            "claude-code",
            "ANTHROPIC_BASE_URL",
        )
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = claude_settings_path() {
            paths.push(path);
        }
        if let Ok(dir) = claude_hooks_dir() {
            paths.push(dir.join("agentpact_pretooluse.sh"));
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["agentpact_pretooluse"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        claude_code_env_exports(listen, inbound_key)
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn configure(&self, _listen: &str, _inbound_key: &str) -> Result<Vec<String>, String> {
        let hooks_dir = claude_hooks_dir()?;
        let script_path = hooks_dir.join("agentpact_pretooluse.sh");
        let settings_path = claude_settings_path()?;
        super::configure::install_live_hook_adapter(
            "claude-code",
            "claude-code",
            "PreToolUse",
            &script_path,
            &settings_path,
        )
    }
    fn undo(&self) -> Result<(), String> {
        let settings_path = claude_settings_path()?;
        if settings_path.exists() {
            let mut settings = read_json_value(&settings_path)?;
            if remove_json_command_hook(&mut settings, "PreToolUse", "agentpact_pretooluse") {
                write_json_value(&settings_path, &settings, "claude-code")?;
                println!("Removed hook from {}", settings_path.display());
            }
        }
        let script = claude_hooks_dir()?.join("agentpact_pretooluse.sh");
        super::undo::remove_file_if_exists(&script)?;
        Ok(())
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        claude_settings_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcpServers"],
            },
        })
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string(), "input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "Bash".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "bash".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "Read".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "Write".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "Edit".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "edit_file".to_string(),
                    action: "write".to_string(),
                },
            ],
            default_action: "call".to_string(),
            response_format: ResponseFormat::Json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testClaudeCodeExportsMultiBackend() {
        let exports = claude_code_env_exports("127.0.0.1:4710", "sk-test");
        let keys: Vec<&str> = exports.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"ANTHROPIC_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_BEDROCK_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_VERTEX_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_FOUNDRY_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_BEDROCK_MANTLE_BASE_URL"));
        assert!(keys.contains(&"CLAUDE_CODE_SKIP_BEDROCK_AUTH"));
        assert!(keys.contains(&"CLAUDE_CODE_SKIP_VERTEX_AUTH"));
        assert!(keys.contains(&"ANTHROPIC_AUTH_TOKEN"));
    }
}
