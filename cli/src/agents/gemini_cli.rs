// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::integration::{read_json_value, remove_json_command_hook, write_json_value};

use super::probe::{ProbeResult, probe_live_hook_agent};
use super::registry::{
    AgentDescriptor, HookProtocol, McpConfigFormat, McpConfigLocation, PrimaryProvider,
    ResponseFormat, ToolMapping, provider_env_exports, which_exists,
};

pub struct GeminiCli;

pub fn gemini_settings_path() -> Result<PathBuf, String> {
    if let Some(path) = crate::integration::find_upwards(".gemini/settings.json") {
        return Ok(path);
    }
    Ok(crate::integration::home_dir()?
        .join(".gemini")
        .join("settings.json"))
}

pub fn gemini_settings_exists() -> bool {
    gemini_settings_path().is_ok_and(|path| path.exists())
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
        let detected = gemini_settings_exists() || which_exists("gemini");
        let settings_path = gemini_settings_path().ok();
        probe_live_hook_agent(
            detected,
            settings_path.as_deref(),
            "BeforeTool",
            "agentpact_beforetool",
            "gemini-cli",
            "GOOGLE_GEMINI_BASE_URL",
        )
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = gemini_settings_path() {
            let script = path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("hooks")
                .join("agentpact_beforetool.sh");
            paths.push(path);
            paths.push(script);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["agentpact_beforetool"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        let mut exports = provider_env_exports(PrimaryProvider::Google, listen, inbound_key);
        exports.push((
            "GOOGLE_VERTEX_BASE_URL".to_string(),
            format!("http://{listen}"),
        ));
        exports
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn configure(&self, _listen: &str, _inbound_key: &str) -> Result<Vec<String>, String> {
        let settings_path = gemini_settings_path()?;
        let script_path = settings_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("hooks")
            .join("agentpact_beforetool.sh");

        let mut changes = super::configure::install_live_hook_adapter(
            "gemini-cli",
            "gemini-cli",
            "BeforeTool",
            &script_path,
            &settings_path,
        )?;

        if settings_path.exists() {
            let mut settings = read_json_value(&settings_path)?;
            if super::configure::apply_json_tool_filters(&mut settings, &["mcpServers"]) {
                write_json_value(&settings_path, &settings, "gemini-cli")?;
                changes.push(format!(
                    "applied MCP tool filters in {}",
                    settings_path.display()
                ));
            }
        }

        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        let settings_path = gemini_settings_path()?;
        if settings_path.exists() {
            let mut settings = read_json_value(&settings_path)?;
            if remove_json_command_hook(&mut settings, "BeforeTool", "agentpact_beforetool") {
                write_json_value(&settings_path, &settings, "gemini-cli")?;
                println!("Removed hook from {}", settings_path.display());
            }
        }
        let script = settings_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("hooks")
            .join("agentpact_beforetool.sh");
        super::undo::remove_file_if_exists(&script)?;
        Ok(())
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        gemini_settings_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcpServers"],
            },
        })
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["arguments".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "shell".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "run_command".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "edit_file".to_string(),
                    action: "write".to_string(),
                },
            ],
            default_action: "call".to_string(),
            response_format: ResponseFormat::Text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testGeminiExportsVertexBaseUrl() {
        let agent = GeminiCli;
        let exports = agent.env_exports("127.0.0.1:4710", "sk-test");
        let keys: Vec<&str> = exports.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"GOOGLE_GEMINI_BASE_URL"));
        assert!(keys.contains(&"GOOGLE_VERTEX_BASE_URL"));
        assert!(keys.contains(&"GEMINI_API_KEY_AUTH_MECHANISM"));
    }
}
