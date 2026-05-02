// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::integration::read_json_value;
use crate::state::restore_manifest_entry;

use super::probe::{
    ProbeResult, env_file_has_var, fingerprint, json_has_mcp_wrap, not_detected,
    probe_config_rewrite_burn_control,
};
use super::registry::{
    AgentDescriptor, McpConfigFormat, McpConfigLocation, PrimaryProvider, provider_env_exports,
};

pub struct Cline;

pub fn cline_settings_path() -> Result<PathBuf, String> {
    Ok(crate::integration::home_dir()?
        .join("Library")
        .join("Application Support")
        .join("Code")
        .join("User")
        .join("settings.json"))
}

pub fn cline_extension_installed() -> bool {
    let ext_dir = crate::integration::home_dir()
        .unwrap_or_else(|_| PathBuf::new())
        .join(".vscode")
        .join("extensions");
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
        use super::profile::{AdaptedMechanism, SurfaceState};
        let detected = cline_extension_installed();
        if !detected {
            return not_detected();
        }
        let has_compiled_policy = env_file_has_var("cline", "CLINE_COMMAND_PERMISSIONS");
        let execution = if has_compiled_policy {
            SurfaceState::adapted(AdaptedMechanism::CompiledPolicy)
        } else {
            SurfaceState::none()
        };

        let settings_path = cline_settings_path().ok();

        let has_mcp_wrap = settings_path
            .as_deref()
            .is_some_and(|p| json_has_mcp_wrap(p, "mcpServers"));
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(AdaptedMechanism::McpWrapping)
        } else {
            SurfaceState::none()
        };

        let burn_control = probe_config_rewrite_burn_control(
            settings_path.as_deref(),
            |v| {
                v.get("anthropicBaseUrl").is_some()
                    || v.get("openAiBaseUrl").is_some()
                    || v.get("geminiBaseUrl").is_some()
            },
            "cline",
            "ANTHROPIC_BASE_URL",
        );

        let mut managed_files = Vec::new();
        if let Some(path) = settings_path.as_deref()
            && let Some(fp) = fingerprint(path)
        {
            managed_files.push(fp);
        }

        ProbeResult {
            detected,
            execution,
            tool,
            burn_control,
            managed_files,
        }
    }
    fn managed_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = cline_settings_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["CLINE_COMMAND_PERMISSIONS", "kyris-mcp"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        provider_env_exports(PrimaryProvider::Anthropic, listen, inbound_key)
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        cline_settings_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcpServers"],
            },
        })
    }
    fn configure(&self, listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
        let path = cline_settings_path()?;
        let base_url = format!("http://{listen}");
        let base_url_v1 = format!("http://{listen}/v1");
        let mut changes = super::configure::apply_json_config_rewrites(
            &path,
            &[
                (&["anthropicBaseUrl"] as &[&str], base_url.as_str()),
                (&["anthropicApiKey"], inbound_key),
                (&["openAiBaseUrl"], base_url_v1.as_str()),
                (&["openAiApiKey"], inbound_key),
                (&["geminiBaseUrl"], base_url.as_str()),
                (&["geminiApiKey"], inbound_key),
            ],
            "cline",
        )?;

        let mut settings = read_json_value(&path)?;
        if super::configure::rewrite_json_mcp_servers(
            &mut settings,
            &["mcpServers"],
            listen,
            inbound_key,
        ) {
            crate::integration::write_json_value(&path, &settings, "cline")?;
            changes.push(format!("rewrote MCP servers in {}", path.display()));
        }

        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        let path = cline_settings_path()?;
        if restore_manifest_entry(&path)? {
            println!("Reverted {}", path.display());
        }
        Ok(())
    }
}
