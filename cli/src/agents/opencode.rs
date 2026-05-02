// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::integration::{read_json_value, set_json_value_path, write_json_value};
use crate::state::restore_manifest_entry;

use super::probe::{
    ProbeResult, fingerprint, json_has_mcp_wrap, not_detected, probe_config_rewrite_burn_control,
};
use super::registry::{
    AgentDescriptor, McpConfigFormat, McpConfigLocation, PrimaryProvider, provider_env_exports,
    which_exists,
};

pub struct OpenCode;

pub fn opencode_config_path() -> Result<PathBuf, String> {
    if let Some(path) = crate::integration::find_upwards("opencode.json") {
        return Ok(path);
    }
    Ok(crate::integration::home_dir()?
        .join(".config")
        .join("opencode")
        .join("opencode.json"))
}

pub fn opencode_config_exists() -> bool {
    opencode_config_path().is_ok_and(|path| path.exists())
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
        use super::profile::{AdaptedMechanism, SurfaceState};
        let detected = opencode_config_exists() || which_exists("opencode");
        if !detected {
            return not_detected();
        }

        let config_path = opencode_config_path().ok();
        let has_compiled_policy = config_path.as_deref().is_some_and(|p| {
            read_json_value(p).is_ok_and(|v| {
                v.get("permission")
                    .and_then(|p| p.get("bash"))
                    .and_then(|b| b.as_object())
                    .is_some_and(|m| !m.is_empty())
            })
        });
        let execution = if has_compiled_policy {
            SurfaceState::adapted(AdaptedMechanism::CompiledPolicy)
        } else {
            SurfaceState::none()
        };

        let has_mcp_wrap = config_path
            .as_deref()
            .is_some_and(|p| json_has_mcp_wrap(p, "mcp"));
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(AdaptedMechanism::McpWrapping)
        } else {
            SurfaceState::none()
        };

        let burn_control = probe_config_rewrite_burn_control(
            config_path.as_deref(),
            |v| {
                let has_provider = |name: &str| {
                    v.get("provider")
                        .and_then(|p| p.get(name))
                        .and_then(|a| a.get("options"))
                        .and_then(|o| o.get("baseURL"))
                        .is_some()
                };
                has_provider("anthropic") || has_provider("openai") || has_provider("google")
            },
            "opencode",
            "ANTHROPIC_BASE_URL",
        );

        let mut managed_files = Vec::new();
        if let Some(path) = config_path.as_deref()
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
        if let Ok(path) = opencode_config_path() {
            paths.push(path);
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["permission", "kyris-mcp"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        provider_env_exports(PrimaryProvider::Anthropic, listen, inbound_key)
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        opencode_config_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcp"],
            },
        })
    }
    fn configure(&self, listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
        let path = opencode_config_path()?;
        let base_url = format!("http://{listen}");
        let base_url_v1 = format!("http://{listen}/v1");
        let mut changes = super::configure::apply_json_config_rewrites(
            &path,
            &[
                (
                    &["provider", "anthropic", "options", "baseURL"] as &[&str],
                    base_url.as_str(),
                ),
                (&["provider", "anthropic", "options", "apiKey"], inbound_key),
                (
                    &["provider", "openai", "options", "baseURL"],
                    base_url_v1.as_str(),
                ),
                (&["provider", "openai", "options", "apiKey"], inbound_key),
                (
                    &["provider", "google", "options", "baseURL"],
                    base_url.as_str(),
                ),
                (&["provider", "google", "options", "apiKey"], inbound_key),
            ],
            "opencode",
        )?;

        let (permissions, _) = crate::compile_policy::compile_opencode_permissions(None)?;
        let mut config = read_json_value(&path)?;
        let mut config_changed = false;
        if let Some(bash) = permissions.get("bash").cloned()
            && set_json_value_path(&mut config, &["permission", "bash"], bash)
        {
            config_changed = true;
        }

        if super::configure::rewrite_json_mcp_servers(&mut config, &["mcp"], listen, inbound_key) {
            config_changed = true;
        }

        if config_changed {
            write_json_value(&path, &config, "opencode")?;
            changes.push(format!("updated {}", path.display()));
        }

        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        let path = opencode_config_path()?;
        if restore_manifest_entry(&path)? {
            println!("Reverted {}", path.display());
        }
        Ok(())
    }
}
