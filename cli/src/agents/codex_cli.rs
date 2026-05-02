// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use crate::integration::{
    ensure_toml_bool_path, read_json_value, read_toml_value, remove_json_command_hook,
    write_json_value, write_toml_value,
};
use crate::state::restore_manifest_entry;

use super::probe::{ProbeResult, env_file_has_var, fingerprint, not_detected};
use super::registry::{
    AgentDescriptor, HookProtocol, McpConfigFormat, McpConfigLocation, PrimaryProvider,
    ResponseFormat, ToolMapping, provider_env_exports,
};

pub struct CodexCli;

pub fn codex_config_path() -> Result<PathBuf, String> {
    if let Some(path) = crate::integration::find_upwards(".codex/config.toml") {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("CODEX_HOME") {
        return Ok(PathBuf::from(path).join("config.toml"));
    }
    Ok(crate::integration::home_dir()?
        .join(".codex")
        .join("config.toml"))
}

pub fn codex_config_exists() -> bool {
    codex_config_path().is_ok_and(|path| path.exists())
}

pub fn codex_dir() -> Result<PathBuf, String> {
    let path = codex_config_path()?;
    path.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("Cannot resolve parent directory for {}", path.display()))
}

pub fn codex_hooks_path() -> Result<PathBuf, String> {
    Ok(codex_dir()?.join("hooks.json"))
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
        use super::profile::{AdaptedMechanism, SurfaceState};
        let detected = codex_config_exists();
        if !detected {
            return not_detected();
        }

        let hooks_path = codex_hooks_path().ok();
        let has_hook = hooks_path.as_deref().is_some_and(|p| {
            p.exists() && std::fs::read_to_string(p).is_ok_and(|c| c.contains("kyris"))
        });

        let config_path = codex_config_path().ok();
        let has_mcp_wrap = config_path.as_deref().is_some_and(|p| {
            read_toml_value(p).is_ok_and(|v| {
                let serialized = toml::to_string(&v).unwrap_or_default();
                serialized.contains("kyris-mcp")
            })
        });

        let execution = if has_hook {
            SurfaceState::adapted(AdaptedMechanism::LiveHook)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(AdaptedMechanism::McpWrapping)
        } else {
            SurfaceState::none()
        };
        let burn_control = if env_file_has_var("codex-cli", "OPENAI_BASE_URL") {
            SurfaceState::adapted(AdaptedMechanism::EnvVarProxy)
        } else {
            SurfaceState::none()
        };

        let mut managed_files = Vec::new();
        if let Some(path) = config_path.as_deref()
            && let Some(fp) = fingerprint(path)
        {
            managed_files.push(fp);
        }
        if let Some(path) = hooks_path.as_deref()
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
        if let Ok(path) = codex_config_path() {
            paths.push(path);
        }
        if let Ok(path) = codex_hooks_path() {
            paths.push(path);
        }
        if let Ok(dir) = codex_dir() {
            paths.push(dir.join("kyris_pretooluse.sh"));
        }
        paths
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["kyris-mcp", "kyris_pretooluse"]
    }
    fn env_exports(&self, listen: &str, inbound_key: &str) -> Vec<(String, String)> {
        provider_env_exports(PrimaryProvider::OpenAI, listen, inbound_key)
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn configure(&self, listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        let hooks_path = codex_hooks_path()?;
        let script_path = codex_dir()?.join("kyris_pretooluse.sh");

        let mut changes = super::configure::install_live_hook_adapter(
            "codex-cli",
            "codex-cli",
            "PreToolUse",
            &script_path,
            &hooks_path,
        )?;

        let mut config = read_toml_value(&config_path)?;
        if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], true) {
            write_toml_value(&config_path, &config, "codex-cli")?;
            changes.push(format!("updated {}", config_path.display()));
        }

        let mut config = read_toml_value(&config_path)?;
        let mut config_changed =
            super::configure::rewrite_codex_mcp_servers(&mut config, listen, inbound_key);
        if super::configure::apply_toml_tool_filters(&mut config) {
            config_changed = true;
        }
        if config_changed {
            write_toml_value(&config_path, &config, "codex-cli")?;
            changes.push(format!("rewrote MCP servers in {}", config_path.display()));
        }

        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        let hooks_path = codex_hooks_path()?;
        if hooks_path.exists() {
            let mut hooks = read_json_value(&hooks_path)?;
            if remove_json_command_hook(&mut hooks, "PreToolUse", "kyris_pretooluse") {
                write_json_value(&hooks_path, &hooks, "codex-cli")?;
                println!("Removed hook from {}", hooks_path.display());
            }
        }

        let config_path = codex_config_path()?;
        if config_path.exists() {
            let mut config = read_toml_value(&config_path)?;
            if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], false) {
                write_toml_value(&config_path, &config, "codex-cli")?;
                println!("Reset codex_hooks in {}", config_path.display());
            }
        }
        restore_manifest_entry(&config_path)?;

        let script = codex_dir()?.join("kyris_pretooluse.sh");
        super::undo::remove_file_if_exists(&script)?;
        Ok(())
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        codex_config_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Toml {
                servers_key: "mcp_servers",
            },
        })
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "shell".to_string(),
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
                    tool_name: "apply_diff".to_string(),
                    action: "write".to_string(),
                },
            ],
            default_action: "call".to_string(),
            response_format: ResponseFormat::Text,
        })
    }
}
