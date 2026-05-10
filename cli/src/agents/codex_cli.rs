// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use crate::config_writer::{NoopValidator, TomlShapeValidator, WellFormedJsonValidator};
use crate::integration::{
    ensure_toml_bool_path, ensure_toml_string_path, read_json_value, read_toml_value,
    remove_json_command_hook, write_json_value, write_toml_value,
};
use crate::state::restore_manifest_entry;

use super::codex_cli_schema::CodexConfigShape;

fn codex_config_validator() -> TomlShapeValidator<CodexConfigShape> {
    TomlShapeValidator::new()
}

use super::probe::{ProbeResult, fingerprint, not_detected};
use super::registry::{
    AgentDescriptor, AllowResponse, HookProtocol, McpConfigFormat, McpConfigLocation, ToolMapping,
};

pub struct CodexCli;

fn ensure_codex_kyris_model_provider(
    config: &mut toml::Value,
    base_url_v1: &str,
    inbound_key: &str,
) -> bool {
    let mut changed = false;
    if ensure_toml_string_path(config, &["model_providers", "kyris", "name"], "Kyris") {
        changed = true;
    }
    if ensure_toml_string_path(
        config,
        &["model_providers", "kyris", "base_url"],
        base_url_v1,
    ) {
        changed = true;
    }
    if ensure_toml_string_path(
        config,
        &["model_providers", "kyris", "wire_api"],
        "responses",
    ) {
        changed = true;
    }
    if ensure_toml_string_path(
        config,
        &["model_providers", "kyris", "experimental_bearer_token"],
        inbound_key,
    ) {
        changed = true;
    }
    changed
}

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
        use super::profile::{AdaptedMechanism, CoverageCeiling, SurfaceState};
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

        let has_compiled_policy = codex_dir()
            .ok()
            .map(|d| d.join("rules").join("agentpact.rules"))
            .is_some_and(|p| p.exists());

        let execution = if has_hook {
            SurfaceState::adapted(AdaptedMechanism::LiveHook)
        } else if has_compiled_policy {
            SurfaceState::adapted(AdaptedMechanism::CompiledPolicy)
                .with_ceiling(CoverageCeiling::Compiled)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(AdaptedMechanism::McpWrapping)
        } else {
            SurfaceState::none()
        };
        let has_base_url_config = config_path.as_deref().is_some_and(|p| {
            read_toml_value(p).is_ok_and(|v| {
                v.get("openai_base_url")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|u| !u.is_empty())
            })
        });
        let burn_control = if has_base_url_config {
            SurfaceState::adapted(AdaptedMechanism::ConfigRewrite)
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
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["kyris-mcp", "kyris_pretooluse"]
    }
    fn env_exports(&self, _base_url: &str, _inbound_key: &str) -> Vec<(String, String)> {
        Vec::new()
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn configure_execution(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        let hooks_path = codex_hooks_path()?;
        let script_path = codex_dir()?.join("kyris_pretooluse.sh");

        let mut changes = super::configure::install_live_hook_adapter(
            "codex-cli",
            "codex-cli",
            "PreToolUse",
            &script_path,
            &hooks_path,
            true,
        )?;

        let mut config = read_toml_value(&config_path)?;
        if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], true) {
            write_toml_value(
                &config_path,
                &config,
                "codex-cli",
                &codex_config_validator(),
            )?;
            changes.push(format!("updated {}", config_path.display()));
        }

        match crate::compile_policy::compile_codex_permissions(None) {
            Ok((rules, _)) => {
                let rules_content = crate::compile_policy::serialize_codex_rules_file(&rules);
                if !rules_content.is_empty() {
                    let rules_path = codex_dir()?.join("rules").join("agentpact.rules");
                    // .rules is opaque text — no schema.
                    if crate::state::write_managed_file(
                        &rules_path,
                        &rules_content,
                        "codex-cli",
                        None,
                        &NoopValidator,
                    )? {
                        changes.push(format!("wrote {}", rules_path.display()));
                    }
                }
            }
            Err(e) => {
                changes.push(format!("warning: compiled policy skipped: {e}"));
            }
        }

        let gaps = crate::compile_policy::detect_codex_gaps(None);
        if !gaps.is_empty() {
            let mut profile = crate::state::load_agent_profile("codex-cli")?
                .unwrap_or_else(|| super::profile::AgentProfile::new_empty("codex-cli"));
            profile.compilation_gaps.clone_from(&gaps);
            crate::state::save_agent_profile(&profile)?;
            for gap in &gaps {
                changes.push(format!("warning: {gap}"));
            }
        }

        Ok(changes)
    }
    fn configure_burn_control(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        let mut changes = Vec::new();

        let mut config = read_toml_value(&config_path)?;

        let base_url_v1 = format!("{base_url}/v1");
        let mut config_changed =
            ensure_toml_string_path(&mut config, &["openai_base_url"], &base_url_v1);
        if ensure_codex_kyris_model_provider(&mut config, &base_url_v1, inbound_key) {
            config_changed = true;
        }

        let mcp_result =
            super::configure::rewrite_codex_mcp_servers(&mut config, base_url, inbound_key);
        if mcp_result.changed {
            config_changed = true;
        }
        if super::configure::apply_toml_tool_filters(&mut config) {
            config_changed = true;
        }
        if config_changed {
            write_toml_value(
                &config_path,
                &config,
                "codex-cli",
                &codex_config_validator(),
            )?;
            changes.push(format!("updated {}", config_path.display()));
        }
        if !mcp_result.http_rewrites.is_empty() {
            super::configure::upsert_mcp_upstreams(&mcp_result.http_rewrites)?;
            changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
        }

        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        let hooks_path = codex_hooks_path()?;
        if hooks_path.exists() {
            let mut hooks = read_json_value(&hooks_path)?;
            if remove_json_command_hook(&mut hooks, "PreToolUse", "kyris_pretooluse") {
                write_json_value(&hooks_path, &hooks, "codex-cli", &WellFormedJsonValidator)?;
                println!("Removed hook from {}", hooks_path.display());
            }
        }

        let config_path = codex_config_path()?;
        if config_path.exists() {
            let mut config = read_toml_value(&config_path)?;
            if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], false) {
                write_toml_value(
                    &config_path,
                    &config,
                    "codex-cli",
                    &codex_config_validator(),
                )?;
                println!("Reset codex_hooks in {}", config_path.display());
            }
        }
        restore_manifest_entry(&config_path)?;

        let script = codex_dir()?.join("kyris_pretooluse.sh");
        super::undo::remove_file_if_exists(&script)?;
        let rules = codex_dir()?.join("rules").join("agentpact.rules");
        super::undo::remove_file_if_exists(&rules)?;
        Ok(())
    }
    fn undo_burn_control(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if restore_manifest_entry(&path)? {
                println!("Reverted {}", path.display());
            }
        }
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
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        codex_config_path().into_iter().collect()
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "Bash".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "apply_patch".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("command".to_string()),
                },
            ],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testCodexKyrisModelProviderIsValidForCodex0130() {
        let mut config: toml::Value =
            toml::from_str("[model_providers.kyris]\nbase_url = \"http://old.example/v1\"\n")
                .expect("parse config");

        assert!(ensure_codex_kyris_model_provider(
            &mut config,
            "http://127.0.0.1:4710/v1",
            "sk-kyris-test"
        ));

        let provider = config["model_providers"]["kyris"]
            .as_table()
            .expect("kyris provider");
        assert_eq!(provider["name"].as_str(), Some("Kyris"));
        assert_eq!(
            provider["base_url"].as_str(),
            Some("http://127.0.0.1:4710/v1")
        );
        assert_eq!(provider["wire_api"].as_str(), Some("responses"));
        assert_eq!(
            provider["experimental_bearer_token"].as_str(),
            Some("sk-kyris-test")
        );
    }
}
