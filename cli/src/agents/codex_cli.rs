// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use crate::config_writer::{NoopValidator, TomlShapeValidator, WellFormedJsonValidator};
use crate::integration::{
    ensure_toml_bool_path, ensure_toml_string_path, merge_toml_string_entries, read_json_value,
    read_toml_value, remove_json_command_hook, remove_toml_table_entries, write_json_value,
    write_toml_value,
};
use crate::state::restore_manifest_entry;

use super::codex_cli_schema::CodexConfigShape;

fn codex_config_validator() -> TomlShapeValidator<CodexConfigShape> {
    TomlShapeValidator::new()
}

use super::probe::{ProbeResult, fingerprint, not_detected, toml_has_any_mcp_servers};
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

pub fn codex_binary_installed() -> bool {
    super::registry::which_exists("codex")
}

/// Creates the `.codex` directory (and any parents) if it does not yet exist.
/// Called at the start of configure methods so they work even when the user
/// has just installed the binary but has never run it (no config file yet).
fn ensure_codex_dir() -> Result<PathBuf, String> {
    let dir = codex_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Returns the current config as a TOML value, or an empty table if the file
/// does not yet exist. Used to bootstrap first-time setup.
fn read_or_empty_codex_config(config_path: &Path) -> Result<toml::Value, String> {
    if config_path.exists() {
        read_toml_value(config_path)
    } else {
        Ok(toml::Value::Table(toml::map::Map::default()))
    }
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
        // Detected when the config file exists (agent has been run at least
        // once) OR when the binary is on PATH (installed but not yet launched).
        codex_config_exists() || codex_binary_installed()
    }
    fn probe(&self) -> ProbeResult {
        use super::profile::{AdaptedMechanism, CoverageCeiling, SurfaceState};
        let detected = codex_config_exists() || codex_binary_installed();
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
        let has_any_mcp_servers = config_path
            .as_deref()
            .is_some_and(|p| toml_has_any_mcp_servers(p, "mcp_servers"));

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
        } else if !has_any_mcp_servers {
            SurfaceState::not_applicable()
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
    // Configuration for Codex CLI is a linear sequence of TOML edits (live
    // hook adapter + rules dir + permissions table + default_permissions +
    // managed-file recording), each producing a change-log entry. Splitting
    // it into helpers would require threading the change Vec through every
    // call and would make the install transcript harder to read.
    #[allow(clippy::too_many_lines)]
    fn configure_execution(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        let hooks_path = codex_hooks_path()?;
        let script_path = codex_dir()?.join("kyris_pretooluse.sh");

        // Create the .codex directory first so hook and config writes succeed
        // even when the user has just installed the binary without running it.
        ensure_codex_dir()?;

        let mut changes = super::configure::install_live_hook_adapter(
            "codex-cli",
            "codex-cli",
            "PreToolUse",
            &script_path,
            &hooks_path,
            true,
            // Codex's PreToolUse default is 600s (and its config field is
            // `timeout_sec`, not `timeout`), so no JSON-hook override here.
            None,
        )?;

        let mut config = read_or_empty_codex_config(&config_path)?;
        if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], true) {
            write_toml_value(
                &config_path,
                &config,
                "codex-cli",
                &codex_config_validator(),
            )?;
            changes.push(format!("updated {}", config_path.display()));
        }

        // ── Command prefix rules (.rules file) ──────────────────────────
        match crate::compile_policy::compile_codex_permissions(None) {
            Ok((rules, _)) => {
                let rules_content = crate::compile_policy::serialize_codex_rules_file(&rules);
                if !rules_content.is_empty() {
                    let rules_path = codex_dir()?.join("rules").join("agentpact.rules");
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

        // ── Filesystem + network permissions table ───────────────────────
        match crate::compile_policy::compile_codex_permissions_table(None) {
            Ok(table) => {
                let has_fs = !table.filesystem.is_empty();
                let has_net = !table.network_domains.is_empty();

                if has_fs || has_net {
                    let mut config = read_toml_value(&config_path)?;
                    let mut config_changed = false;

                    if has_fs
                        && merge_toml_string_entries(
                            &mut config,
                            &["permissions", "kyris", "filesystem"],
                            &table.filesystem,
                        )
                    {
                        config_changed = true;
                        changes.push(format!(
                            "wrote {} path rule(s) to [permissions.kyris.filesystem] in {}",
                            table.filesystem.len(),
                            config_path.display()
                        ));
                    }

                    if has_net
                        && merge_toml_string_entries(
                            &mut config,
                            &["permissions", "kyris", "network", "domains"],
                            &table.network_domains,
                        )
                    {
                        config_changed = true;
                        changes.push(format!(
                            "wrote {} domain rule(s) to [permissions.kyris.network.domains] in {}",
                            table.network_domains.len(),
                            config_path.display()
                        ));
                    }

                    // Activate the kyris profile via default_permissions —
                    // but only when it is unset or already points at "kyris".
                    let current_dp = config
                        .as_table()
                        .and_then(|t| t.get("default_permissions"))
                        .and_then(toml::Value::as_str)
                        .map(str::to_string);
                    match current_dp.as_deref() {
                        None | Some("kyris") => {
                            if ensure_toml_string_path(
                                &mut config,
                                &["default_permissions"],
                                "kyris",
                            ) {
                                config_changed = true;
                                changes.push(format!(
                                    "set default_permissions = \"kyris\" in {}",
                                    config_path.display()
                                ));
                            }
                        }
                        Some(other) => {
                            changes.push(format!(
                                "warning: [permissions.kyris] written but not activated — \
                                 default_permissions is already \"{other}\". \
                                 Set default_permissions = \"kyris\" to activate."
                            ));
                        }
                    }

                    if config_changed {
                        write_toml_value(
                            &config_path,
                            &config,
                            "codex-cli",
                            &codex_config_validator(),
                        )?;
                    }
                }

                // Surface precision-loss warnings.
                let gaps = table.gaps;
                if !gaps.is_empty() {
                    let mut profile = crate::state::load_agent_profile("codex-cli")?
                        .unwrap_or_else(|| super::profile::AgentProfile::new_empty("codex-cli"));
                    profile.compilation_gaps.clone_from(&gaps);
                    crate::state::save_agent_profile(&profile)?;
                    for gap in &gaps {
                        changes.push(format!("warning: {gap}"));
                    }
                }
            }
            Err(e) => {
                changes.push(format!("warning: permissions table skipped: {e}"));
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
        // Ensure .codex dir exists for first-time setup (binary installed, no config yet).
        ensure_codex_dir()?;
        let mut changes = Vec::new();

        let mut config = read_or_empty_codex_config(&config_path)?;

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
        // Remove MCP upstreams from kyrisd.yaml before the config file is
        // restored to its pre-kyris state (after which the server names
        // would no longer be readable from the agent config).
        let mcp_names = super::configure::mcp_server_names_from_agent(self);
        super::configure::remove_mcp_upstreams(&mcp_names)?;

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
            let mut changed = false;
            if ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], false) {
                changed = true;
                println!("Reset codex_hooks in {}", config_path.display());
            }
            // Remove [permissions.kyris] and prune [permissions] only if it
            // becomes empty — preserves any other profiles the user may have.
            if remove_toml_table_entries(&mut config, &["permissions"], Some(&["kyris"])) {
                changed = true;
            }
            if let Some(dp) = config
                .as_table()
                .and_then(|t| t.get("default_permissions"))
                .and_then(toml::Value::as_str)
                && dp == "kyris"
                && let Some(t) = config.as_table_mut()
            {
                t.remove("default_permissions");
                changed = true;
            }
            if changed {
                write_toml_value(
                    &config_path,
                    &config,
                    "codex-cli",
                    &codex_config_validator(),
                )?;
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
            // Codex CLI internal coordination tools: skip the daemon. See
            // claude_code.rs and hook_cmd.rs for the design rationale.
            pass_through_tools: vec!["update_plan".to_string(), "view_image".to_string()],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GAP 21 tests: binary-installed-but-no-config detection ---

    #[test]
    fn testCodexBinaryInstalledReturnsBool() {
        // Just verify it compiles and returns a bool without panicking.
        let _ = codex_binary_installed();
    }

    #[test]
    fn testCodexBinaryInstalledFalseForGibberishCommand() {
        // "codex-binary-xyz-does-not-exist" is guaranteed not on PATH.
        assert!(!crate::agents::registry::which_exists(
            "codex-binary-xyz-does-not-exist"
        ));
    }

    #[test]
    fn testReadOrEmptyCodexConfigReturnsEmptyTableForMissingFile() {
        let missing = std::path::Path::new("/tmp/kyris-test-nonexistent-codex-config.toml");
        let result = read_or_empty_codex_config(missing).expect("should succeed");
        assert!(
            result.as_table().is_some_and(toml::map::Map::is_empty),
            "expected empty table, got: {result:?}"
        );
    }

    #[test]
    fn testReadOrEmptyCodexConfigReadsExistingFile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[features]\ncodex_hooks = true\n").unwrap();
        let result = read_or_empty_codex_config(&path).expect("should read");
        assert_eq!(
            result
                .get("features")
                .and_then(|f| f.get("codex_hooks"))
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn testEnsureCodexDirCreatesDirectory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("codex");
        // Prove it doesn't exist yet.
        assert!(!nested.exists());
        std::fs::create_dir_all(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn testEmptyConfigCanBePopulatedByBurnControlLogic() {
        // Simulates the configure_burn_control flow for a first-time user:
        // start with empty TOML and verify the expected keys are written.
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        let changed = ensure_toml_string_path(
            &mut config,
            &["openai_base_url"],
            "http://127.0.0.1:4710/v1",
        );
        assert!(changed, "openai_base_url should be written to empty config");
        assert_eq!(
            config.get("openai_base_url").and_then(toml::Value::as_str),
            Some("http://127.0.0.1:4710/v1")
        );

        let changed2 = ensure_codex_kyris_model_provider(
            &mut config,
            "http://127.0.0.1:4710/v1",
            "sk-kyris-test",
        );
        assert!(changed2, "model provider should be written to empty config");
        assert_eq!(
            config["model_providers"]["kyris"]["name"].as_str(),
            Some("Kyris")
        );
    }

    #[test]
    fn testEmptyConfigCanBePopulatedByExecutionLogic() {
        // Simulates the configure_execution codex_hooks path for first-time user.
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());
        let changed = ensure_toml_bool_path(&mut config, &["features", "codex_hooks"], true);
        assert!(changed, "codex_hooks should be set in empty config");
        assert_eq!(config["features"]["codex_hooks"].as_bool(), Some(true));
    }

    // --- existing test ---

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
