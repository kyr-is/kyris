// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{read_json_value, set_json_string_path, write_json_value};
use crate::state::restore_manifest_entry;

use super::probe::{
    ProbeResult, env_file_has_var, env_loader_sourced, fingerprint, json_has_any_mcp_servers,
    json_has_mcp_wrap, not_detected,
};
use super::registry::{AgentDescriptor, McpConfigFormat, McpConfigLocation};

pub struct Cline;

fn vscode_global_storage_dir() -> Result<PathBuf, String> {
    Ok(crate::integration::home_dir()?
        .join("Library")
        .join("Application Support")
        .join("Code")
        .join("User")
        .join("globalStorage")
        .join("saoudrizwan.claude-dev"))
}

pub fn cline_global_state_path() -> Result<PathBuf, String> {
    Ok(crate::integration::home_dir()?
        .join(".cline")
        .join("data")
        .join("globalState.json"))
}

pub fn cline_mcp_settings_path() -> Result<PathBuf, String> {
    Ok(vscode_global_storage_dir()?.join("cline_mcp_settings.json"))
}

fn has_vscode_extension() -> bool {
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

fn has_cline_cli() -> bool {
    super::registry::which_exists("cline")
}

pub fn cline_extension_installed() -> bool {
    has_vscode_extension() || has_cline_cli()
}

pub fn cline_is_vscode_only() -> bool {
    has_vscode_extension() && !has_cline_cli()
}

fn install_cline_policy_launchd(json: &str, changes: &mut Vec<String>) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;

    // Write the JSON value to a file so the plist script can read it
    let value_path = std::path::PathBuf::from(&home)
        .join(".kyris")
        .join("env")
        .join("cline-policy.json");
    if crate::state::write_managed_file(
        &value_path,
        json,
        "cline",
        Some(0o600),
        &WellFormedJsonValidator,
    )? {
        changes.push(format!("wrote {}", value_path.display()));
    }

    // Write a plist that loads the value at login
    let plist_path = std::path::PathBuf::from(&home)
        .join("Library")
        .join("LaunchAgents")
        .join("is.kyr.cline-policy.plist");
    let plist_contents = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>is.kyr.cline-policy</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>launchctl setenv CLINE_COMMAND_PERMISSIONS "$(cat {value_path})"</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"#,
        value_path = value_path.display()
    );
    // launchd plist is XML; we don't have an XML validator. plutil-lint via
    // CommandValidator could be added later; for now skip schema check.
    if crate::state::write_managed_file(
        &plist_path,
        &plist_contents,
        "cline",
        Some(0o644),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", plist_path.display()));
    }

    // Set immediately for the current session
    let status = std::process::Command::new("launchctl")
        .args(["setenv", "CLINE_COMMAND_PERMISSIONS", json])
        .status()
        .map_err(|e| format!("Failed to run launchctl setenv: {e}"))?;
    if status.success() {
        changes.push("set CLINE_COMMAND_PERMISSIONS in launchd session".to_string());
    }

    // Bootstrap the plist for RunAtLoad
    let domain = format!("gui/{}", crate::service::uid());
    let _ = std::process::Command::new("launchctl")
        .args(["bootstrap", &domain, &plist_path.to_string_lossy()])
        .status();

    Ok(())
}

fn uninstall_cline_policy_launchd() {
    let home = std::env::var("HOME").unwrap_or_default();
    let plist_path = std::path::PathBuf::from(&home)
        .join("Library")
        .join("LaunchAgents")
        .join("is.kyr.cline-policy.plist");

    if plist_path.exists() {
        let domain = format!("gui/{}", crate::service::uid());
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &domain, &plist_path.to_string_lossy()])
            .status();
        let _ = std::fs::remove_file(&plist_path);
    }

    let _ = std::process::Command::new("launchctl")
        .args(["unsetenv", "CLINE_COMMAND_PERMISSIONS"])
        .status();

    let value_path = std::path::PathBuf::from(&home)
        .join(".kyris")
        .join("env")
        .join("cline-policy.json");
    let _ = std::fs::remove_file(&value_path);
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
        use super::profile::{AdaptedMechanism, CoverageCeiling, SurfaceState};
        let detected = cline_extension_installed();
        if !detected {
            return not_detected();
        }
        let vscode_only = cline_is_vscode_only();

        let has_env_file = env_file_has_var("cline", "CLINE_COMMAND_PERMISSIONS");
        let has_launchd_plist = crate::integration::home_dir()
            .ok()
            .map(|h| {
                h.join("Library")
                    .join("LaunchAgents")
                    .join("is.kyr.cline-policy.plist")
            })
            .is_some_and(|p| p.exists());
        let env_reachable = (has_env_file && env_loader_sourced()) || has_launchd_plist;
        let execution = if env_reachable {
            let state = SurfaceState::adapted(AdaptedMechanism::CompiledPolicy);
            if vscode_only {
                state.with_ceiling(CoverageCeiling::Observed)
            } else {
                state.with_ceiling(CoverageCeiling::Compiled)
            }
        } else {
            SurfaceState::none()
        };

        let mcp_path = cline_mcp_settings_path().ok();
        let has_mcp_wrap = mcp_path
            .as_deref()
            .is_some_and(|p| json_has_mcp_wrap(p, "mcpServers"));
        let has_any_mcp_servers = mcp_path
            .as_deref()
            .is_some_and(|p| json_has_any_mcp_servers(p, "mcpServers"));
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(AdaptedMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };

        let has_base_url_rewrite = cline_global_state_path().ok().is_some_and(|p| {
            read_json_value(&p).is_ok_and(|v| {
                v.get("anthropicBaseUrl")
                    .and_then(|u| u.as_str())
                    .is_some_and(|u| !u.is_empty())
            })
        });
        let burn_control = if has_base_url_rewrite {
            SurfaceState::adapted(AdaptedMechanism::ConfigRewrite)
        } else {
            SurfaceState::none()
        };

        let mut managed_files = Vec::new();
        if let Some(path) = mcp_path.as_deref()
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
        &["kyris-mcp"]
    }
    fn env_exports(&self, _base_url: &str, _inbound_key: &str) -> Vec<(String, String)> {
        Vec::new()
    }
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        (true, true, true)
    }
    fn surface_design_ceilings(
        &self,
    ) -> (
        Option<super::profile::CoverageCeiling>,
        Option<super::profile::CoverageCeiling>,
        Option<super::profile::CoverageCeiling>,
    ) {
        // cline has no live-hook path — compiled policy is the maximum
        // achievable command-control coverage.
        (Some(super::profile::CoverageCeiling::Compiled), None, None)
    }
    fn configure_execution(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let (permissions, gaps) = crate::compile_policy::compile_cline_permissions(None)?;
        let json = serde_json::to_string(&permissions)
            .map_err(|e| format!("Cannot serialize compiled Cline permissions: {e}"))?;

        let mut changes = Vec::new();

        // Shell env file for terminal Cline CLI. The value must be properly
        // single-quoted: `\'` does NOT escape a quote inside POSIX single
        // quotes (backslash is literal there), so JSON containing an apostrophe
        // would terminate the string early and break sourcing.
        let contents = format!(
            "# SPDX-License-Identifier: Apache-2.0\nexport CLINE_COMMAND_PERMISSIONS={}\n",
            super::prestage::shell_single_quote(&json)
        );
        let loader_changes = super::prestage::ensure_env_loader()?;
        changes.extend(loader_changes);
        let env_file = crate::state::env_dir()?.join("cline-policy.sh");
        // Shell env file (export VAR='...') — opaque text, no schema.
        if crate::state::write_managed_file(
            &env_file,
            &contents,
            "cline",
            Some(0o600),
            &NoopValidator,
        )? {
            changes.push(format!("wrote {}", env_file.display()));
        }

        // launchctl setenv for VS Code extension host (GUI processes)
        if has_vscode_extension() {
            install_cline_policy_launchd(&json, &mut changes)?;
        }

        if !gaps.ask_dropped.is_empty() {
            changes.push(format!(
                "warning: dropped {} ask rules: {}",
                gaps.ask_dropped.len(),
                gaps.ask_dropped.join(", ")
            ));

            let mut profile = crate::state::load_agent_profile("cline")?
                .unwrap_or_else(|| super::profile::AgentProfile::new_empty("cline"));
            profile.compilation_gaps = gaps
                .ask_dropped
                .iter()
                .map(|cmd| format!("ask rule not expressible: {cmd}"))
                .collect();
            crate::state::save_agent_profile(&profile)?;
        }

        Ok(changes)
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        cline_mcp_settings_path()
            .ok()
            .map(|path| McpConfigLocation {
                path,
                format: McpConfigFormat::Json {
                    servers_path: vec!["mcpServers"],
                },
            })
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Ok(path) = cline_mcp_settings_path() {
            paths.push(path);
        }
        if let Ok(path) = cline_global_state_path() {
            paths.push(path);
        }
        paths
    }
    fn configure_burn_control(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let mcp_path = cline_mcp_settings_path()?;
        let mut changes = Vec::new();

        if mcp_path.exists() {
            let mut settings = read_json_value(&mcp_path)?;
            let mcp_result = super::configure::rewrite_json_mcp_servers(
                &mut settings,
                &["mcpServers"],
                base_url,
                inbound_key,
            );
            if mcp_result.changed {
                write_json_value(&mcp_path, &settings, "cline", &WellFormedJsonValidator)?;
                changes.push(format!("rewrote MCP servers in {}", mcp_path.display()));
            }
            if !mcp_result.http_rewrites.is_empty() {
                super::configure::upsert_mcp_upstreams(&mcp_result.http_rewrites)?;
                changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
            }
        }

        let global_state_path = cline_global_state_path()?;
        let base_url_v1 = format!("{base_url}/v1");
        let mut state = read_json_value(&global_state_path)?;
        let mut state_changed = false;
        for (key, value) in [
            ("anthropicBaseUrl", base_url),
            ("openAiBaseUrl", base_url_v1.as_str()),
        ] {
            if set_json_string_path(&mut state, &[key], value) {
                state_changed = true;
            }
        }
        if state_changed {
            write_json_value(
                &global_state_path,
                &state,
                "cline",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!(
                "wrote base URLs in {}",
                global_state_path.display()
            ));
        }

        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        let policy_file = crate::state::env_dir()?.join("cline-policy.sh");
        super::undo::remove_file_if_exists(&policy_file)?;
        uninstall_cline_policy_launchd();
        self.undo_burn_control()?;
        Ok(())
    }
    fn undo_burn_control(&self) -> Result<(), String> {
        // Remove MCP upstreams before restoring the MCP settings file.
        let mcp_names = super::configure::mcp_server_names_from_agent(self);
        super::configure::remove_mcp_upstreams(&mcp_names)?;

        let mcp_path = cline_mcp_settings_path()?;
        if restore_manifest_entry(&mcp_path)? {
            println!("Reverted {}", mcp_path.display());
        }
        let global_state_path = cline_global_state_path()?;
        if global_state_path.exists() {
            let mut state = read_json_value(&global_state_path)?;
            if let Some(obj) = state.as_object_mut() {
                let mut changed = false;
                for key in ["anthropicBaseUrl", "openAiBaseUrl"] {
                    if obj.remove(key).is_some() {
                        changed = true;
                    }
                }
                if changed {
                    write_json_value(
                        &global_state_path,
                        &state,
                        "cline",
                        &WellFormedJsonValidator,
                    )?;
                    println!(
                        "Removed base URL overrides from {}",
                        global_state_path.display()
                    );
                }
            }
        }
        Ok(())
    }
}
