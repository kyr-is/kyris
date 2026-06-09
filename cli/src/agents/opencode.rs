// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::WellFormedJsonValidator;
use crate::integration::{read_json_value, set_json_value_path, write_json_value};
use crate::state::restore_manifest_entry_component;

use super::probe::{
    ProbeResult, fingerprint, json_has_any_mcp_servers, json_has_mcp_wrap, not_detected,
    probe_config_rewrite_burn_control,
};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AttributionMechanism, BurnControlMechanism,
    ExecutionMechanism, McpConfigFormat, McpConfigLocation, SurfaceIntegration, ToolMechanism,
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
        use super::profile::{CoverageCeiling, SurfaceState};
        let detected = opencode_config_exists() || which_exists("opencode");
        if !detected {
            return not_detected();
        }

        let config_path = opencode_config_path().ok();
        let has_compiled_policy = config_path.as_deref().is_some_and(|p| {
            read_json_value(p).is_ok_and(|v| {
                let perm = v.get("permission");
                let has_section = |name: &str| {
                    perm.and_then(|p| p.get(name))
                        .and_then(|s| s.as_object())
                        .is_some_and(|m| !m.is_empty())
                };
                has_section("bash") || has_section("edit") || has_section("webfetch")
            })
        });
        let execution = if has_compiled_policy {
            SurfaceState::adapted(ExecutionMechanism::CompiledPolicy)
                .with_ceiling(CoverageCeiling::Compiled)
        } else {
            SurfaceState::none()
        };

        let has_mcp_wrap = config_path
            .as_deref()
            .is_some_and(|p| json_has_mcp_wrap(p, "mcp"));
        let has_any_mcp_servers = config_path
            .as_deref()
            .is_some_and(|p| json_has_any_mcp_servers(p, "mcp"));
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(ToolMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            SurfaceState::not_applicable()
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
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["permission", "kyris-mcp"]
    }
    fn env_exports(&self, _base_url: &str, _inbound_key: &str) -> Vec<(String, String)> {
        Vec::new()
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        super::capabilities::apply_declared_capabilities(
            self.canonical_id(),
            AgentIntegrationPlan {
                // opencode has no live-hook path — compiled policy is the maximum
                // achievable command-control coverage.
                execution: SurfaceIntegration::adapted_with_ceiling(
                    &[ExecutionMechanism::CompiledPolicy],
                    super::profile::CoverageCeiling::Compiled,
                ),
                tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
                burn_control: SurfaceIntegration::adapted(&[BurnControlMechanism::ConfigRewrite]),
                attribution: &[
                    AttributionMechanism::KyrisPathShim,
                    AttributionMechanism::ProcessLineage,
                ],
                agentpact_native_attribution: false,
            },
        )
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        opencode_config_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcp"],
            },
        })
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        opencode_config_path().into_iter().collect()
    }
    fn configure_execution_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let path = opencode_config_path()?;
        let mut changes = Vec::new();

        let (permissions, _) = crate::compile_policy::compile_opencode_permissions(None)?;
        let mut config = read_json_value(&path)?;
        let mut config_changed = false;
        for section in ["bash", "edit", "webfetch"] {
            if let Some(val) = permissions.get(section).cloned()
                && set_json_value_path(&mut config, &["permission", section], val)
            {
                config_changed = true;
            }
        }
        if config_changed {
            write_json_value(
                &path,
                &config,
                "opencode:execution",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!("updated {}", path.display()));
        }

        Ok(changes)
    }
    fn configure_burn_control_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let path = opencode_config_path()?;
        let base_url_v1 = format!("{base_url}/v1");
        let changes = super::configure::apply_json_config_rewrites(
            &path,
            &[
                (
                    &["provider", "anthropic", "options", "baseURL"] as &[&str],
                    base_url,
                ),
                (&["provider", "anthropic", "options", "apiKey"], inbound_key),
                (
                    &["provider", "openai", "options", "baseURL"],
                    base_url_v1.as_str(),
                ),
                (&["provider", "openai", "options", "apiKey"], inbound_key),
                (&["provider", "google", "options", "baseURL"], base_url),
                (&["provider", "google", "options", "apiKey"], inbound_key),
            ],
            "opencode:burn-control",
        )?;

        Ok(changes)
    }
    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        // opencode's `permission` config targets built-in tools, not a
        // per-MCP-server tool denylist, so it uses the default (no) extra filter
        // and relies on the runtime wrap/routing backstop — see configure.rs.
        super::configure::configure_json_mcp_tool_surface(self, base_url, inbound_key)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        super::configure::undo_json_mcp_tool_surface(self)
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        let path = opencode_config_path()?;
        if restore_manifest_entry_component(&path, "opencode:execution")? {
            println!("Reverted {}", path.display());
        }
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if restore_manifest_entry_component(&path, "opencode:burn-control")? {
                println!("Reverted {}", path.display());
            }
        }
        Ok(())
    }
}
