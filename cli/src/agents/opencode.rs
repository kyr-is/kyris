// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::WellFormedJsonValidator;
use crate::integration::{
    read_json_value, remove_json_string_if_equals, set_json_string_path, set_json_value_path,
    write_json_value,
};
use crate::state::restore_manifest_entry_component;

use super::probe::{
    ProbeResult, fingerprint, json_has_any_mcp_servers, json_has_mcp_wrap, not_detected,
    probe_config_rewrite_burn_control,
};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, McpConfigFormat, McpConfigLocation,
    SurfaceIntegration, ToolMapping, ToolMechanism, which_exists,
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

/// The kyris governance plugin lives next to the config that registers it, so the
/// path in the `plugin` array resolves regardless of where opencode's config is.
fn opencode_plugin_path() -> Result<PathBuf, String> {
    let config = opencode_config_path()?;
    let dir = config
        .parent()
        .ok_or_else(|| format!("cannot resolve parent of {}", config.display()))?;
    Ok(dir.join("kyris-governance.js"))
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
        use super::profile::SurfaceState;
        let detected = opencode_config_exists() || which_exists("opencode");
        if !detected {
            return not_detected();
        }

        let config_path = opencode_config_path().ok();
        // Live-hook adapter: the kyris governance plugin is registered in the
        // config's `plugin` array AND present on disk.
        let plugin_path = opencode_plugin_path().ok();
        let has_live_hook = config_path.as_deref().is_some_and(|p| {
            read_json_value(p).is_ok_and(|v| {
                v.get("plugin")
                    .and_then(|a| a.as_array())
                    .is_some_and(|items| {
                        items
                            .iter()
                            .filter_map(|i| i.as_str())
                            .any(|s| s.contains("kyris-governance"))
                    })
            })
        }) && plugin_path.as_deref().is_some_and(std::path::Path::exists);
        let execution = if has_live_hook {
            SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter)
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
        &["kyris-governance", "kyris-mcp"]
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        super::capabilities::apply_declared_capabilities(
            self.canonical_id(),
            AgentIntegrationPlan {
                // opencode's plugin system (`tool.execute.before`) gives a real
                // live-hook adapter — the kyris governance plugin bridges every
                // tool call to `kyris hook check` → agentpactd, same as the
                // native-hook agents.
                execution: SurfaceIntegration::adapted(&[ExecutionMechanism::LiveHookAdapter]),
                tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
                burn_control: SurfaceIntegration::adapted(&[BurnControlMechanism::ConfigRewrite]),
                attribution: &[
                    AttributionMechanism::KyrisPathShim,
                    AttributionMechanism::NativeHookPayload,
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
        let plugin_path = opencode_plugin_path()?;

        // Live-hook adapter: write + register the kyris governance plugin, which
        // bridges opencode's `tool.execute.before` to `kyris hook check` → agentpactd.
        let mut changes = super::configure::install_plugin_hook_adapter(
            self.id(),
            "opencode:execution",
            &plugin_path,
            &path,
        )?;

        // Make opencode's NATIVE permissions permissive so every tool reaches the
        // plugin — the plugin (→ agentpactd) is the sole gate, the same
        // "permissive native + hook governs" model used for codex/claude. (Without
        // this, opencode's own permission prompts would pre-empt the hook in
        // headless mode.)
        //
        // Use the top-level bare-`Action` form (`permission: "allow"`): opencode's
        // PermissionConfig is `Action | object`, and the per-surface schema is
        // heterogeneous — bash/edit accept a pattern map but webfetch/websearch/
        // question accept ONLY a bare action, so a `{"*":"allow"}` map is invalid
        // there. The top-level string normalizes to allow-all across every tool.
        let mut config = read_json_value(&path)?;
        let mut config_changed = false;
        if set_json_value_path(&mut config, &["permission"], serde_json::json!("allow")) {
            config_changed = true;
        }
        if config_changed {
            write_json_value(
                &path,
                &config,
                "opencode:execution",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!(
                "set permissive native permissions in {}",
                path.display()
            ));
        }

        Ok(changes)
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "bash".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "edit".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
                ToolMapping {
                    tool_name: "write".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
                ToolMapping {
                    tool_name: "patch".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
                ToolMapping {
                    tool_name: "read".to_string(),
                    action: "read".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
            ],
            // opencode-internal / read-only tools: skip the daemon (mirrors the
            // pass-through lists for the native-hook agents).
            pass_through_tools: [
                "glob",
                "grep",
                "list",
                "todo",
                "task",
                "fetch",
                "webfetch",
                "websearch",
                "skill",
                "lsp",
                "question",
                "plan",
                "invalid",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            detail_pass_throughs: Vec::new(),
            default_action: "call".to_string(),
            // The plugin reads `kyris hook check`'s EXIT CODE (0 allow / 2 deny),
            // not stdout, so the allow shape is the empty default.
            allow_response: AllowResponse::EmptyStdout,
        })
    }
    fn configure_burn_control_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let path = opencode_config_path()?;
        let agent_id = self.canonical_id();
        let v1 = format!("{base_url}/v1");
        let v1beta = format!("{base_url}/v1beta");
        // Each provider's baseURL must carry the suffix its AI SDK provider expects
        // — opencode passes baseURL straight through and the SDK appends its own
        // path (anthropic/openai default `…/v1` then `/messages`,`/chat/completions`;
        // google default `…/v1beta` then `/models/{m}:generateContent`). A bare host
        // → the SDK hits `…/messages` etc. → kyrisd 404.
        let providers: [(&str, &str); 3] = [
            ("anthropic", v1.as_str()),
            ("openai", v1.as_str()),
            ("google", v1beta.as_str()),
        ];

        let mut config = read_json_value(&path)?;
        let mut config_changed = false;
        for (provider, provider_base_url) in providers {
            // Route through kyrisd.
            if set_json_string_path(
                &mut config,
                &["provider", provider, "options", "baseURL"],
                provider_base_url,
            ) {
                config_changed = true;
            }
            // Gate secret + agent-id ride in custom headers (the AI SDK merges them
            // alongside the resolved x-api-key — see opencode provider-options.ts).
            for (header, value) in [
                ("x-kyris-inbound", inbound_key),
                ("x-kyris-agent-id", agent_id),
            ] {
                if set_json_string_path(
                    &mut config,
                    &["provider", provider, "options", "headers", header],
                    value,
                ) {
                    config_changed = true;
                }
            }
            // The agent's OWN provider key (env / `opencode auth`) is the upstream
            // credential kyrisd forwards — we must NOT set `apiKey`. Migrate away a
            // stale `apiKey == inbound_key` from older installs (it overrode the real
            // key and was rejected upstream); leave a user's real apiKey untouched.
            if remove_json_string_if_equals(
                &mut config,
                &["provider", provider, "options", "apiKey"],
                inbound_key,
            ) {
                config_changed = true;
            }
        }

        let mut changes = Vec::new();
        if config_changed {
            write_json_value(
                &path,
                &config,
                "opencode:burn-control",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!("updated {}", path.display()));
        }

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
        // Reverts both the permissive-permission edit and the `plugin`-array
        // registration recorded under this component.
        if restore_manifest_entry_component(&path, "opencode:execution")? {
            println!("Reverted {}", path.display());
        }
        // Drop the governance plugin file (restore to its pre-state, else delete).
        let plugin_path = opencode_plugin_path()?;
        if !restore_manifest_entry_component(&plugin_path, "opencode:execution")? {
            super::undo::remove_file_if_exists(&plugin_path)?;
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
