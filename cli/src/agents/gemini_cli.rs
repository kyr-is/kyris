// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{read_json_value, set_json_string_path, write_json_value};

use super::probe::{
    ProbeResult, env_reaches_agent, fingerprint, json_has_any_mcp_servers, json_has_mcp_wrap,
    not_detected,
};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, McpConfigFormat, McpConfigLocation,
    ProviderRouting, SurfaceIntegration, ToolMapping, ToolMechanism, which_exists,
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

pub fn gemini_policies_dir() -> Result<PathBuf, String> {
    Ok(crate::integration::home_dir()?
        .join(".gemini")
        .join("policies"))
}

/// Current settings as a JSON value, or an empty object if the file is absent —
/// so burn-control setup works on a fresh install that has never run gemini.
fn read_or_empty_gemini_settings(path: &std::path::Path) -> Result<serde_json::Value, String> {
    if path.exists() {
        read_json_value(path)
    } else {
        Ok(serde_json::Value::Object(serde_json::Map::new()))
    }
}

/// Gemini OAuth (Code Assist) ignores `GOOGLE_GEMINI_BASE_URL`, so an OAuth or
/// unset auth selection bypasses kyrisd entirely. Switch ONLY a non-routable
/// selection to the API-key path; an already-routable one
/// (`gemini-api-key` / `vertex-ai` / `gateway`) is left untouched so a user who
/// has deliberately chosen Vertex/gateway keeps it. Returns whether `settings`
/// changed.
fn ensure_gemini_routable_auth_type(settings: &mut serde_json::Value) -> bool {
    const ROUTABLE: &[&str] = &["gemini-api-key", "vertex-ai", "gateway"];
    let current = settings
        .get("security")
        .and_then(|s| s.get("auth"))
        .and_then(|a| a.get("selectedType"))
        .and_then(serde_json::Value::as_str);
    if current.is_some_and(|t| ROUTABLE.contains(&t)) {
        return false;
    }
    set_json_string_path(
        settings,
        &["security", "auth", "selectedType"],
        "gemini-api-key",
    )
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
        use super::profile::{CoverageCeiling, SurfaceState};
        let detected = gemini_settings_exists() || which_exists("gemini");
        if !detected {
            return not_detected();
        }

        let settings_path = gemini_settings_path().ok();
        let has_hook = settings_path.as_deref().is_some_and(|p| {
            crate::integration::read_json_value(p).is_ok_and(|v| {
                let serialized = serde_json::to_string(&v).unwrap_or_default();
                serialized.contains("agentpact_beforetool")
            })
        });
        let has_mcp_wrap = settings_path
            .as_deref()
            .is_some_and(|p| json_has_mcp_wrap(p, "mcpServers"));
        let has_any_mcp_servers = settings_path
            .as_deref()
            .is_some_and(|p| json_has_any_mcp_servers(p, "mcpServers"));

        let has_compiled_policy = gemini_policies_dir()
            .ok()
            .map(|d| d.join("agentpact.toml"))
            .is_some_and(|p| p.exists());

        let execution = if has_hook {
            SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter)
        } else if has_compiled_policy {
            SurfaceState::adapted(ExecutionMechanism::CompiledPolicy)
                .with_ceiling(CoverageCeiling::Compiled)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(ToolMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };
        let burn_control = if env_reaches_agent("gemini-cli", "GOOGLE_GEMINI_BASE_URL") {
            SurfaceState::adapted(BurnControlMechanism::EnvVarProxy)
        } else {
            SurfaceState::none()
        };

        let mut managed_files = Vec::new();
        if let Some(path) = settings_path.as_deref()
            && let Some(fp) = fingerprint(path)
        {
            managed_files.push(fp);
        }
        if let Some(fp) = gemini_policies_dir()
            .ok()
            .map(|d| d.join("agentpact.toml"))
            .and_then(|p| fingerprint(&p))
        {
            managed_files.push(fp);
        }

        ProbeResult {
            detected: true,
            execution,
            tool,
            burn_control,
            managed_files,
        }
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["agentpact_beforetool", "kyris-mcp", "Generated by Kyris"]
    }
    fn provider_routing(&self) -> Option<ProviderRouting> {
        // Repoint Gemini's API + Vertex base URLs at kyrisd; the gate secret +
        // agent-id ride in GEMINI_CLI_CUSTOM_HEADERS (comma-separated, the format
        // Gemini's parseCustomHeaders expects). The agent's OWN GEMINI_API_KEY is
        // deliberately NOT set — it flows through as the upstream credential
        // (x-goog-api-key) for kyrisd to forward and classify. Routing only takes
        // effect when the configured auth type is API-key/gateway, not OAuth (see
        // configure_burn_control_surface) — Gemini OAuth ignores the base URL.
        Some(ProviderRouting {
            base_url_vars: &["GOOGLE_GEMINI_BASE_URL", "GOOGLE_VERTEX_BASE_URL"],
            auth_skip_flags: &[],
            custom_headers_var: "GEMINI_CLI_CUSTOM_HEADERS",
            header_separator: ", ",
        })
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        super::capabilities::apply_declared_capabilities(
            self.canonical_id(),
            AgentIntegrationPlan {
                execution: SurfaceIntegration::adapted(&[
                    ExecutionMechanism::LiveHookAdapter,
                    ExecutionMechanism::CompiledPolicy,
                ]),
                tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
                burn_control: SurfaceIntegration::adapted(&[BurnControlMechanism::EnvVarProxy]),
                attribution: &[
                    AttributionMechanism::KyrisPathShim,
                    AttributionMechanism::NativeHookPayload,
                    AttributionMechanism::ProcessLineage,
                ],
                agentpact_native_attribution: false,
            },
        )
    }
    fn supported_settings(&self) -> &'static [(&'static str, &'static str)] {
        &[(
            "maxSessionTurns",
            "Max agent turns per session (writes maxSessionTurns to settings.json)",
        )]
    }
    fn launch_dir_env(&self) -> Option<&'static str> {
        // Gemini CLI's hook payload `cwd` is already the fixed launch dir, but
        // it also exports `GEMINI_PROJECT_DIR` — use it as the explicit, stable
        // permitted-domain anchor.
        Some("GEMINI_PROJECT_DIR")
    }
    fn configure_execution_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let settings_path = gemini_settings_path()?;
        let script_path = settings_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("hooks")
            .join("agentpact_beforetool.sh");

        let mut changes = super::configure::install_live_hook_adapter(
            "gemini-cli",
            "gemini-cli:execution",
            "BeforeTool",
            &script_path,
            &settings_path,
            // Gemini 0.41 requires the NESTED hook shape — `BeforeTool: [{ hooks:
            // [{ type, command }] }]` — and silently DISCARDS the flat
            // `{ type, command }` form ("Discarding invalid hook definition for
            // BeforeTool"), so governance never fires. Must be nested (like codex).
            true,
            // Gemini's default hook timeout is 60s — below kyris's ~590s no-TTY
            // poll window — so it would kill the hook mid-wait. Pin it to 600s
            // (Gemini's `timeout` is in milliseconds).
            Some(600_000),
        )?;

        match crate::compile_policy::compile_gemini_permissions(None) {
            Ok((rules, _)) => {
                let has_rules = rules.as_array().is_some_and(|a| !a.is_empty());
                if has_rules {
                    let toml_content = crate::compile_policy::serialize_gemini_policy_toml(&rules);
                    let policy_path = gemini_policies_dir()?.join("agentpact.toml");
                    // Compiled policy TOML is generated by kyris itself —
                    // we trust the serializer; no shape check needed beyond
                    // well-formedness, but keep it simple with NoopValidator.
                    if crate::state::write_managed_file(
                        &policy_path,
                        &toml_content,
                        "gemini-cli:execution",
                        None,
                        &NoopValidator,
                    )? {
                        changes.push(format!("wrote {}", policy_path.display()));
                    }
                }
            }
            Err(e) => {
                changes.push(format!("warning: compiled policy skipped: {e}"));
            }
        }

        Ok(changes)
    }
    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        super::configure::configure_json_mcp_tool_surface(self, base_url, inbound_key)
    }
    fn apply_extra_tool_filters(&self, settings: &mut serde_json::Value) -> bool {
        // Gemini natively supports a per-server tool denylist via `excludeTools`.
        super::configure::apply_json_tool_filters(settings, &["mcpServers"])
    }
    fn configure_burn_control_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let settings_path = gemini_settings_path()?;
        let mut changes = Vec::new();

        let mut settings = read_or_empty_gemini_settings(&settings_path)?;
        let mut settings_changed = false;

        // Force a kyrisd-routable auth type (only when the current one isn't),
        // else the env redirect in `provider_routing` is silently ignored.
        if ensure_gemini_routable_auth_type(&mut settings) {
            settings_changed = true;
            changes.push(format!(
                "set security.auth.selectedType = \"gemini-api-key\" in {} \
                 (prior selection could not route through kyrisd)",
                settings_path.display()
            ));
        }

        if let Some(val) = agent_specific.get("maxSessionTurns") {
            // Loud on a bad value rather than silently skipping it.
            let n: u64 = val.parse().map_err(|_| {
                format!("maxSessionTurns must be a non-negative integer, got '{val}'")
            })?;
            settings["maxSessionTurns"] = serde_json::json!(n);
            settings_changed = true;
        }

        if settings_changed {
            write_json_value(
                &settings_path,
                &settings,
                "gemini-cli:burn-control",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!("updated {}", settings_path.display()));
        }

        Ok(changes)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        super::configure::undo_json_mcp_tool_surface(self)
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        let settings_path = gemini_settings_path()?;
        if crate::state::restore_manifest_entry_component(&settings_path, "gemini-cli:execution")? {
            println!("Reverted {}", settings_path.display());
        }
        let script = settings_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("hooks")
            .join("agentpact_beforetool.sh");
        if !crate::state::restore_manifest_entry_component(&script, "gemini-cli:execution")? {
            super::undo::remove_file_if_exists(&script)?;
        }
        let policy = gemini_policies_dir()?.join("agentpact.toml");
        if !crate::state::restore_manifest_entry_component(&policy, "gemini-cli:execution")? {
            super::undo::remove_file_if_exists(&policy)?;
        }
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if crate::state::restore_manifest_entry_component(&path, "gemini-cli:burn-control")? {
                println!("Reverted {}", path.display());
            }
        }
        let env_file = crate::state::env_dir()?.join("gemini-cli.sh");
        super::undo::remove_file_if_exists(&env_file)?;
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
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        gemini_settings_path().into_iter().collect()
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "run_shell_command".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "replace".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
            ],
            // Gemini CLI internal coordination tools: skip the daemon. See
            // claude_code.rs and hook_cmd.rs for the design rationale.
            pass_through_tools: vec![
                "google_search".to_string(),
                "save_memory".to_string(),
                "list_directory".to_string(),
                "glob".to_string(),
                "search_file_content".to_string(),
                "web_fetch".to_string(),
            ],
            detail_pass_throughs: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::Json {
                body: serde_json::json!({"decision": "allow"}),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testGeminiExportsRouteViaCustomHeaderGate() {
        let agent = GeminiCli;
        let exports = agent.env_exports("http://127.0.0.1:4710", "sk-test");
        let keys: Vec<&str> = exports.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"GOOGLE_GEMINI_BASE_URL"));
        assert!(keys.contains(&"GOOGLE_VERTEX_BASE_URL"));
        // Gate secret + agent-id ride in the custom-headers env var; the agent's
        // own GEMINI_API_KEY is left untouched (it flows through as the upstream
        // credential), and the GATEWAY-ignored bearer mechanism is gone.
        assert!(keys.contains(&"GEMINI_CLI_CUSTOM_HEADERS"));
        assert!(!keys.contains(&"GEMINI_API_KEY"));
        assert!(!keys.contains(&"GEMINI_API_KEY_AUTH_MECHANISM"));
        let custom = exports
            .iter()
            .find(|(k, _)| k == "GEMINI_CLI_CUSTOM_HEADERS")
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            custom,
            "x-kyris-inbound: sk-test, x-kyris-agent-id: google/gemini-cli"
        );
    }

    #[test]
    fn testEnsureGeminiRoutableAuthTypeOnlySwitchesNonRoutable() {
        // OAuth/unset → switched to the API-key path.
        let mut oauth =
            serde_json::json!({"security": {"auth": {"selectedType": "oauth-personal"}}});
        assert!(ensure_gemini_routable_auth_type(&mut oauth));
        assert_eq!(
            oauth["security"]["auth"]["selectedType"].as_str(),
            Some("gemini-api-key")
        );
        let mut empty = serde_json::json!({});
        assert!(ensure_gemini_routable_auth_type(&mut empty));
        assert_eq!(
            empty["security"]["auth"]["selectedType"].as_str(),
            Some("gemini-api-key")
        );

        // Already-routable selections are left untouched.
        for routable in ["gemini-api-key", "vertex-ai", "gateway"] {
            let mut s = serde_json::json!({"security": {"auth": {"selectedType": routable}}});
            assert!(!ensure_gemini_routable_auth_type(&mut s));
            assert_eq!(
                s["security"]["auth"]["selectedType"].as_str(),
                Some(routable)
            );
        }
    }
}
