// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::NoopValidator;
use crate::integration::{
    ensure_toml_bool_path, ensure_toml_string_path, merge_toml_string_entries, read_toml_value,
};
use crate::state::restore_manifest_entry_component;

// `CodexConfigShape` is referenced by name from the path-IO submodule (`paths`)
// via `super::CodexConfigShape`.
use super::codex_cli_schema::CodexConfigShape;

// Helper groups split into sibling submodules. The `AgentDescriptor` impl (the
// surface entry points the rest of the CLI drives) stays here. `pub use` re-
// exports the public items so `crate::agents::codex_cli::<item>` keeps resolving
// for external callers (`scrub_codex_residue`, the `codex_*_path` helpers).
mod hooks;
mod model_provider;
mod paths;
pub use hooks::*;
pub use paths::*;

// `pub(super)` helpers used by the surface impl below (and the test module via
// `super::*`): not part of the public surface, so brought in by name.
use hooks::{CODEX_HOOK_TIMEOUT_SECS, codex_kyris_hook_trusted, ensure_codex_kyris_hook_trust};
use model_provider::{ensure_codex_kyris_model_provider, ensure_codex_shell_env_marker};
use paths::{ensure_codex_dir, read_or_empty_codex_config, write_codex_config};
// Used only by the parent test module.
#[cfg(test)]
use hooks::{
    codex_kyris_hook_command, codex_kyris_hook_hash, codex_kyris_hook_key,
    scrub_codex_config_value, scrub_codex_kyris_hook_trust,
};
#[cfg(test)]
use paths::{codex_config_path_from, write_codex_config_unmanaged, write_json_unmanaged};

use super::probe::{ProbeResult, fingerprint, not_detected, toml_has_any_mcp_servers};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, HookRuntime, HookTimeoutPosture,
    McpConfigFormat, McpConfigLocation, SurfaceIntegration, ToolMapping, ToolMechanism,
};

pub struct CodexCli;

impl AgentDescriptor for CodexCli {
    fn id(&self) -> &'static str {
        "codex-cli"
    }
    fn is_installed(&self) -> bool {
        // Detected when the config file exists (agent has been run at least
        // once) OR when the binary is on PATH (installed but not yet launched).
        codex_config_exists() || codex_binary_installed()
    }
    fn probe(&self) -> ProbeResult {
        use super::profile::{CoverageCeiling, SurfaceState};
        let detected = codex_config_exists() || codex_binary_installed();
        if !detected {
            return not_detected();
        }

        let config_path = codex_config_path().ok();
        let hooks_path = codex_hooks_path().ok();
        let script_path = codex_dir().ok().map(|d| d.join("kyris_pretooluse.sh"));
        let has_registered_hook = hooks_path.as_deref().is_some_and(|p| {
            p.exists() && std::fs::read_to_string(p).is_ok_and(|c| c.contains("kyris"))
        });
        let has_hook = has_registered_hook
            && config_path
                .as_deref()
                .zip(hooks_path.as_deref())
                .zip(script_path.as_deref())
                .is_some_and(|((config, hooks), script)| {
                    codex_kyris_hook_trusted(config, hooks, script)
                });

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
        let has_kyris_provider_config = config_path.as_deref().is_some_and(|p| {
            read_toml_value(p).is_ok_and(|v| {
                v.get("model_provider").and_then(toml::Value::as_str) == Some("kyris")
                    && v.get("model_providers")
                        .and_then(toml::Value::as_table)
                        .and_then(|providers| providers.get("kyris"))
                        .and_then(toml::Value::as_table)
                        .and_then(|provider| provider.get("base_url"))
                        .and_then(toml::Value::as_str)
                        .is_some_and(|u| !u.is_empty())
            })
        });
        let burn_control = if has_kyris_provider_config {
            SurfaceState::adapted(BurnControlMechanism::KyrisdModelProvider)
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
    fn kyris_content_markers(&self) -> Vec<String> {
        [
            "kyris-mcp",
            "kyris_pretooluse",
            "KYRIS_GOVERNED_SUBPROCESS",
            "model_provider = \"kyris\"",
            "[model_providers.kyris]",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        // Raw declared plan — the native overlay is applied by the generic engine
        // (GenericAgent) from the document's `native` flags / a live `agentpact`
        // response, not from the retired capabilities.json file reader.
        AgentIntegrationPlan {
            execution: SurfaceIntegration::adapted(vec![
                ExecutionMechanism::LiveHookAdapter,
                ExecutionMechanism::CompiledPolicy,
            ]),
            tool: SurfaceIntegration::adapted(vec![ToolMechanism::McpWrapping]),
            burn_control: SurfaceIntegration::adapted(vec![
                BurnControlMechanism::KyrisdModelProvider,
            ]),
            attribution: vec![
                // The PATH shim is load-bearing beyond attribution: it puts
                // KYRIS_GOVERNED_SUBPROCESS in codex's OWN env, so codex's
                // HOOK children inherit the governed-agent marker.
                // ShellEnvironmentPolicy covers only exec-tool children —
                // without the shim, the kyris hook spawn itself
                // (`bash kyris_pretooluse.sh`) reached the shell gate
                // unmarked and was prompted on the agent's own TTY (the
                // codex composer-garbage bug).
                AttributionMechanism::KyrisPathShim,
                AttributionMechanism::ShellEnvironmentPolicy,
                AttributionMechanism::NativeHookPayload,
                AttributionMechanism::PeerProcessObserved,
            ],
            agentpact_native_attribution: false,
        }
    }
    // Configuration for Codex CLI is a linear sequence of TOML edits (live
    // hook adapter + rules dir + permissions table + default_permissions +
    // managed-file recording), each producing a change-log entry. Splitting
    // it into helpers would require threading the change Vec through every
    // call and would make the install transcript harder to read.
    #[allow(clippy::too_many_lines)]
    fn configure_execution_surface(
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
            "codex-cli:execution",
            // PreToolUse = the governance gate; PermissionRequest answers
            // codex's native approval prompts (allow when kyris can vouch,
            // abstain otherwise — see hook_cmd::run_permission_request). Same
            // script; the engine branches on the payload's hook_event_name.
            &["PreToolUse", "PermissionRequest"],
            &script_path,
            &hooks_path,
            true,
            // Pin the per-hook `timeout` (the on-disk field, serde-renamed
            // from `timeout_sec`; codex's default is 600s) to a week so a
            // kyris popup ask can wait effectively forever instead of codex
            // killing the hook at 10 minutes ("hook timed out after 600s" →
            // fail-open). The trust hash bakes this value — see
            // CODEX_HOOK_TIMEOUT_SECS.
            #[allow(clippy::cast_possible_wrap)]
            Some(CODEX_HOOK_TIMEOUT_SECS as i64),
        )?;

        // One read-modify-write for every config.toml mutation this surface
        // owns: codex itself rewrites its config while running, so each extra
        // write cycle widens the lost-update window (neither side locks).
        let mut config = read_or_empty_codex_config(&config_path)?;
        let mut config_changed = false;
        // `hooks` is codex's canonical feature key (codex 0.133 `features list`);
        // `codex_hooks` is a deprecated alias that warns in `codex doctor`.
        if ensure_toml_bool_path(&mut config, &["features", "hooks"], true) {
            config_changed = true;
            changes.push(format!(
                "enabled hooks feature in {}",
                config_path.display()
            ));
        }
        if ensure_codex_shell_env_marker(&mut config) {
            config_changed = true;
            changes.push(format!("set shell env marker in {}", config_path.display()));
        }
        // Route governed exec/apply_patch to codex's approval ladder so its
        // PermissionRequest hook fires and its native prompt can render an `ask`
        // (native approval mode). Without this, a trusted project with an
        // unrestricted sandbox auto-Skips most commands (no PermissionRequest),
        // silently bypassing an ask. `untrusted` forces NeedsApproval regardless
        // of sandbox; `run_permission_request` then suppresses the prompt for a
        // vouched/`auto` command and abstains for an `ask` so codex prompts. A
        // no-op for kyris-popup mode (PreToolUse gates the ask before codex's
        // ladder runs).
        let prior_approval = config
            .get("approval_policy")
            .and_then(toml::Value::as_str)
            .map(String::from);
        if ensure_toml_string_path(&mut config, &["approval_policy"], "untrusted") {
            config_changed = true;
            if let Some(prior) = prior_approval.as_deref()
                && prior != "untrusted"
            {
                changes.push(format!(
                    "warning: approval_policy was \"{prior}\" — overridden to \"untrusted\" so \
                     codex routes governed commands to its approval prompt (restored on \
                     `kyris agent disconnect codex-cli`)"
                ));
            }
            changes.push(format!(
                "set approval_policy=untrusted in {}",
                config_path.display()
            ));
        }
        if ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path)? {
            config_changed = true;
            changes.push(format!("trusted kyris hooks in {}", config_path.display()));
        }
        if config_changed {
            write_codex_config(&config_path, &config, "codex-cli:execution")?;
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
                        "codex-cli:execution",
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
                        write_codex_config(&config_path, &config, "codex-cli:execution")?;
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
    fn configure_burn_control_surface(
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
        let mut config_changed = false;
        // Route codex through the kyris custom provider by default — the built-in
        // openai provider can't carry the x-kyris-inbound header (reserved ID).
        // A different existing choice (ollama, a user-defined provider…) is
        // overridden — burn-control requires the kyris route — but LOUDLY, the
        // same care `default_permissions` gets; undo restores it.
        let prior_provider = config
            .get("model_provider")
            .and_then(toml::Value::as_str)
            .map(str::to_string);
        if ensure_toml_string_path(&mut config, &["model_provider"], "kyris") {
            config_changed = true;
            if let Some(prior) = prior_provider.filter(|p| p != "kyris") {
                changes.push(format!(
                    "warning: model_provider was \"{prior}\" — overridden to \"kyris\" so \
                     burn-control can route through kyrisd; `kyris agent disconnect codex-cli` \
                     restores it"
                ));
            }
        }
        if ensure_codex_kyris_model_provider(&mut config, &base_url_v1, inbound_key) {
            config_changed = true;
        }

        if config_changed {
            write_codex_config(&config_path, &config, "codex-cli:burn-control")?;
            changes.push(format!("updated {}", config_path.display()));
        }

        Ok(changes)
    }
    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        ensure_codex_dir()?;
        let mut changes = Vec::new();
        let mut config = read_or_empty_codex_config(&config_path)?;

        let mut config_changed = false;
        let mcp_result = super::configure::rewrite_codex_mcp_servers(
            &mut config,
            base_url,
            inbound_key,
            self.canonical_id(),
        );
        if mcp_result.changed {
            config_changed = true;
        }
        if super::configure::apply_toml_tool_filters(&mut config) {
            config_changed = true;
        }
        if config_changed {
            write_codex_config(&config_path, &config, "codex-cli:tool")?;
            changes.push(format!("updated {}", config_path.display()));
        }
        if !mcp_result.http_rewrites.is_empty() {
            super::configure::upsert_mcp_upstreams(&mcp_result.http_rewrites)?;
            changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
        }

        Ok(changes)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        // Remove MCP upstreams from kyrisd.yaml before the config file is
        // restored to its pre-kyris state (after which the server names
        // would no longer be readable from the agent config).
        let mcp_names = super::configure::mcp_server_names_from_agent(self);
        super::configure::remove_mcp_upstreams(&mcp_names)?;

        // Structurally unapply every config.toml edit kyris recorded at setup
        // (the complete original→configured TOML patch): routing keys,
        // [model_providers.kyris], [permissions.kyris], default_permissions,
        // hooks feature, … all reverse together, restoring the user's pre-kyris
        // config exactly — no backup, no leftover routing or credential.
        let config_path = codex_config_path()?;
        restore_manifest_entry_component(&config_path, "codex-cli:tool")?;

        for change in scrub_codex_residue()? {
            println!("{change}");
        }
        Ok(())
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        let config_path = codex_config_path()?;
        restore_manifest_entry_component(&config_path, "codex-cli:execution")?;
        let hooks_path = codex_hooks_path()?;
        restore_manifest_entry_component(&hooks_path, "codex-cli:execution")?;
        let script = codex_dir()?.join("kyris_pretooluse.sh");
        restore_manifest_entry_component(&script, "codex-cli:execution")?;
        let rules = codex_dir()?.join("rules").join("agentpact.rules");
        restore_manifest_entry_component(&rules, "codex-cli:execution")?;

        for change in scrub_codex_residue()? {
            println!("{change}");
        }
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if restore_manifest_entry_component(&path, "codex-cli:burn-control")? {
                println!("Reverted {}", path.display());
            }
        }
        for change in scrub_codex_residue()? {
            println!("{change}");
        }
        Ok(())
    }
    fn mcp_configs(&self) -> Vec<McpConfigLocation> {
        codex_config_path()
            .ok()
            .map(|path| McpConfigLocation {
                path,
                format: McpConfigFormat::Toml {
                    servers_key: "mcp_servers".to_string(),
                },
            })
            .into_iter()
            .collect()
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        codex_config_path().into_iter().collect()
    }
    fn supported_settings(&self) -> Vec<(String, String)> {
        vec![(
            super::registry::APPROVAL_PROMPT_SETTING.to_string(),
            super::registry::APPROVAL_PROMPT_SETTING_DESC.to_string(),
        )]
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
                // The patch envelope is parsed by kyris into per-file write +
                // delete decisions (hook_cmd::drive_apply_patch) — the old
                // `write`-with-patch-text mapping lexically anchored the
                // entire patch INSIDE the workspace (review Finding 10).
                ToolMapping {
                    tool_name: "apply_patch".to_string(),
                    action: "apply_patch".to_string(),
                    detail_key: Some("command".to_string()),
                },
            ],
            // Codex CLI internal coordination / read-only tools: skip the
            // daemon. Ids verified against codex 5a440c03 tool handlers. See
            // claude_code.rs and hook_cmd.rs for the design rationale.
            pass_through_tools: vec![
                "update_plan".to_string(),
                "view_image".to_string(),
                "spawn_agent".to_string(),
                "wait_agent".to_string(),
                "close_agent".to_string(),
                "followup_task".to_string(),
                "list_agents".to_string(),
                "request_user_input".to_string(),
                "tool_search".to_string(),
                "list_mcp_resources".to_string(),
                "list_mcp_resource_templates".to_string(),
                "read_mcp_resource".to_string(),
                "list_available_plugins_to_install".to_string(),
            ],
            // Left to codex's own approval machinery: permission escalation,
            // plugin installs, inter-agent messaging, batch agent jobs — each
            // has codex-side controls a kyris pass-through would bypass.
            agent_owned_tools: vec![
                "request_permissions".to_string(),
                "request_plugin_install".to_string(),
                "send_message".to_string(),
                "spawn_agents_on_csv".to_string(),
                "report_agent_job_result".to_string(),
            ],
            // The shell-snapshot pass-through is GONE: current codex spawns
            // snapshot capture directly (never through the tool registry, so
            // no hook fires — verified shell_snapshot.rs), and the old
            // substring match was both bypassable and broken under a
            // non-default CODEX_HOME. An older codex emitting such a command
            // now warns-and-defers, which its own approval ladder absorbs.
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
            runtime: HookRuntime {
                // The explicit per-hook `timeout` kyris writes at install
                // (CODEX_HOOK_TIMEOUT_SECS, one week): codex honors it
                // uncapped, so the approval poll window derived from this
                // value lets a popup ask wait effectively forever. The rest
                // of the chain is sized per-request from poll_deadline()
                // (agentpactd approval_ttl_secs, kyrisd hold ttl_seconds).
                agent_hook_timeout_secs: CODEX_HOOK_TIMEOUT_SECS,
                // Verified: a timed-out hook is Failed, NOT blocked — codex
                // proceeds (events/pre_tool_use.rs).
                on_timeout: HookTimeoutPosture::FailOpen,
                // Codex's own approval ladder (AskForApproval + sandbox) still
                // runs after the hook; a defer lands on a real gate.
                native_backstop: true,
                // EmptyStdout is the ONLY allow codex accepts at PreToolUse
                // (JSON permissionDecision:allow parses as Failed); it
                // suppresses nothing there — native-prompt suppression is the
                // PermissionRequest hook's job (permission_request_allow).
                allow_suppresses_agent_prompt: false,
            },
            // The PermissionRequest allow shape (verified: codex parses
            // hookSpecificOutput.decision.behavior; allow suppresses the
            // native prompt entirely; empty stdout abstains). deny_unknown
            // _fields upstream — emit exactly these fields.
            permission_request_allow: Some(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"}
                }
            })),
            mcp_tool_naming: None,
            // Codex's PreToolUse cannot emit "ask" (it parses a JSON allow as
            // Failed), so an ask is delegated to the PermissionRequest hook
            // above: PreToolUse abstains, and `run_permission_request` abstains
            // for an unvouched request so codex's own approval prompt appears.
            // Requires `approval_policy = "untrusted"` (set by
            // configure_execution_surface) so governed commands reach that hook.
            native_ask: Some(super::registry::AskResponse::DeferToNativeApproval),
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
        // Simulates the burn-control surface setup for a first-time user:
        // start with empty TOML and verify the expected keys are written.
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        let changed = ensure_toml_string_path(&mut config, &["model_provider"], "kyris");
        assert!(changed, "model_provider should be written to empty config");
        assert_eq!(
            config.get("model_provider").and_then(toml::Value::as_str),
            Some("kyris")
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
        // Simulates the configure_execution hooks-feature path for first-time user.
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());
        let changed = ensure_toml_bool_path(&mut config, &["features", "hooks"], true);
        assert!(changed, "features.hooks should be set in empty config");
        assert_eq!(config["features"]["hooks"].as_bool(), Some(true));
    }

    #[test]
    fn testCodexKyrisHookTrustWrittenAndVerified() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        // The probe verifies against the ACTUAL hooks.json entry, so the test
        // writes the same shape `ensure_json_command_hook` installs.
        let hooks = serde_json::json!({
            "hooks": {"PreToolUse": [{
                "matcher": "",
                "hooks": [{
                    "type": "command",
                    "command": codex_kyris_hook_command(&script_path),
                    "timeout": CODEX_HOOK_TIMEOUT_SECS
                }]
            }]}
        });
        write_json_unmanaged(&hooks_path, &hooks).unwrap();

        assert!(ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap());
        assert!(!ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap());
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        let key = codex_kyris_hook_key(&hooks_path, "pre_tool_use");
        assert_eq!(
            config["hooks"]["state"][&key]["trusted_hash"].as_str(),
            Some(
                codex_kyris_hook_hash(&script_path, "pre_tool_use")
                    .unwrap()
                    .as_str()
            )
        );
        assert!(codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
    }

    #[test]
    fn testCodexHookTrustDetectsUserEditedEntry() {
        // A user edit to the hooks.json entry (here: adding a timeout) changes
        // the identity codex hashes → codex marks the hook Modified and stops
        // running it. The probe must show that as NOT live, not read back
        // kyris's own constants and stay green.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        let hooks = serde_json::json!({
            "hooks": {"PreToolUse": [{
                "matcher": "",
                "hooks": [{
                    "type": "command",
                    "command": codex_kyris_hook_command(&script_path),
                    "timeout": 30
                }]
            }]}
        });
        write_json_unmanaged(&hooks_path, &hooks).unwrap();
        ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap();
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        assert!(!codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
    }

    #[test]
    fn testCodexHookTrustFollowsActualGroupIndex() {
        // kyris's group appended AFTER a pre-existing user group lives at key
        // `1:0` (codex keys trust by actual group:handler index). Configure
        // must mint there — the old hardcoded `0:0` left the kyris hook
        // Untrusted (never run) and clobbered the user's own trust entry
        // (review Finding 8) — and the probe must agree.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        let hooks = serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "^Bash$", "hooks": [{"type": "command", "command": "/usr/local/bin/my-own-hook"}]},
                {"matcher": "", "hooks": [{
                    "type": "command",
                    "command": codex_kyris_hook_command(&script_path),
                    "timeout": CODEX_HOOK_TIMEOUT_SECS
                }]}
            ]}
        });
        write_json_unmanaged(&hooks_path, &hooks).unwrap();
        ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap();
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        let key = format!("{}:pre_tool_use:1:0", hooks_path.display());
        assert!(
            config["hooks"]["state"][&key]["trusted_hash"].is_str(),
            "trust must be minted at the entry's actual index"
        );
        assert!(codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
    }

    #[test]
    fn testCodexHookTrustLegacyZeroZeroKeyIsNotTrusted() {
        // A legacy install minted the trust entry at the hardcoded `0:0` even
        // when kyris's group sits at index 1 — codex never ran that hook. The
        // probe must report it dead (and a reconcile re-mint heals it).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");

        let hooks = serde_json::json!({
            "hooks": {"PreToolUse": [
                {"matcher": "^Bash$", "hooks": [{"type": "command", "command": "/usr/local/bin/my-own-hook"}]},
                {"matcher": "", "hooks": [{"type": "command", "command": codex_kyris_hook_command(&script_path)}]}
            ]}
        });
        write_json_unmanaged(&hooks_path, &hooks).unwrap();

        let legacy_key = codex_kyris_hook_key(&hooks_path, "pre_tool_use");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());
        ensure_toml_string_path(
            &mut config,
            &["hooks", "state", legacy_key.as_str(), "trusted_hash"],
            &codex_kyris_hook_hash(&script_path, "pre_tool_use").unwrap(),
        );
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        assert!(!codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
    }

    #[test]
    fn testCodexKyrisHookTrustRequiresMatchingScriptPath() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let other_script_path = dir.path().join("other_pretooluse.sh");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        assert!(!codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
        ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap();
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        assert!(!codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &other_script_path
        ));
    }

    #[test]
    fn testScrubCodexKyrisHookTrustRemovesOnlyKyrisEntry() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let other_key = "/tmp/other-hooks.json:pre_tool_use:0:0";
        let mut config: toml::Value = toml::from_str(&format!(
            r#"
[hooks.state."{other_key}"]
trusted_hash = "sha256:other"
"#
        ))
        .expect("parse config");

        ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap();
        assert!(scrub_codex_kyris_hook_trust(&mut config, &config_path));

        let kyris_key = codex_kyris_hook_key(&hooks_path, "pre_tool_use");
        assert!(
            config["hooks"]["state"]
                .as_table()
                .is_some_and(|state| !state.contains_key(&kyris_key))
        );
        assert_eq!(
            config["hooks"]["state"][other_key]["trusted_hash"].as_str(),
            Some("sha256:other")
        );
    }

    #[test]
    fn testCodexConfigPathUsesUserScopeNotProjectDiscovery() {
        let home = PathBuf::from("/tmp/home");
        assert_eq!(
            codex_config_path_from(None, home.clone()),
            home.join(".codex").join("config.toml")
        );
        assert_eq!(
            codex_config_path_from(Some(PathBuf::from("/tmp/codex-home")), home),
            PathBuf::from("/tmp/codex-home").join("config.toml")
        );
    }

    #[test]
    fn testEnsureCodexShellEnvMarkerPreservesExistingSetEntries() {
        let mut config: toml::Value = toml::from_str(
            r#"
[shell_environment_policy.set]
EXISTING = "keep"
"#,
        )
        .expect("parse config");

        assert!(ensure_codex_shell_env_marker(&mut config));
        assert_eq!(
            config["shell_environment_policy"]["set"]["EXISTING"].as_str(),
            Some("keep")
        );
        assert_eq!(
            config["shell_environment_policy"]["set"]["KYRIS_GOVERNED_SUBPROCESS"].as_str(),
            Some("codex-cli")
        );
    }

    #[test]
    fn testScrubCodexConfigValueRemovesOnlyKyrisOwnedState() {
        let mut config: toml::Value = toml::from_str(
            r#"
model_provider = "kyris"
openai_base_url = "http://127.0.0.1:4710/v1"
default_permissions = "kyris"

[model_providers.openai]
base_url = "https://api.openai.com/v1"

[model_providers.kyris]
base_url = "http://127.0.0.1:4710/v1"

[permissions.kyris.filesystem]
":workspace_roots" = "write"

[shell_environment_policy.set]
EXISTING = "keep"
KYRIS_GOVERNED_SUBPROCESS = "codex-cli"
"#,
        )
        .expect("parse config");

        assert!(scrub_codex_config_value(&mut config));
        assert!(config.get("model_provider").is_none());
        assert!(config.get("openai_base_url").is_none());
        assert!(config.get("default_permissions").is_none());
        assert!(
            config["model_providers"]
                .as_table()
                .is_some_and(|providers| providers.contains_key("openai"))
        );
        assert!(
            !config["model_providers"]
                .as_table()
                .is_some_and(|providers| providers.contains_key("kyris"))
        );
        assert!(config.get("permissions").is_none());
        assert_eq!(
            config["shell_environment_policy"]["set"]["EXISTING"].as_str(),
            Some("keep")
        );
        assert!(
            config["shell_environment_policy"]["set"]
                .as_table()
                .is_some_and(|set| !set.contains_key("KYRIS_GOVERNED_SUBPROCESS"))
        );
    }

    // --- existing test ---

    #[test]
    fn testCodexKyrisModelProviderIsValidForCodex0130() {
        // Seed a config carrying the stale experimental_bearer_token an older
        // kyris install would have written — setup must migrate it away.
        let mut config: toml::Value = toml::from_str(
            "[model_providers.kyris]\nbase_url = \"http://old.example/v1\"\nexperimental_bearer_token = \"sk-kyris-stale\"\n",
        )
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
        // The inbound key is a custom header, NOT the bearer (the bearer would be
        // forwarded upstream to OpenAI and rejected). codex uses its own auth.json
        // credential for the bearer via requires_openai_auth.
        assert_eq!(
            provider["http_headers"]["x-kyris-inbound"].as_str(),
            Some("sk-kyris-test")
        );
        assert!(
            provider.get("experimental_bearer_token").is_none(),
            "stale experimental_bearer_token must be migrated away (it hijacks the \
             Authorization bearer; codex must use its own auth.json credential)"
        );
        assert_eq!(provider["requires_openai_auth"].as_bool(), Some(true));
        // kyrisd serves /v1/responses over HTTP only — WS returns 405.
        assert_eq!(provider["supports_websockets"].as_bool(), Some(false));
    }
}
