// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{read_json_value, set_json_string_path, write_json_value};

use super::probe::{ProbeResult, env_routes_to_kyrisd, fingerprint, not_detected};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, HookRuntime, HookTimeoutPosture,
    McpConfigFormat, McpConfigLocation, ProviderRouting, SurfaceIntegration, ToolMapping,
    ToolMechanism, which_exists,
};

// KNOWN COVERAGE GAP (review Finding 14, accepted): gemini skips ALL
// settings-sourced hooks — including user-scope ones — in folders the user has
// not trusted (`hookRegistry` registers everything as Project source and gates
// on `isTrustedFolder()`); trust lives in `~/.gemini/trustedFolders.json` with
// env/IDE/setting overrides. In an untrusted folder kyris execution governance
// silently does not fire; gemini's own restrictions still apply, and the
// compiled policy file (loaded through the policy engine, not the hook system)
// keeps its allow/deny rules active. Detection was considered and rejected:
// the trust verdict depends on runtime state kyris cannot fully see
// (GEMINI_CLI_TRUST_WORKSPACE, IDE-provided trust, security.folderTrust), so a
// half-right "untrusted here" probe would mislead more than it informs.
pub struct GeminiCli;

/// `~/.gemini/settings.json` — the USER-scope settings file, the target of
/// every kyris write. Gemini merges user then workspace settings (workspace
/// wins per key; hooks arrays CONCAT with name:command dedupe), so a hook
/// registered here fires in every project — the old behavior of writing to an
/// upward-found WORKSPACE file made governance exist only in that one project,
/// produced gemini's project-hooks trust warning, and made undo cwd-dependent.
pub fn gemini_settings_path() -> Result<PathBuf, String> {
    Ok(crate::integration::home_dir()?
        .join(".gemini")
        .join("settings.json"))
}

/// A workspace `.gemini/settings.json` found upward from the cwd, when it is
/// not the user file. Read-mostly: a second MCP location to wrap, and the
/// target of the migration that removes hooks older kyris versions wrote there.
fn gemini_workspace_settings_path() -> Option<PathBuf> {
    let user = gemini_settings_path().ok()?;
    let workspace = crate::integration::find_upwards(".gemini/settings.json")?;
    (workspace != user).then_some(workspace)
}

pub fn gemini_settings_exists() -> bool {
    gemini_settings_path().is_ok_and(|path| path.exists())
        || gemini_workspace_settings_path().is_some_and(|path| path.exists())
}

pub fn gemini_policies_dir() -> Result<PathBuf, String> {
    Ok(crate::integration::home_dir()?
        .join(".gemini")
        .join("policies"))
}

/// The single compiled-policy file kyris writes — one source for the write,
/// probe, and undo paths so they cannot drift.
fn gemini_policy_file() -> Result<PathBuf, String> {
    Ok(gemini_policies_dir()?.join("agentpact.toml"))
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

/// The hook `timeout` value (milliseconds) the install writes, derived from the
/// declared [`HookRuntime`] deadline so install pin and poll window cannot
/// drift apart.
fn gemini_hook_timeout_ms() -> Result<i64, String> {
    let proto = GeminiCli
        .hook_protocol()
        .ok_or_else(|| "gemini-cli declares no hook protocol".to_string())?;
    i64::try_from(proto.runtime.agent_hook_timeout_secs * 1000)
        .map_err(|_| "gemini hook timeout overflows milliseconds".to_string())
}

/// Auth types whose traffic honors `GOOGLE_GEMINI_BASE_URL` (the kyrisd
/// route). OAuth (`oauth-personal`) and Compute ADC take the Code Assist
/// branch, which never consults the base URL.
const ROUTABLE_AUTH_TYPES: &[&str] = &["gemini-api-key", "vertex-ai", "gateway"];

fn gemini_selected_auth_type(settings: &serde_json::Value) -> Option<&str> {
    settings
        .get("security")
        .and_then(|s| s.get("auth"))
        .and_then(|a| a.get("selectedType"))
        .and_then(serde_json::Value::as_str)
}

/// Whether the user has a usable Gemini API key that the `gemini-api-key`
/// auth path would resolve (its order: `GEMINI_API_KEY` env, then the stored
/// key — macOS keychain service `gemini-cli-api-key` / account
/// `default-api-key`, with a `~/.gemini/gemini-credentials.json` file
/// fallback). Forcing the API-key auth path WITHOUT a key would dump the user
/// into gemini's key-entry dialog on every start (and hard-fail headless runs)
/// — the Finding-13 breakage — so the auth switch is gated on this.
fn gemini_api_key_available() -> bool {
    if std::env::var("GEMINI_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
        return true;
    }
    if crate::integration::home_dir()
        .is_ok_and(|h| h.join(".gemini").join("gemini-credentials.json").exists())
    {
        return true;
    }
    // Keychain metadata lookup (no secret read, so no ACL prompt). Failure of
    // any kind — non-macOS, no `security`, no entry — just means "not found".
    std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "gemini-cli-api-key",
            "-a",
            "default-api-key",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Gemini OAuth (Code Assist) ignores `GOOGLE_GEMINI_BASE_URL`, so an OAuth or
/// unset auth selection bypasses kyrisd entirely. Switch ONLY a non-routable
/// selection to the API-key path; an already-routable one
/// (`gemini-api-key` / `vertex-ai` / `gateway`) is left untouched so a user who
/// has deliberately chosen Vertex/gateway keeps it. The caller gates this on
/// [`gemini_api_key_available`]. Returns whether `settings` changed.
fn ensure_gemini_routable_auth_type(settings: &mut serde_json::Value) -> bool {
    if gemini_selected_auth_type(settings).is_some_and(|t| ROUTABLE_AUTH_TYPES.contains(&t)) {
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
        // The hook is registered user-level now, but a PRE-placement-fix
        // install may have it only in the workspace file — and gemini CONCATs
        // hooks from both, so it really fires. Check both scopes so status is
        // accurate (the next setup migrates it to the user file).
        let hook_in = |p: &std::path::Path| {
            crate::integration::read_json_value(p).is_ok_and(|v| {
                serde_json::to_string(&v)
                    .unwrap_or_default()
                    .contains("agentpact_beforetool")
            })
        };
        let has_hook = settings_path.as_deref().is_some_and(hook_in)
            || gemini_workspace_settings_path().is_some_and(|p| hook_in(&p));
        let (has_mcp_wrap, has_any_mcp_servers) = super::probe::mcp_locations_status(self);

        // Semantic, not existence: the file must contain rules gemini's loader
        // would actually accept ([[rule]], lowercase decisions, required
        // integer priority). A file that loads zero rules is a dead artifact,
        // not an adapted surface — the serializer now emits the real contract
        // (Finding 5 fixed), and this keeps the probe honest if it ever drifts.
        let has_compiled_policy = gemini_policy_file()
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .is_some_and(|contents| {
                crate::compile_policy::gemini_policy_file_is_loadable(&contents)
            });

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
        // Value-aware AND auth-aware: the var must point AT kyrisd, and the
        // EFFECTIVE auth selection (workspace settings win over user) must be
        // one that honors the base URL — an OAuth/Code-Assist session ignores
        // it entirely, so reporting burn-control adapted there would be the
        // exact over-claim the review flagged (Finding 13).
        let effective_auth_routable = {
            let user_selected = settings_path
                .as_deref()
                .and_then(|p| crate::integration::read_json_value(p).ok())
                .and_then(|v| gemini_selected_auth_type(&v).map(str::to_string));
            let workspace_selected = gemini_workspace_settings_path()
                .and_then(|p| crate::integration::read_json_value(&p).ok())
                .and_then(|v| gemini_selected_auth_type(&v).map(str::to_string));
            workspace_selected
                .or(user_selected)
                .is_some_and(|t| ROUTABLE_AUTH_TYPES.contains(&t.as_str()))
        };
        let burn_control = if effective_auth_routable
            && env_routes_to_kyrisd("gemini-cli", "GOOGLE_GEMINI_BASE_URL")
        {
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
        if let Some(fp) = gemini_policy_file().ok().and_then(|p| fingerprint(&p)) {
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
        &[
            (
                "maxSessionTurns",
                "Max agent turns per session (writes model.maxSessionTurns to settings.json; \
                 0 or below means unlimited)",
            ),
            (
                super::registry::APPROVAL_PROMPT_SETTING,
                super::registry::APPROVAL_PROMPT_SETTING_DESC,
            ),
        ]
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
            &["BeforeTool"],
            &script_path,
            &settings_path,
            // Gemini 0.41 requires the NESTED hook shape — `BeforeTool: [{ hooks:
            // [{ type, command }] }]` — and silently DISCARDS the flat
            // `{ type, command }` form ("Discarding invalid hook definition for
            // BeforeTool"), so governance never fires. Must be nested (like codex).
            true,
            // Gemini's default hook timeout is 60s — below kyris's no-TTY poll
            // window — so it would kill the hook mid-wait. Pin it (in ms) to the
            // deadline declared in this agent's HookRuntime, the single source
            // the poll window is also derived from.
            Some(gemini_hook_timeout_ms()?),
        )?;

        match crate::compile_policy::compile_gemini_permissions(None) {
            Ok((rules, _)) => {
                let has_rules = rules.as_array().is_some_and(|a| !a.is_empty());
                if has_rules {
                    let toml_content = crate::compile_policy::serialize_gemini_policy_toml(&rules);
                    let policy_path = gemini_policy_file()?;
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

        // Migration: older kyris versions registered the hook in an
        // upward-found WORKSPACE settings file. Gemini CONCATs user+workspace
        // hooks (deduped by command), so the leftover is redundant — and it
        // keeps triggering gemini's project-hooks trust warning banner. Remove
        // it; the managed write makes undo restore the workspace file too.
        if let Some(workspace) = gemini_workspace_settings_path()
            && workspace.exists()
        {
            let mut workspace_settings = read_json_value(&workspace)?;
            if crate::integration::remove_json_command_hook(
                &mut workspace_settings,
                "BeforeTool",
                "agentpact_beforetool",
            ) {
                write_json_value(
                    &workspace,
                    &workspace_settings,
                    "gemini-cli:execution",
                    &WellFormedJsonValidator,
                )?;
                changes.push(format!(
                    "moved kyris hook out of workspace settings {} (now user-level)",
                    workspace.display()
                ));
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

        // Force a kyrisd-routable auth type — but ONLY when a usable API key
        // exists for the forced path to resolve. Forcing `gemini-api-key` on a
        // key-less OAuth user broke them at startup (key-entry dialog / fatal
        // headless exit) and reconcile kept flipping the selection back — the
        // Finding-13 tug-of-war. Without a key, the gap is INDICATED instead:
        // routing stays inert and the probe reports burn-control off.
        let routable =
            gemini_selected_auth_type(&settings).is_some_and(|t| ROUTABLE_AUTH_TYPES.contains(&t));
        if !routable {
            if gemini_api_key_available() {
                if ensure_gemini_routable_auth_type(&mut settings) {
                    settings_changed = true;
                    changes.push(format!(
                        "set security.auth.selectedType = \"gemini-api-key\" in {} \
                         (prior selection could not route through kyrisd)",
                        settings_path.display()
                    ));
                }
            } else {
                changes.push(
                    "warning: gemini is using OAuth/Code Assist and no GEMINI_API_KEY is \
                     available — kyris cannot meter that traffic (the base-URL redirect is \
                     ignored on the OAuth path). Provide a GEMINI_API_KEY and re-run \
                     `kyris agents setup gemini-cli` to enable burn-control."
                        .to_string(),
                );
            }
        }

        if let Some(val) = agent_specific.get("maxSessionTurns") {
            // Loud on a bad value rather than silently skipping it.
            let n: u64 = val.parse().map_err(|_| {
                format!("maxSessionTurns must be a non-negative integer, got '{val}'")
            })?;
            // Gemini reads the NESTED `model.maxSessionTurns` (a top-level key
            // is silently ignored — its root schema is passthrough). Fail loud
            // rather than let set_json_value_path replace a non-object `model`
            // (e.g. a hand-edited `"model": "<name>"`) and drop the user's
            // model selection.
            if settings
                .get("model")
                .is_some_and(|m| !m.is_object() && !m.is_null())
            {
                return Err(format!(
                    "cannot set maxSessionTurns: {} has a non-object `model` value; \
                     fix it to an object first",
                    settings_path.display()
                ));
            }
            crate::integration::set_json_value_path(
                &mut settings,
                &["model", "maxSessionTurns"],
                serde_json::json!(n),
            );
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
        // Manifest-driven: setup may have recorded edits in files an undo run
        // from another cwd would never re-derive (a migrated workspace
        // settings file, a pre-placement-fix install's project file).
        for path in crate::state::restore_manifest_component("gemini-cli:execution")? {
            println!("Reverted {}", path.display());
        }
        // Unrecorded leftovers (older installs): remove outright.
        let script = gemini_settings_path()?
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("hooks")
            .join("agentpact_beforetool.sh");
        super::undo::remove_file_if_exists(&script)?;
        super::undo::remove_file_if_exists(&gemini_policy_file()?)?;
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in crate::state::restore_manifest_component("gemini-cli:burn-control")? {
            println!("Reverted {}", path.display());
        }
        let env_file = crate::state::env_dir()?.join("gemini-cli.sh");
        super::undo::remove_file_if_exists(&env_file)?;
        Ok(())
    }
    fn mcp_configs(&self) -> Vec<McpConfigLocation> {
        // User-scope settings plus a workspace settings file when one is in
        // scope: gemini SHALLOW-merges `mcpServers` from both (workspace wins
        // per name), so servers in either file are live and must be wrapped.
        let json_location = |path: PathBuf| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcpServers".to_string()],
            },
        };
        let mut locations: Vec<McpConfigLocation> = gemini_settings_path()
            .ok()
            .map(json_location)
            .into_iter()
            .collect();
        if let Some(workspace) = gemini_workspace_settings_path() {
            locations.push(json_location(workspace));
        }
        locations
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
            // Gemini CLI read-only / internal coordination tools: skip the
            // daemon. Ids verified against gemini 0567b25a2 (base-declarations
            // + registration); the old list carried `google_search` (real id
            // `google_web_search`) and the removed `save_memory`, so those
            // calls warned-and-deferred on every use. `search_file_content`
            // stays as the still-working legacy alias of `grep_search`.
            // See claude_code.rs and hook_cmd.rs for the design rationale.
            pass_through_tools: vec![
                "glob".to_string(),
                "grep_search".to_string(),
                "search_file_content".to_string(),
                "list_directory".to_string(),
                "google_web_search".to_string(),
                "update_topic".to_string(),
                "read_mcp_resource".to_string(),
                "list_mcp_resources".to_string(),
                "tracker_create_task".to_string(),
                "tracker_update_task".to_string(),
                "tracker_get_task".to_string(),
                "tracker_list_tasks".to_string(),
                "tracker_add_dependency".to_string(),
                "tracker_visualize".to_string(),
                "write_todos".to_string(),
                "list_background_processes".to_string(),
                "read_background_output".to_string(),
                "invoke_agent".to_string(),
                "complete_task".to_string(),
                "get_internal_docs".to_string(),
            ],
            // Left to gemini's own policy/confirmation machinery — each has a
            // native gate worth preserving: web_fetch's dedicated URL-listing
            // confirm dialog, activate_skill's ask rule, read_many_files'
            // default ask (multi-glob reads kyris cannot yet govern per path),
            // ask_user's forced-ask, and the plan-mode entry/exit matrix.
            agent_owned_tools: vec![
                "web_fetch".to_string(),
                "activate_skill".to_string(),
                "read_many_files".to_string(),
                "ask_user".to_string(),
                "enter_plan_mode".to_string(),
                "exit_plan_mode".to_string(),
            ],
            default_action: "call".to_string(),
            allow_response: AllowResponse::Json {
                body: serde_json::json!({"decision": "allow"}),
            },
            runtime: HookRuntime {
                // Gemini's default is 60s — BELOW the approval window — so the
                // install pins the hook's `timeout` to this value (in ms; see
                // configure_execution_surface, which derives from here).
                agent_hook_timeout_secs: 600,
                // Conservative: assume a killed hook does not block the tool.
                on_timeout: HookTimeoutPosture::FailOpen,
                // Gemini's policy engine + confirmation flow still gate
                // anything kyris defers.
                native_backstop: true,
                // VERIFIED NOT to suppress: gemini parses `{"decision":
                // "allow"}` but its scheduler only consumes block/ask/modify —
                // the native confirmation still runs after a kyris allow
                // (hook-utils.ts / scheduler.ts). The JSON shape is kept for
                // forward compatibility, but the audit must not claim the
                // prompt was suppressed.
                allow_suppresses_agent_prompt: false,
            },
            permission_request_allow: None,
            mcp_tool_naming: None,
            // Gemini's scheduler consumes a hook `decision` of block/ask/modify
            // (hook-utils.ts / scheduler.ts): `{"decision": "ask"}` routes to
            // ASK_USER and shows gemini's native confirmation. (Bypassed only by
            // `--yolo`, which is a non-interactive flag.)
            native_ask: Some(super::registry::AskResponse::NativePrompt {
                body: serde_json::json!({
                    "decision": "ask",
                    "reason": "AgentPact policy requires your confirmation"
                }),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testWorkspaceHookMigrationRemovesOnlyKyrisEntry() {
        // The migration (configure_execution_surface) strips a legacy kyris
        // hook from a workspace settings file via remove_json_command_hook,
        // which must handle gemini's NESTED matcher-group shape and leave a
        // user's own BeforeTool hook intact.
        let mut workspace = serde_json::json!({
            "hooks": {
                "BeforeTool": [
                    {"matcher": "", "hooks": [
                        {"type": "command", "command": "bash /old/agentpact_beforetool.sh"}
                    ]},
                    {"matcher": "Edit", "hooks": [
                        {"type": "command", "command": "bash ~/my-own-hook.sh"}
                    ]}
                ]
            }
        });
        let removed = crate::integration::remove_json_command_hook(
            &mut workspace,
            "BeforeTool",
            "agentpact_beforetool",
        );
        assert!(removed);
        let groups = workspace["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(groups.len(), 1, "only the kyris group is removed");
        assert!(
            serde_json::to_string(&groups[0])
                .unwrap()
                .contains("my-own-hook"),
            "the user's own hook survives"
        );
    }

    #[test]
    fn testMaxSessionTurnsWritesNestedKeyPreservingSiblings() {
        // Finding 11: gemini reads model.maxSessionTurns (nested); a sibling
        // model setting must be preserved, not clobbered.
        let mut settings = serde_json::json!({"model": {"name": "gemini-3-pro"}});
        crate::integration::set_json_value_path(
            &mut settings,
            &["model", "maxSessionTurns"],
            serde_json::json!(100),
        );
        assert_eq!(settings["model"]["maxSessionTurns"], 100);
        assert_eq!(settings["model"]["name"], "gemini-3-pro");
    }

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
    fn testGeminiToolTableUsesVerifiedIds() {
        // Review Finding 18 (gemini slice): the old table carried
        // `google_search` (real id google_web_search) and the removed
        // `save_memory`; tools with native gates must be agent_owned, not
        // prompt-suppressing pass-throughs.
        let proto = GeminiCli.hook_protocol().expect("hook protocol");
        for stale in ["google_search", "save_memory"] {
            assert!(
                !proto.pass_through_tools.iter().any(|t| t == stale)
                    && !proto.agent_owned_tools.iter().any(|t| t == stale),
                "stale name {stale} still present"
            );
        }
        for current in ["grep_search", "google_web_search", "write_todos"] {
            assert!(
                proto.pass_through_tools.iter().any(|t| t == current),
                "{current} must be pass-through"
            );
        }
        for owned in ["web_fetch", "read_many_files", "activate_skill", "ask_user"] {
            assert!(
                proto.agent_owned_tools.iter().any(|t| t == owned),
                "{owned} must be agent_owned (native gate preserved)"
            );
        }
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
