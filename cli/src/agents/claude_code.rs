// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use super::probe::{ProbeResult, env_routes_to_kyrisd, fingerprint, not_detected};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, HookRuntime, HookTimeoutPosture,
    McpConfigFormat, McpConfigLocation, ProviderRouting, SurfaceIntegration, ToolMapping,
    ToolMechanism,
};

pub struct ClaudeCode;

/// True iff the installed hook-launcher script at `path` matches what
/// `super::configure::hook_script_source(agent_id)` would write today.
/// Missing file or read error → `false` (drift).
fn script_matches_template(path: &std::path::Path, agent_id: &str) -> bool {
    let Ok(actual) = std::fs::read_to_string(path) else {
        return false;
    };
    actual == super::configure::hook_script_source(agent_id)
}

pub fn claude_settings_path() -> Result<PathBuf, String> {
    let home = crate::integration::home_dir()?;
    Ok(home.join(".claude").join("settings.json"))
}

/// `~/.claude.json` — Claude Code's main state/config store and the file MCP
/// servers actually live in: `mcpServers` (user scope, `claude mcp add --scope
/// user`) and `projects.<abs project dir>.mcpServers` (local scope — `claude
/// mcp add`'s DEFAULT). Verified empirically against claude 2.x: `settings.json`
/// has no `mcpServers` key and is never consulted for servers. Note this file
/// is rewritten by claude itself constantly (caches, oauth, counters) — kyris
/// fingerprints it only while kyris content is present (see `probe`).
pub fn claude_user_config_path() -> Result<PathBuf, String> {
    let home = crate::integration::home_dir()?;
    Ok(home.join(".claude.json"))
}

pub fn claude_hooks_dir() -> Result<PathBuf, String> {
    let home = crate::integration::home_dir()?;
    Ok(home.join(".claude").join("hooks"))
}

/// Detected when the `claude` binary is on PATH (installed but maybe never run)
/// OR `~/.claude/` exists (run at least once) — parity with the other agents,
/// which also treat binary-on-PATH as installed. Configuring claude creates
/// `~/.claude/` if absent, so the binary-only case is handled.
fn claude_code_detected() -> bool {
    super::registry::which_exists("claude")
        || crate::integration::home_dir().is_ok_and(|h| h.join(".claude").is_dir())
}

// Claude Code's multi-backend base-URL vars all repoint at kyrisd; the gate
// secret + agent-id ride in ANTHROPIC_CUSTOM_HEADERS (newline-separated, Claude
// Code's documented multi-header format). The agent's OWN credential —
// subscription OAuth or the user's API key — is deliberately NOT set here, so it
// flows through to the provider untouched for kyrisd to forward and classify
// included-vs-overage. The actual env is built by the trait's default
// `env_exports` from this declaration.
//
// Third-party backend posture (deliberate): the Bedrock/Vertex/Foundry/Mantle
// repoints + skip-auth flags capture those backends' traffic too, but kyrisd
// holds no provider credentials and cannot SigV4/GCP-sign — a user on those
// backends fails LOUDLY at kyrisd instead of running metered-nowhere. Loud
// breakage over silent unmetered traffic is the chosen trade; undo restores
// them. The ANTHROPIC_BASE_URL var and SKIP_BEDROCK_AUTH are upstream-verified;
// the Vertex/Foundry/Mantle var names rest on docs (harmless if wrong — an
// unread env var).
//
// Known accepted gaps: the env file the shim sources OVERRIDES a user's own
// ANTHROPIC_* env on every launch (routing must win), and a `claude` launched
// by absolute path bypasses the shim entirely (no env delivery; the probe
// cannot see launch paths).
const CLAUDE_CODE_ROUTING: ProviderRouting = ProviderRouting {
    base_url_vars: &[
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "ANTHROPIC_VERTEX_BASE_URL",
        "ANTHROPIC_FOUNDRY_BASE_URL",
        "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
    ],
    auth_skip_flags: &[
        ("CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1"),
        ("CLAUDE_CODE_SKIP_VERTEX_AUTH", "1"),
    ],
    custom_headers_var: "ANTHROPIC_CUSTOM_HEADERS",
    header_separator: "\n",
};

impl AgentDescriptor for ClaudeCode {
    fn id(&self) -> &'static str {
        "claude-code"
    }
    fn is_installed(&self) -> bool {
        claude_code_detected()
    }
    fn probe(&self) -> ProbeResult {
        use super::profile::SurfaceState;
        let detected = claude_code_detected();
        if !detected {
            return not_detected();
        }

        let settings_path = claude_settings_path().ok();
        let has_hook = settings_path.as_deref().is_some_and(|p| {
            crate::integration::read_json_value(p).is_ok_and(|v| {
                let serialized = serde_json::to_string(&v).unwrap_or_default();
                serialized.contains("agentpact_pretooluse")
            })
        });

        // Drift check: if the hook is registered in settings.json but the
        // on-disk script differs from what the current kyris would write,
        // treat the surface as not-adapted so `kyris status` flags it and
        // the user knows to re-run `kyris install` / `kyris agent setup`.
        // Without this, an older kyris version's hook script (which may have
        // emitted empty stdout, causing the double-prompt symptom) stays in
        // place silently forever.
        let hook_script_drifted = has_hook
            && claude_hooks_dir().is_ok_and(|d| {
                !script_matches_template(&d.join("agentpact_pretooluse.sh"), "claude-code")
            });
        let has_hook = has_hook && !hook_script_drifted;
        // Multi-scope: servers live in ~/.claude.json (user + per-project local
        // scopes) and project .mcp.json — see `mcp_configs`.
        let (has_mcp_wrap, has_any_mcp_servers) = super::probe::mcp_locations_status(self);

        let execution = if has_hook {
            SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(ToolMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            // No MCP servers in any scope — wrap surface is structurally
            // inert until the user adds an MCP server. Treat as N/A so the
            // agent isn't flagged "incomplete" for a non-issue.
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };
        // Value-aware: the var must point AT kyrisd, not merely exist — an
        // ANTHROPIC_BASE_URL aimed elsewhere is not kyris burn-control.
        let burn_control = if env_routes_to_kyrisd("claude-code", "ANTHROPIC_BASE_URL") {
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
        // Fingerprint the MCP store files ONLY while they carry kyris content:
        // ~/.claude.json is rewritten by claude itself on nearly every run, so
        // an unconditional fingerprint would hash-drift on every reconcile and
        // (with no kyris marker present to vouch for it) trigger an endless
        // repair loop. With a marker present, the marker check vouches for the
        // drifted hash and repair stays quiet.
        let mut seen: Vec<std::path::PathBuf> = Vec::new();
        for location in self.mcp_configs() {
            if seen.contains(&location.path) {
                continue;
            }
            seen.push(location.path.clone());
            let has_marker = std::fs::read_to_string(&location.path)
                .is_ok_and(|contents| contents.contains("kyris-mcp"));
            if has_marker && let Some(fp) = fingerprint(&location.path) {
                managed_files.push(fp);
            }
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
        &["agentpact_pretooluse", "kyris-mcp"]
    }
    fn provider_routing(&self) -> Option<ProviderRouting> {
        Some(CLAUDE_CODE_ROUTING)
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        super::capabilities::apply_declared_capabilities(
            self.canonical_id(),
            AgentIntegrationPlan {
                execution: SurfaceIntegration::adapted(&[ExecutionMechanism::LiveHookAdapter]),
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
    fn launch_dir_env(&self) -> Option<&'static str> {
        // Claude Code's PreToolUse payload `cwd` is the LIVE working directory
        // (moves with `cd`); `$CLAUDE_PROJECT_DIR` is the fixed session root and
        // is the correct permitted-domain anchor.
        Some("CLAUDE_PROJECT_DIR")
    }
    fn configure_execution_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let hooks_dir = claude_hooks_dir()?;
        let script_path = hooks_dir.join("agentpact_pretooluse.sh");
        let settings_path = claude_settings_path()?;
        super::configure::install_live_hook_adapter(
            "claude-code",
            "claude-code:execution",
            &["PreToolUse"],
            &script_path,
            &settings_path,
            true,
            // Claude's PreToolUse default is 600s, which already clears kyris's
            // ~590s no-TTY poll window — no explicit override needed.
            None,
        )
    }
    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let mut changes =
            super::configure::configure_json_mcp_tool_surface(self, base_url, inbound_key)?;

        // Supplementary deny steering: claude has no per-server denylist field,
        // so policy-blocked MCP tools become `permissions.deny` entries
        // (mcp__server__tool) in settings.json. Cross-file by nature — the
        // servers live in ~/.claude.json/.mcp.json (see mcp_configs), the deny
        // rules in settings.json — so this cannot ride the shared helper's
        // per-file `apply_extra_tool_filters` hook. Enforcement remains the
        // runtime wrap/routing; this only spares wasted round-trips.
        let present_servers = super::configure::mcp_server_names_from_agent(self);
        let settings_path = claude_settings_path()?;
        let mut settings = crate::integration::read_json_value(&settings_path)?;
        if super::configure::apply_claude_mcp_tool_denies(&mut settings, &present_servers) {
            crate::integration::write_json_value(
                &settings_path,
                &settings,
                "claude-code:tool",
                &crate::config_writer::WellFormedJsonValidator,
            )?;
            changes.push(format!(
                "applied MCP tool policy in {}",
                settings_path.display()
            ));
        }
        Ok(changes)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        // The shared manifest-driven restore reverts everything recorded under
        // `claude-code:tool` — the MCP store rewrites AND the settings.json
        // deny supplement — including `.mcp.json` files wrapped from another
        // cwd that a re-enumeration here would never find.
        super::configure::undo_json_mcp_tool_surface(self)
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        let settings_path = claude_settings_path()?;
        if crate::state::restore_manifest_entry_component(&settings_path, "claude-code:execution")?
        {
            println!("Reverted {}", settings_path.display());
        }
        let script = claude_hooks_dir()?.join("agentpact_pretooluse.sh");
        if !crate::state::restore_manifest_entry_component(&script, "claude-code:execution")? {
            super::undo::remove_file_if_exists(&script)?;
        }
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if crate::state::restore_manifest_entry_component(&path, "claude-code:burn-control")? {
                println!("Reverted {}", path.display());
            }
        }
        let env_file = crate::state::env_dir()?.join("claude-code.sh");
        super::undo::remove_file_if_exists(&env_file)?;
        Ok(())
    }
    fn mcp_configs(&self) -> Vec<McpConfigLocation> {
        // Empirically verified scopes (claude 2.x, `claude mcp add`):
        //   user    → ~/.claude.json  mcpServers
        //   local   → ~/.claude.json  projects.<canonical abs dir>.mcpServers
        //             (the DEFAULT scope — most servers land here)
        //   project → <dir>/.mcp.json mcpServers (found upward from cwd, the
        //             same cwd-anchored discovery gemini/opencode use)
        // settings.json has no mcpServers key — the pre-review integration
        // wrapped a location claude never reads.
        let mut locations = Vec::new();
        if let Ok(user_config) = claude_user_config_path() {
            locations.push(McpConfigLocation {
                path: user_config.clone(),
                format: McpConfigFormat::Json {
                    servers_path: vec!["mcpServers".to_string()],
                },
            });
            // Local scopes are dynamic keys — enumerate every project entry
            // that actually has servers, so setup wraps all of them at once
            // regardless of where it runs.
            if let Ok(val) = crate::integration::read_json_value(&user_config)
                && let Some(projects) = val.get("projects").and_then(|p| p.as_object())
            {
                for (project_dir, entry) in projects {
                    let has_servers = entry
                        .get("mcpServers")
                        .and_then(|m| m.as_object())
                        .is_some_and(|m| !m.is_empty());
                    if has_servers {
                        locations.push(McpConfigLocation {
                            path: user_config.clone(),
                            format: McpConfigFormat::Json {
                                servers_path: vec![
                                    "projects".to_string(),
                                    project_dir.clone(),
                                    "mcpServers".to_string(),
                                ],
                            },
                        });
                    }
                }
            }
        }
        if let Some(project_mcp) = crate::integration::find_upwards(".mcp.json") {
            locations.push(McpConfigLocation {
                path: project_mcp,
                format: McpConfigFormat::Json {
                    servers_path: vec!["mcpServers".to_string()],
                },
            });
        }
        locations
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        claude_settings_path().into_iter().collect()
    }
    #[allow(clippy::too_many_lines)] // a declarative table, not logic
    fn supported_settings(&self) -> &'static [(&'static str, &'static str)] {
        &[(
            super::registry::APPROVAL_PROMPT_SETTING,
            super::registry::APPROVAL_PROMPT_SETTING_DESC,
        )]
    }
    #[allow(clippy::too_many_lines)]
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string(), "input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "Bash".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "bash".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "Read".to_string(),
                    action: "read".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "Write".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "Edit".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                ToolMapping {
                    tool_name: "edit_file".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("file_path".to_string()),
                },
                // NotebookEdit WRITES files (review Finding 6) — it was wrongly
                // pass-through, which suppressed both kyris's and Claude's own
                // prompt for a file write.
                ToolMapping {
                    tool_name: "NotebookEdit".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("notebook_path".to_string()),
                },
                // Windows twin of Bash (claude runs PowerShell there); inert on
                // Unix, governed if it ever appears.
                ToolMapping {
                    tool_name: "PowerShell".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
            ],
            // LLM coordination primitives and read-only views. These have no
            // governable side effect; skip the agentpactd round-trip entirely
            // (the daemon contract for action=call requires context.mcp_server,
            // which built-ins cannot supply). In enforce mode these emit the
            // native JSON allow — suppressing Claude's own prompt — so a tool
            // belongs here ONLY when frictionless execution is the intended
            // outcome; tools with their own claude-side controls go in
            // agent_owned_tools below. New Claude built-ins not listed anywhere
            // will warn-and-defer at run time — kyris hands them to Claude's
            // own permission prompt rather than suppressing it. See hook_cmd.rs.
            pass_through_tools: vec![
                "AskUserQuestion".to_string(),
                "TodoWrite".to_string(),
                "ExitPlanMode".to_string(),
                "EnterPlanMode".to_string(),
                "Task".to_string(),
                "Agent".to_string(),
                "Glob".to_string(),
                "Grep".to_string(),
                "LSP".to_string(),
                "BashOutput".to_string(),
                "KillShell".to_string(),
                "ToolSearch".to_string(),
                "Skill".to_string(),
                "Monitor".to_string(),
                "ScheduleWakeup".to_string(),
                "TaskCreate".to_string(),
                "TaskGet".to_string(),
                "TaskList".to_string(),
                "TaskUpdate".to_string(),
                "TaskOutput".to_string(),
                "TaskStop".to_string(),
            ],
            // Known tools deliberately left to CLAUDE's own permission system —
            // suppressing its prompt would remove a real control (review:
            // WebFetch/WebSearch domain rules; SendMessage cross-session
            // targeting; SlashCommand allowed-tools grants; worktree/cron/
            // notification tools are session- or outward-facing). EmptyStdout,
            // no warning, audited as agent_owned.
            agent_owned_tools: vec![
                "WebFetch".to_string(),
                "WebSearch".to_string(),
                "SendMessage".to_string(),
                "SlashCommand".to_string(),
                "EnterWorktree".to_string(),
                "ExitWorktree".to_string(),
                "CronCreate".to_string(),
                "CronDelete".to_string(),
                "CronList".to_string(),
                "PushNotification".to_string(),
                "RemoteTrigger".to_string(),
            ],
            default_action: "call".to_string(),
            // Claude Code's PreToolUse hook treats exit-0 with empty stdout as
            // "no decision" and falls back to its own permission prompt — which
            // double-prompts after AgentPact already approved. Emitting the
            // hookSpecificOutput shape with permissionDecision=allow suppresses
            // Claude's prompt entirely.
            allow_response: AllowResponse::Json {
                body: serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": "approved by AgentPact policy"
                    }
                }),
            },
            runtime: HookRuntime {
                // Claude's PreToolUse default (raised from 60s in 2.1.3); the
                // install relies on it (no explicit per-hook timeout written).
                agent_hook_timeout_secs: 600,
                // Conservative: assume a timed-out hook does not block. kyris's
                // poll deadline returns (denying) inside the window either way.
                on_timeout: HookTimeoutPosture::FailOpen,
                // Claude's own permission ladder still gates anything kyris
                // defers (EmptyStdout), and deny rules override hook allows.
                native_backstop: true,
                // The JSON permissionDecision:allow genuinely suppresses
                // Claude's prompt (the reason this shape exists — see above).
                allow_suppresses_agent_prompt: true,
            },
            permission_request_allow: None,
            mcp_tool_naming: None,
            // Claude Code's PreToolUse hook natively supports
            // `permissionDecision: "ask"`, which forces Claude's own permission
            // prompt regardless of its settings. Single-phase, airtight: no
            // synchronous kyris hold, no 600s race.
            native_ask: Some(super::registry::AskResponse::NativePrompt {
                body: serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": "AgentPact policy requires your confirmation"
                    }
                }),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testClaudeCodeAllowEmitsHookSpecificOutput() {
        // Regression test: Claude Code's PreToolUse hook ignores exit-0 with
        // empty stdout and falls back to its own permission prompt, causing a
        // double-prompt after AgentPact already approved. The allow response
        // must use the hookSpecificOutput shape with permissionDecision=allow.
        let proto = ClaudeCode
            .hook_protocol()
            .expect("claude-code hook protocol");
        match proto.allow_response {
            AllowResponse::Json { body } => {
                let hso = body
                    .get("hookSpecificOutput")
                    .expect("hookSpecificOutput present");
                assert_eq!(
                    hso.get("hookEventName").and_then(|v| v.as_str()),
                    Some("PreToolUse")
                );
                assert_eq!(
                    hso.get("permissionDecision").and_then(|v| v.as_str()),
                    Some("allow")
                );
            }
            AllowResponse::EmptyStdout => {
                panic!(
                    "Claude Code allow must emit JSON, not empty stdout — would cause double prompt"
                );
            }
        }
    }

    #[test]
    fn testNotebookEditIsGovernedAsWrite() {
        // Review Finding 6: NotebookEdit WRITES files; as a pass-through it
        // suppressed both kyris's and Claude's own prompt for a file write.
        let proto = ClaudeCode.hook_protocol().expect("hook protocol");
        let mapping = proto
            .tool_mappings
            .iter()
            .find(|m| m.tool_name == "NotebookEdit")
            .expect("NotebookEdit must be a governed mapping");
        assert_eq!(mapping.action, "write");
        assert_eq!(mapping.detail_key.as_deref(), Some("notebook_path"));
        assert!(!proto.pass_through_tools.iter().any(|t| t == "NotebookEdit"));
    }

    #[test]
    fn testClaudeOwnedToolsKeepClaudesOwnControls() {
        // These tools have real claude-side permission controls (WebFetch
        // domain rules, SendMessage targeting, SlashCommand allowed-tools);
        // blessing them as pass-through would emit the JSON allow and suppress
        // those controls. They must be agent_owned (EmptyStdout, no warning).
        let proto = ClaudeCode.hook_protocol().expect("hook protocol");
        for tool in [
            "WebFetch",
            "WebSearch",
            "SendMessage",
            "SlashCommand",
            "EnterWorktree",
            "ExitWorktree",
            "CronCreate",
            "PushNotification",
            "RemoteTrigger",
        ] {
            assert!(
                proto.agent_owned_tools.iter().any(|t| t == tool),
                "{tool} must be agent_owned"
            );
            assert!(
                !proto.pass_through_tools.iter().any(|t| t == tool),
                "{tool} must not be pass-through (would suppress claude's prompt)"
            );
        }
    }

    #[test]
    fn testStaleToolNamesDropped() {
        // Names that never shipped (KillBash alias, ShareOnboardingGuide) must
        // not be carried — the table is verified-names-only (review Finding 18).
        let proto = ClaudeCode.hook_protocol().expect("hook protocol");
        for stale in ["KillBash", "ShareOnboardingGuide"] {
            assert!(
                !proto.pass_through_tools.iter().any(|t| t == stale)
                    && !proto.agent_owned_tools.iter().any(|t| t == stale),
                "stale name {stale} still present"
            );
        }
    }

    #[test]
    fn testScriptMatchesTemplateMatch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.sh");
        let expected = super::super::configure::hook_script_source("claude-code");
        std::fs::write(&path, &expected).unwrap();
        assert!(script_matches_template(&path, "claude-code"));
    }

    #[test]
    fn testScriptMatchesTemplateDriftDetected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.sh");
        std::fs::write(&path, "#!/bin/bash\n# stale older script\nexit 0\n").unwrap();
        assert!(!script_matches_template(&path, "claude-code"));
    }

    #[test]
    fn testScriptMatchesTemplateMissingFileIsDrift() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.sh");
        assert!(!script_matches_template(&path, "claude-code"));
    }

    #[test]
    fn testClaudeCodeExportsMultiBackend() {
        let exports = ClaudeCode.env_exports("http://127.0.0.1:4710", "sk-test");
        let keys: Vec<&str> = exports.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"ANTHROPIC_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_BEDROCK_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_VERTEX_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_FOUNDRY_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_BEDROCK_MANTLE_BASE_URL"));
        assert!(keys.contains(&"CLAUDE_CODE_SKIP_BEDROCK_AUTH"));
        assert!(keys.contains(&"CLAUDE_CODE_SKIP_VERTEX_AUTH"));
        // The gate secret rides in a custom header; the agent's own credential
        // is left untouched (no forced ANTHROPIC_API_KEY/AUTH_TOKEN).
        assert!(keys.contains(&"ANTHROPIC_CUSTOM_HEADERS"));
        assert!(!keys.contains(&"ANTHROPIC_API_KEY"));
        assert!(!keys.contains(&"ANTHROPIC_AUTH_TOKEN"));
        let custom = exports
            .iter()
            .find(|(k, _)| k == "ANTHROPIC_CUSTOM_HEADERS")
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            custom,
            "x-kyris-inbound: sk-test\nx-kyris-agent-id: anthropic/claude-code"
        );
    }
}
