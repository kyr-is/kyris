// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use super::probe::{
    ProbeResult, env_reaches_agent, fingerprint, json_has_any_mcp_servers, json_has_mcp_wrap,
    not_detected,
};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, McpConfigFormat, McpConfigLocation,
    SurfaceIntegration, ToolMapping, ToolMechanism,
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

fn claude_code_env_exports(
    base_url: &str,
    inbound_key: &str,
    agent_id: &str,
) -> Vec<(String, String)> {
    vec![
        ("ANTHROPIC_BASE_URL".to_string(), base_url.to_string()),
        // Deliver the kyrisd gate secret in a dedicated header (parsed by Claude
        // Code's ANTHROPIC_CUSTOM_HEADERS) so the agent's OWN credential —
        // subscription OAuth or the user's API key — flows through to the
        // provider untouched. That lets kyrisd forward it and classify usage as
        // included (subscription/burn-only) vs overage (API key). We deliberately
        // do NOT set ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN, which would override
        // the subscription OAuth.
        (
            "ANTHROPIC_CUSTOM_HEADERS".to_string(),
            // Two newline-separated headers (Claude Code's documented format for
            // multiple): the kyrisd gate secret, and the agent id so kyrisd can
            // attribute the model-call burn to this agent on the gateway record.
            format!("x-kyris-inbound: {inbound_key}\nx-kyris-agent-id: {agent_id}"),
        ),
        (
            "ANTHROPIC_BEDROCK_BASE_URL".to_string(),
            base_url.to_string(),
        ),
        ("CLAUDE_CODE_SKIP_BEDROCK_AUTH".to_string(), "1".to_string()),
        (
            "ANTHROPIC_VERTEX_BASE_URL".to_string(),
            base_url.to_string(),
        ),
        ("CLAUDE_CODE_SKIP_VERTEX_AUTH".to_string(), "1".to_string()),
        (
            "ANTHROPIC_FOUNDRY_BASE_URL".to_string(),
            base_url.to_string(),
        ),
        (
            "ANTHROPIC_BEDROCK_MANTLE_BASE_URL".to_string(),
            base_url.to_string(),
        ),
    ]
}

impl AgentDescriptor for ClaudeCode {
    fn id(&self) -> &'static str {
        "claude-code"
    }
    fn display_name(&self) -> &'static str {
        "Claude Code"
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
        // the user knows to re-run `kyris install` / `kyris agents reconcile`.
        // Without this, an older kyris version's hook script (which may have
        // emitted empty stdout, causing the double-prompt symptom) stays in
        // place silently forever.
        let hook_script_drifted = has_hook
            && claude_hooks_dir().is_ok_and(|d| {
                !script_matches_template(&d.join("agentpact_pretooluse.sh"), "claude-code")
            });
        let has_hook = has_hook && !hook_script_drifted;
        let has_mcp_wrap = settings_path
            .as_deref()
            .is_some_and(|p| json_has_mcp_wrap(p, "mcpServers"));
        let has_any_mcp_servers = settings_path
            .as_deref()
            .is_some_and(|p| json_has_any_mcp_servers(p, "mcpServers"));

        let execution = if has_hook {
            SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(ToolMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            // Nothing in settings.json to wrap — wrap surface is structurally
            // inert until the user adds an MCP server. Treat as N/A so the
            // agent isn't flagged "incomplete" for a non-issue.
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };
        let burn_control = if env_reaches_agent("claude-code", "ANTHROPIC_BASE_URL") {
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
    fn env_exports(&self, base_url: &str, inbound_key: &str) -> Vec<(String, String)> {
        claude_code_env_exports(base_url, inbound_key, self.canonical_id())
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
            "PreToolUse",
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
        super::configure::configure_json_mcp_tool_surface(self, base_url, inbound_key)
    }
    fn apply_extra_tool_filters(&self, settings: &mut serde_json::Value) -> bool {
        // Claude has no per-server denylist field, so deny policy-blocked MCP
        // tools via `permissions.deny` (mcp__server__tool). Supplementary to the
        // runtime wrap/routing — see configure.rs.
        super::configure::apply_claude_mcp_tool_denies(settings)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
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
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        claude_settings_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Json {
                servers_path: vec!["mcpServers"],
            },
        })
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        claude_settings_path().into_iter().collect()
    }
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
            ],
            // LLM coordination primitives and read-only views. These have no
            // governable side effect; skip the agentpactd round-trip entirely
            // (the daemon contract for action=call requires context.mcp_server,
            // which built-ins cannot supply). New Claude built-ins not listed
            // here will warn-and-defer at run time — kyris hands them to
            // Claude's own permission prompt rather than suppressing it. See
            // hook_cmd.rs.
            pass_through_tools: vec![
                "AskUserQuestion".to_string(),
                "TodoWrite".to_string(),
                "ExitPlanMode".to_string(),
                "EnterPlanMode".to_string(),
                "Task".to_string(),
                "Agent".to_string(),
                "Glob".to_string(),
                "Grep".to_string(),
                "NotebookEdit".to_string(),
                "BashOutput".to_string(),
                "KillShell".to_string(),
                "KillBash".to_string(),
                "ToolSearch".to_string(),
                "Skill".to_string(),
                "Monitor".to_string(),
                "ScheduleWakeup".to_string(),
                "WebFetch".to_string(),
                "WebSearch".to_string(),
                "ShareOnboardingGuide".to_string(),
            ],
            detail_pass_throughs: Vec::new(),
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
        let exports =
            claude_code_env_exports("http://127.0.0.1:4710", "sk-test", "anthropic/claude-code");
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
