// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::WellFormedJsonValidator;
use crate::integration::{read_json_value, write_json_value};

use super::probe::{
    ProbeResult, env_file_has_var, env_loader_sourced, fingerprint, json_has_any_mcp_servers,
    json_has_mcp_wrap, not_detected,
};
use super::registry::{
    AgentDescriptor, AllowResponse, HookProtocol, McpConfigFormat, McpConfigLocation, ToolMapping,
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

fn claude_code_env_exports(base_url: &str, inbound_key: &str) -> Vec<(String, String)> {
    vec![
        ("ANTHROPIC_BASE_URL".to_string(), base_url.to_string()),
        ("ANTHROPIC_API_KEY".to_string(), inbound_key.to_string()),
        ("ANTHROPIC_AUTH_TOKEN".to_string(), inbound_key.to_string()),
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
        crate::integration::home_dir().is_ok_and(|h| h.join(".claude").is_dir())
    }
    fn probe(&self) -> ProbeResult {
        use super::profile::{AdaptedMechanism, SurfaceState};
        let detected = crate::integration::home_dir().is_ok_and(|h| h.join(".claude").is_dir());
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
            SurfaceState::adapted(AdaptedMechanism::LiveHook)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(AdaptedMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            // Nothing in settings.json to wrap — wrap surface is structurally
            // inert until the user adds an MCP server. Treat as N/A so the
            // agent isn't flagged "incomplete" for a non-issue.
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };
        let has_env_file = env_file_has_var("claude-code", "ANTHROPIC_BASE_URL");
        let burn_control = if has_env_file && env_loader_sourced() {
            SurfaceState::adapted(AdaptedMechanism::EnvVarProxy)
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
        claude_code_env_exports(base_url, inbound_key)
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
        let hooks_dir = claude_hooks_dir()?;
        let script_path = hooks_dir.join("agentpact_pretooluse.sh");
        let settings_path = claude_settings_path()?;
        super::configure::install_live_hook_adapter(
            "claude-code",
            "claude-code",
            "PreToolUse",
            &script_path,
            &settings_path,
            true,
        )
    }
    fn configure_burn_control(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let settings_path = claude_settings_path()?;
        let mut changes = Vec::new();
        if settings_path.exists() {
            let mut settings = read_json_value(&settings_path)?;
            let mcp_result = super::configure::rewrite_json_mcp_servers(
                &mut settings,
                &["mcpServers"],
                base_url,
                inbound_key,
            );
            if mcp_result.changed {
                write_json_value(
                    &settings_path,
                    &settings,
                    "claude-code",
                    &WellFormedJsonValidator,
                )?;
                changes.push(format!(
                    "rewrote MCP servers in {}",
                    settings_path.display()
                ));
            }
            if !mcp_result.http_rewrites.is_empty() {
                super::configure::upsert_mcp_upstreams(&mcp_result.http_rewrites)?;
                changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
            }
        }
        Ok(changes)
    }
    fn undo(&self) -> Result<(), String> {
        // Remove MCP upstreams before restoring settings.json to its
        // pre-kyris state (server names become unreadable after restore).
        let mcp_names = super::configure::mcp_server_names_from_agent(self);
        super::configure::remove_mcp_upstreams(&mcp_names)?;

        let settings_path = claude_settings_path()?;
        if crate::state::restore_manifest_entry(&settings_path)? {
            println!("Reverted {}", settings_path.display());
        }
        let script = claude_hooks_dir()?.join("agentpact_pretooluse.sh");
        super::undo::remove_file_if_exists(&script)?;
        Ok(())
    }
    fn undo_burn_control(&self) -> Result<(), String> {
        // MCP cleanup is handled in undo(); undo_burn_control handles
        // the remaining burn-control artifacts.
        for path in self.burn_control_config_paths() {
            if crate::state::restore_manifest_entry(&path)? {
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
        let exports = claude_code_env_exports("http://127.0.0.1:4710", "sk-test");
        let keys: Vec<&str> = exports.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"ANTHROPIC_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_BEDROCK_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_VERTEX_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_FOUNDRY_BASE_URL"));
        assert!(keys.contains(&"ANTHROPIC_BEDROCK_MANTLE_BASE_URL"));
        assert!(keys.contains(&"CLAUDE_CODE_SKIP_BEDROCK_AUTH"));
        assert!(keys.contains(&"CLAUDE_CODE_SKIP_VERTEX_AUTH"));
        assert!(keys.contains(&"ANTHROPIC_AUTH_TOKEN"));
    }
}
