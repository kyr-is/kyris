// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::probe::ProbeResult;

pub trait AgentDescriptor {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn is_installed(&self) -> bool;
    fn probe(&self) -> ProbeResult;
    fn kyris_content_markers(&self) -> &'static [&'static str];
    fn env_exports(&self, base_url: &str, inbound_key: &str) -> Vec<(String, String)>;
    fn expected_surfaces(&self) -> (bool, bool, bool);
    fn configure_execution(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn configure_burn_control(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn undo(&self) -> Result<(), String>;
    fn undo_burn_control(&self) -> Result<(), String> {
        Ok(())
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        None
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        None
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub enum McpConfigFormat {
    Json { servers_path: Vec<&'static str> },
    Toml { servers_key: &'static str },
}

#[derive(Debug, Clone)]
pub struct McpConfigLocation {
    pub path: std::path::PathBuf,
    pub format: McpConfigFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMapping {
    pub tool_name: String,
    pub action: String,
    pub detail_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookProtocol {
    pub tool_name_field: String,
    pub detail_fields: Vec<String>,
    /// Tools that route through `agentpactd` for policy enforcement
    /// (Bash → execute, Read → read, MCP servers → call, …).
    pub tool_mappings: Vec<ToolMapping>,
    /// Tools that are allowed without contacting `agentpactd` — LLM
    /// coordination primitives with no governable side effect
    /// (`AskUserQuestion`, `TodoWrite`, `ExitPlanMode`, etc.). Skipping the
    /// daemon is required because the daemon contract for `action=call`
    /// demands `context.mcp_server`, which these tools cannot supply.
    /// Unmapped tools not in this list emit a stderr warning and are
    /// allowed (fail-open) so a new agent built-in doesn't lock the user out.
    pub pass_through_tools: Vec<String>,
    pub default_action: String,
    pub allow_response: AllowResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowResponse {
    EmptyStdout,
    Json { body: serde_json::Value },
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum PrimaryProvider {
    OpenAI,
    Google,
}

pub fn provider_env_exports(
    provider: PrimaryProvider,
    base_url: &str,
    inbound_key: &str,
) -> Vec<(String, String)> {
    match provider {
        PrimaryProvider::OpenAI => vec![
            ("OPENAI_BASE_URL".to_string(), format!("{base_url}/v1")),
            ("OPENAI_API_KEY".to_string(), inbound_key.to_string()),
        ],
        PrimaryProvider::Google => vec![
            ("GOOGLE_GEMINI_BASE_URL".to_string(), base_url.to_string()),
            ("GEMINI_API_KEY".to_string(), inbound_key.to_string()),
            (
                "GEMINI_API_KEY_AUTH_MECHANISM".to_string(),
                "bearer".to_string(),
            ),
        ],
    }
}

pub fn which_exists(cmd: &str) -> bool {
    crate::state::find_in_path(cmd).is_some()
}

macro_rules! agent_registry {
    ($($id:literal => $mod:ident::$ty:ident),* $(,)?) => {
        pub fn all_agents() -> Vec<Box<dyn AgentDescriptor>> {
            vec![$(Box::new(super::$mod::$ty)),*]
        }
        pub fn agent_by_id(id: &str) -> Option<Box<dyn AgentDescriptor>> {
            match id {
                $($id => Some(Box::new(super::$mod::$ty)),)*
                _ => None,
            }
        }
    };
}

agent_registry! {
    "claude-code"  => claude_code::ClaudeCode,
    "codex-cli"    => codex_cli::CodexCli,
    "gemini-cli"   => gemini_cli::GeminiCli,
    "cline"        => cline::Cline,
    "opencode"     => opencode::OpenCode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testAllAgentsReturnsFive() {
        assert_eq!(all_agents().len(), 5);
    }

    #[test]
    fn testAgentByIdKnown() {
        assert!(agent_by_id("claude-code").is_some());
        assert!(agent_by_id("codex-cli").is_some());
        assert!(agent_by_id("gemini-cli").is_some());
        assert!(agent_by_id("cline").is_some());
        assert!(agent_by_id("opencode").is_some());
    }

    #[test]
    fn testAgentByIdUnknown() {
        assert!(agent_by_id("nonexistent").is_none());
    }

    #[test]
    fn testAllAgentsHaveUniqueIds() {
        let agents = all_agents();
        let mut ids: Vec<&str> = agents.iter().map(|a| a.id()).collect();
        let len_before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), len_before);
    }

    #[test]
    fn testExpectedSurfacesAllAgents() {
        let expected: &[(&str, (bool, bool, bool))] = &[
            ("claude-code", (true, true, true)),
            ("codex-cli", (true, true, true)),
            ("gemini-cli", (true, true, true)),
            ("cline", (true, true, true)),
            ("opencode", (true, true, true)),
        ];
        for (id, surfaces) in expected {
            let agent = agent_by_id(id).unwrap_or_else(|| panic!("missing agent: {id}"));
            assert_eq!(
                agent.expected_surfaces(),
                *surfaces,
                "expected_surfaces mismatch for {id}"
            );
        }
    }

    #[test]
    fn testEveryAgentDeclaresExpectedSurfaces() {
        for agent in all_agents() {
            let (exec, tool, burn) = agent.expected_surfaces();
            assert!(
                exec || tool || burn,
                "{} declares no expected surfaces",
                agent.id()
            );
        }
    }

    #[test]
    fn testEveryAgentHasMcpConfigOrHookProtocol() {
        for agent in all_agents() {
            let has_mcp = agent.mcp_config().is_some();
            let has_hook = agent.hook_protocol().is_some();
            assert!(
                has_mcp || has_hook,
                "{} has neither mcp_config nor hook_protocol",
                agent.id()
            );
        }
    }
}
