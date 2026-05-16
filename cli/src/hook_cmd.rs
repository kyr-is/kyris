// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris hook check` — native agent hook adapter. Reads an agent's hook
//! payload from stdin, maps it through the agent's `HookProtocol`, round-trips
//! to `agentpactd`, and handles `PACT_ASK` via `kyrisd`'s pending-approval
//! system. Writes the agent-native response (JSON or text) to stdout.
//!
//! This replaces `kyris-hook check-hook` for native agent hooks (Claude Code
//! `PreToolUse`, Codex CLI `PreToolUse`, Gemini CLI `BeforeTool`). Shell hooks
//! continue to use `kyris-hook check` for the fast synchronous path.

use clap::Args;
use std::io::Read as _;

use kyris_agentpact_client::{self as agentpact, ApprovalResponse, McpPermissionDecision};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use crate::agents::registry::{self, AllowResponse, HookProtocol, ToolMapping};

#[derive(Args)]
pub struct HookArgs {
    #[command(subcommand)]
    pub command: HookCommand,
}

#[derive(clap::Subcommand)]
pub enum HookCommand {
    Check(HookCheckArgs),
    /// Delegate a `PACT_ASK` or circuit-breaker approval to kyrisd's
    /// pending-approval system. Used by shell hooks in non-interactive
    /// (no-TTY) shells where prompting is impossible. Blocks until the
    /// developer resolves the request via `kyris pending`, then sends
    /// `permission.respond` to agentpactd and exits 0 (approved) or
    /// non-zero (denied/failed).
    Hold(HookHoldArgs),
}

#[derive(Args)]
pub struct HookHoldArgs {
    /// Approval ID from agentpactd (`req_id` field in kyris-hook output).
    #[arg(long)]
    pub req_id: String,
    /// Approval token from agentpactd.
    #[arg(long)]
    pub token: String,
    /// Human-readable description shown in `kyris pending` (the command text).
    #[arg(long)]
    pub display: String,
    /// Path to the agentpactd UDS socket (defaults to the standard location).
    #[arg(long)]
    pub socket: Option<String>,
}

#[derive(Args)]
pub struct HookCheckArgs {
    #[arg(long)]
    pub agent: String,
}

pub fn run(args: HookArgs) {
    match args.command {
        HookCommand::Check(check_args) => run_check(check_args),
        HookCommand::Hold(hold_args) => run_hold(hold_args),
    }
}

fn run_hold(args: HookHoldArgs) {
    let sock_path = args
        .socket
        .unwrap_or_else(|| agentpact::default_socket_path().display().to_string());
    let socket_timeout = std::time::Duration::from_secs(5);

    // Reuse resolve_ask: it holds the request in kyrisd's pending system,
    // polls for developer resolution, sends permission.respond to agentpactd,
    // and returns the exit code.  EmptyStdout means no extra output — the
    // shell hook only cares about the exit code.
    let ask_ctx = AskContext {
        allow_response: &AllowResponse::EmptyStdout,
        approval_id: &args.req_id,
        approval_token: &args.token,
        server: &args.display,
        tool: "",
        sock_path: &sock_path,
        socket_timeout,
    };
    let exit_code = resolve_ask(&ask_ctx);
    std::process::exit(exit_code);
}

fn discover_agent_pid() -> Option<u32> {
    let sig_table = ::agentpact::attribution::signatures::SignatureTable::default_phase1();
    let refresh_kind = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    let mut sys = sysinfo::System::new();

    let my_pid = std::process::id();
    let mut current = my_pid;

    for _ in 0..64 {
        if current <= 1 {
            return None;
        }
        let sysinfo_pid = Pid::from_u32(current);
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[sysinfo_pid]),
            false,
            refresh_kind,
        );
        let proc = sys.process(sysinfo_pid)?;

        let exe_str = proc
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cmd: Vec<String> = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();

        if sig_table.match_process(&exe_str, &cmd).is_some() {
            return Some(current);
        }

        current = match proc.parent() {
            Some(ppid) if ppid.as_u32() > 1 => ppid.as_u32(),
            _ => return None,
        };
    }
    None
}

fn run_check(args: HookCheckArgs) {
    let agent = &args.agent;

    if let Err(msg) = agentpact::check_protocol_compatibility() {
        emit_deny(&msg);
        std::process::exit(2);
    }

    let mut payload = String::new();
    std::io::stdin().read_to_string(&mut payload).unwrap_or(0);

    let hook_input: serde_json::Value =
        serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null);

    let protocol = registry::agent_by_id(agent).and_then(|a| a.hook_protocol());
    let (action, detail) = map_payload(protocol.as_ref(), &hook_input);

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    let seed_pid = discover_agent_pid();

    let sock_path = agentpact::default_socket_path().display().to_string();
    let socket_timeout = std::time::Duration::from_secs(5);

    let outcome = agentpact::request_hook_permission(
        &sock_path,
        "kyris-hook",
        &action,
        &detail,
        cwd.as_deref(),
        seed_pid,
        socket_timeout,
    );

    let allow_response = protocol
        .as_ref()
        .map_or(AllowResponse::EmptyStdout, |p| p.allow_response.clone());

    match outcome {
        Ok(McpPermissionDecision::Allow) => {
            emit_allow(&allow_response);
            std::process::exit(0);
        }
        Ok(McpPermissionDecision::Ask {
            approval_id,
            approval_token,
        }) => {
            let ask_ctx = AskContext {
                allow_response: &allow_response,
                approval_id: &approval_id,
                approval_token: &approval_token,
                server: &action,
                tool: &detail,
                sock_path: &sock_path,
                socket_timeout,
            };
            let exit_code = resolve_ask(&ask_ctx);
            std::process::exit(exit_code);
        }
        Err(_) if agentpact::allow_on_daemon_unavailable() => {
            kyris_core::fail_open_log::record(&action, &detail, agent, cwd.as_deref());
            emit_allow(&allow_response);
            std::process::exit(0);
        }
        Ok(McpPermissionDecision::Deny { reason, .. }) | Err(reason) => {
            emit_deny(&reason);
            std::process::exit(2);
        }
    }
}

struct AskContext<'a> {
    allow_response: &'a AllowResponse,
    approval_id: &'a str,
    approval_token: &'a str,
    server: &'a str,
    tool: &'a str,
    sock_path: &'a str,
    socket_timeout: std::time::Duration,
}

fn resolve_ask(ctx: &AskContext<'_>) -> i32 {
    let Some(conn) = kyris_core::config::load_kyrisd_connection() else {
        deny_ask_immediately(ctx.approval_token, ctx.sock_path, ctx.socket_timeout);
        emit_deny("kyrisd unreachable — cannot delegate approval");
        return 2;
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let resolution = rt.block_on(async {
        let client = reqwest::Client::new();
        eprintln!(
            "[kyris] {}/{} held for approval — resolve with 'kyris pending'",
            ctx.server, ctx.tool,
        );
        kyris_core::pending::hold_poll_resolve(
            &client,
            &conn,
            ctx.approval_id,
            ctx.approval_token,
            ctx.server,
            ctx.tool,
        )
        .await
    });

    match resolution {
        kyris_core::pending::Resolution::Approved => {
            emit_allow(ctx.allow_response);
            0
        }
        kyris_core::pending::Resolution::Denied => {
            emit_deny("denied by developer via kyris pending");
            2
        }
        kyris_core::pending::Resolution::Failed(reason) => {
            deny_ask_immediately(ctx.approval_token, ctx.sock_path, ctx.socket_timeout);
            emit_deny(&reason);
            2
        }
    }
}

fn deny_ask_immediately(
    approval_token: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) {
    let _ = agentpact::send_permission_response(
        sock_path,
        "kyris-hook-deny",
        approval_token,
        ApprovalResponse::Denied,
        Some(socket_timeout),
    );
}

fn map_payload(protocol: Option<&HookProtocol>, input: &serde_json::Value) -> (String, String) {
    let Some(protocol) = protocol else {
        let method = input["method"].as_str().unwrap_or("call");
        let detail = input["detail"].as_str().unwrap_or("");
        return (method.to_string(), detail.to_string());
    };

    let tool = if let Some(t) = input[&protocol.tool_name_field].as_str() {
        t
    } else {
        eprintln!(
            "[agentpact] warning: payload missing '{}' field, defaulting to unknown",
            protocol.tool_name_field
        );
        "unknown"
    };

    let mapping = protocol.tool_mappings.iter().find(|m| m.tool_name == tool);

    let action = mapping.map_or(protocol.default_action.as_str(), |m| m.action.as_str());

    let detail = extract_detail(protocol, mapping, input, tool);

    (action.to_string(), detail)
}

fn extract_detail(
    protocol: &HookProtocol,
    mapping: Option<&ToolMapping>,
    input: &serde_json::Value,
    tool: &str,
) -> String {
    for field in &protocol.detail_fields {
        let value = &input[field];
        if let Some(s) = value.as_str() {
            return s.to_string();
        }
        if value.is_object() {
            if let Some(key) = mapping.and_then(|m| m.detail_key.as_deref())
                && let Some(s) = value[key].as_str()
            {
                return s.to_string();
            }
            return value.to_string();
        }
    }
    tool.to_string()
}

// --- Response formatting ---
// All agents treat exit 2 + stderr as a hard block, so deny is universal.
// Allow varies per agent: some expect empty stdout, others expect JSON.

fn emit_allow(allow_response: &AllowResponse) {
    match allow_response {
        AllowResponse::EmptyStdout => {}
        AllowResponse::Json { body } => {
            println!("{}", serde_json::to_string(body).unwrap_or_default());
        }
    }
}

fn emit_deny(reason: &str) {
    eprintln!("[agentpact] {reason}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testMapPayloadWithoutProtocol() {
        let input = serde_json::json!({"method": "execute", "detail": "git status"});
        let (action, detail) = map_payload(None, &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "git status");
    }

    #[test]
    fn testMapPayloadStringDetail() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![ToolMapping {
                tool_name: "Bash".to_string(),
                action: "execute".to_string(),
                detail_key: Some("command".to_string()),
            }],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input = serde_json::json!({"tool_name": "Bash", "tool_input": "ls -la"});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "ls -la");
    }

    #[test]
    fn testMapPayloadStructuredDetailWithKey() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![ToolMapping {
                tool_name: "Bash".to_string(),
                action: "execute".to_string(),
                detail_key: Some("command".to_string()),
            }],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp"}});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "rm -rf /tmp");
    }

    #[test]
    fn testMapPayloadStructuredDetailFallbackJson() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![ToolMapping {
                tool_name: "CustomTool".to_string(),
                action: "call".to_string(),
                detail_key: None,
            }],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input = serde_json::json!({"tool_name": "CustomTool", "tool_input": {"foo": "bar"}});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"foo":"bar"}"#);
    }

    #[test]
    fn testMapPayloadDefaultAction() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input = serde_json::json!({"tool_name": "Read", "tool_input": "/tmp/file"});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "/tmp/file");
    }

    #[test]
    fn testMapPayloadMissingFields() {
        let input = serde_json::json!({});
        let (action, detail) = map_payload(None, &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "");
    }

    fn agent_protocol(id: &str) -> HookProtocol {
        registry::agent_by_id(id)
            .expect("agent exists")
            .hook_protocol()
            .expect("agent has hook protocol")
    }

    // --- Claude Code real payload fixtures ---

    #[test]
    fn testClaudeCodeBashStringPayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "git diff --stat"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "git diff --stat");
    }

    #[test]
    fn testClaudeCodeReadFilePayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Read",
            "tool_input": {"file_path": "/home/user/project/src/main.rs"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "read");
        assert_eq!(detail, "/home/user/project/src/main.rs");
    }

    #[test]
    fn testClaudeCodeWriteFilePayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/output.txt", "content": "hello"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/tmp/output.txt");
    }

    #[test]
    fn testClaudeCodeEditFilePayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {"file_path": "/home/user/lib.rs", "old_string": "foo", "new_string": "bar"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/home/user/lib.rs");
    }

    #[test]
    fn testClaudeCodeLowercaseBashVariant() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "bash",
            "tool_input": {"command": "npm test"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "npm test");
    }

    #[test]
    fn testClaudeCodeUnknownToolDefaultsToCall() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "WebSearch",
            "tool_input": {"query": "rust async"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"query":"rust async"}"#);
    }

    // --- Codex CLI real payload fixtures ---

    #[test]
    fn testCodexCliBashPayload() {
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "cargo build --release"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "cargo build --release");
    }

    #[test]
    fn testCodexCliApplyPatchPayload() {
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": {"command": "--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-old\n+new"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(
            detail,
            "--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-old\n+new"
        );
    }

    #[test]
    fn testCodexCliUnknownToolDefaultsToCall() {
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "browser",
            "tool_input": {"url": "https://example.com"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"url":"https://example.com"}"#);
    }

    // --- Gemini CLI real payload fixtures ---

    #[test]
    fn testGeminiCliShellPayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "run_shell_command",
            "tool_input": {"command": "python3 -m pytest"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "python3 -m pytest");
    }

    #[test]
    fn testGeminiCliReadFilePayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "read_file",
            "tool_input": {"file_path": "/home/user/package.json"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "read");
        assert_eq!(detail, "/home/user/package.json");
    }

    #[test]
    fn testGeminiCliWriteFilePayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "write_file",
            "tool_input": {"file_path": "/home/user/output.ts", "content": "new code"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/home/user/output.ts");
    }

    #[test]
    fn testGeminiCliReplacePayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "replace",
            "tool_input": {"file_path": "/home/user/index.ts", "old_text": "foo", "new_text": "bar"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/home/user/index.ts");
    }

    #[test]
    fn testGeminiCliUnknownToolDefaultsToCall() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "google_search",
            "tool_input": {"query": "rust async runtime"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"query":"rust async runtime"}"#);
    }
}
