// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Minimal shell hook helper (`kyris-hook`). Translates agent hook events
//! (check, respond, send) into `AgentPact` UDS protocol calls. Intentionally
//! tiny — stdlib + serde only, no Tokio, no `DuckDB` — to keep cold start
//! under 5ms and binary under 1MB.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

use std::io::{Read, Write};
use std::process::ExitCode;

#[derive(Debug, PartialEq, Eq)]
enum CheckResponse {
    Allow {
        inform_reason: Option<String>,
    },
    Deny {
        reason: Option<String>,
    },
    Ask {
        approval_id: String,
        approval_token: String,
        breaker_count: Option<String>,
    },
    Invalid(String),
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: kyris-hook <check|respond|check-hook|send> [args...]");
        return ExitCode::from(1);
    }

    match args[1].as_str() {
        "check" => cmd_check(&args[2..]),
        "respond" => cmd_respond(&args[2..]),
        "check-hook" => cmd_check_hook(&args[2..]),
        "send" => cmd_send(&args[2..]),
        other => {
            eprintln!("Unknown command: {other}");
            ExitCode::from(1)
        }
    }
}

fn cmd_check(args: &[String]) -> ExitCode {
    let (command, cwd, socket_path) = parse_check_args(args);

    if let Err(msg) = check_protocol_version(&socket_path) {
        eprintln!("[agentpact] {msg}");
        return ExitCode::from(10);
    }

    let exec_token = std::env::var("AGENTPACT_EXEC_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());

    let mut request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.request",
        "action": "execute",
        "detail": command,
        "context": {
            "working_dir": cwd,
        }
    });
    if let Some(ref token) = exec_token {
        request["exec_token"] = serde_json::Value::String(token.clone());
    }

    let Ok(response) = send_request(&socket_path, &request) else {
        if daemon_state_allows(&socket_path) {
            write_fail_open_event("execute", &command, &cwd);
            return ExitCode::from(11);
        }
        return ExitCode::from(10);
    };

    match parse_check_response(&response) {
        CheckResponse::Allow { inform_reason } => {
            if let Some(reason) = inform_reason {
                eprintln!("[agentpact] {reason}");
            }
            ExitCode::from(0)
        }
        CheckResponse::Deny { reason } => {
            if let Some(reason) = reason {
                eprintln!("[agentpact] denied: {reason}");
            }
            ExitCode::from(1)
        }
        CheckResponse::Ask {
            approval_id,
            approval_token,
            breaker_count,
        } => {
            if let Some(count) = breaker_count {
                print!("{approval_id}\t{approval_token}\t{count}");
                ExitCode::from(3)
            } else {
                print!("{approval_id}\t{approval_token}");
                ExitCode::from(2)
            }
        }
        CheckResponse::Invalid(reason) => {
            eprintln!("[agentpact] {reason}");
            ExitCode::from(1)
        }
    }
}

fn parse_check_response(response: &serde_json::Value) -> CheckResponse {
    match response.get("code").and_then(|value| value.as_str()) {
        Some("PACT_OK") => CheckResponse::Allow {
            inform_reason: if response.get("decision").and_then(|value| value.as_str())
                == Some("inform")
            {
                response
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            } else {
                None
            },
        },
        Some("PACT_DENIED") => CheckResponse::Deny {
            reason: response
                .get("reason")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        },
        Some("PACT_ASK") => {
            let approval_id = response
                .get("approval_id")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let approval_token = response
                .get("approval_token")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let Some(approval_id) = approval_id else {
                return CheckResponse::Invalid(
                    "invalid PACT_ASK response from agentpactd: missing approval_id".to_string(),
                );
            };
            let Some(approval_token) = approval_token else {
                return CheckResponse::Invalid(
                    "invalid PACT_ASK response from agentpactd: missing approval_token".to_string(),
                );
            };
            let breaker_count = response
                .get("extensions")
                .and_then(|ext| ext.get("circuit_breaker"))
                .and_then(|cb| cb.get("count"))
                .and_then(serde_json::Value::as_u64)
                .map(|c| c.to_string());
            CheckResponse::Ask {
                approval_id,
                approval_token,
                breaker_count,
            }
        }
        Some("PACT_POLICY_ERROR" | "PACT_PROTOCOL_ERROR" | "PACT_CAP_EXCEEDED") => {
            let error = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            let hint = response.get("recovery_hint").and_then(|v| v.as_str());
            let reason = match hint {
                Some(h) => format!("{error} ({h})"),
                None => error.to_string(),
            };
            CheckResponse::Deny {
                reason: Some(reason),
            }
        }
        Some(other) => {
            CheckResponse::Invalid(format!("unexpected response code from agentpactd: {other}"))
        }
        None => {
            CheckResponse::Invalid("invalid response from agentpactd: missing code".to_string())
        }
    }
}

fn cmd_respond(args: &[String]) -> ExitCode {
    let mut socket_path = default_socket();
    let mut req_id = String::new();
    let mut token = String::new();
    let mut response_value = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" if i + 1 < args.len() => {
                socket_path.clone_from(&args[i + 1]);
                i += 2;
            }
            "--req-id" if i + 1 < args.len() => {
                req_id.clone_from(&args[i + 1]);
                i += 2;
            }
            "--token" if i + 1 < args.len() => {
                token.clone_from(&args[i + 1]);
                i += 2;
            }
            "--response" if i + 1 < args.len() => {
                response_value.clone_from(&args[i + 1]);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let request = serde_json::json!({
        "id": req_id,
        "method": "permission.respond",
        "approval_token": token,
        "response": response_value,
    });

    match send_request(&socket_path, &request) {
        Ok(resp) => {
            if resp["code"].as_str() == Some("PACT_OK") {
                ExitCode::from(0)
            } else {
                if let Some(reason) = resp["error"].as_str() {
                    eprintln!("{reason}");
                }
                ExitCode::from(1)
            }
        }
        Err(_) => ExitCode::from(10),
    }
}

fn cmd_check_hook(args: &[String]) -> ExitCode {
    let mut agent = String::new();
    let mut socket_path = default_socket();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent" if i + 1 < args.len() => {
                agent.clone_from(&args[i + 1]);
                i += 2;
            }
            "--socket" if i + 1 < args.len() => {
                socket_path.clone_from(&args[i + 1]);
                i += 2;
            }
            _ => i += 1,
        }
    }

    if let Err(msg) = check_protocol_version(&socket_path) {
        print_hook_response(&agent, "error", &msg);
        return ExitCode::from(1);
    }

    let mut payload = String::new();
    std::io::stdin().read_to_string(&mut payload).unwrap_or(0);

    let hook_input: serde_json::Value =
        serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null);

    let (action, detail) = map_agent_payload(&agent, &hook_input);

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    let request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.request",
        "action": action,
        "detail": detail,
        "context": {
            "working_dir": cwd,
        }
    });

    let Ok(response) = send_request(&socket_path, &request) else {
        if daemon_state_allows(&socket_path) {
            write_fail_open_event(&action, &detail, cwd.as_deref().unwrap_or(""));
            print_hook_response(&agent, "auto", "");
            return ExitCode::from(0);
        }
        print_hook_response(&agent, "error", "daemon unreachable");
        return ExitCode::from(1);
    };

    match parse_check_response(&response) {
        CheckResponse::Allow { .. } => {
            print_hook_response(&agent, "auto", "");
            ExitCode::from(0)
        }
        CheckResponse::Deny { reason } => {
            print_hook_response(&agent, "deny", reason.as_deref().unwrap_or(""));
            ExitCode::from(1)
        }
        CheckResponse::Ask {
            approval_token,
            approval_id,
            breaker_count,
        } => {
            send_void(&socket_path, &approval_token);
            let reason = response
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("requires approval");
            let detail = match breaker_count {
                Some(count) => format!(
                    "{reason} ({count} commands without human input) [approval_id={approval_id}]"
                ),
                None => format!("{reason} [approval_id={approval_id}]"),
            };
            print_hook_ask_response(&agent, &detail);
            ExitCode::from(1)
        }
        CheckResponse::Invalid(_) => {
            let reason = response
                .get("error")
                .or_else(|| response.get("reason"))
                .and_then(|v| v.as_str())
                .unwrap_or("denied by policy");
            print_hook_response(&agent, "deny", reason);
            ExitCode::from(1)
        }
    }
}

fn cmd_send(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("Usage: kyris-hook send <socket_path> <json_message>");
        return ExitCode::from(1);
    }

    let socket_path = &args[0];
    let message = &args[1];

    let value: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid JSON: {e}");
            return ExitCode::from(1);
        }
    };

    match send_request(socket_path, &value) {
        Ok(resp) => {
            println!("{}", serde_json::to_string(&resp).unwrap_or_default());
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("Send failed: {e}");
            ExitCode::from(10)
        }
    }
}

fn parse_check_args(args: &[String]) -> (String, String, String) {
    let mut command = String::new();
    let mut cwd = String::new();
    let mut socket = default_socket();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cwd" if i + 1 < args.len() => {
                cwd.clone_from(&args[i + 1]);
                i += 2;
            }
            "--socket" if i + 1 < args.len() => {
                socket.clone_from(&args[i + 1]);
                i += 2;
            }
            _ => {
                if command.is_empty() {
                    command.clone_from(&args[i]);
                }
                i += 1;
            }
        }
    }

    (command, cwd, socket)
}

fn send_void(socket_path: &str, approval_token: &str) {
    let request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.respond",
        "approval_token": approval_token,
        "response": "voided",
    });
    let _ = send_request(socket_path, &request);
}

#[cfg(unix)]
fn send_request(
    socket_path: &str,
    request: &serde_json::Value,
) -> Result<serde_json::Value, std::io::Error> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    let mut payload = serde_json::to_vec(request)?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes)?;
    trim_socket_message(&mut response_bytes);
    serde_json::from_slice(&response_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(not(unix))]
fn send_request(
    _socket_path: &str,
    _request: &serde_json::Value,
) -> Result<serde_json::Value, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "UDS not supported on this platform",
    ))
}

fn write_fail_open_event(action: &str, detail: &str, working_dir: &str) {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = format!("{home}/.kyris/fail-open.jsonl");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = ts.as_secs();
    let line = serde_json::json!({
        "id": format!("kyris-{}", ts.as_nanos()),
        "timestamp": format_utc_timestamp(secs),
        "agent": "unknown",
        "action": action,
        "detail": detail,
        "decision": "auto",
        "working_dir": working_dir,
        "attribution_method": "unknown",
        "mode": "log",
        "event_kind": "action",
        "coverage_state": "unknown",
        "source": "fail-open",
    });
    let _ = writeln!(file, "{line}");
}

fn format_utc_timestamp(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let day_secs = epoch_secs % secs_per_day;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;

    let (year, month, day) = days_to_ymd(days + 719_468);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(day_count: u64) -> (u64, u64, u64) {
    let era = day_count / 146_097;
    let doe = day_count - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

const PROTOCOL_VERSION: u64 = 1;

fn read_daemon_state(socket_path: &str) -> Option<serde_json::Value> {
    let path = std::path::Path::new(socket_path)
        .parent()
        .map(|dir| dir.join("daemon.state"))?;
    let contents = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn daemon_state_allows(socket_path: &str) -> bool {
    read_daemon_state(socket_path)
        .as_ref()
        .and_then(|v| v.get("on_daemon_unavailable"))
        .and_then(|val| val.as_str())
        == Some("allow")
}

fn check_protocol_version(socket_path: &str) -> Result<(), String> {
    let Some(state) = read_daemon_state(socket_path) else {
        return Ok(());
    };
    let Some(version) = state
        .get("protocol_version")
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(());
    };
    if version == PROTOCOL_VERSION {
        return Ok(());
    }
    if version > PROTOCOL_VERSION {
        Err(format!(
            "agentpactd protocol version {version} is newer than kyris-hook expects ({PROTOCOL_VERSION}). \
             Upgrade kyris: brew upgrade kyris"
        ))
    } else {
        Err(format!(
            "agentpactd protocol version {version} is older than kyris-hook expects ({PROTOCOL_VERSION}). \
             Upgrade agentpact: brew upgrade agentpact"
        ))
    }
}

fn default_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn trim_socket_message(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

fn generate_id() -> String {
    format!(
        "kyris-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

#[derive(serde::Deserialize)]
struct ToolMapping {
    tool_name: String,
    action: String,
}

#[derive(serde::Deserialize)]
struct HookProtocol {
    tool_name_field: String,
    detail_fields: Vec<String>,
    tool_mappings: Vec<ToolMapping>,
    default_action: String,
    response_format: ResponseFormat,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum ResponseFormat {
    Json,
    Text,
}

fn load_hook_protocol(agent: &str) -> Option<HookProtocol> {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = format!("{home}/.kyris/agents/{agent}/hook-protocol.json");
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn map_agent_payload(agent: &str, input: &serde_json::Value) -> (String, String) {
    if let Some(protocol) = load_hook_protocol(agent) {
        return map_with_protocol(&protocol, input);
    }
    let method = input["method"].as_str().unwrap_or("call");
    let detail = input["detail"].as_str().unwrap_or("");
    (method.to_string(), detail.to_string())
}

fn map_with_protocol(protocol: &HookProtocol, input: &serde_json::Value) -> (String, String) {
    let tool = input[&protocol.tool_name_field]
        .as_str()
        .unwrap_or("unknown");

    let action = protocol
        .tool_mappings
        .iter()
        .find(|m| m.tool_name == tool)
        .map_or(protocol.default_action.as_str(), |m| m.action.as_str());

    let detail = protocol
        .detail_fields
        .iter()
        .find_map(|field| input[field].as_str())
        .unwrap_or(tool);

    (action.to_string(), detail.to_string())
}

fn response_format_for_agent(agent: &str) -> ResponseFormat {
    load_hook_protocol(agent).map_or(ResponseFormat::Text, |p| p.response_format)
}

fn print_hook_ask_response(agent: &str, reason: &str) {
    match response_format_for_agent(agent) {
        ResponseFormat::Json => {
            let result = serde_json::json!({"decision": "deny", "reason": reason});
            println!("{}", serde_json::to_string(&result).unwrap_or_default());
        }
        ResponseFormat::Text => {
            eprintln!("[agentpact] {reason}");
            println!("deny");
        }
    }
}

fn print_hook_response(agent: &str, decision: &str, error_msg: &str) {
    match response_format_for_agent(agent) {
        ResponseFormat::Json => {
            let result = match decision {
                "auto" | "inform" => serde_json::json!({"decision": "approve"}),
                _ => serde_json::json!({"decision": "deny", "reason": error_msg}),
            };
            println!("{}", serde_json::to_string(&result).unwrap_or_default());
        }
        ResponseFormat::Text => {
            if decision == "auto" || decision == "inform" {
                println!("allow");
            } else {
                println!("deny");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude_code_protocol() -> HookProtocol {
        HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string(), "input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "Bash".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "bash".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "Read".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "Write".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "Edit".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "edit_file".to_string(),
                    action: "write".to_string(),
                },
            ],
            default_action: "call".to_string(),
            response_format: ResponseFormat::Json,
        }
    }

    fn codex_cli_protocol() -> HookProtocol {
        HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "shell".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "apply_diff".to_string(),
                    action: "write".to_string(),
                },
            ],
            default_action: "call".to_string(),
            response_format: ResponseFormat::Text,
        }
    }

    fn gemini_cli_protocol() -> HookProtocol {
        HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["arguments".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "shell".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "run_command".to_string(),
                    action: "execute".to_string(),
                },
                ToolMapping {
                    tool_name: "read_file".to_string(),
                    action: "read".to_string(),
                },
                ToolMapping {
                    tool_name: "write_file".to_string(),
                    action: "write".to_string(),
                },
                ToolMapping {
                    tool_name: "edit_file".to_string(),
                    action: "write".to_string(),
                },
            ],
            default_action: "call".to_string(),
            response_format: ResponseFormat::Text,
        }
    }

    #[test]
    fn testMapClaudeCodePayload() {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": "git status"
        });
        let (action, detail) = map_with_protocol(&claude_code_protocol(), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "git status");
    }

    #[test]
    fn testMapClaudeCodeReadTool() {
        let input = serde_json::json!({
            "tool_name": "Read",
            "tool_input": "/tmp/file.txt"
        });
        let (action, _) = map_with_protocol(&claude_code_protocol(), &input);
        assert_eq!(action, "read");
    }

    #[test]
    fn testMapClaudeCodeWriteTools() {
        let protocol = claude_code_protocol();
        for tool in ["Write", "write_file", "Edit", "edit_file"] {
            let input = serde_json::json!({ "tool_name": tool, "tool_input": "/tmp/f" });
            let (action, _) = map_with_protocol(&protocol, &input);
            assert_eq!(action, "write", "failed for tool: {tool}");
        }
    }

    #[test]
    fn testMapClaudeCodeUnknownToolFallsBackToCall() {
        let input = serde_json::json!({ "tool_name": "CustomMcpTool", "tool_input": "data" });
        let (action, detail) = map_with_protocol(&claude_code_protocol(), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "data");
    }

    #[test]
    fn testMapClaudeCodeFallsBackToToolNameWhenNoInput() {
        let input = serde_json::json!({ "tool_name": "SomeTool" });
        let (action, detail) = map_with_protocol(&claude_code_protocol(), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "SomeTool");
    }

    #[test]
    fn testMapCodexCliPayload() {
        let input = serde_json::json!({
            "tool_name": "shell",
            "input": "ls -la"
        });
        let (action, detail) = map_with_protocol(&codex_cli_protocol(), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "ls -la");
    }

    #[test]
    fn testMapCodexCliWriteTools() {
        let protocol = codex_cli_protocol();
        for tool in ["write_file", "apply_diff"] {
            let input = serde_json::json!({ "tool_name": tool, "input": "content" });
            let (action, _) = map_with_protocol(&protocol, &input);
            assert_eq!(action, "write", "failed for tool: {tool}");
        }
    }

    #[test]
    fn testMapGeminiCliPayload() {
        let input = serde_json::json!({
            "tool_name": "run_command",
            "arguments": "echo hello"
        });
        let (action, detail) = map_with_protocol(&gemini_cli_protocol(), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "echo hello");
    }

    #[test]
    fn testMapGeminiCliWriteTools() {
        let protocol = gemini_cli_protocol();
        for tool in ["write_file", "edit_file"] {
            let input = serde_json::json!({ "tool_name": tool, "arguments": "content" });
            let (action, _) = map_with_protocol(&protocol, &input);
            assert_eq!(action, "write", "failed for tool: {tool}");
        }
    }

    #[test]
    fn testMapUnknownAgent() {
        let input = serde_json::json!({
            "method": "call",
            "detail": "some action"
        });
        let (action, detail) = map_agent_payload("unknown-agent", &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "some action");
    }

    #[test]
    fn testMapUnknownAgentMissingFields() {
        let input = serde_json::json!({});
        let (action, detail) = map_agent_payload("unknown-agent", &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "");
    }

    #[test]
    fn testParseCheckResponseAllowsInform() {
        let response = serde_json::json!({
            "code": "PACT_OK",
            "decision": "inform",
            "reason": "heads up"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Allow {
                inform_reason: Some("heads up".to_string()),
            }
        );
    }

    #[test]
    fn testParseCheckResponseAskBreakerFromExtensions() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "apr_123",
            "approval_token": "tok_123",
            "extensions": {
                "circuit_breaker": { "count": 50 }
            }
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Ask {
                approval_id: "apr_123".to_string(),
                approval_token: "tok_123".to_string(),
                breaker_count: Some("50".to_string()),
            }
        );
    }

    #[test]
    fn testParseCheckResponseAskNoBreakerWithoutExtensions() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "apr_123",
            "approval_token": "tok_123",
            "reason": "requires approval"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Ask {
                approval_id: "apr_123".to_string(),
                approval_token: "tok_123".to_string(),
                breaker_count: None,
            }
        );
    }

    #[test]
    fn testParseCheckResponseRejectsUnknownCode() {
        let response = serde_json::json!({
            "code": "PACT_FUTURE"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Invalid(
                "unexpected response code from agentpactd: PACT_FUTURE".to_string()
            )
        );
    }

    #[test]
    fn testParseCheckResponseRejectsMalformedAsk() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "apr_123"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Invalid(
                "invalid PACT_ASK response from agentpactd: missing approval_token".to_string(),
            )
        );
    }

    #[test]
    fn testGenerateIdNotEmpty() {
        let id = generate_id();
        assert!(id.starts_with("kyris-"));
        assert!(id.len() > 6);
    }

    #[test]
    fn testGenerateIdUnique() {
        let id1 = generate_id();
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let id2 = generate_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn testParseCheckArgsAllFlags() {
        let args: Vec<String> = vec![
            "--cwd",
            "/home/user/project",
            "--socket",
            "/tmp/test.sock",
            "rm -rf /",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (command, cwd, socket) = parse_check_args(&args);
        assert_eq!(command, "rm -rf /");
        assert_eq!(cwd, "/home/user/project");
        assert_eq!(socket, "/tmp/test.sock");
    }

    #[test]
    fn testParseCheckArgsCommandOnly() {
        let args: Vec<String> = vec!["git status"].into_iter().map(String::from).collect();
        let (command, cwd, socket) = parse_check_args(&args);
        assert_eq!(command, "git status");
        assert_eq!(cwd, "");
        assert!(socket.ends_with("agentpact.sock"));
    }

    #[test]
    fn testParseCheckArgsEmpty() {
        let args: Vec<String> = vec![];
        let (command, cwd, _) = parse_check_args(&args);
        assert_eq!(command, "");
        assert_eq!(cwd, "");
    }

    #[test]
    fn testPrintHookResponseClaudeCodeApprove() {
        let result = hook_response_json("claude-code", "auto", "");
        assert_eq!(result["decision"], "approve");
    }

    #[test]
    fn testPrintHookResponseClaudeCodeInform() {
        let result = hook_response_json("claude-code", "inform", "");
        assert_eq!(result["decision"], "approve");
    }

    #[test]
    fn testPrintHookResponseClaudeCodeDeny() {
        let result = hook_response_json("claude-code", "deny", "not allowed");
        assert_eq!(result["decision"], "deny");
        assert_eq!(result["reason"], "not allowed");
    }

    fn hook_response_json(agent: &str, decision: &str, error_msg: &str) -> serde_json::Value {
        match agent {
            "claude-code" => match decision {
                "auto" | "inform" => serde_json::json!({"decision": "approve"}),
                _ => serde_json::json!({"decision": "deny", "reason": error_msg}),
            },
            _ => serde_json::Value::Null,
        }
    }

    #[test]
    fn testDaemonStateAllowsReturnsTrue() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":1,"on_daemon_unavailable":"allow","on_log_broken":"continue"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testDaemonStateBlockReturnsFalse() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":1,"on_daemon_unavailable":"block","on_log_broken":"continue"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(!daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testDaemonStateMissingFileReturnsFalse() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(!daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testDaemonStateAllowsWithSpaces() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version": 1, "on_daemon_unavailable": "allow", "on_log_broken": "continue"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testWriteFailOpenEvent() {
        let dir = tempfile::tempdir().unwrap();
        let kyris_dir = dir.path().join(".kyris");
        std::fs::create_dir_all(&kyris_dir).unwrap();
        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };

        write_fail_open_event("execute", "rm -rf /", "/home/user/project");

        let path = kyris_dir.join("fail-open.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["action"], "execute");
        assert_eq!(parsed["detail"], "rm -rf /");
        assert_eq!(parsed["working_dir"], "/home/user/project");
        assert_eq!(parsed["source"], "fail-open");
        assert_eq!(parsed["coverage_state"], "unknown");
    }

    #[test]
    fn testFormatUtcTimestamp() {
        // 2026-01-01T00:00:00Z
        assert_eq!(format_utc_timestamp(1_767_225_600), "2026-01-01T00:00:00Z");
        // 2026-04-27T12:30:45Z
        assert_eq!(format_utc_timestamp(1_777_293_045), "2026-04-27T12:30:45Z");
    }

    #[test]
    fn testDefaultSocketUsesEnvVar() {
        unsafe { std::env::set_var("AGENTPACT_SOCK", "/custom/path.sock") };
        let sock = default_socket();
        assert_eq!(sock, "/custom/path.sock");
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
    }

    #[test]
    fn testDefaultSocketFallsBackToHome() {
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
        let sock = default_socket();
        assert!(sock.ends_with(".agentpact/agentpact.sock"));
    }

    #[test]
    fn testCheckProtocolVersionMatchingVersion() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":1,"on_daemon_unavailable":"block"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(check_protocol_version(socket_path.to_str().unwrap()).is_ok());
    }

    #[test]
    fn testCheckProtocolVersionNewerDaemon() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":99,"on_daemon_unavailable":"block"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        let result = check_protocol_version(socket_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Upgrade kyris"));
    }

    #[test]
    fn testCheckProtocolVersionOlderDaemon() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":0,"on_daemon_unavailable":"block"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        let result = check_protocol_version(socket_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Upgrade agentpact"));
    }

    #[test]
    fn testCheckProtocolVersionMissingState() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(check_protocol_version(socket_path.to_str().unwrap()).is_ok());
    }

    #[test]
    fn testCheckProtocolVersionMissingField() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(&state_path, r#"{"on_daemon_unavailable":"block"}"#).unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(check_protocol_version(socket_path.to_str().unwrap()).is_ok());
    }
}
