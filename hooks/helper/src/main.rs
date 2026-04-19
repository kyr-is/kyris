// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

use std::io::{Read, Write};
use std::process::ExitCode;

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

    let request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.request",
        "action": "execute",
        "detail": command,
        "context": {
            "working_dir": cwd,
        }
    });

    let Ok(response) = send_request(&socket_path, &request) else {
        return ExitCode::from(10);
    };

    let code = response["code"].as_str().unwrap_or("");

    match code {
        "PACT_OK" => {
            if response["decision"].as_str() == Some("inform")
                && let Some(reason) = response["reason"].as_str()
            {
                eprintln!("[agentpact] {reason}");
            }
            ExitCode::from(0)
        }
        "PACT_DENIED" => {
            if let Some(reason) = response["reason"].as_str() {
                eprintln!("[agentpact] denied: {reason}");
            }
            ExitCode::from(1)
        }
        "PACT_ASK" => {
            let req_id = response["approval_id"].as_str().unwrap_or("");
            let token = response["approval_token"].as_str().unwrap_or("");
            let reason = response["reason"].as_str().unwrap_or("");

            if reason.contains("Autonomous limit") {
                let count = extract_count(reason);
                print!("{req_id}\t{token}\t{count}");
                ExitCode::from(3)
            } else {
                print!("{req_id}\t{token}");
                ExitCode::from(2)
            }
        }
        _ => ExitCode::from(0),
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

    let mut payload = String::new();
    std::io::stdin().read_to_string(&mut payload).unwrap_or(0);

    let hook_input: serde_json::Value =
        serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null);

    let (action, detail) = map_agent_payload(&agent, &hook_input);

    let request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.request",
        "action": action,
        "detail": detail,
    });

    let Ok(response) = send_request(&socket_path, &request) else {
        print_hook_response(&agent, "error", "daemon unreachable");
        return ExitCode::from(1);
    };

    let decision = response["decision"].as_str().unwrap_or("deny");
    print_hook_response(&agent, decision, "");
    ExitCode::from(0)
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

#[cfg(unix)]
fn send_request(
    socket_path: &str,
    request: &serde_json::Value,
) -> Result<serde_json::Value, std::io::Error> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    let payload = serde_json::to_vec(request)?;
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes)?;
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

fn default_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
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

fn extract_count(reason: &str) -> &str {
    reason
        .split_whitespace()
        .find(|w| w.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("0")
}

fn map_agent_payload(agent: &str, input: &serde_json::Value) -> (String, String) {
    match agent {
        "claude-code" => {
            let tool = input["tool_name"].as_str().unwrap_or("unknown");
            let action = match tool {
                "Bash" | "bash" => "execute",
                "Read" | "read_file" => "read",
                "Write" | "write_file" | "Edit" | "edit_file" => "write",
                _ => "call",
            };
            let detail = input["tool_input"]
                .as_str()
                .or_else(|| input["input"].as_str())
                .unwrap_or(tool);
            (action.to_string(), detail.to_string())
        }
        "codex-cli" => {
            let tool = input["tool_name"].as_str().unwrap_or("unknown");
            let action = match tool {
                "shell" => "execute",
                "read_file" => "read",
                "write_file" | "apply_diff" => "write",
                _ => "call",
            };
            let detail = input["input"].as_str().unwrap_or(tool);
            (action.to_string(), detail.to_string())
        }
        "gemini-cli" => {
            let tool = input["tool_name"].as_str().unwrap_or("unknown");
            let action = match tool {
                "shell" | "run_command" => "execute",
                "read_file" => "read",
                "write_file" | "edit_file" => "write",
                _ => "call",
            };
            let detail = input["arguments"].as_str().unwrap_or(tool);
            (action.to_string(), detail.to_string())
        }
        _ => {
            let method = input["method"].as_str().unwrap_or("call");
            let detail = input["detail"].as_str().unwrap_or("");
            (method.to_string(), detail.to_string())
        }
    }
}

fn print_hook_response(agent: &str, decision: &str, error_msg: &str) {
    match agent {
        "claude-code" => {
            let result = match decision {
                "auto" | "inform" => serde_json::json!({"decision": "approve"}),
                _ => serde_json::json!({"decision": "deny", "reason": error_msg}),
            };
            println!("{}", serde_json::to_string(&result).unwrap_or_default());
        }
        _ => {
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

    #[test]
    fn testExtractCount() {
        assert_eq!(
            extract_count("Autonomous limit: 50 commands without human input"),
            "50"
        );
        assert_eq!(extract_count("no digits here"), "0");
    }

    #[test]
    fn testMapClaudeCodePayload() {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": "git status"
        });
        let (action, detail) = map_agent_payload("claude-code", &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "git status");
    }

    #[test]
    fn testMapClaudeCodeReadTool() {
        let input = serde_json::json!({
            "tool_name": "Read",
            "tool_input": "/tmp/file.txt"
        });
        let (action, _) = map_agent_payload("claude-code", &input);
        assert_eq!(action, "read");
    }

    #[test]
    fn testMapCodexCliPayload() {
        let input = serde_json::json!({
            "tool_name": "shell",
            "input": "ls -la"
        });
        let (action, detail) = map_agent_payload("codex-cli", &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "ls -la");
    }

    #[test]
    fn testMapGeminiCliPayload() {
        let input = serde_json::json!({
            "tool_name": "run_command",
            "arguments": "echo hello"
        });
        let (action, detail) = map_agent_payload("gemini-cli", &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "echo hello");
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
    fn testGenerateIdNotEmpty() {
        let id = generate_id();
        assert!(id.starts_with("kyris-"));
        assert!(id.len() > 6);
    }
}
