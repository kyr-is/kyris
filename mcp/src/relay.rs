// SPDX-License-Identifier: Apache-2.0
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::framing;

const RETRY_BACKOFFS: &[u64] = &[50, 100, 250];

type SharedStdout = std::sync::Arc<tokio::sync::Mutex<tokio::io::Stdout>>;

const CHILD_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn run_wrapper(
    server_name: &str,
    cmd: &str,
    args: &[String],
    has_tty: bool,
    socket_timeout: std::time::Duration,
) -> Result<u8, Box<dyn std::error::Error>> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let child_id = child.id();
    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    let stdin = tokio::io::stdin();
    let stdout: SharedStdout = std::sync::Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));

    let server_name_owned = server_name.to_string();

    let agent_to_server = tokio::spawn(relay_agent_to_server(
        stdin,
        child_stdin,
        stdout.clone(),
        server_name_owned.clone(),
        has_tty,
        socket_timeout,
    ));

    let server_to_agent = tokio::spawn(relay_server_to_agent(child_stdout, stdout));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("register SIGTERM");
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("register SIGINT");

    tokio::select! {
        result = agent_to_server => {
            let inner = result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            inner.map_err(|e| -> Box<dyn std::error::Error> { e })?;
        }
        result = server_to_agent => {
            let inner = result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            inner.map_err(|e| -> Box<dyn std::error::Error> { e })?;
        }
        _ = sigterm.recv() => {
            forward_signal_to_child(child_id, nix::sys::signal::Signal::SIGTERM);
        }
        _ = sigint.recv() => {
            forward_signal_to_child(child_id, nix::sys::signal::Signal::SIGINT);
        }
    }

    match tokio::time::timeout(CHILD_KILL_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let code = status.code().unwrap_or(1) as u8;
            Ok(code)
        }
        Ok(Err(e)) => Err(Box::new(e)),
        Err(_) => {
            child.kill().await.ok();
            Ok(1)
        }
    }
}

fn forward_signal_to_child(child_id: Option<u32>, signal: nix::sys::signal::Signal) {
    if let Some(pid) = child_id {
        let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
        let _ = nix::sys::signal::kill(nix_pid, signal);
    }
}

fn extract_tool_name(bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("params")?.get("name")?.as_str().map(String::from)
}

fn extract_request_id(bytes: &[u8]) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("id").cloned()
}

fn build_permission_request(tool_name: &str) -> String {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));
    let context = match cwd {
        Some(dir) => serde_json::json!({"working_dir": dir}),
        None => serde_json::json!({}),
    };
    serde_json::json!({
        "id": format!("kyris-mcp-{}", uuid::Uuid::now_v7()),
        "method": "permission.request",
        "action": "call",
        "detail": tool_name,
        "context": context
    })
    .to_string()
}

fn build_permission_respond_request(approval_token: &str, response: &str) -> String {
    serde_json::json!({
        "id": format!("kyris-mcp-resp-{}", uuid::Uuid::now_v7()),
        "method": "permission.respond",
        "approval_token": approval_token,
        "response": response
    })
    .to_string()
}

fn build_denied_response(original_id: &serde_json::Value, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": original_id,
        "error": {
            "code": -32001,
            "message": message
        }
    })
    .to_string()
}

#[derive(Debug, PartialEq)]
enum PactDecision {
    Allow,
    Deny(String),
}

#[derive(Debug, PartialEq)]
enum PermissionRequestOutcome {
    Allow,
    Deny(String),
    Ask { approval_token: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserApprovalResponse {
    Approved,
    Denied,
    Always,
}

impl UserApprovalResponse {
    fn as_agentpact_response(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Always => "always",
        }
    }

    fn allows_execution(self) -> bool {
        matches!(self, Self::Approved | Self::Always)
    }
}

fn daemon_unavailable_message() -> String {
    "AgentPact daemon is unreachable. MCP governance cannot be evaluated.".to_string()
}

fn no_tty_message() -> String {
    "Kyris: tool requires approval but no terminal is available. Adjust policy to 'auto' for this tool or run from a terminal."
        .to_string()
}

fn agentpact_socket_path() -> Result<String, String> {
    if let Ok(path) = std::env::var("AGENTPACT_SOCK") {
        return Ok(path);
    }
    let home = std::env::var("HOME").map_err(|_| daemon_unavailable_message())?;
    Ok(format!("{home}/.agentpact/agentpact.sock"))
}

fn send_daemon_request_to_socket(
    sock_path: &str,
    payload: &str,
    socket_timeout: std::time::Duration,
) -> Result<serde_json::Value, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path).map_err(|_| daemon_unavailable_message())?;
    let _ = stream.set_read_timeout(Some(socket_timeout));
    let _ = stream.set_write_timeout(Some(socket_timeout));
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("failed to send request to agentpactd: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("failed to close request body: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("failed to read response from agentpactd: {e}"))?;
    serde_json::from_slice(&response).map_err(|e| format!("invalid response from agentpactd: {e}"))
}

fn parse_permission_request_response(response: &serde_json::Value) -> PermissionRequestOutcome {
    match response.get("code").and_then(|code| code.as_str()) {
        Some("PACT_OK") => PermissionRequestOutcome::Allow,
        Some("PACT_DENIED") => {
            let reason = response
                .get("reason")
                .and_then(|value| value.as_str())
                .unwrap_or("blocked by policy")
                .to_string();
            PermissionRequestOutcome::Deny(reason)
        }
        Some("PACT_ASK") => PermissionRequestOutcome::Ask {
            approval_token: response
                .get("approval_token")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
        },
        _ => PermissionRequestOutcome::Deny("invalid response from agentpactd".to_string()),
    }
}

fn send_permission_request_with_socket(
    sock_path: &str,
    tool_name: &str,
    socket_timeout: std::time::Duration,
) -> Result<PermissionRequestOutcome, String> {
    let request = build_permission_request(tool_name);
    send_daemon_request_with_retry(sock_path, &request, socket_timeout)
        .map(|response| parse_permission_request_response(&response))
}

fn send_permission_response_with_socket(
    sock_path: &str,
    approval_token: &str,
    response: UserApprovalResponse,
    socket_timeout: std::time::Duration,
) -> Result<(), String> {
    let request =
        build_permission_respond_request(approval_token, response.as_agentpact_response());
    let response_value = send_daemon_request_to_socket(sock_path, &request, socket_timeout)?;
    match response_value.get("code").and_then(|code| code.as_str()) {
        Some("PACT_OK") => Ok(()),
        Some("PACT_DENIED") if response == UserApprovalResponse::Denied => Ok(()),
        Some(code) => {
            let reason = response_value
                .get("reason")
                .or_else(|| response_value.get("error"))
                .and_then(|value| value.as_str())
                .unwrap_or(code);
            Err(format!("agentpactd rejected approval response: {reason}"))
        }
        None => Err("agentpactd returned a malformed approval response".to_string()),
    }
}

fn prompt_user_tty(server_name: &str, tool_name: &str) -> UserApprovalResponse {
    use std::io::{BufRead, Write};

    let Ok(tty_write) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
        return UserApprovalResponse::Denied;
    };
    let Ok(tty_read) = std::fs::OpenOptions::new().read(true).open("/dev/tty") else {
        return UserApprovalResponse::Denied;
    };

    let mut writer = std::io::BufWriter::new(tty_write);
    let _ = write!(
        writer,
        "[kyris] allow {server_name}/{tool_name}? [y/n/always] "
    );
    let _ = writer.flush();

    let mut reader = std::io::BufReader::new(tty_read);
    let mut input = String::new();
    if reader.read_line(&mut input).is_err() {
        return UserApprovalResponse::Denied;
    }

    let trimmed = input.trim().to_lowercase();
    match trimmed.as_str() {
        "y" | "yes" => UserApprovalResponse::Approved,
        "a" | "always" => UserApprovalResponse::Always,
        _ => UserApprovalResponse::Denied,
    }
}

async fn check_permission(
    server_name: &str,
    tool_name: &str,
    has_tty: bool,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let sock_path = agentpact_socket_path().unwrap_or_default();
    check_permission_with_socket(server_name, tool_name, has_tty, &sock_path, socket_timeout).await
}

async fn check_permission_with_socket(
    server_name: &str,
    tool_name: &str,
    has_tty: bool,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let tool = tool_name.to_string();
    let server = server_name.to_string();
    let tty = has_tty;
    let socket = sock_path.to_string();
    let timeout = socket_timeout;

    let decision = tokio::task::spawn_blocking(move || {
        match send_permission_request_with_socket(&socket, &tool, timeout) {
            Ok(PermissionRequestOutcome::Allow) => PactDecision::Allow,
            Ok(PermissionRequestOutcome::Deny(reason)) => {
                PactDecision::Deny(format!("Blocked by policy: {reason}"))
            }
            Ok(PermissionRequestOutcome::Ask { approval_token }) => {
                let user_response = if tty {
                    prompt_user_tty(&server, &tool)
                } else {
                    UserApprovalResponse::Denied
                };
                let denied_message = if tty {
                    "Blocked by policy".to_string()
                } else {
                    no_tty_message()
                };
                match send_permission_response_with_socket(&socket, &approval_token, user_response, timeout)
                {
                    Ok(()) if user_response.allows_execution() => PactDecision::Allow,
                    Ok(()) => PactDecision::Deny(denied_message),
                    Err(reason) => PactDecision::Deny(reason),
                }
            }
            Err(_reason) if allow_on_daemon_unavailable() => PactDecision::Allow,
            Err(reason) => PactDecision::Deny(reason),
        }
    })
    .await;

    decision.unwrap_or_else(|_| PactDecision::Deny(daemon_unavailable_message()))
}

fn send_daemon_request_with_retry(
    sock_path: &str,
    payload: &str,
    socket_timeout: std::time::Duration,
) -> Result<serde_json::Value, String> {
    let mut attempts = RETRY_BACKOFFS.iter().copied().peekable();
    loop {
        match send_daemon_request_to_socket(sock_path, payload, socket_timeout) {
            Ok(response) => return Ok(response),
            Err(error) => {
                let Some(backoff_ms) = attempts.next() else {
                    return Err(error);
                };
                let _ = restart_agentpactd();
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            }
        }
    }
}

fn restart_agentpactd() -> Result<(), String> {
    let uid = nix::unistd::getuid().as_raw();
    std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &format!("gui/{uid}/so.kyri.agentpactd")])
        .status()
        .map_err(|e| format!("failed to restart agentpactd: {e}"))
        .map(|_| ())
}

fn allow_on_daemon_unavailable() -> bool {
    policy_candidates().iter().any(|path| {
        std::fs::read_to_string(path).is_ok_and(|contents| {
            contents
                .lines()
                .any(|line| line.trim() == "on_daemon_unavailable: allow")
        })
    })
}

fn policy_candidates() -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("AGENTPACT_POLICY_FILE") {
        candidates.push(std::path::PathBuf::from(path));
    }
    if let Ok(home) = std::env::var("HOME") {
        let home = std::path::PathBuf::from(home);
        candidates.push(home.join(".agentpact").join("policy").join("pact.yaml"));
        candidates.push(home.join(".agentpact").join("policy").join("caps.yaml"));
    }
    candidates
}

async fn relay_agent_to_server(
    stdin: tokio::io::Stdin,
    mut child_stdin: tokio::process::ChildStdin,
    stdout: SharedStdout,
    server_name: String,
    has_tty: bool,
    socket_timeout: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let bytes = line.as_bytes();
        if framing::is_tools_call(bytes) {
            let tool_name = extract_tool_name(bytes).unwrap_or_default();
            let original_id = extract_request_id(bytes).unwrap_or(serde_json::Value::Null);

            let decision = check_permission(&server_name, &tool_name, has_tty, socket_timeout).await;

            match decision {
                PactDecision::Allow => {
                    child_stdin.write_all(bytes).await?;
                    child_stdin.write_all(b"\n").await?;
                    child_stdin.flush().await?;
                }
                PactDecision::Deny(message) => {
                    let error_response = build_denied_response(&original_id, &message);
                    let mut out = stdout.lock().await;
                    out.write_all(error_response.as_bytes()).await?;
                    out.write_all(b"\n").await?;
                    out.flush().await?;
                }
            }
        } else {
            child_stdin.write_all(bytes).await?;
            child_stdin.write_all(b"\n").await?;
            child_stdin.flush().await?;
        }
    }

    Ok(())
}

async fn relay_server_to_agent(
    child_stdout: tokio::process::ChildStdout,
    stdout: SharedStdout,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reader = BufReader::new(child_stdout);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let mut out = stdout.lock().await;
        out.write_all(line.as_bytes()).await?;
        out.write_all(b"\n").await?;
        out.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn testBuildPermissionRequest() {
        let req = build_permission_request("read_file");
        let v: serde_json::Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "permission.request");
        assert_eq!(v["action"], "call");
        assert_eq!(v["detail"], "read_file");
        let ctx = &v["context"];
        if let Some(dir) = ctx.get("working_dir") {
            assert!(dir.is_string());
        }
        let id = v["id"].as_str().unwrap();
        assert!(id.starts_with("kyris-mcp-"));
    }

    #[test]
    fn testExtractToolName() {
        let msg = br#"{"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
        assert_eq!(extract_tool_name(msg), Some("read_file".to_string()));

        let no_params = br#"{"method":"tools/call"}"#;
        assert_eq!(extract_tool_name(no_params), None);
    }

    #[test]
    fn testExtractRequestId() {
        let msg = br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{}}"#;
        assert_eq!(extract_request_id(msg), Some(serde_json::json!(42)));

        let str_id = br#"{"jsonrpc":"2.0","id":"abc","method":"tools/call"}"#;
        assert_eq!(extract_request_id(str_id), Some(serde_json::json!("abc")));
    }

    #[test]
    fn testBuildDeniedResponse() {
        let resp = build_denied_response(&serde_json::json!(7), "Blocked by policy");
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], -32001);
        assert_eq!(v["error"]["message"], "Blocked by policy");
    }

    #[test]
    fn testParsePermissionRequestResponseOk() {
        let response = serde_json::json!({"code": "PACT_OK", "decision": "auto"});
        assert_eq!(
            parse_permission_request_response(&response),
            PermissionRequestOutcome::Allow
        );
    }

    #[test]
    fn testParsePermissionRequestResponseDenied() {
        let response = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"});
        assert_eq!(
            parse_permission_request_response(&response),
            PermissionRequestOutcome::Deny("blocked by policy".to_string())
        );
    }

    #[test]
    fn testParsePermissionRequestResponseAsk() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_token": "apt_123"
        });
        assert_eq!(
            parse_permission_request_response(&response),
            PermissionRequestOutcome::Ask {
                approval_token: "apt_123".to_string()
            }
        );
    }

    #[test]
    fn testParsePermissionRequestResponseInvalid() {
        let response = serde_json::json!({"result": "UNKNOWN"});
        assert_eq!(
            parse_permission_request_response(&response),
            PermissionRequestOutcome::Deny("invalid response from agentpactd".to_string())
        );
    }

    #[test]
    fn testBuildPermissionRespondRequest() {
        let req = build_permission_respond_request("apt_123", "always");
        let v: serde_json::Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "permission.respond");
        assert_eq!(v["approval_token"], "apt_123");
        assert_eq!(v["response"], "always");
    }

    #[test]
    fn testUserApprovalResponseAllowsExecution() {
        assert!(UserApprovalResponse::Approved.allows_execution());
        assert!(UserApprovalResponse::Always.allows_execution());
        assert!(!UserApprovalResponse::Denied.allows_execution());
    }

    #[tokio::test]
    async fn test_check_permission_ask_without_tty_denies_and_responds() {
        let socket_path = unique_socket_path("ask-deny");
        let listener = UnixListener::bind(&socket_path).expect("bind socket");

        let server = std::thread::spawn(move || {
            for step in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept socket");
                let mut request_body = Vec::new();
                stream.read_to_end(&mut request_body).expect("read request");
                let request: serde_json::Value =
                    serde_json::from_slice(&request_body).expect("parse request");

                let response = match step {
                    0 => {
                        assert_eq!(request["method"], "permission.request");
                        assert_eq!(request["detail"], "read_file");
                        serde_json::json!({
                            "code": "PACT_ASK",
                            "approval_token": "apt_123"
                        })
                    }
                    1 => {
                        assert_eq!(request["method"], "permission.respond");
                        assert_eq!(request["approval_token"], "apt_123");
                        assert_eq!(request["response"], "denied");
                        serde_json::json!({
                            "code": "PACT_DENIED",
                            "reason": "denied"
                        })
                    }
                    _ => unreachable!(),
                };

                stream
                    .write_all(response.to_string().as_bytes())
                    .expect("write response");
            }
        });

        let decision = check_permission_with_socket(
            "test-server",
            "read_file",
            false,
            &socket_path_string(&socket_path),
            std::time::Duration::from_millis(500),
        )
        .await;
        assert_eq!(decision, PactDecision::Deny(no_tty_message()));

        server.join().expect("join server");
        let _ = std::fs::remove_file(&socket_path);
    }

    fn unique_socket_path(name: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "kyris-mcp-{name}-{}-{timestamp}.sock",
            std::process::id()
        ))
    }

    fn socket_path_string(path: &std::path::Path) -> String {
        path.to_string_lossy().to_string()
    }
}
