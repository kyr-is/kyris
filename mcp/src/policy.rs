// SPDX-License-Identifier: Apache-2.0

use kyris_agentpact_client::{self as agentpact, ApprovalResponse as UserApprovalResponse};

#[derive(Debug, PartialEq)]
pub enum PactDecision {
    Allow,
    Deny(String),
}

type PermissionRequestOutcome = agentpact::McpPermissionDecision;

fn daemon_unavailable_message() -> String {
    agentpact::daemon_unavailable_message()
}

fn no_tty_message() -> String {
    "Kyris: tool requires approval but no terminal is available. Use 'kyris pending' to approve, adjust policy to 'auto', or run from a terminal."
        .to_string()
}

fn agentpact_socket_path() -> String {
    agentpact::default_socket_path().display().to_string()
}

fn current_working_dir() -> Option<String> {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));
    match cwd {
        Some(dir) if !dir.is_empty() => Some(dir),
        _ => None,
    }
}

fn send_permission_request_with_socket(
    sock_path: &str,
    server_name: &str,
    tool_name: &str,
    socket_timeout: std::time::Duration,
) -> Result<PermissionRequestOutcome, String> {
    let working_dir = current_working_dir();
    agentpact::request_mcp_tool_permission(
        sock_path,
        "kyris-mcp",
        server_name,
        tool_name,
        working_dir.as_deref(),
        socket_timeout,
    )
}

fn send_permission_response_with_socket(
    sock_path: &str,
    approval_token: &str,
    response: UserApprovalResponse,
    socket_timeout: std::time::Duration,
) -> Result<(), String> {
    agentpact::send_permission_response(
        sock_path,
        "kyris-mcp-resp",
        approval_token,
        response,
        Some(socket_timeout),
    )
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

pub async fn check_permission(
    server_name: &str,
    tool_name: &str,
    has_tty: bool,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let sock_path = agentpact_socket_path();
    check_permission_with_socket(server_name, tool_name, has_tty, &sock_path, socket_timeout).await
}

pub async fn check_permission_with_socket(
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

    let outcome = tokio::task::spawn_blocking(move || {
        send_permission_request_with_socket(&socket, &server, &tool, timeout)
    })
    .await;

    let Ok(outcome) = outcome else {
        if allow_on_daemon_unavailable() {
            return PactDecision::Allow;
        }
        return PactDecision::Deny(daemon_unavailable_message());
    };

    match outcome {
        Ok(PermissionRequestOutcome::Allow) => PactDecision::Allow,
        Ok(PermissionRequestOutcome::Deny(reason)) => {
            PactDecision::Deny(format!("Blocked by policy: {reason}"))
        }
        Ok(PermissionRequestOutcome::Ask {
            approval_id,
            approval_token,
        }) => {
            if tty {
                resolve_ask_via_tty(
                    server_name,
                    tool_name,
                    &approval_token,
                    sock_path,
                    socket_timeout,
                )
                .await
            } else {
                resolve_ask_via_kyrisd(
                    &approval_id,
                    &approval_token,
                    server_name,
                    tool_name,
                    sock_path,
                    socket_timeout,
                )
                .await
            }
        }
        Err(_) if allow_on_daemon_unavailable() => PactDecision::Allow,
        Err(reason) => PactDecision::Deny(reason),
    }
}

async fn resolve_ask_via_tty(
    server_name: &str,
    tool_name: &str,
    approval_token: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let server = server_name.to_string();
    let tool = tool_name.to_string();
    let token = approval_token.to_string();
    let socket = sock_path.to_string();
    let timeout = socket_timeout;

    let decision = tokio::task::spawn_blocking(move || {
        let user_response = prompt_user_tty(&server, &tool);
        match send_permission_response_with_socket(&socket, &token, user_response, timeout) {
            Ok(()) if user_response.allows_execution() => PactDecision::Allow,
            Ok(()) => PactDecision::Deny("Blocked by policy".to_string()),
            Err(reason) => PactDecision::Deny(reason),
        }
    })
    .await;

    decision.unwrap_or_else(|_| PactDecision::Deny(daemon_unavailable_message()))
}

const KYRISD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const KYRISD_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

async fn resolve_ask_via_kyrisd(
    approval_id: &str,
    approval_token: &str,
    server_name: &str,
    tool_name: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let conn = kyris_core::config::load_kyrisd_connection();
    let Some(conn) = conn else {
        return deny_ask_immediately(approval_token, sock_path, socket_timeout).await;
    };

    let client = reqwest::Client::new();
    let hold_body = serde_json::json!({
        "id": approval_id,
        "approval_token": approval_token,
        "server": server_name,
        "tool": tool_name,
    });

    let hold_result = client
        .post(format!("{}/api/pending/hold", conn.base_url))
        .header("authorization", format!("Bearer {}", conn.operator_key))
        .json(&hold_body)
        .send()
        .await;

    if hold_result.is_err() || !hold_result.as_ref().unwrap().status().is_success() {
        return deny_ask_immediately(approval_token, sock_path, socket_timeout).await;
    }

    eprintln!(
        "[kyris-mcp] {server_name}/{tool_name} held for approval — resolve with 'kyris pending'"
    );

    let deadline = tokio::time::Instant::now() + KYRISD_POLL_TIMEOUT;
    loop {
        tokio::time::sleep(KYRISD_POLL_INTERVAL).await;
        if tokio::time::Instant::now() >= deadline {
            cancel_held_request(&client, &conn.base_url, &conn.operator_key, approval_id).await;
            return deny_ask_immediately(approval_token, sock_path, socket_timeout).await;
        }

        let status_result = client
            .get(format!(
                "{}/api/pending/{}/status",
                conn.base_url, approval_id
            ))
            .header("authorization", format!("Bearer {}", conn.operator_key))
            .send()
            .await;

        let Ok(resp) = status_result else {
            continue;
        };
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };

        match body.get("state").and_then(|s| s.as_str()) {
            Some("held") => {}
            Some("approved") => return PactDecision::Allow,
            Some("denied") => return PactDecision::Deny(no_tty_message()),
            _ => {
                cancel_held_request(&client, &conn.base_url, &conn.operator_key, approval_id).await;
                return deny_ask_immediately(approval_token, sock_path, socket_timeout).await;
            }
        }
    }
}

async fn cancel_held_request(
    client: &reqwest::Client,
    base_url: &str,
    operator_key: &str,
    pending_id: &str,
) {
    let url = format!("{base_url}/api/pending/{pending_id}/cancel");
    let _ = client
        .delete(&url)
        .header("authorization", format!("Bearer {operator_key}"))
        .send()
        .await;
}

async fn deny_ask_immediately(
    approval_token: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let token = approval_token.to_string();
    let socket = sock_path.to_string();
    let timeout = socket_timeout;
    let result = tokio::task::spawn_blocking(move || {
        send_permission_response_with_socket(&socket, &token, UserApprovalResponse::Denied, timeout)
    })
    .await;
    match result {
        Ok(Err(e)) => eprintln!("[kyris-mcp] failed to send deny to agentpactd: {e}"),
        Err(e) => eprintln!("[kyris-mcp] deny task panicked: {e}"),
        Ok(Ok(())) => {}
    }
    PactDecision::Deny(no_tty_message())
}

fn allow_on_daemon_unavailable() -> bool {
    agentpact::allow_on_daemon_unavailable()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn testBuildPermissionRequest() {
        let req = agentpact::build_mcp_permission_request(
            "kyris-mcp",
            "github",
            "read_file",
            Some("/tmp/repo"),
        );
        assert_eq!(req["method"], "permission.request");
        assert_eq!(req["action"], "call");
        assert_eq!(req["detail"], "read_file");
        assert_eq!(req["context"]["mcp_server"], "github");
        assert_eq!(req["context"]["working_dir"], "/tmp/repo");
        let id = req["id"].as_str().unwrap();
        assert!(id.starts_with("kyris-mcp-"));
    }

    #[test]
    fn testBuildPermissionRespondRequest() {
        let req = agentpact::build_permission_respond_request(
            "kyris-mcp-resp",
            "apt_123",
            UserApprovalResponse::Always,
        );
        assert_eq!(req["method"], "permission.respond");
        assert_eq!(req["approval_token"], "apt_123");
        assert_eq!(req["response"], "always");
    }

    #[test]
    fn testParsePermissionRequestResponseOk() {
        let response = serde_json::json!({"code": "PACT_OK", "decision": "auto"});
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Allow
        );
    }

    #[test]
    fn testParsePermissionRequestResponseDenied() {
        let response = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"});
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Deny("blocked by policy".to_string())
        );
    }

    #[test]
    fn testParsePermissionRequestResponseAsk() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "req-42",
            "approval_token": "apt_123"
        });
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Ask {
                approval_id: "req-42".to_string(),
                approval_token: "apt_123".to_string()
            }
        );
    }

    #[test]
    fn testParsePermissionRequestResponseInvalid() {
        let response = serde_json::json!({"result": "UNKNOWN"});
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Deny("invalid response from agentpactd".to_string())
        );
    }

    #[test]
    fn testUserApprovalResponseAllowsExecution() {
        assert!(UserApprovalResponse::Approved.allows_execution());
        assert!(UserApprovalResponse::Always.allows_execution());
        assert!(!UserApprovalResponse::Denied.allows_execution());
    }

    #[tokio::test]
    async fn testCheckPermissionAskWithoutTtyDeniesAndResponds() {
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
                        assert_eq!(request["context"]["mcp_server"], "test-server");
                        serde_json::json!({
                            "code": "PACT_ASK",
                            "approval_id": "req-42",
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

    #[test]
    fn testAgentpactSocketPathUsesEnvVar() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("AGENTPACT_SOCK", "/custom/sock.path") };
        let path = agentpact_socket_path();
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
        assert_eq!(path, "/custom/sock.path");
    }

    #[test]
    fn testAgentpactSocketPathFallsBackToHome() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
        let path = agentpact_socket_path();
        assert!(path.ends_with(".agentpact/agentpact.sock"));
    }

    #[test]
    fn testAllowOnDaemonUnavailableWithStateFile() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join("daemon.state");
        std::fs::write(
            &state_file,
            r#"{"on_daemon_unavailable":"allow","on_log_broken":"continue"}"#,
        )
        .unwrap();
        let sock = dir.path().join("agentpact.sock");
        unsafe { std::env::set_var("AGENTPACT_SOCK", sock.to_str().unwrap()) };
        assert!(allow_on_daemon_unavailable());
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
    }

    #[test]
    fn testAllowOnDaemonUnavailableDenyByDefault() {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };
        assert!(!allow_on_daemon_unavailable());
    }

    #[test]
    fn testAllowOnDaemonUnavailableBlockFromStateFile() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join("daemon.state");
        std::fs::write(
            &state_file,
            r#"{"on_daemon_unavailable":"block","on_log_broken":"continue"}"#,
        )
        .unwrap();
        let sock = dir.path().join("agentpact.sock");
        unsafe { std::env::set_var("AGENTPACT_SOCK", sock.to_str().unwrap()) };
        assert!(!allow_on_daemon_unavailable());
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
    }

    #[tokio::test]
    async fn testCheckPermissionDaemonUnreachableDenies() {
        {
            let _lock = ENV_MUTEX.lock().unwrap();
            unsafe { std::env::remove_var("AGENTPACT_POLICY_FILE") };
        }
        let decision = check_permission_with_socket(
            "test-server",
            "dangerous_tool",
            true,
            "/nonexistent/path.sock",
            std::time::Duration::from_millis(100),
        )
        .await;
        assert!(matches!(decision, PactDecision::Deny(_)));
    }

    #[tokio::test]
    async fn testCheckPermissionAllowPath() {
        let socket_path = unique_socket_path("allow");
        let listener = UnixListener::bind(&socket_path).expect("bind socket");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut req = Vec::new();
            stream.read_to_end(&mut req).expect("read");
            let response = serde_json::json!({"code": "PACT_OK", "decision": "auto"});
            stream
                .write_all(response.to_string().as_bytes())
                .expect("write");
        });

        let decision = check_permission_with_socket(
            "test-server",
            "read_file",
            false,
            &socket_path_string(&socket_path),
            std::time::Duration::from_millis(500),
        )
        .await;
        assert_eq!(decision, PactDecision::Allow);
        server.join().expect("join");
        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn testCheckPermissionDenyPath() {
        let socket_path = unique_socket_path("deny");
        let listener = UnixListener::bind(&socket_path).expect("bind socket");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut req = Vec::new();
            stream.read_to_end(&mut req).expect("read");
            let response = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by admin"});
            stream
                .write_all(response.to_string().as_bytes())
                .expect("write");
        });

        let decision = check_permission_with_socket(
            "test-server",
            "write_file",
            true,
            &socket_path_string(&socket_path),
            std::time::Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            decision,
            PactDecision::Deny("Blocked by policy: blocked by admin".to_string())
        );
        server.join().expect("join");
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
