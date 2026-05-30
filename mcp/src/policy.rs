// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

use kyris_agentpact_client::{
    self as agentpact, ApprovalResponse as UserApprovalResponse, McpContext, ToolAnnotations,
};

pub use kyris_core::agentpact::DenyCode;

#[derive(Debug, PartialEq)]
pub enum PactDecision {
    Allow,
    Deny {
        code: DenyCode,
        reason: String,
        /// Daemon-supplied recovery hint; `None` means use the static I-05 table.
        hint: Option<String>,
    },
}

type PermissionRequestOutcome = agentpact::McpPermissionDecision;

fn daemon_unavailable_deny() -> PactDecision {
    PactDecision::Deny {
        code: DenyCode::DaemonUnreachable,
        reason: agentpact::daemon_unavailable_message(),
        hint: None,
    }
}

fn no_tty_deny() -> PactDecision {
    PactDecision::Deny {
        code: DenyCode::PolicyDenied,
        reason: "tool requires approval but no terminal is available".to_string(),
        hint: Some(
            "Use 'kyris pending' to approve, adjust policy to 'auto', or run from a terminal"
                .to_string(),
        ),
    }
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
    mcp_operation: Option<&str>,
    annotations: &ToolAnnotations,
    socket_timeout: std::time::Duration,
) -> Result<(PermissionRequestOutcome, String), String> {
    let mcp_ctx = McpContext {
        working_dir: current_working_dir(),
        mcp_operation: mcp_operation.map(str::to_owned),
        annotations: annotations.clone(),
    };
    agentpact::request_mcp_tool_permission_with_id(
        sock_path,
        "kyris-mcp",
        server_name,
        tool_name,
        &mcp_ctx,
        socket_timeout,
    )
}

fn send_permission_response_with_socket(
    sock_path: &str,
    approval_token: &str,
    response: UserApprovalResponse,
    socket_timeout: std::time::Duration,
) -> Result<(), String> {
    // The optional advisory warning (e.g. an "always" grant that could not be
    // persisted) is logged by agentpactd; the MCP wrapper has no inline channel
    // to surface it, so discard it here.
    agentpact::send_permission_response(
        sock_path,
        "kyris-mcp-resp",
        approval_token,
        response,
        Some(socket_timeout),
    )
    .map(|_warning| ())
}

fn prompt_user_tty(server_name: &str, tool_name: &str, allow_always: bool) -> UserApprovalResponse {
    use std::io::{BufRead, Write};

    let Ok(tty_write) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
        return UserApprovalResponse::Denied;
    };
    let Ok(tty_read) = std::fs::OpenOptions::new().read(true).open("/dev/tty") else {
        return UserApprovalResponse::Denied;
    };

    // Offer "always" only when the daemon says a grant would actually persist.
    let choices = if allow_always {
        "[y/n/always]"
    } else {
        "[y/n]"
    };
    let mut writer = std::io::BufWriter::new(tty_write);
    let _ = write!(
        writer,
        "[kyris] allow {server_name}/{tool_name}? {choices} "
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
        // "always" is honored only when persistable; otherwise the daemon
        // would refuse it anyway, so treat it as a one-time approval.
        "a" | "always" => {
            if allow_always {
                UserApprovalResponse::Always
            } else {
                UserApprovalResponse::Approved
            }
        }
        _ => UserApprovalResponse::Denied,
    }
}

pub async fn check_permission(
    server_name: &str,
    tool_name: &str,
    has_tty: bool,
    mcp_operation: Option<&str>,
    annotations: &ToolAnnotations,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let sock_path = agentpact_socket_path();
    check_permission_with_socket(
        server_name,
        tool_name,
        has_tty,
        mcp_operation,
        annotations,
        &sock_path,
        socket_timeout,
    )
    .await
}

pub async fn check_permission_with_socket(
    server_name: &str,
    tool_name: &str,
    has_tty: bool,
    mcp_operation: Option<&str>,
    annotations: &ToolAnnotations,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    if let Err(msg) = agentpact::check_protocol_compatibility() {
        return PactDecision::Deny {
            code: DenyCode::PolicyError,
            reason: msg,
            hint: Some("Check that kyris and agentpactd use the same protocol version".to_string()),
        };
    }

    let tool = tool_name.to_string();
    let server = server_name.to_string();
    let tty = has_tty;
    let socket = sock_path.to_string();
    let timeout = socket_timeout;
    let operation = mcp_operation.map(str::to_owned);
    let ann = annotations.clone();

    let outcome = tokio::task::spawn_blocking(move || {
        send_permission_request_with_socket(
            &socket,
            &server,
            &tool,
            operation.as_deref(),
            &ann,
            timeout,
        )
    })
    .await;

    let Ok(outcome) = outcome else {
        if allow_on_daemon_unavailable() {
            return fail_open_allow(server_name, tool_name);
        }
        return daemon_unavailable_deny();
    };

    // `request_id` is the agentpactd request id (echoed in its response) —
    // logged on a daemon-returned deny so it can be traced to the event.
    let (outcome, request_id) = match outcome {
        Ok((inner, id)) => (Ok(inner), id),
        Err(reason) => (Err(reason), String::new()),
    };

    match outcome {
        Ok(PermissionRequestOutcome::Allow { .. }) => PactDecision::Allow,
        Ok(PermissionRequestOutcome::Deny { code, reason, hint }) => {
            eprintln!(
                "[kyris-mcp] denied {server_name}/{tool_name} (agentpactd id={request_id}, code={code:?}): {reason}"
            );
            PactDecision::Deny { code, reason, hint }
        }
        Ok(PermissionRequestOutcome::Ask {
            approval_id,
            approval_token,
            allow_always,
        }) => {
            if tty {
                resolve_ask_via_tty(
                    server_name,
                    tool_name,
                    &approval_token,
                    allow_always,
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
                    allow_always,
                    sock_path,
                    socket_timeout,
                )
                .await
            }
        }
        Err(_) if allow_on_daemon_unavailable() => fail_open_allow(server_name, tool_name),
        Err(reason) => PactDecision::Deny {
            code: DenyCode::DaemonUnreachable,
            reason,
            hint: None,
        },
    }
}

/// Fail-open path: agentpactd is unreachable but policy says allow. Logs the
/// allow and records a fail-open event, then allows the tool call.
fn fail_open_allow(server_name: &str, tool_name: &str) -> PactDecision {
    eprintln!(
        "[kyris-mcp] agentpactd unavailable, allowing {server_name}/{tool_name} due to policy"
    );
    kyris_core::fail_open_log::record(
        "call",
        tool_name,
        server_name,
        current_working_dir().as_deref(),
    );
    PactDecision::Allow
}

async fn resolve_ask_via_tty(
    server_name: &str,
    tool_name: &str,
    approval_token: &str,
    allow_always: bool,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let server = server_name.to_string();
    let tool = tool_name.to_string();
    let token = approval_token.to_string();
    let socket = sock_path.to_string();
    let timeout = socket_timeout;

    let decision = tokio::task::spawn_blocking(move || {
        let user_response = prompt_user_tty(&server, &tool, allow_always);
        match send_permission_response_with_socket(&socket, &token, user_response, timeout) {
            Ok(()) if user_response.allows_execution() => PactDecision::Allow,
            Ok(()) => PactDecision::Deny {
                code: DenyCode::PolicyDenied,
                reason: "User denied".to_string(),
                hint: None,
            },
            Err(reason) => PactDecision::Deny {
                code: DenyCode::DaemonUnreachable,
                reason,
                hint: None,
            },
        }
    })
    .await;

    decision.unwrap_or_else(|_| daemon_unavailable_deny())
}

async fn resolve_ask_via_kyrisd(
    approval_id: &str,
    approval_token: &str,
    server_name: &str,
    tool_name: &str,
    allow_always: bool,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) -> PactDecision {
    let conn = kyris_core::config::load_kyrisd_connection();
    let Some(conn) = conn else {
        return deny_ask_immediately(approval_token, sock_path, socket_timeout).await;
    };

    let client = reqwest::Client::new();

    eprintln!(
        "[kyris-mcp] {server_name}/{tool_name} held for approval — resolve with 'kyris pending'"
    );

    let resolution = kyris_core::pending::hold_poll_resolve(
        &client,
        &conn,
        kyris_core::pending::PendingApproval {
            approval_id,
            approval_token,
            server: server_name,
            tool: tool_name,
            // MCP tool calls don't carry a verbatim "code" payload here;
            // the daemon falls back to plain-text informativeText. Adding
            // the serialized args is a follow-up.
            code: None,
            // Authoritative server signal: only offer "Always" when the daemon
            // would actually persist the grant (e.g. not a non-cacheable call).
            allow_always,
        },
    )
    .await;

    match resolution {
        kyris_core::pending::Resolution::Approved => PactDecision::Allow,
        kyris_core::pending::Resolution::Denied => no_tty_deny(),
        // No-TTY MCP has no agent prompt to defer to, so a couldn't-render
        // (`Unreachable`) and a rendered-then-lost (`Failed`) both deny.
        kyris_core::pending::Resolution::Unreachable
        | kyris_core::pending::Resolution::Failed(_) => {
            deny_ask_immediately(approval_token, sock_path, socket_timeout).await
        }
    }
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
    no_tty_deny()
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
            &agentpact::McpContext {
                working_dir: Some("/tmp/repo".to_string()),
                mcp_operation: Some("tools/call".to_string()),
                annotations: ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: None,
                },
            },
        );
        assert_eq!(req["method"], "permission.request");
        assert_eq!(req["action"], "call");
        assert_eq!(req["detail"], "read_file");
        assert_eq!(req["context"]["mcp_server"], "github");
        assert_eq!(req["context"]["working_dir"], "/tmp/repo");
        assert_eq!(req["context"]["mcp_operation"], "tools/call");
        assert_eq!(req["context"]["read_only_hint"], true);
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
        use kyris_agentpact_client::Mode;
        let response =
            serde_json::json!({"code": "PACT_OK", "decision": "auto", "mode": "enforce"});
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Allow {
                mode: Mode::Enforce
            }
        );
    }

    #[test]
    fn testParsePermissionRequestResponseDenied() {
        let response = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"});
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Deny {
                code: DenyCode::PolicyDenied,
                reason: "blocked by policy".to_string(),
                hint: None,
            }
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
                approval_token: "apt_123".to_string(),
                allow_always: false,
            }
        );
    }

    #[test]
    fn testParsePermissionRequestResponseInvalid() {
        let response = serde_json::json!({"result": "UNKNOWN"});
        assert_eq!(
            agentpact::parse_mcp_permission_response(&response),
            PermissionRequestOutcome::Deny {
                code: DenyCode::PolicyError,
                reason: "invalid response from agentpactd".to_string(),
                hint: None,
            }
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
            Some("tools/call"),
            &ToolAnnotations::default(),
            &socket_path_string(&socket_path),
            std::time::Duration::from_millis(500),
        )
        .await;
        assert!(matches!(
            decision,
            PactDecision::Deny {
                code: DenyCode::PolicyDenied,
                ..
            }
        ));

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
            Some("tools/call"),
            &ToolAnnotations::default(),
            "/nonexistent/path.sock",
            std::time::Duration::from_millis(100),
        )
        .await;
        assert!(matches!(decision, PactDecision::Deny { .. }));
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
            Some("tools/call"),
            &ToolAnnotations::default(),
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
            Some("tools/call"),
            &ToolAnnotations::default(),
            &socket_path_string(&socket_path),
            std::time::Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            decision,
            PactDecision::Deny {
                code: DenyCode::PolicyDenied,
                reason: "blocked by admin".to_string(),
                hint: None,
            }
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
