// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! UDS client for the `AgentPact` daemon. Sends permission requests and
//! trace-attach calls over a Unix domain socket with retry backoff
//! ([50, 100, 250]ms). Falls back to a daemon-unavailable state when
//! `agentpactd` is unreachable.
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

use std::path::PathBuf;
use std::time::Duration;

pub use kyris_core::agentpact::{
    ApprovalResponse, McpPermissionDecision, build_mcp_permission_request,
    build_permission_respond_request, daemon_unavailable_message, default_socket_path,
    parse_mcp_permission_response,
};

const RETRY_BACKOFFS: &[u64] = &[50, 100, 250];

/// Requests `AgentPact` permission for an MCP tool invocation.
///
/// # Errors
///
/// Returns an error when the request cannot be sent to `agentpactd` or when the daemon
/// response is malformed.
pub fn request_mcp_tool_permission(
    socket_path: &str,
    request_id_prefix: &str,
    server_name: &str,
    tool_name: &str,
    working_dir: Option<&str>,
    socket_timeout: Duration,
) -> Result<McpPermissionDecision, String> {
    let request =
        build_mcp_permission_request(request_id_prefix, server_name, tool_name, working_dir);
    send_daemon_request_with_retry(socket_path, &request, socket_timeout)
        .map(|response| parse_mcp_permission_response(&response))
}

/// Sends a `trace.attach` request to `agentpactd`, binding a `trace_token`
/// (from `usage.report`) to a `trace_id` (from kyrisd's gateway record).
///
/// On success, returns the `working_dir` reported by `agentpactd` (if any).
///
/// # Errors
///
/// Returns an error when `agentpactd` is unreachable or rejects the attach.
pub fn send_trace_attach(
    socket_path: &str,
    trace_token: &str,
    trace_id: &str,
    socket_timeout: Option<Duration>,
) -> Result<Option<String>, String> {
    let request = serde_json::json!({
        "id": format!("kyrisd-trace-{}", uuid::Uuid::now_v7()),
        "method": "trace.attach",
        "trace_token": trace_token,
        "trace_id": trace_id,
    });
    let response = send_daemon_request_to_socket(socket_path, &request, socket_timeout)?;
    match response.get("code").and_then(|c| c.as_str()) {
        Some("PACT_OK") => {
            let working_dir = response
                .get("working_dir")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            Ok(working_dir)
        }
        Some(code) => {
            let error = response
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown");
            Err(format!("trace.attach rejected: {code}: {error}"))
        }
        None => Err("trace.attach returned malformed response".to_string()),
    }
}

/// Sends a user approval decision back to `agentpactd`.
///
/// # Errors
///
/// Returns an error when the response cannot be delivered to `agentpactd` or when the
/// daemon rejects the supplied approval token/decision.
pub fn send_permission_response(
    socket_path: &str,
    request_id_prefix: &str,
    approval_token: &str,
    response: ApprovalResponse,
    socket_timeout: Option<Duration>,
) -> Result<(), String> {
    let request = build_permission_respond_request(request_id_prefix, approval_token, response);
    let response_value = send_daemon_request_to_socket(socket_path, &request, socket_timeout)?;
    match parse_mcp_permission_response(&response_value) {
        McpPermissionDecision::Allow => Ok(()),
        McpPermissionDecision::Deny(_) if response == ApprovalResponse::Denied => Ok(()),
        McpPermissionDecision::Deny(reason) => {
            Err(format!("agentpactd rejected approval response: {reason}"))
        }
        McpPermissionDecision::Ask { .. } => {
            Err("agentpactd returned an unexpected ask response".to_string())
        }
    }
}

#[must_use]
pub fn allow_on_daemon_unavailable() -> bool {
    let state_path = daemon_state_path();
    let Some(path) = state_path else {
        return false;
    };
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return false;
    };
    match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(v) => v.get("on_daemon_unavailable").and_then(|val| val.as_str()) == Some("allow"),
        Err(_) => false,
    }
}

fn daemon_state_path() -> Option<PathBuf> {
    if let Ok(sock) = std::env::var("AGENTPACT_SOCK") {
        return std::path::Path::new(&sock)
            .parent()
            .map(|dir| dir.join("daemon.state"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".agentpact").join("daemon.state"))
}

fn send_daemon_request_with_retry(
    socket_path: &str,
    request: &serde_json::Value,
    socket_timeout: Duration,
) -> Result<serde_json::Value, String> {
    let mut attempts = RETRY_BACKOFFS.iter().copied().peekable();
    loop {
        match send_daemon_request_to_socket(socket_path, request, Some(socket_timeout)) {
            Ok(response) => return Ok(response),
            Err(error) => {
                let Some(backoff_ms) = attempts.next() else {
                    return Err(error);
                };
                let _ = restart_agentpactd();
                std::thread::sleep(Duration::from_millis(backoff_ms));
            }
        }
    }
}

#[cfg(unix)]
fn send_daemon_request_to_socket(
    socket_path: &str,
    request: &serde_json::Value,
    socket_timeout: Option<Duration>,
) -> Result<serde_json::Value, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).map_err(|_| daemon_unavailable_message())?;
    let _ = stream.set_read_timeout(socket_timeout);
    let _ = stream.set_write_timeout(socket_timeout);

    let mut payload =
        serde_json::to_vec(request).map_err(|e| format!("failed to serialize request: {e}"))?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|e| format!("failed to send request to agentpactd: {e}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| format!("failed to close request body: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("failed to read response from agentpactd: {e}"))?;
    trim_socket_message(&mut response);
    serde_json::from_slice(&response).map_err(|e| format!("invalid response from agentpactd: {e}"))
}

#[cfg(not(unix))]
fn send_daemon_request_to_socket(
    _socket_path: &str,
    _request: &serde_json::Value,
    _socket_timeout: Option<Duration>,
) -> Result<serde_json::Value, String> {
    Err("UDS not supported on this platform".to_string())
}

fn trim_socket_message(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

fn restart_agentpactd() -> Result<(), String> {
    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|stdout| stdout.trim().parse::<u32>().ok())
        .unwrap_or(0);
    std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &format!("gui/{uid}/is.kyr.agentpactd")])
        .status()
        .map_err(|e| format!("failed to restart agentpactd: {e}"))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testReexportedTypesAccessible() {
        let decision = McpPermissionDecision::Allow;
        assert_eq!(decision, McpPermissionDecision::Allow);

        assert!(ApprovalResponse::Approved.allows_execution());
        assert!(!ApprovalResponse::Denied.allows_execution());
    }

    #[test]
    fn testSendTraceAttachToUnreachableSocketReturnsError() {
        let result = send_trace_attach(
            "/tmp/nonexistent-agentpact.sock",
            "tok-abc",
            "trace-xyz",
            Some(Duration::from_millis(100)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn testBuildAndParseMcpPermissionRoundTrip() {
        let request = build_mcp_permission_request("test", "srv", "tool", Some("/tmp"));
        assert_eq!(request["action"], "call");
        assert_eq!(request["detail"], "tool");

        let ok_resp = serde_json::json!({"code": "PACT_OK"});
        assert_eq!(
            parse_mcp_permission_response(&ok_resp),
            McpPermissionDecision::Allow
        );
    }
}
