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
    ApprovalResponse, DenyCode, McpContext, McpPermissionDecision, ToolAnnotations,
    daemon_unavailable_message, default_socket_path,
};

/// Builds a `permission.request` for an agent hook action (native hooks).
///
/// The hook flow sends one of `execute`/`read`/`write`/`call` plus a free-form
/// detail string and an optional `working_dir`. `seed_boundary_pid`, when
/// supplied, registers the caller's PID as a boundary anchor — agentpactd
/// validates ancestry and signature-table match before honoring it.
#[must_use]
pub fn build_hook_permission_request(
    request_id_prefix: &str,
    action: &str,
    detail: &str,
    working_dir: Option<&str>,
    seed_boundary_pid: Option<u32>,
) -> serde_json::Value {
    let mut context = serde_json::json!({});
    if let Some(dir) = working_dir {
        context["working_dir"] = serde_json::json!(dir);
    }
    let mut request = serde_json::json!({
        "id": format!("{request_id_prefix}-{}", uuid::Uuid::now_v7()),
        "method": "permission.request",
        "action": action,
        "detail": detail,
        "context": context,
    });
    if let Some(pid) = seed_boundary_pid {
        request["seed_boundary_pid"] = serde_json::json!(pid);
    }
    request
}

/// Builds a `permission.request` for an MCP tool invocation.
///
/// MCP requests always carry `action: "call"`, the server name in
/// `context.mcp_server`, and any read-only / destructive hints from the
/// tool's MCP annotations.
#[must_use]
pub fn build_mcp_permission_request(
    request_id_prefix: &str,
    server_name: &str,
    tool_name: &str,
    mcp_ctx: &McpContext,
) -> serde_json::Value {
    let mut context = serde_json::json!({
        "mcp_server": server_name,
    });
    if let Some(ref dir) = mcp_ctx.working_dir {
        context["working_dir"] = serde_json::json!(dir);
    }
    if let Some(ref op) = mcp_ctx.mcp_operation {
        context["mcp_operation"] = serde_json::json!(op);
    }
    if let Some(ro) = mcp_ctx.annotations.read_only_hint {
        context["read_only_hint"] = serde_json::json!(ro);
    }
    if let Some(d) = mcp_ctx.annotations.destructive_hint {
        context["destructive_hint"] = serde_json::json!(d);
    }
    serde_json::json!({
        "id": format!("{request_id_prefix}-{}", uuid::Uuid::now_v7()),
        "method": "permission.request",
        "action": "call",
        "detail": tool_name,
        "context": context,
    })
}

/// Builds a `permission.respond` to deliver a user decision back to agentpactd.
#[must_use]
pub fn build_permission_respond_request(
    request_id_prefix: &str,
    approval_token: &str,
    response: ApprovalResponse,
) -> serde_json::Value {
    serde_json::json!({
        "id": format!("{request_id_prefix}-{}", uuid::Uuid::now_v7()),
        "method": "permission.respond",
        "approval_token": approval_token,
        "response": response.as_agentpact_response(),
    })
}

/// Parses an agentpactd permission response into a typed `McpPermissionDecision`.
///
/// Maps `PACT_OK` → `Allow`, `PACT_DENIED` → `Deny{PolicyDenied}`,
/// `PACT_ASK` → `Ask{id, token}`, `PACT_POLICY_ERROR`/`PACT_PROTOCOL_ERROR`
/// → `Deny{PolicyError}` (surfacing recovery hint when present),
/// `PACT_CAP_EXCEEDED` → `Deny{CapExceeded}`, anything else → `Deny{PolicyError}`.
#[must_use]
pub fn parse_mcp_permission_response(response: &serde_json::Value) -> McpPermissionDecision {
    match response.get("code").and_then(|code| code.as_str()) {
        Some("PACT_OK") => McpPermissionDecision::Allow,
        Some("PACT_DENIED") => {
            let reason = response
                .get("reason")
                .or_else(|| response.get("error"))
                .and_then(|value| value.as_str())
                .unwrap_or("denied by policy")
                .to_string();
            McpPermissionDecision::Deny {
                code: DenyCode::PolicyDenied,
                reason,
                hint: None,
            }
        }
        Some("PACT_ASK") => {
            let approval_id = response
                .get("approval_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            let approval_token = response
                .get("approval_token")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            if approval_id.is_empty() || approval_token.is_empty() {
                McpPermissionDecision::Deny {
                    code: DenyCode::PolicyError,
                    reason: "invalid approval response from agentpactd".to_string(),
                    hint: None,
                }
            } else {
                McpPermissionDecision::Ask {
                    approval_id,
                    approval_token,
                }
            }
        }
        Some("PACT_POLICY_ERROR" | "PACT_PROTOCOL_ERROR") => {
            let reason = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            let hint = response
                .get("recovery_hint")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            McpPermissionDecision::Deny {
                code: DenyCode::PolicyError,
                reason,
                hint,
            }
        }
        Some("PACT_CAP_EXCEEDED") => {
            let reason = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            let hint = response
                .get("recovery_hint")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            McpPermissionDecision::Deny {
                code: DenyCode::CapExceeded,
                reason,
                hint,
            }
        }
        _ => McpPermissionDecision::Deny {
            code: DenyCode::PolicyError,
            reason: "invalid response from agentpactd".to_string(),
            hint: None,
        },
    }
}

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
    mcp_ctx: &McpContext,
    socket_timeout: Duration,
) -> Result<McpPermissionDecision, String> {
    let request = build_mcp_permission_request(request_id_prefix, server_name, tool_name, mcp_ctx);
    send_daemon_request_with_retry(socket_path, &request, socket_timeout)
        .map(|response| parse_mcp_permission_response(&response))
}

/// Requests `AgentPact` permission for an agent hook action (native hooks).
///
/// Unlike `request_mcp_tool_permission`, this preserves the `HookProtocol`-mapped
/// action (execute/read/write/call) and sends only `working_dir` in context — no
/// `mcp_server` field. When `seed_boundary_pid` is provided, the daemon will
/// attempt to register the given PID as a boundary anchor after validating
/// ancestry and signature table match.
///
/// Returns the decision plus the daemon-reported compound `segments` (Some only
/// when the daemon split a compound shell command into more than one segment).
/// Callers that don't care about segments can ignore the second tuple element.
///
/// # Errors
///
/// Returns an error when the request cannot be sent to `agentpactd` or when the daemon
/// response is malformed.
pub fn request_hook_permission(
    socket_path: &str,
    request_id_prefix: &str,
    action: &str,
    detail: &str,
    working_dir: Option<&str>,
    seed_boundary_pid: Option<u32>,
    socket_timeout: Duration,
) -> Result<(McpPermissionDecision, Option<Vec<String>>), String> {
    let request = build_hook_permission_request(
        request_id_prefix,
        action,
        detail,
        working_dir,
        seed_boundary_pid,
    );
    send_daemon_request_with_retry(socket_path, &request, socket_timeout).map(|response| {
        let decision = parse_mcp_permission_response(&response);
        let segments = parse_response_segments(&response);
        (decision, segments)
    })
}

/// Extracts the `segments` array from an agentpactd permission response, if
/// present. Returns `None` for non-execute actions, single-segment commands,
/// and fail-closed parses — i.e. whenever the daemon decided segmentation
/// added no information beyond `detail` itself.
#[must_use]
pub fn parse_response_segments(response: &serde_json::Value) -> Option<Vec<String>> {
    response
        .get("segments")?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect()
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
        McpPermissionDecision::Deny { .. } if response == ApprovalResponse::Denied => Ok(()),
        McpPermissionDecision::Deny { reason, .. } => {
            Err(format!("agentpactd rejected approval response: {reason}"))
        }
        McpPermissionDecision::Ask { .. } => {
            Err("agentpactd returned an unexpected ask response".to_string())
        }
    }
}

pub const PROTOCOL_VERSION: u64 = 1;

#[must_use]
pub fn allow_on_daemon_unavailable() -> bool {
    let state = read_daemon_state();
    state
        .as_ref()
        .and_then(|v| v.get("on_daemon_unavailable"))
        .and_then(|val| val.as_str())
        == Some("allow")
}

/// Reads `daemon.state` and checks that `protocol_version` matches
/// `PROTOCOL_VERSION`. Missing state file or missing field = Ok (pass-through).
///
/// # Errors
///
/// Returns a human-readable upgrade instruction when versions diverge.
pub fn check_protocol_compatibility() -> Result<(), String> {
    let Some(state) = read_daemon_state() else {
        return Ok(());
    };
    check_daemon_protocol_version(&state)
}

/// Pure protocol version check against a parsed `daemon.state` value.
/// Missing `protocol_version` field = Ok.
///
/// # Errors
///
/// Returns a human-readable upgrade instruction when versions diverge.
pub fn check_daemon_protocol_version(state: &serde_json::Value) -> Result<(), String> {
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
            "agentpactd protocol version {version} is newer than kyris expects ({PROTOCOL_VERSION}). \
             Upgrade kyris: brew upgrade kyris"
        ))
    } else {
        Err(format!(
            "agentpactd protocol version {version} is older than kyris expects ({PROTOCOL_VERSION}). \
             Upgrade agentpact: brew upgrade agentpact"
        ))
    }
}

fn read_daemon_state() -> Option<serde_json::Value> {
    let path = daemon_state_path()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn daemon_state_path() -> Option<PathBuf> {
    // Override 1: explicit socket path → daemon.state is in the same dir.
    // Useful for test harnesses that point everything at a tempdir.
    if let Ok(sock) = std::env::var("AGENTPACT_SOCK") {
        return std::path::Path::new(&sock)
            .parent()
            .map(|dir| dir.join("daemon.state"));
    }
    // Override 2: XDG_STATE_HOME — agentpact moved daemon.state under
    // XDG_STATE_HOME with its XDG migration. Honor it directly.
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return Some(PathBuf::from(state).join("agentpact").join("daemon.state"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("agentpact")
            .join("daemon.state"),
    )
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
        .args(["kickstart", &format!("gui/{uid}/is.kyr.agentpactd")])
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
        let request = build_mcp_permission_request(
            "test",
            "srv",
            "tool",
            &McpContext {
                working_dir: Some("/tmp".to_string()),
                mcp_operation: Some("tools/call".to_string()),
                ..McpContext::default()
            },
        );
        assert_eq!(request["action"], "call");
        assert_eq!(request["detail"], "tool");
        assert_eq!(request["context"]["mcp_operation"], "tools/call");

        let ok_resp = serde_json::json!({"code": "PACT_OK"});
        assert_eq!(
            parse_mcp_permission_response(&ok_resp),
            McpPermissionDecision::Allow
        );
    }

    #[test]
    fn testProtocolVersionMatchingIsOk() {
        let state = serde_json::json!({"protocol_version": 1});
        assert!(check_daemon_protocol_version(&state).is_ok());
    }

    #[test]
    fn testProtocolVersionNewerDaemonSuggestsUpgradeKyris() {
        let state = serde_json::json!({"protocol_version": 99});
        let err = check_daemon_protocol_version(&state).unwrap_err();
        assert!(err.contains("Upgrade kyris"), "{err}");
        assert!(err.contains("99"), "{err}");
    }

    #[test]
    fn testProtocolVersionOlderDaemonSuggestsUpgradeAgentpact() {
        let state = serde_json::json!({"protocol_version": 0});
        let err = check_daemon_protocol_version(&state).unwrap_err();
        assert!(err.contains("Upgrade agentpact"), "{err}");
    }

    #[test]
    fn testProtocolVersionMissingFieldIsOk() {
        let state = serde_json::json!({"on_daemon_unavailable": "block"});
        assert!(check_daemon_protocol_version(&state).is_ok());
    }

    #[test]
    fn testProtocolVersionNullFieldIsOk() {
        let state = serde_json::json!({"protocol_version": null});
        assert!(check_daemon_protocol_version(&state).is_ok());
    }

    #[test]
    fn testCheckProtocolCompatibilityMissingStateFileIsOk() {
        let _ = check_protocol_compatibility();
    }

    // --- Wire-message builder/parser tests (moved from kyris-core when the
    // builders themselves were lifted here so kyris-agentpact-client is the
    // single audited path that constructs agentpactd wire messages). ---

    #[test]
    fn testBuildMcpPermissionRequest() {
        let request = build_mcp_permission_request(
            "kyris-mcp",
            "github",
            "read_file",
            &McpContext {
                working_dir: Some("/tmp/repo".to_string()),
                mcp_operation: Some("tools/call".to_string()),
                annotations: ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: None,
                },
            },
        );
        assert_eq!(request["method"], "permission.request");
        assert_eq!(request["action"], "call");
        assert_eq!(request["detail"], "read_file");
        assert_eq!(request["context"]["mcp_server"], "github");
        assert_eq!(request["context"]["working_dir"], "/tmp/repo");
        assert_eq!(request["context"]["mcp_operation"], "tools/call");
        assert_eq!(request["context"]["read_only_hint"], true);
        assert!(request["context"]["destructive_hint"].is_null());
        assert!(
            request["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("kyris-mcp-"))
        );
    }

    #[test]
    fn testBuildHookPermissionRequest() {
        let request = build_hook_permission_request(
            "kyris-hook",
            "execute",
            "ls -la",
            Some("/tmp/repo"),
            None,
        );
        assert_eq!(request["method"], "permission.request");
        assert_eq!(request["action"], "execute");
        assert_eq!(request["detail"], "ls -la");
        assert_eq!(request["context"]["working_dir"], "/tmp/repo");
        assert!(request["context"]["mcp_server"].is_null());
        assert!(request["seed_boundary_pid"].is_null());
        assert!(
            request["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("kyris-hook-"))
        );
    }

    #[test]
    fn testBuildHookPermissionRequestNoWorkingDir() {
        let request = build_hook_permission_request("kyris-hook", "call", "unknown", None, None);
        assert_eq!(request["action"], "call");
        assert!(request["context"]["working_dir"].is_null());
    }

    #[test]
    fn testBuildHookPermissionRequestWithSeedPid() {
        let request = build_hook_permission_request(
            "kyris-hook",
            "execute",
            "git status",
            Some("/tmp"),
            Some(12345),
        );
        assert_eq!(request["seed_boundary_pid"], 12345);
    }

    #[test]
    fn testBuildPermissionRespondRequest() {
        let request =
            build_permission_respond_request("kyris-mcp-resp", "apt_123", ApprovalResponse::Always);
        assert_eq!(request["method"], "permission.respond");
        assert_eq!(request["approval_token"], "apt_123");
        assert_eq!(request["response"], "always");
        assert!(
            request["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("kyris-mcp-resp-"))
        );
    }

    #[test]
    fn testParseMcpPermissionResponseAllow() {
        let response = serde_json::json!({"code": "PACT_OK", "decision": "auto"});
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Allow
        );
    }

    #[test]
    fn testParseMcpPermissionResponseDeny() {
        let response = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"});
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Deny {
                code: DenyCode::PolicyDenied,
                reason: "blocked by policy".to_string(),
                hint: None,
            }
        );
    }

    #[test]
    fn testParseMcpPermissionResponseAsk() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "req-42",
            "approval_token": "apt_123"
        });
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Ask {
                approval_id: "req-42".to_string(),
                approval_token: "apt_123".to_string(),
            }
        );
    }

    #[test]
    fn testParsePolicyErrorSurfacesErrorAndHint() {
        let response = serde_json::json!({
            "code": "PACT_POLICY_ERROR",
            "error": "malformed pact.yaml",
            "recovery_hint": "Fix policy files: run agentpactd schema to validate"
        });
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Deny {
                code: DenyCode::PolicyError,
                reason: "malformed pact.yaml".to_string(),
                hint: Some("Fix policy files: run agentpactd schema to validate".to_string()),
            }
        );
    }

    #[test]
    fn testParseProtocolErrorSurfacesError() {
        let response = serde_json::json!({
            "code": "PACT_PROTOCOL_ERROR",
            "error": "missing method field"
        });
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Deny {
                code: DenyCode::PolicyError,
                reason: "missing method field".to_string(),
                hint: None,
            }
        );
    }

    #[test]
    fn testParseResponseSegmentsPresent() {
        let response = serde_json::json!({
            "code": "PACT_OK",
            "segments": ["ls /tmp", "echo hi"]
        });
        assert_eq!(
            parse_response_segments(&response),
            Some(vec!["ls /tmp".to_string(), "echo hi".to_string()])
        );
    }

    #[test]
    fn testParseResponseSegmentsAbsent() {
        let response = serde_json::json!({"code": "PACT_OK"});
        assert_eq!(parse_response_segments(&response), None);
    }

    #[test]
    fn testParseCapExceededSurfacesError() {
        let response = serde_json::json!({
            "code": "PACT_CAP_EXCEEDED",
            "error": "daily premium cap reached",
            "recovery_hint": "Wait until 2026-01-02T00:00:00Z or adjust caps policy"
        });
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Deny {
                code: DenyCode::CapExceeded,
                reason: "daily premium cap reached".to_string(),
                hint: Some("Wait until 2026-01-02T00:00:00Z or adjust caps policy".to_string()),
            }
        );
    }
}
