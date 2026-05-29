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
// `Mode` is the wire value type canonically defined by agentpact
// (the server crate's policy engine owns the semantics). Re-export
// from `agentpact-types` so external consumers can continue to
// `use kyris_agentpact_client::Mode` without a separate import.
pub use agentpact_types::Mode;

/// Builds a `permission.request` for an agent hook action (native hooks).
///
/// The hook flow sends one of `execute`/`read`/`write`/`call` plus a free-form
/// detail string and an optional `working_dir`. `seed_boundary_pid`, when
/// supplied, registers the caller's PID as a boundary anchor — agentpactd
/// validates ancestry and signature-table match before honoring it.
///
/// `anchor_pid`, when supplied, asks agentpactd to tag the `exec_token` issued
/// on this request with that PID, so a later request from a descendant of
/// `anchor_pid` can consume the token via `ppid_chain` without holding the
/// token string. Typical caller: the native hook adapter inside the agent's
/// hook process, passing its own `getppid()` (= the agent's PID).
///
/// `ppid_chain`, when supplied, asks agentpactd to look up an existing
/// anchored `exec_token` whose anchor sits anywhere in the chain. Typical
/// caller: a shell trap inside an agent-spawned subshell, reporting its
/// own ancestor chain so the daemon can find the token the native hook
/// anchored to the agent.
#[must_use]
pub fn build_hook_permission_request(
    request_id_prefix: &str,
    action: &str,
    detail: &str,
    working_dir: Option<&str>,
    seed_boundary_pid: Option<u32>,
    anchor_pid: Option<u32>,
    ppid_chain: Option<&[u32]>,
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
    if let Some(pid) = anchor_pid {
        request["anchor_pid"] = serde_json::json!(pid);
    }
    if let Some(chain) = ppid_chain
        && !chain.is_empty()
    {
        request["ppid_chain"] = serde_json::json!(chain);
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
        Some("PACT_OK") => {
            // `mode` is required on every PACT_OK from current
            // agentpactd. A missing/unknown value indicates either
            // a malformed daemon response or a downstream proxy that
            // stripped the field — fail safe by treating it as
            // `enforce` (agent keeps its prompt UX) rather than
            // assuming the laxer `log` posture.
            let mode = response
                .get("mode")
                .and_then(serde_json::Value::as_str)
                .and_then(Mode::from_wire)
                .unwrap_or(Mode::Enforce);
            McpPermissionDecision::Allow { mode }
        }
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
                    allow_always: response
                        .get("allow_always")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
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

/// Deny — without sending — an `execute` command longer than the shared
/// governance ceiling ([`agentpact_types::MAX_COMMAND_LENGTH_CEILING`]). A
/// command that long cannot fit within agentpactd's socket message limit, so
/// it could never be received intact, and it is auto-denied regardless.
/// Guarding here makes that deny deterministic: it avoids transmitting a
/// payload the daemon would reject mid-read, which could otherwise surface as
/// a transport error and fail *open* under `on_daemon_unavailable: allow`.
fn oversized_execute_deny(action: &str, detail: &str) -> Option<McpPermissionDecision> {
    (action == "execute" && detail.len() > agentpact_types::MAX_COMMAND_LENGTH_CEILING).then(|| {
        McpPermissionDecision::Deny {
            code: DenyCode::PolicyDenied,
            reason: format!(
                "command exceeds the {}-byte governance ceiling (length {}); split it into smaller commands",
                agentpact_types::MAX_COMMAND_LENGTH_CEILING,
                detail.len()
            ),
            hint: None,
        }
    })
}

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
    request_mcp_tool_permission_with_id(
        socket_path,
        request_id_prefix,
        server_name,
        tool_name,
        mcp_ctx,
        socket_timeout,
    )
    .map(|(decision, _id)| decision)
}

/// Same as [`request_mcp_tool_permission`] but also returns the agentpactd
/// request `id` so a caller surfacing a deny/error can log it for tracing.
///
/// The id (`"{prefix}-{uuid}"`) is the one embedded in the request and echoed
/// by agentpactd in its response — the same id the daemon records on its
/// governance event, so it ties a user-visible denial back to that event.
///
/// # Errors
///
/// Returns an error when the request cannot be sent to `agentpactd` or when the daemon
/// response is malformed.
pub fn request_mcp_tool_permission_with_id(
    socket_path: &str,
    request_id_prefix: &str,
    server_name: &str,
    tool_name: &str,
    mcp_ctx: &McpContext,
    socket_timeout: Duration,
) -> Result<(McpPermissionDecision, String), String> {
    let request = build_mcp_permission_request(request_id_prefix, server_name, tool_name, mcp_ctx);
    let request_id = request
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    send_daemon_request_with_retry(socket_path, &request, socket_timeout)
        .map(|response| (parse_mcp_permission_response(&response), request_id))
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
#[allow(clippy::too_many_arguments)]
pub fn request_hook_permission(
    socket_path: &str,
    request_id_prefix: &str,
    action: &str,
    detail: &str,
    working_dir: Option<&str>,
    seed_boundary_pid: Option<u32>,
    anchor_pid: Option<u32>,
    ppid_chain: Option<&[u32]>,
    socket_timeout: Duration,
) -> Result<(McpPermissionDecision, Option<Vec<String>>), String> {
    if let Some(deny) = oversized_execute_deny(action, detail) {
        return Ok((deny, None));
    }
    let request = build_hook_permission_request(
        request_id_prefix,
        action,
        detail,
        working_dir,
        seed_boundary_pid,
        anchor_pid,
        ppid_chain,
    );
    send_daemon_request_with_retry(socket_path, &request, socket_timeout).map(|response| {
        let decision = parse_mcp_permission_response(&response);
        let segments = parse_response_segments(&response);
        (decision, segments)
    })
}

/// Classify a hook command **without side effects** — a preview request.
///
/// Unlike [`request_hook_permission`], this sets `preview: true`, so the
/// daemon evaluates policy and returns the decision (and the compound
/// `segments` it parsed) but issues **no** approval token and stores no
/// pending entry. Used by the per-segment hook flow to learn how a
/// compound splits and whether any part needs asking, before issuing the
/// real, token-bearing per-segment requests that drive the popups.
///
/// # Errors
///
/// Returns an error when `agentpactd` is unreachable or returns a
/// malformed response.
pub fn request_hook_permission_preview(
    socket_path: &str,
    request_id_prefix: &str,
    action: &str,
    detail: &str,
    working_dir: Option<&str>,
    seed_boundary_pid: Option<u32>,
    socket_timeout: Duration,
) -> Result<(McpPermissionDecision, Option<Vec<String>>), String> {
    if let Some(deny) = oversized_execute_deny(action, detail) {
        return Ok((deny, None));
    }
    // Preview is strictly side-effect-free: it never mints or consumes
    // exec_tokens, so anchor_pid and ppid_chain would do nothing here and
    // are intentionally omitted from the preview API.
    let mut request = build_hook_permission_request(
        request_id_prefix,
        action,
        detail,
        working_dir,
        seed_boundary_pid,
        None,
        None,
    );
    request["preview"] = serde_json::json!(true);
    send_daemon_request_with_retry(socket_path, &request, socket_timeout).map(|response| {
        // A preview `PACT_ASK` carries no approval token (the daemon
        // issues none for previews). `parse_mcp_permission_response`
        // treats a token-less ASK as an error, so map it to `Ask`
        // ourselves; the preview caller only inspects the variant, never
        // the (empty) token. PACT_OK / PACT_DENIED / errors parse normally.
        let decision = match response.get("code").and_then(|c| c.as_str()) {
            Some("PACT_ASK") => McpPermissionDecision::Ask {
                approval_id: String::new(),
                approval_token: String::new(),
                allow_always: response
                    .get("allow_always")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            },
            _ => parse_mcp_permission_response(&response),
        };
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
/// On success returns an optional advisory **warning** the daemon attached to
/// the response (its `reason` field) — non-`None` when the decision was applied
/// but a side effect could not be completed, e.g. an `Always` grant that was
/// approved once but could not be persisted (read-only policy dir). Callers
/// that surface UI should show it to the developer; others may ignore it (the
/// daemon also logs it). `None` on an ordinary, fully-applied response.
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
) -> Result<Option<String>, String> {
    let request = build_permission_respond_request(request_id_prefix, approval_token, response);
    let response_value = send_daemon_request_to_socket(socket_path, &request, socket_timeout)?;
    let warning = response_value
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .filter(|reason| !reason.is_empty())
        .map(str::to_owned);
    match parse_mcp_permission_response(&response_value) {
        McpPermissionDecision::Allow { .. } => Ok(warning),
        McpPermissionDecision::Deny { .. } if response == ApprovalResponse::Denied => Ok(warning),
        McpPermissionDecision::Deny { reason, .. } => {
            Err(format!("agentpactd rejected approval response: {reason}"))
        }
        McpPermissionDecision::Ask { .. } => {
            Err("agentpactd returned an unexpected ask response".to_string())
        }
    }
}

/// Probe agentpactd liveness with a real `daemon.health` round-trip.
///
/// Unlike a bare `UnixStream::connect()`, this writes a request, reads
/// the response, and only returns `true` when the daemon answers
/// `PACT_OK`. That means it actually exercises the accept loop and
/// method dispatch — a bare connect succeeds whenever the kernel queues
/// the connection, even if the daemon's accept loop is wedged, so it
/// can't distinguish "alive" from "hung".
///
/// It also completes a full request/response and shuts the write half
/// down cleanly (via [`send_daemon_request_to_socket`]), so the daemon
/// never sees a connection that vanished mid-accept. A bare connect that
/// is dropped immediately races the server's `accept()` and surfaces
/// there as a transient `ENOTCONN`, which spammed agentpactd's logs once
/// per probe.
///
/// Returns `false` on any connect/transport/parse failure or non-`OK`
/// code — i.e. "treat as unreachable."
#[must_use]
pub fn probe_daemon_health(socket_path: &str, timeout: Duration) -> bool {
    let request = serde_json::json!({
        "id": "kyrisd-health",
        "method": "daemon.health",
    });
    match send_daemon_request_to_socket(socket_path, &request, Some(timeout)) {
        Ok(response) => response.get("code").and_then(|c| c.as_str()) == Some("PACT_OK"),
        Err(_) => false,
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
        let decision = McpPermissionDecision::Allow {
            mode: Mode::Enforce,
        };
        assert_eq!(
            decision,
            McpPermissionDecision::Allow {
                mode: Mode::Enforce
            }
        );

        assert!(ApprovalResponse::Approved.allows_execution());
        assert!(!ApprovalResponse::Denied.allows_execution());
    }

    #[test]
    fn testOversizedExecuteDeniedWithoutSending() {
        // Over the ceiling → denied locally; the (nonexistent) socket is never
        // contacted, so we get a Deny rather than a transport Err.
        let big = "a".repeat(agentpact_types::MAX_COMMAND_LENGTH_CEILING + 1);
        let result = request_hook_permission(
            "/tmp/nonexistent-agentpact.sock",
            "test",
            "execute",
            &big,
            None,
            None,
            None,
            None,
            Duration::from_millis(50),
        );
        match result {
            Ok((McpPermissionDecision::Deny { code, .. }, segments)) => {
                assert_eq!(code, DenyCode::PolicyDenied);
                assert!(segments.is_none());
            }
            other => panic!("expected local deny, got {other:?}"),
        }
    }

    #[test]
    fn testAtCeilingExecuteIsStillSent() {
        // Exactly at the ceiling is allowed through to the daemon for the
        // precise decision; with no daemon that surfaces as a transport Err,
        // proving we attempted to send rather than denying locally.
        let at = "a".repeat(agentpact_types::MAX_COMMAND_LENGTH_CEILING);
        let result = request_hook_permission(
            "/tmp/nonexistent-agentpact.sock",
            "test",
            "execute",
            &at,
            None,
            None,
            None,
            None,
            Duration::from_millis(50),
        );
        assert!(
            result.is_err(),
            "at-ceiling command must be sent: {result:?}"
        );
    }

    #[test]
    fn testNonExecuteIsNotLengthCapped() {
        // The cap is for commands only; a long read path is not denied locally
        // (unreachable socket → Err, proving it tried to send).
        let big = "a".repeat(agentpact_types::MAX_COMMAND_LENGTH_CEILING + 1);
        let result = request_hook_permission(
            "/tmp/nonexistent-agentpact.sock",
            "test",
            "read",
            &big,
            None,
            None,
            None,
            None,
            Duration::from_millis(50),
        );
        assert!(result.is_err(), "non-execute must not be length-capped");
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

        // Per the new protocol, a PACT_OK response always carries a
        // `mode` field. The parser surfaces it on the typed Allow
        // variant so hook adapters can branch on log vs. enforce
        // without re-reading any YAML.
        let ok_log_resp = serde_json::json!({"code": "PACT_OK", "mode": "log"});
        assert_eq!(
            parse_mcp_permission_response(&ok_log_resp),
            McpPermissionDecision::Allow { mode: Mode::Log }
        );
        let ok_enforce_resp = serde_json::json!({"code": "PACT_OK", "mode": "enforce"});
        assert_eq!(
            parse_mcp_permission_response(&ok_enforce_resp),
            McpPermissionDecision::Allow {
                mode: Mode::Enforce
            }
        );
    }

    #[test]
    fn testParsePactOkWithMissingModeFallsBackToEnforce() {
        // Future-proofing: a malformed daemon or a downstream proxy
        // that strips the field must NOT cause kyris to silently
        // assume log mode (which would suppress the agent's own
        // prompt). Treat the absence as enforce — keep the agent
        // honest.
        let resp = serde_json::json!({"code": "PACT_OK"});
        assert_eq!(
            parse_mcp_permission_response(&resp),
            McpPermissionDecision::Allow {
                mode: Mode::Enforce
            }
        );
    }

    #[test]
    fn testParsePactOkWithUnknownModeFallsBackToEnforce() {
        let resp = serde_json::json!({"code": "PACT_OK", "mode": "paranoid"});
        assert_eq!(
            parse_mcp_permission_response(&resp),
            McpPermissionDecision::Allow {
                mode: Mode::Enforce
            }
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
            None,
            None,
        );
        assert_eq!(request["method"], "permission.request");
        assert_eq!(request["action"], "execute");
        assert_eq!(request["detail"], "ls -la");
        assert_eq!(request["context"]["working_dir"], "/tmp/repo");
        assert!(request["context"]["mcp_server"].is_null());
        assert!(request["seed_boundary_pid"].is_null());
        assert!(request["anchor_pid"].is_null());
        assert!(request["ppid_chain"].is_null());
        assert!(
            request["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("kyris-hook-"))
        );
    }

    #[test]
    fn testBuildHookPermissionRequestNoWorkingDir() {
        let request =
            build_hook_permission_request("kyris-hook", "call", "unknown", None, None, None, None);
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
            None,
            None,
        );
        assert_eq!(request["seed_boundary_pid"], 12345);
    }

    #[test]
    fn testBuildHookPermissionRequestWithAnchorPid() {
        // The native-hook adapter passes its own getppid() as the anchor so
        // the issued exec_token gets tagged with the agent's PID — letting a
        // later shell trap consume it via `ppid_chain` without env propagation.
        let request = build_hook_permission_request(
            "kyris-hook",
            "execute",
            "git status",
            Some("/tmp"),
            None,
            Some(54321),
            None,
        );
        assert_eq!(request["anchor_pid"], 54321);
        assert!(request["ppid_chain"].is_null());
    }

    #[test]
    fn testBuildHookPermissionRequestWithPpidChain() {
        // The shell trap inside an agent subshell reports its ancestor chain
        // so agentpactd can find an anchored token tagged with the agent's PID.
        let request = build_hook_permission_request(
            "kyris-hook",
            "execute",
            "ls /tmp",
            Some("/tmp"),
            None,
            None,
            Some(&[9999, 5678, 4321]),
        );
        assert_eq!(request["ppid_chain"][0], 9999);
        assert_eq!(request["ppid_chain"][1], 5678);
        assert_eq!(request["ppid_chain"][2], 4321);
        assert!(request["anchor_pid"].is_null());
    }

    #[test]
    fn testBuildHookPermissionRequestEmptyPpidChainOmittedFromWire() {
        // An empty chain would always miss daemon-side and bloats the
        // payload — the builder must drop it rather than serialize `[]`.
        let request = build_hook_permission_request(
            "kyris-hook",
            "execute",
            "ls",
            None,
            None,
            None,
            Some(&[]),
        );
        assert!(request["ppid_chain"].is_null());
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
        let response =
            serde_json::json!({"code": "PACT_OK", "decision": "auto", "mode": "enforce"});
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Allow {
                mode: Mode::Enforce
            }
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
        // No allow_always field → conservative default false.
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
                allow_always: false,
            }
        );
    }

    #[test]
    fn testParseMcpPermissionResponseAskCarriesAllowAlways() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "req-42",
            "approval_token": "apt_123",
            "allow_always": true
        });
        assert_eq!(
            parse_mcp_permission_response(&response),
            McpPermissionDecision::Ask {
                approval_id: "req-42".to_string(),
                approval_token: "apt_123".to_string(),
                allow_always: true,
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
