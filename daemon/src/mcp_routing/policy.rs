// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};
use std::time::Duration;

use kyris_agentpact_client as agentpact;
use kyris_agentpact_client::{McpContext, ToolAnnotations};

use crate::fail_open_log;

#[cfg(test)]
static TEST_AGENTPACT_SOCKET: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[derive(Debug, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
    Ask {
        approval_id: String,
        approval_token: String,
        /// Daemon's authoritative signal: whether "Always" would persist.
        allow_always: bool,
    },
}

fn agentpact_socket() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_AGENTPACT_SOCKET
        .lock()
        .expect("lock test socket")
        .clone()
    {
        return path;
    }

    if let Ok(path) = std::env::var("AGENTPACT_SOCK") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.agentpact/agentpact.sock"))
}

#[cfg(test)]
pub fn set_test_agentpact_socket(path: Option<PathBuf>) {
    *TEST_AGENTPACT_SOCKET.lock().expect("lock test socket") = path;
}

pub async fn check_permission(
    server_name: &str,
    path: &str,
    body: &[u8],
    working_dir: Option<&str>,
    mcp_operation: Option<&str>,
    annotations: &ToolAnnotations,
    socket_timeout: Duration,
) -> PolicyDecision {
    if !is_tools_call_request(path, body) {
        return PolicyDecision::Allow;
    }

    if let Err(msg) = agentpact::check_protocol_compatibility() {
        return PolicyDecision::Deny(msg);
    }

    let tool = extract_tool_name(path, body).unwrap_or_else(|| "unknown".to_string());
    tracing::debug!(server = %server_name, tool = %tool, "mcp policy check: tools/call detected");

    let sock = agentpact_socket();
    match request_permission(
        &sock,
        server_name,
        &tool,
        working_dir,
        mcp_operation,
        annotations,
        socket_timeout,
    )
    .await
    {
        Ok(decision) => decision,
        Err(e) => {
            // agentpactd (the decider) is unreachable — fail open rather than
            // block the agent's routed MCP tool call. A down daemon must never
            // block; the call is spooled to the fail-open log for the audit trail.
            tracing::warn!(error = %e, "agentpactd unavailable, allowing (fail-open)");
            fail_open_log::record("call", &tool, server_name, working_dir);
            PolicyDecision::Allow
        }
    }
}

async fn request_permission(
    sock: &Path,
    server_name: &str,
    tool: &str,
    working_dir: Option<&str>,
    mcp_operation: Option<&str>,
    annotations: &ToolAnnotations,
    socket_timeout: Duration,
) -> Result<PolicyDecision, String> {
    let socket = sock.to_string_lossy().to_string();
    let server = server_name.to_string();
    let tool = tool.to_string();
    let mcp_ctx = McpContext {
        working_dir: working_dir.map(str::to_owned),
        mcp_operation: mcp_operation.map(str::to_owned),
        annotations: annotations.clone(),
    };
    tokio::task::spawn_blocking(move || {
        agentpact::request_mcp_tool_permission(
            &socket,
            "kyris",
            &server,
            &tool,
            &mcp_ctx,
            socket_timeout,
        )
        .map(map_permission_decision)
    })
    .await
    .map_err(|e| format!("permission.request task failed: {e}"))?
}

fn map_permission_decision(decision: agentpact::McpPermissionDecision) -> PolicyDecision {
    match decision {
        agentpact::McpPermissionDecision::Allow { .. } => PolicyDecision::Allow,
        agentpact::McpPermissionDecision::Deny { reason, .. } => PolicyDecision::Deny(reason),
        agentpact::McpPermissionDecision::Ask {
            approval_id,
            approval_token,
            allow_always,
        } => PolicyDecision::Ask {
            approval_id,
            approval_token,
            allow_always,
        },
    }
}

pub fn is_tools_call_request(path: &str, body: &[u8]) -> bool {
    let is_tools_call_path = path.contains("tools/call");

    let is_tools_call_body = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(String::from))
        .is_some_and(|m| m == "tools/call");

    is_tools_call_path || is_tools_call_body
}

pub fn extract_tool_name(path: &str, body: &[u8]) -> Option<String> {
    let is_tools_call_path = path.contains("tools/call");

    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;

    let is_tools_call_body = parsed
        .get("method")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == "tools/call");

    if !is_tools_call_path && !is_tools_call_body {
        return None;
    }

    parsed
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn testNonToolsCallAllowed() {
        let body = br#"{"method":"ping"}"#;
        let decision = check_permission(
            "test-server",
            "/mcp/test/ping",
            body,
            None,
            None,
            &ToolAnnotations::default(),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn testExtractToolNameFromPath() {
        let body = br#"{"params":{"name":"write_file"}}"#;
        let name = extract_tool_name("tools/call", body);
        assert_eq!(name, Some("write_file".to_string()));
    }

    #[test]
    fn testExtractToolNameFromBody() {
        let body = br#"{"method":"tools/call","params":{"name":"exec_cmd"}}"#;
        let name = extract_tool_name("/some/path", body);
        assert_eq!(name, Some("exec_cmd".to_string()));
    }

    #[test]
    fn testExtractToolNameNonToolsCall() {
        let body = br#"{"method":"ping"}"#;
        let name = extract_tool_name("/some/path", body);
        assert_eq!(name, None);
    }

    #[test]
    fn testExtractToolNameInvalidJson() {
        let name = extract_tool_name("tools/call", b"not json");
        assert_eq!(name, None);
    }

    #[test]
    fn testIsToolsCallRequestFromPath() {
        assert!(is_tools_call_request("tools/call", br#"{"params":{}}"#));
    }

    #[test]
    fn testIsToolsCallRequestFromBody() {
        assert!(is_tools_call_request(
            "/other",
            br#"{"method":"tools/call"}"#
        ));
    }

    #[test]
    fn testIsToolsCallRequestNonToolsCall() {
        assert!(!is_tools_call_request("/other", br#"{"method":"ping"}"#));
    }

    #[test]
    fn testIsToolsCallRequestInvalidJson() {
        assert!(!is_tools_call_request("/other", b"not json"));
    }

    #[test]
    fn testIsToolsCallRequestInvalidJsonOnToolsCallPath() {
        assert!(is_tools_call_request("tools/call", b"not json"));
    }

    #[test]
    fn testParsePermissionResponseOk() {
        let resp = serde_json::json!({"code": "PACT_OK", "decision": "auto"});
        assert_eq!(
            map_permission_decision(agentpact::parse_mcp_permission_response(&resp)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn testParsePermissionResponseDenied() {
        let resp = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"});
        assert_eq!(
            map_permission_decision(agentpact::parse_mcp_permission_response(&resp)),
            PolicyDecision::Deny("blocked by policy".to_string())
        );
    }

    #[test]
    fn testParsePermissionResponseAsk() {
        let resp = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "req-42",
            "approval_token": "tok-abc"
        });
        assert_eq!(
            map_permission_decision(agentpact::parse_mcp_permission_response(&resp)),
            PolicyDecision::Ask {
                approval_id: "req-42".to_string(),
                approval_token: "tok-abc".to_string(),
                // No allow_always in the response → parser default false.
                allow_always: false,
            }
        );
    }

    #[test]
    fn testParsePermissionResponseUnknownCode() {
        let resp = serde_json::json!({"code": "SOMETHING_NEW"});
        assert_eq!(
            map_permission_decision(agentpact::parse_mcp_permission_response(&resp)),
            PolicyDecision::Deny("invalid response from agentpactd".to_string())
        );
    }

    #[test]
    fn testPolicyDecisionVariants() {
        let deny = PolicyDecision::Deny("test reason".to_string());
        assert_eq!(deny, PolicyDecision::Deny("test reason".to_string()));

        let ask = PolicyDecision::Ask {
            approval_id: "id".to_string(),
            approval_token: "tok".to_string(),
            allow_always: true,
        };
        if let PolicyDecision::Ask { approval_id, .. } = ask {
            assert_eq!(approval_id, "id");
        }
    }
}
