// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpPermissionDecision {
    Allow,
    Deny(String),
    Ask {
        approval_id: String,
        approval_token: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResponse {
    Approved,
    Denied,
    Always,
}

impl ApprovalResponse {
    #[must_use]
    pub fn as_agentpact_response(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Always => "always",
        }
    }

    #[must_use]
    pub fn allows_execution(self) -> bool {
        matches!(self, Self::Approved | Self::Always)
    }
}

#[must_use]
pub fn daemon_unavailable_message() -> String {
    "AgentPact daemon is unreachable.".to_string()
}

#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("AGENTPACT_SOCK") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.agentpact/agentpact.sock"))
}

#[must_use]
pub fn build_mcp_permission_request(
    request_id_prefix: &str,
    server_name: &str,
    tool_name: &str,
    working_dir: Option<&str>,
) -> serde_json::Value {
    let context = match working_dir {
        Some(dir) => serde_json::json!({
            "working_dir": dir,
            "mcp_server": server_name,
        }),
        None => serde_json::json!({
            "mcp_server": server_name,
        }),
    };
    serde_json::json!({
        "id": format!("{request_id_prefix}-{}", uuid::Uuid::now_v7()),
        "method": "permission.request",
        "action": "call",
        "detail": tool_name,
        "context": context,
    })
}

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
            McpPermissionDecision::Deny(reason)
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
                McpPermissionDecision::Deny("invalid approval response from agentpactd".to_string())
            } else {
                McpPermissionDecision::Ask {
                    approval_id,
                    approval_token,
                }
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
            McpPermissionDecision::Deny(reason)
        }
        _ => McpPermissionDecision::Deny("invalid response from agentpactd".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testBuildMcpPermissionRequest() {
        let request =
            build_mcp_permission_request("kyris-mcp", "github", "read_file", Some("/tmp/repo"));
        assert_eq!(request["method"], "permission.request");
        assert_eq!(request["action"], "call");
        assert_eq!(request["detail"], "read_file");
        assert_eq!(request["context"]["mcp_server"], "github");
        assert_eq!(request["context"]["working_dir"], "/tmp/repo");
        assert!(
            request["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("kyris-mcp-"))
        );
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
            McpPermissionDecision::Deny("blocked by policy".to_string())
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
            McpPermissionDecision::Deny(
                "malformed pact.yaml (Fix policy files: run agentpactd schema to validate)"
                    .to_string()
            )
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
            McpPermissionDecision::Deny("missing method field".to_string())
        );
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
            McpPermissionDecision::Deny(
                "daily premium cap reached (Wait until 2026-01-02T00:00:00Z or adjust caps policy)"
                    .to_string()
            )
        );
    }

    #[test]
    fn testApprovalResponseAllowsExecution() {
        assert!(ApprovalResponse::Approved.allows_execution());
        assert!(ApprovalResponse::Always.allows_execution());
        assert!(!ApprovalResponse::Denied.allows_execution());
    }
}
