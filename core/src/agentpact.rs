// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

/// Machine-readable cause code for a governance denial (I-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyCode {
    /// `PACT_DENIED` — tool blocked by policy.
    PolicyDenied,
    /// `PACT_CAP_EXCEEDED` — spend / rate cap exceeded.
    CapExceeded,
    /// `PACT_POLICY_ERROR` / `PACT_PROTOCOL_ERROR` — policy or protocol misconfiguration.
    PolicyError,
    /// Daemon unreachable (connection error, not a daemon response code).
    DaemonUnreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpPermissionDecision {
    Allow,
    Deny {
        code: DenyCode,
        reason: String,
        /// Daemon-supplied recovery hint. `None` → caller uses static I-05 table.
        hint: Option<String>,
    },
    Ask {
        approval_id: String,
        approval_token: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ToolAnnotations {
    pub read_only_hint: Option<bool>,
    pub destructive_hint: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct McpContext {
    pub working_dir: Option<String>,
    pub mcp_operation: Option<String>,
    pub annotations: ToolAnnotations,
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn testApprovalResponseAllowsExecution() {
        assert!(ApprovalResponse::Approved.allows_execution());
        assert!(ApprovalResponse::Always.allows_execution());
        assert!(!ApprovalResponse::Denied.allows_execution());
    }
}
