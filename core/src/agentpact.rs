// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//
// AgentPact wire types shared across the kyris workspace. The wire-message
// *builders* and the response parser live in `kyris-agentpact-client` — per
// BOUNDARY.md only that crate may construct or interpret agentpactd wire
// messages. The types below are read-only value types that other kyris
// crates need without ever talking to the daemon directly.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testApprovalResponseAllowsExecution() {
        assert!(ApprovalResponse::Approved.allows_execution());
        assert!(ApprovalResponse::Always.allows_execution());
        assert!(!ApprovalResponse::Denied.allows_execution());
    }
}
