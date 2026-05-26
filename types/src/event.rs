// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Event {
    pub id: String,
    pub timestamp: String,
    pub agent: String,
    pub action: Action,
    pub detail: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_remote_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default)]
    pub binary: String,
    #[serde(default)]
    pub attribution_method: AttributionMethod,
    #[serde(default)]
    pub sync_state: SyncState,
    #[serde(default)]
    pub coverage_state: CoverageState,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event_kind: String,
}

// Action lives in `agentpact-types` (the canonical home for wire
// value types shared with agentpact). Re-exported here so kyris
// consumers can keep importing `kyris_types::event::Action`.
// The `JsonSchema` derive lives on the canonical definition,
// gated by agentpact-types' `schema` feature which kyris-types'
// own `schema` feature forwards to (see Cargo.toml).
pub use agentpact_types::Action;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Auto,
    Inform,
    Ask,
    Deny,
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Inform => f.write_str("inform"),
            Self::Ask => f.write_str("ask"),
            Self::Deny => f.write_str("deny"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// AttributionMethod lives in `agentpact-types`; see Action above.
pub use agentpact_types::AttributionMethod;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    SyncedToEnterprise,
    PendingSync,
    #[default]
    #[serde(other)]
    LocalOnly,
}

impl std::fmt::Display for SyncState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyncedToEnterprise => f.write_str("synced_to_enterprise"),
            Self::LocalOnly => f.write_str("local_only"),
            Self::PendingSync => f.write_str("pending_sync"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Enforced,
    Observed,
    VendorReported,
    #[default]
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for CoverageState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enforced => f.write_str("enforced"),
            Self::Observed => f.write_str("observed"),
            Self::VendorReported => f.write_str("vendor_reported"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testActionSerializesSnakeCase() {
        assert_eq!(
            serde_json::to_string(&Action::Execute).unwrap(),
            r#""execute""#
        );
        assert_eq!(serde_json::to_string(&Action::Think).unwrap(), r#""think""#);
    }

    #[test]
    fn testActionDeserializesSnakeCase() {
        let action: Action = serde_json::from_str(r#""call""#).unwrap();
        assert_eq!(action, Action::Call);
    }

    #[test]
    fn testActionDeserializeUnknownFallsBack() {
        let action: Action = serde_json::from_str(r#""deploy""#).unwrap();
        assert_eq!(action, Action::Unknown);
        assert_eq!(action.to_string(), "unknown");
    }

    #[test]
    fn testDecisionDeserializeUnknownFallsBack() {
        let decision: Decision = serde_json::from_str(r#""escalate""#).unwrap();
        assert_eq!(decision, Decision::Unknown);
        assert_eq!(decision.to_string(), "unknown");
    }

    #[test]
    fn testDecisionDisplay() {
        assert_eq!(Decision::Auto.to_string(), "auto");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn testSyncStateDefault() {
        let state = SyncState::default();
        assert_eq!(state, SyncState::LocalOnly);
    }

    #[test]
    fn testCoverageStateDefault() {
        let state = CoverageState::default();
        assert_eq!(state, CoverageState::Unknown);
    }

    #[test]
    fn testCoverageStateDeserializeUnknownFallsBack() {
        let state: CoverageState = serde_json::from_str(r#""audited""#).unwrap();
        assert_eq!(state, CoverageState::Unknown);
    }

    #[test]
    fn testAttributionMethodDefault() {
        let method = AttributionMethod::default();
        assert_eq!(method, AttributionMethod::Unknown);
    }

    #[test]
    fn testAttributionMethodDeserializeUnknownFallsBack() {
        let method: AttributionMethod = serde_json::from_str(r#""heuristic""#).unwrap();
        assert_eq!(method, AttributionMethod::Unknown);
    }

    #[test]
    fn testEventRoundTrip() {
        let json = r#"{
            "id": "evt-1",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "claude-code",
            "action": "execute",
            "detail": "git status",
            "decision": "auto",
            "working_dir": "/tmp/project",
            "binary": "claude",
            "attribution_method": "lineage"
        }"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.id, "evt-1");
        assert_eq!(event.agent, "claude-code");
        assert_eq!(event.action, Action::Execute);
        assert_eq!(event.decision, Decision::Auto);
        assert_eq!(event.binary, "claude");
        assert_eq!(event.attribution_method, AttributionMethod::Lineage);
        assert_eq!(event.sync_state, SyncState::LocalOnly);
        assert_eq!(event.coverage_state, CoverageState::Unknown);
    }

    #[test]
    fn testEventMinimalDeserialization() {
        let json = r#"{
            "id": "evt-2",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "unknown",
            "action": "think",
            "detail": "model call",
            "decision": "auto"
        }"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.working_dir.is_none());
        assert!(event.routing_trace_id.is_none());
        assert_eq!(event.attribution_method, AttributionMethod::Unknown);
    }

    #[test]
    fn testActionDisplayAll() {
        assert_eq!(Action::Execute.to_string(), "execute");
        assert_eq!(Action::Call.to_string(), "call");
        assert_eq!(Action::Read.to_string(), "read");
        assert_eq!(Action::Write.to_string(), "write");
        assert_eq!(Action::Think.to_string(), "think");
    }

    #[test]
    fn testDecisionDisplayAll() {
        assert_eq!(Decision::Auto.to_string(), "auto");
        assert_eq!(Decision::Inform.to_string(), "inform");
        assert_eq!(Decision::Ask.to_string(), "ask");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn testAttributionMethodDisplayAll() {
        assert_eq!(AttributionMethod::Boundary.to_string(), "boundary");
        assert_eq!(AttributionMethod::Lineage.to_string(), "lineage");
        assert_eq!(AttributionMethod::Unknown.to_string(), "unknown");
    }

    #[test]
    fn testSyncStateDisplayAll() {
        assert_eq!(
            SyncState::SyncedToEnterprise.to_string(),
            "synced_to_enterprise"
        );
        assert_eq!(SyncState::LocalOnly.to_string(), "local_only");
        assert_eq!(SyncState::PendingSync.to_string(), "pending_sync");
    }

    #[test]
    fn testCoverageStateDisplayAll() {
        assert_eq!(CoverageState::Enforced.to_string(), "enforced");
        assert_eq!(CoverageState::Observed.to_string(), "observed");
        assert_eq!(CoverageState::VendorReported.to_string(), "vendor_reported");
        assert_eq!(CoverageState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn testEventSkipsNoneFieldsSerialization() {
        let event = Event {
            id: "evt-3".to_string(),
            timestamp: "2026-04-12T00:00:00Z".to_string(),
            agent: "test".to_string(),
            action: Action::Execute,
            detail: "ls".to_string(),
            decision: Decision::Auto,
            rule_kind: None,
            rule_id: None,
            reason: None,
            working_dir: None,
            routing_trace_id: None,
            git_remote_origin: None,
            mcp_server: None,
            mcp_operation: None,
            approval_id: None,
            tier: None,
            plan_status: None,
            response: None,
            success: None,
            exit_code: None,
            result_summary: None,
            session: None,
            binary: String::new(),
            attribution_method: AttributionMethod::default(),
            sync_state: SyncState::default(),
            coverage_state: CoverageState::default(),
            mode: String::new(),
            event_kind: String::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("rule_kind"));
        assert!(!json.contains("reason"));
    }
}
