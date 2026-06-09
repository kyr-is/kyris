// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::registry::{BurnControlMechanism, ExecutionMechanism, ToolMechanism};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapLevel {
    None = 0,
    Adapted = 1,
    Native = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageCeiling {
    Compiled,
    Observed,
}

/// Observed state of one governance surface. Generic over `M`, the surface's
/// own mechanism enum (`ExecutionMechanism` / `ToolMechanism` /
/// `BurnControlMechanism`) — the SAME enum the plan declares — so the realized
/// mechanism and the planned mechanism are drawn from one vocabulary and cannot
/// render a skew. There is intentionally no flat cross-surface "observed" enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceState<M> {
    pub level: CapLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<M>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<CoverageCeiling>,
    // True when the surface has nothing to do for this agent in the current
    // user environment (e.g., claude-code's MCP wrap when settings.json has
    // no mcpServers). Treated as "met" by completeness checks.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub not_applicable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedFileFingerprint {
    pub path: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NativeEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burn_control: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfile {
    pub agent_id: String,
    pub detected: bool,
    pub execution: SurfaceState<ExecutionMechanism>,
    pub tool: SurfaceState<ToolMechanism>,
    pub burn_control: SurfaceState<BurnControlMechanism>,
    pub managed_files: Vec<ManagedFileFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reconciled: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(note = "use native_evidence per-surface fields")]
    pub last_native_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_native_evidence_empty")]
    pub native_evidence: NativeEvidence,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub agent_specific: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compilation_gaps: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    pub version: u32,
}

fn is_native_evidence_empty(ev: &NativeEvidence) -> bool {
    ev.execution.is_none() && ev.tool.is_none() && ev.burn_control.is_none()
}

impl<M> SurfaceState<M> {
    pub fn none() -> Self {
        Self {
            level: CapLevel::None,
            mechanism: None,
            ceiling: None,
            not_applicable: false,
        }
    }

    pub fn not_applicable() -> Self {
        Self {
            level: CapLevel::None,
            mechanism: None,
            ceiling: None,
            not_applicable: true,
        }
    }

    pub fn adapted(mechanism: M) -> Self {
        Self {
            level: CapLevel::Adapted,
            mechanism: Some(mechanism),
            ceiling: None,
            not_applicable: false,
        }
    }

    pub fn native() -> Self {
        Self {
            level: CapLevel::Native,
            mechanism: None,
            ceiling: None,
            not_applicable: false,
        }
    }

    pub fn with_ceiling(mut self, ceiling: CoverageCeiling) -> Self {
        self.ceiling = Some(ceiling);
        self
    }

    pub fn is_compiled_only(&self) -> bool {
        self.ceiling == Some(CoverageCeiling::Compiled)
    }
}

impl AgentProfile {
    #[allow(deprecated)]
    pub fn new_empty(agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            detected: false,
            execution: SurfaceState::none(),
            tool: SurfaceState::none(),
            burn_control: SurfaceState::none(),
            managed_files: Vec::new(),
            last_reconciled: None,
            last_native_seen: None,
            native_evidence: NativeEvidence::default(),
            agent_specific: HashMap::new(),
            compilation_gaps: Vec::new(),
            disabled: false,
            version: 1,
        }
    }

    pub fn migrate_native_evidence(&mut self) {
        #[allow(deprecated)]
        if let Some(ts) = self.last_native_seen
            && self.native_evidence.burn_control.is_none()
        {
            self.native_evidence.burn_control = Some(ts);
        }
    }
}

impl NativeEvidence {
    pub fn merge_missing_from(&mut self, other: Self) -> bool {
        let mut changed = false;
        if self.execution.is_none() && other.execution.is_some() {
            self.execution = other.execution;
            changed = true;
        }
        if self.tool.is_none() && other.tool.is_some() {
            self.tool = other.tool;
            changed = true;
        }
        if self.burn_control.is_none() && other.burn_control.is_some() {
            self.burn_control = other.burn_control;
            changed = true;
        }
        changed
    }
}

impl std::fmt::Display for CapLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Adapted => write!(f, "adapted"),
            Self::Native => write!(f, "native"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn testSerializeDeserializeRoundTrip() {
        let profile = AgentProfile {
            agent_id: "claude-code".to_string(),
            detected: true,
            execution: SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter),
            tool: SurfaceState::adapted(ToolMechanism::LiveHookAdapter),
            burn_control: SurfaceState::adapted(BurnControlMechanism::EnvVarProxy),
            managed_files: vec![ManagedFileFingerprint {
                path: "~/.claude/settings.json".to_string(),
                content_hash: "abc123".to_string(),
            }],
            last_reconciled: Some(Utc::now()),
            last_native_seen: None,
            native_evidence: NativeEvidence {
                execution: None,
                tool: None,
                burn_control: Some(Utc::now()),
            },
            agent_specific: HashMap::from([("max-budget-usd".to_string(), "50".to_string())]),
            compilation_gaps: Vec::new(),
            disabled: false,
            version: 1,
        };

        let json = serde_json::to_string_pretty(&profile).expect("serialize");
        let restored: AgentProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.agent_id, "claude-code");
        assert_eq!(restored.execution.level, CapLevel::Adapted);
        assert_eq!(
            restored.execution.mechanism,
            Some(ExecutionMechanism::LiveHookAdapter)
        );
        // Back-compat: the on-disk string stayed "live_hook" across the rename.
        assert!(json.contains("\"live_hook\""));
        assert_eq!(restored.burn_control.level, CapLevel::Adapted);
        assert!(restored.last_native_seen.is_none());
        assert!(restored.native_evidence.burn_control.is_some());
        assert!(restored.native_evidence.execution.is_none());
        assert_eq!(restored.agent_specific.get("max-budget-usd").unwrap(), "50");
        assert_eq!(restored.version, 1);
    }

    #[test]
    fn testCapLevelOrdering() {
        assert!(CapLevel::None < CapLevel::Adapted);
        assert!(CapLevel::Adapted < CapLevel::Native);
    }

    #[test]
    fn testForwardCompatibility() {
        let json = r#"{
            "agent_id": "claude-code",
            "detected": true,
            "execution": {"level": "adapted", "mechanism": "live_hook"},
            "tool": {"level": "none"},
            "burn_control": {"level": "none"},
            "managed_files": [],
            "version": 1,
            "unknown_future_field": "should be ignored"
        }"#;
        let profile: AgentProfile = serde_json::from_str(json).expect("deserialize with unknown");
        assert_eq!(profile.agent_id, "claude-code");
        assert!(profile.detected);
    }

    #[test]
    fn testNewEmpty() {
        let profile = AgentProfile::new_empty("codex-cli");
        assert_eq!(profile.agent_id, "codex-cli");
        assert!(!profile.detected);
        assert_eq!(profile.execution.level, CapLevel::None);
        assert_eq!(profile.version, 1);
    }

    #[test]
    fn testNativeEvidenceMergePreservesExistingSurfaceTimestamp() {
        let existing = Utc::now();
        let incoming = existing + chrono::Duration::seconds(10);
        let mut evidence = NativeEvidence {
            execution: Some(existing),
            tool: None,
            burn_control: None,
        };

        let changed = evidence.merge_missing_from(NativeEvidence {
            execution: Some(incoming),
            tool: Some(incoming),
            burn_control: None,
        });

        assert!(changed);
        assert_eq!(evidence.execution, Some(existing));
        assert_eq!(evidence.tool, Some(incoming));
        assert_eq!(evidence.burn_control, None);
    }
}
