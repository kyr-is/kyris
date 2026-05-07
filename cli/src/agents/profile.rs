// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapLevel {
    None = 0,
    Adapted = 1,
    Native = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptedMechanism {
    LiveHook,
    CompiledPolicy,
    EnvVarProxy,
    ConfigRewrite,
    McpWrapping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageCeiling {
    Compiled,
    Observed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceState {
    pub level: CapLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<AdaptedMechanism>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<CoverageCeiling>,
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
    pub execution: SurfaceState,
    pub tool: SurfaceState,
    pub burn_control: SurfaceState,
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

impl SurfaceState {
    pub fn none() -> Self {
        Self {
            level: CapLevel::None,
            mechanism: None,
            ceiling: None,
        }
    }

    pub fn adapted(mechanism: AdaptedMechanism) -> Self {
        Self {
            level: CapLevel::Adapted,
            mechanism: Some(mechanism),
            ceiling: None,
        }
    }

    pub fn native() -> Self {
        Self {
            level: CapLevel::Native,
            mechanism: None,
            ceiling: None,
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

impl std::fmt::Display for CapLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Adapted => write!(f, "adapted"),
            Self::Native => write!(f, "native"),
        }
    }
}

impl std::fmt::Display for AdaptedMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiveHook => write!(f, "hook"),
            Self::CompiledPolicy => write!(f, "policy"),
            Self::EnvVarProxy => write!(f, "proxy"),
            Self::ConfigRewrite => write!(f, "config"),
            Self::McpWrapping => write!(f, "mcp"),
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
            execution: SurfaceState::adapted(AdaptedMechanism::LiveHook),
            tool: SurfaceState::adapted(AdaptedMechanism::LiveHook),
            burn_control: SurfaceState::adapted(AdaptedMechanism::EnvVarProxy),
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
            Some(AdaptedMechanism::LiveHook)
        );
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
}
