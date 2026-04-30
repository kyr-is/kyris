// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceState {
    pub level: CapLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<AdaptedMechanism>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedFileFingerprint {
    pub path: String,
    pub content_hash: String,
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
    pub last_native_seen: Option<DateTime<Utc>>,
    pub version: u32,
}

impl SurfaceState {
    pub fn none() -> Self {
        Self {
            level: CapLevel::None,
            mechanism: None,
        }
    }

    pub fn adapted(mechanism: AdaptedMechanism) -> Self {
        Self {
            level: CapLevel::Adapted,
            mechanism: Some(mechanism),
        }
    }

    pub fn native() -> Self {
        Self {
            level: CapLevel::Native,
            mechanism: None,
        }
    }
}

impl AgentProfile {
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
            version: 1,
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
