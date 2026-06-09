// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use serde::Deserialize;

use super::registry::AgentIntegrationPlan;

// One independent flag per capability surface; not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeCapabilityDeclaration {
    pub execution: bool,
    pub tool: bool,
    pub burn_control: bool,
    pub attribution: bool,
}

#[derive(Debug, Deserialize)]
struct AgentCapabilitiesManifest {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    #[serde(rename = "agent_id")]
    agent_id: String,
    #[serde(default)]
    native: NativeCapabilities,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Deserialize)]
struct NativeCapabilities {
    #[serde(default)]
    execution: bool,
    #[serde(default)]
    tool: bool,
    #[serde(default)]
    burn_control: bool,
    #[serde(default)]
    attribution: bool,
}

pub fn apply_declared_capabilities(
    canonical_id: &str,
    fallback: AgentIntegrationPlan,
) -> AgentIntegrationPlan {
    declared_native_capabilities(canonical_id)
        .map_or(fallback, |decl| fallback.with_native_capabilities(decl))
}

pub fn declared_native_capabilities(canonical_id: &str) -> Option<NativeCapabilityDeclaration> {
    let path = capability_manifest_path(canonical_id)?;
    let contents = std::fs::read_to_string(path).ok()?;
    parse_capabilities_manifest(&contents, canonical_id).ok()
}

fn capability_manifest_path(canonical_id: &str) -> Option<PathBuf> {
    let mut parts = canonical_id.split('/');
    let vendor = parts.next()?;
    let product = parts.next()?;
    if parts.next().is_some() || vendor.is_empty() || product.is_empty() {
        return None;
    }
    Some(
        agentpact_config_dir()
            .join("agents")
            .join(vendor)
            .join(product)
            .join("capabilities.json"),
    )
}

fn agentpact_config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map_or_else(
            |_| {
                crate::integration::home_dir()
                    .unwrap_or_else(|_| PathBuf::from("/"))
                    .join(".config")
            },
            PathBuf::from,
        )
        .join("agentpact")
}

fn parse_capabilities_manifest(
    contents: &str,
    expected_agent_id: &str,
) -> Result<NativeCapabilityDeclaration, String> {
    let manifest: AgentCapabilitiesManifest =
        serde_json::from_str(contents).map_err(|e| format!("invalid capabilities JSON: {e}"))?;
    if manifest.api_version != "agentpact/v1" {
        return Err(format!(
            "unsupported capabilities apiVersion: {}",
            manifest.api_version
        ));
    }
    if manifest.kind != "AgentCapabilities" {
        return Err(format!("unsupported capabilities kind: {}", manifest.kind));
    }
    if manifest.agent_id != expected_agent_id {
        return Err(format!(
            "capabilities agent_id {} does not match {}",
            manifest.agent_id, expected_agent_id
        ));
    }
    Ok(NativeCapabilityDeclaration {
        execution: manifest.native.execution,
        tool: manifest.native.tool,
        burn_control: manifest.native.burn_control,
        attribution: manifest.native.attribution,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testParseCapabilitiesManifest() {
        let manifest = r#"{
            "apiVersion": "agentpact/v1",
            "kind": "AgentCapabilities",
            "agent_id": "openai/codex-cli",
            "native": {
                "execution": true,
                "tool": true,
                "burn_control": false,
                "attribution": true
            }
        }"#;

        let parsed =
            parse_capabilities_manifest(manifest, "openai/codex-cli").expect("capabilities");

        assert!(parsed.execution);
        assert!(parsed.tool);
        assert!(!parsed.burn_control);
        assert!(parsed.attribution);
    }

    #[test]
    fn testParseCapabilitiesRejectsWrongAgent() {
        let manifest = r#"{
            "apiVersion": "agentpact/v1",
            "kind": "AgentCapabilities",
            "agent_id": "openai/codex-cli",
            "native": {"execution": true}
        }"#;

        let error = parse_capabilities_manifest(manifest, "anthropic/claude-code")
            .expect_err("wrong agent rejected");

        assert!(error.contains("does not match"));
    }

    #[test]
    fn testCapabilityManifestPathUsesCanonicalAgentId() {
        let path = capability_manifest_path("openai/codex-cli").expect("path");

        assert!(path.ends_with("agentpact/agents/openai/codex-cli/capabilities.json"));
    }
}
