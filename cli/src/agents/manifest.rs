// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The parsed `AgentPact` `AgentCapabilities` document (agentpact README §13.3 /
//! §13.4) and its single validation gate.
//!
//! There is ONE shape and ONE parser for both sources of the document:
//! the in-code per-agent documents kyris ships, and a live `<agent> agentpact`
//! command response. [`parse_and_validate`] is the gate; it fails closed (any
//! error → the caller falls back to the in-code document, i.e. fully adapted),
//! so an unparseable, wrong-version, or wrong-agent response can never reduce
//! governance.
//!
//! The CORE fields (`apiVersion`, `kind`, `protocol_version`, `agent`,
//! `agent_version`, `native`) are the open-standard capability declaration
//! honored from a live response. The `adaptation` profile (§13.4) is the
//! vendor-neutral description of how a non-native agent is governed; it is
//! honored only from the in-code document today (a live self-declared profile is
//! a future end-state with its own trust rules). Its typed shape grows as each
//! agent is ported; until then it is carried verbatim.

use serde::Deserialize;

use super::adaptation::AdaptationProfile;
use super::capabilities::NativeCapabilityDeclaration;

/// The capability-declaration contract version this build understands (§13.3
/// `protocol_version`). A document declaring a higher version is rejected rather
/// than guessed at.
const SUPPORTED_PROTOCOL_VERSION: u32 = 1;

fn default_protocol_version() -> u32 {
    // §13.3: an absent `protocol_version` MUST be treated as 1.
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentManifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    pub agent: String,
    /// §13.3 SHOULD field — the agent's own version, captured for diagnostics /
    /// future version-keyed caching of the live query; not consumed yet.
    #[serde(default)]
    #[allow(dead_code)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub native: NativeDeclaration,
    /// §13.4 adaptation profile — how a non-native agent is governed. `None`
    /// when the document declares no externally-governable surfaces.
    #[serde(default)]
    pub adaptation: Option<AdaptationProfile>,
}

/// The four native-capability flags. The standard wire key for burn-control is
/// `cost` (agentpact §13.4); kyris keeps `burn_control` as the internal name.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct NativeDeclaration {
    #[serde(default)]
    pub execution: bool,
    #[serde(default)]
    pub tool: bool,
    #[serde(default, rename = "cost")]
    pub burn_control: bool,
    #[serde(default)]
    pub attribution: bool,
}

impl AgentManifest {
    /// The CORE `native{}` flags as the existing overlay type. These are the
    /// only fields honored from a live `agentpact` response.
    #[must_use]
    pub fn native_capabilities(&self) -> NativeCapabilityDeclaration {
        NativeCapabilityDeclaration {
            execution: self.native.execution,
            tool: self.native.tool,
            burn_control: self.native.burn_control,
            attribution: self.native.attribution,
        }
    }
}

/// The §13.3 validation gate, used for both in-code documents and live
/// responses. Returns an error (caller falls back to fully adapted) on: invalid
/// JSON, unsupported `apiVersion`, wrong `kind`, a `protocol_version` newer than
/// this build, or an `agent` that does not match the agent kyris invoked.
/// Unknown keys anywhere are ignored (forward-compatible, I-06).
pub fn parse_and_validate(json: &str, expected_agent: &str) -> Result<AgentManifest, String> {
    let manifest: AgentManifest =
        serde_json::from_str(json).map_err(|e| format!("invalid AgentCapabilities JSON: {e}"))?;
    if manifest.api_version != "agentpact/v1" {
        return Err(format!("unsupported apiVersion: {}", manifest.api_version));
    }
    if manifest.kind != "AgentCapabilities" {
        return Err(format!("unsupported kind: {}", manifest.kind));
    }
    if manifest.protocol_version > SUPPORTED_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol_version {} (this build supports up to {SUPPORTED_PROTOCOL_VERSION})",
            manifest.protocol_version
        ));
    }
    if manifest.agent != expected_agent {
        return Err(format!(
            "capabilities agent {} does not match {expected_agent}",
            manifest.agent
        ));
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE: &str = r#"{
        "apiVersion": "agentpact/v1",
        "kind": "AgentCapabilities",
        "protocol_version": 1,
        "agent": "openai/codex-cli",
        "agent_version": "1.2.3",
        "native": { "execution": true, "tool": false, "cost": true, "attribution": false }
    }"#;

    #[test]
    fn testParsesCoreAndMapsCostToBurnControl() {
        let m = parse_and_validate(CORE, "openai/codex-cli").expect("valid");
        assert_eq!(m.protocol_version, 1);
        assert_eq!(m.agent_version.as_deref(), Some("1.2.3"));
        let n = m.native_capabilities();
        assert!(n.execution);
        assert!(!n.tool);
        // wire `cost` → internal `burn_control`
        assert!(n.burn_control);
        assert!(!n.attribution);
    }

    #[test]
    fn testAbsentProtocolVersionDefaultsToOne() {
        let json =
            r#"{"apiVersion":"agentpact/v1","kind":"AgentCapabilities","agent":"a/b","native":{}}"#;
        let m = parse_and_validate(json, "a/b").expect("valid");
        assert_eq!(m.protocol_version, 1);
    }

    #[test]
    fn testNewerProtocolVersionRejected() {
        let json = r#"{"apiVersion":"agentpact/v1","kind":"AgentCapabilities","protocol_version":2,"agent":"a/b","native":{}}"#;
        let err = parse_and_validate(json, "a/b").expect_err("newer version rejected");
        assert!(err.contains("protocol_version"));
    }

    #[test]
    fn testWrongAgentRejected() {
        let err = parse_and_validate(CORE, "anthropic/claude-code").expect_err("agent mismatch");
        assert!(err.contains("does not match"));
    }

    #[test]
    fn testWrongApiVersionAndKindRejected() {
        let bad_api =
            r#"{"apiVersion":"agentpact/v2","kind":"AgentCapabilities","agent":"a/b","native":{}}"#;
        assert!(parse_and_validate(bad_api, "a/b").is_err());
        let bad_kind = r#"{"apiVersion":"agentpact/v1","kind":"Pact","agent":"a/b","native":{}}"#;
        assert!(parse_and_validate(bad_kind, "a/b").is_err());
    }

    #[test]
    fn testUnknownKeysIgnoredAndAdaptationCarried() {
        let json = r#"{
            "apiVersion":"agentpact/v1","kind":"AgentCapabilities","agent":"a/b",
            "native":{},
            "future_field":"ignored",
            "adaptation":{"detect":{"binaries":["x"]}}
        }"#;
        let m = parse_and_validate(json, "a/b").expect("valid");
        assert!(m.adaptation.is_some());
        // unknown top-level key did not break parsing (forward-compat, I-06)
    }

    #[test]
    fn testInvalidJsonRejected() {
        assert!(parse_and_validate("not json", "a/b").is_err());
    }
}
