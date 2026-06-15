// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The typed §13.4 adaptation profile — the vendor-neutral declaration of how a
//! non-native agent is governed, plus the bounded realization op-lists kyris's
//! generic engine executes against it.
//!
//! Two layers, both DATA (so there is no per-agent Rust):
//! - **Declared facts** (standard, §13.4): `detect`, `config_files`/`discovery`,
//!   per-surface `mechanisms`, the `hook_protocol` IO contract, `markers`,
//!   `settings`, `attribution`. These describe the agent's real surfaces.
//! - **Realization ops** (implementation-specific, §13.4 boundary note): the
//!   `configure`/`probe`/`undo` lists per surface. A bounded, frozen op
//!   vocabulary the engine maps to the existing shared write/probe/restore
//!   helpers. The vocabulary grows only by a deliberate engine change, never by
//!   new JSON control constructs (see `forest/design/agent-integration.md`).
//!
//! The type set is grown agent-by-agent against proven need; cline is the first.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::profile::CoverageCeiling;
use super::registry::{
    AttributionMechanism, BurnControlMechanism, ExecutionMechanism, HookProtocol, ToolMechanism,
};

#[derive(Debug, Clone, Deserialize)]
pub struct AdaptationProfile {
    #[serde(default)]
    pub detect: Detect,
    /// Named config files → how to locate them. Ops and probes reference a file
    /// by name, so the same physical file is resolved once.
    #[serde(default)]
    pub config_files: BTreeMap<String, ConfigFile>,
    #[serde(default)]
    pub surfaces: Surfaces,
    #[serde(default)]
    pub attribution: Vec<AttributionMechanism>,
    #[serde(default)]
    pub agentpact_native_attribution: bool,
    /// Env var carrying the agent's fixed launch/permitted dir into its hook
    /// (e.g. `CLAUDE_PROJECT_DIR`); `None` → the hook payload `cwd` is the anchor.
    #[serde(default)]
    pub launch_dir: Option<String>,
    /// For an agent whose governance *realization* (probe / configure / undo) is
    /// too irreducible to express as data ops (codex: trust-hashing, TOML-shape
    /// validation, compiled rules, single read-modify-write), the daemon handler
    /// id that realizes it. The document still carries all DATA (surfaces, hook
    /// contract, mechanisms); only the realization is delegated — and it is
    /// bypassed entirely for any surface the agent later declares native (§13.4:
    /// daemon realization is implementation-specific, outside the standard).
    #[serde(default)]
    pub delegate: Option<String>,
    /// The agent's hook IO contract (already-serde `HookProtocol`).
    #[serde(default)]
    pub hook_protocol: Option<HookProtocol>,
    /// Substrings that identify a kyris installation in the agent's files
    /// (drift/repair detection).
    #[serde(default)]
    pub markers: Vec<String>,
    /// `kyris agent setup --set KEY=VALUE` keys this agent accepts.
    #[serde(default)]
    pub settings: Vec<SettingSpec>,
    /// Whether to run the agent's `agentpact` capability-declaration command at
    /// setup/reconcile to discover native support (§13.3). `false` until the
    /// agent actually ships the command — flipping this one flag is how an agent
    /// going native is picked up, with no other code change. Default `false` so a
    /// non-supporting binary is never invoked with an unknown subcommand.
    #[serde(default)]
    pub live_query: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Detect {
    /// Binaries that, if on `PATH`, prove the agent present.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// `config_files` names whose existence proves the agent present.
    #[serde(default)]
    pub config_paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    pub discovery: Discovery,
    #[serde(default)]
    pub format: FileFormat,
}

/// The bounded set of ways an agent's config is located (frozen to the 5 agents).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discovery {
    /// A fixed path; `~` expands to the home directory.
    Static { path: String },
    /// `<env or fallback>/subpath` (e.g. `CODEX_HOME`).
    EnvRooted {
        env: String,
        subpath: String,
        fallback: String,
    },
    /// First of `filenames` found walking up from the working directory; if none,
    /// the same `filenames` preference within `global_dir`, defaulting to the
    /// last filename there when none exist.
    WalkUp {
        filenames: Vec<String>,
        global_dir: String,
    },
    /// A file resolved as a sibling of another named config file — the resolved
    /// path of `file`'s parent joined with `name` (e.g. opencode's plugin next
    /// to whichever config registered it).
    SiblingOf { file: String, name: String },
    /// First of `filenames` found walking up from the working directory, with NO
    /// global fallback — resolution fails (and the referencing source is
    /// skipped) when none is found (Claude's project `.mcp.json`).
    WalkUpOptional { filenames: Vec<String> },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileFormat {
    #[default]
    Json,
    Toml,
    /// JSON with comments / trailing commas (opencode).
    Jsonc,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Surfaces {
    #[serde(default)]
    pub execution: Option<ExecutionSurface>,
    #[serde(default)]
    pub tool: Option<ToolSurface>,
    /// The standard surface name is `model_routing` (§13.4); kyris's internal
    /// surface for it is burn-control.
    #[serde(default)]
    pub model_routing: Option<ModelRoutingSurface>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionSurface {
    #[serde(default)]
    pub mechanisms: Vec<ExecutionMechanism>,
    #[serde(default)]
    pub configure: Vec<ConfigureOp>,
    /// Primary detection: any rule matching reports `mechanisms[0]`.
    #[serde(default)]
    pub probe: Vec<ProbeRule>,
    /// Secondary detection used when `probe` doesn't match — reports its own
    /// mechanism/ceiling (e.g. gemini's compiled-policy fallback under the live
    /// hook, with a `compiled` coverage ceiling).
    #[serde(default)]
    pub fallback: Option<ExecutionFallback>,
    #[serde(default)]
    pub undo: Vec<UndoOp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionFallback {
    pub probe: Vec<ProbeRule>,
    pub mechanism: ExecutionMechanism,
    #[serde(default)]
    pub ceiling: Option<CoverageCeiling>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolSurface {
    #[serde(default)]
    pub mechanisms: Vec<ToolMechanism>,
    /// Where this agent's MCP servers are configured — one or more sources
    /// (Claude has three: user, per-project, and a walk-up `.mcp.json`).
    pub mcp: Vec<McpSource>,
    /// Key path to the MCP servers object for the native per-server tool
    /// denylist (`excludeTools`) — gemini. Drives `apply_extra_tool_filters`.
    #[serde(default)]
    pub exclude_tools: Option<Vec<String>>,
    #[serde(default)]
    pub configure: Vec<ConfigureOp>,
    // No `probe` field: tool detection is always the specialized MCP-wrap status
    // (with the not-applicable nuance for "no servers configured"), evaluated in
    // `GenericAgent::probe`, not a generic probe-rule list.
    #[serde(default)]
    pub undo: Vec<UndoOp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpSource {
    /// `config_files` name holding the MCP servers.
    pub config: String,
    /// Key path to the servers object within that file. With `nested_scope`, a
    /// `"*"` segment is a wildcard enumerated over the parent object's keys
    /// (Claude's `projects.*.mcpServers`).
    pub servers_key: Vec<String>,
    /// Expand a `"*"` in `servers_key` over the parent object's keys, emitting a
    /// location per child that has a non-empty servers object. A source whose
    /// file does not resolve (e.g. a `walk_up_optional` `.mcp.json` not found) is
    /// simply skipped.
    #[serde(default)]
    pub nested_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingKind {
    /// Base-URL/header environment variables the agent honors (claude, gemini).
    Env,
    /// Base-URL stored in config keys (cline, opencode).
    Config,
    /// A custom provider table the agent supports (codex).
    ProviderTable,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelRoutingSurface {
    /// The §13.4 routing kind (env / config / `provider_table`) — vendor-facing
    /// declaration. kyris derives its realization from `mechanisms`/`env`, so it
    /// is not consumed here; kept for spec fidelity and other daemons.
    #[allow(dead_code)]
    pub kind: RoutingKind,
    #[serde(default)]
    pub mechanisms: Vec<BurnControlMechanism>,
    /// For `kind: env` — the env vars/headers the agent honors, delivered via
    /// the launch env file (not a config write). Drives `provider_routing`.
    #[serde(default)]
    pub env: Option<EnvRouting>,
    #[serde(default)]
    pub configure: Vec<ConfigureOp>,
    #[serde(default)]
    pub probe: Vec<ProbeRule>,
    #[serde(default)]
    pub undo: Vec<UndoOp>,
}

/// Env routing for a `kind: env` model-routing surface — the provider base-URL
/// vars to repoint, auth-skip flags, and the custom-headers var carrying the
/// gate secret + agent id. Delivered via the launch env file.
#[derive(Debug, Clone, Deserialize)]
pub struct EnvRouting {
    pub base_url_vars: Vec<String>,
    #[serde(default)]
    pub auth_skip_flags: Vec<(String, String)>,
    pub custom_headers_var: String,
    pub header_separator: String,
}

/// Bounded configure operations the engine executes (frozen vocabulary).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigureOp {
    /// Write a named bridge/plugin template to a `config_files` dest, with
    /// `{spawn_timeout_ms}` etc. substituted from the hook runtime.
    InstallFile {
        template: String,
        dest: String,
        #[serde(default)]
        mode: Option<String>,
    },
    /// Set a key path in a config file to a value. The value is a JSON literal;
    /// string values are templated with `{base_url}`, `{base_url_v1}`,
    /// `{inbound_key}`, `{agent_id}`.
    SetKey {
        file: String,
        path: Vec<String>,
        value: serde_json::Value,
    },
    /// Route the tool surface's MCP servers through kyrisd (shared rewrite).
    RouteMcp,
    /// Install a JS plugin bridge (source generated per agent) to `dest` and
    /// register its path in the `register_in` config's `plugin` array
    /// (opencode's plugin system).
    InstallPlugin { dest: String, register_in: String },
    /// Refuse to proceed if `file` is JSONC-syntax (comments / trailing commas)
    /// that kyris cannot round-trip — fail loudly with a convert-to-JSON hint
    /// rather than silently mangle it. No-op for strict-JSON or absent files.
    RequireWritable { file: String },
    /// Apply opencode's scoped governed-tool permissions (`bash`/`edit`/`write`
    /// = allow, dropping a blunt allow-all, preserving the user's other rules).
    SetGovernedPermissions { file: String },
    /// Remove the key at `path` in `file` when its value equals the inbound key
    /// (stale-credential cleanup from older installs).
    StripKeyIfEqualsInbound { file: String, path: Vec<String> },
    /// Install a live-hook adapter: write the agent's hook launcher script to
    /// `script` and register `events` in the `register_in` config (Claude's
    /// `PreToolUse`). `register_settings` toggles writing the settings entry.
    InstallHook {
        script: String,
        register_in: String,
        events: Vec<String>,
        /// Nested hook-config layout (the agent nests hooks under an event key).
        #[serde(default)]
        nested: bool,
        /// Per-hook timeout in the agent's native units (ms for gemini), when its
        /// default is below kyris's poll window (Gemini's 60s default).
        #[serde(default)]
        hook_timeout: Option<i64>,
    },
    /// Write the agent's native per-tool MCP deny entries (`mcp__{server}__{tool}`)
    /// for the currently-configured MCP servers into `file` (Claude's
    /// `permissions.deny`).
    McpDerivedDenies { file: String },
    /// Compile kyris policy to the agent's native compiled-policy format and
    /// write it to `dest` (gemini's `policies/agentpact.toml`).
    WriteCompiledPolicy { dest: String },
    /// Force a kyrisd-routable auth selection in `file` when the current one is
    /// not routable AND a usable API key exists; otherwise warn (gemini).
    EnsureRoutableAuth { file: String },
    /// Set `path` in `file` from the `--set` value named `input`, when provided
    /// (parsed as a non-negative integer); gemini's `model.maxSessionTurns`.
    SetSettingFromInput {
        file: String,
        path: Vec<String>,
        input: String,
    },
    /// Remove a legacy command hook (whose command contains `marker`) from
    /// `file`'s `event` hook array — a one-time migration of a stray hook an
    /// older install left in a secondary file (gemini's workspace-settings
    /// `BeforeTool`, redundant with the user-level hook + trips a trust banner).
    /// No-op when `file` does not resolve / exist. Recorded under the surface's
    /// component so undo restores it.
    RemoveLegacyHook {
        file: String,
        event: String,
        marker: String,
    },
}

/// Bounded probe rules; each records the given mechanism on the surface when it
/// matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeRule {
    /// The named config file exists.
    FileExists { file: String },
    /// The named config file's contents contain `marker` (e.g. a hook is
    /// registered in settings).
    ContainsMarker { file: String, marker: String },
    /// kyris-wrapped MCP servers are present (shared MCP-wrap status).
    McpWrap,
    /// `file` at `path` equals kyrisd's base URL (+ optional `suffix`, e.g. `/v1`).
    KeyEqualsKyrisd {
        file: String,
        path: Vec<String>,
        #[serde(default)]
        suffix: Option<String>,
    },
    /// The string array at `path` in `file` contains an entry matching `value`.
    ArrayContains {
        file: String,
        path: Vec<String>,
        value: String,
    },
    /// The environment variable `var` routes to kyrisd (env-proxy evidence).
    EnvPointsKyrisd { var: String },
    /// The compiled-policy file at `file` loads at least one rule (gemini).
    CompiledPolicyLoadable { file: String },
    /// The agent's effective auth selection routes through kyrisd — `file`'s
    /// (and optional `alt_file`'s, which wins) `security.auth.selectedType` is a
    /// routable type (gemini).
    AuthRoutable {
        file: String,
        #[serde(default)]
        alt_file: Option<String>,
    },
    /// All nested rules must match (AND); a surface's top-level probe list is
    /// otherwise OR (any rule matches).
    All { rules: Vec<ProbeRule> },
    /// The installed hook launcher script at `file` matches what the current
    /// kyris would write (drift detection — a stale script reads as not-adapted).
    HookScriptMatches { file: String },
}

/// Bounded undo operations.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoOp {
    /// Semantic reversible restore of a managed file by manifest scope; if no
    /// manifest entry exists, delete the file when `delete_if_unmanaged`.
    ManifestRestore {
        file: String,
        scope: String,
        #[serde(default)]
        delete_if_unmanaged: bool,
    },
    /// Undo the shared MCP tool surface.
    UndoMcp,
    /// Delete the agent's launch env file (`~/.kyris/env/<id>.sh`) — the
    /// env-proxy burn-control artifact.
    DeleteEnvFile,
    /// Restore every file recorded under a manifest `scope` (covers files an
    /// undo run from another cwd could not re-derive — gemini).
    RestoreComponent { scope: String },
    /// Delete a named config file outright (unrecorded leftover cleanup).
    DeleteFile { file: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct SettingSpec {
    pub key: String,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::super::manifest::parse_and_validate;
    use super::*;

    #[test]
    fn testClineDocumentParsesIntoTypedAdaptation() {
        let m = parse_and_validate(super::super::documents::CLINE, "cline/cline")
            .expect("cline document valid");
        // core: non-native today
        let n = m.native_capabilities();
        assert!(!n.execution && !n.tool && !n.burn_control && !n.attribution);

        let ad = m
            .adaptation
            .as_ref()
            .expect("cline has an adaptation profile");
        // detect
        assert!(ad.detect.binaries.contains(&"cline".to_string()));
        assert!(ad.detect.config_paths.contains(&"hook".to_string()));
        // attribution facts preserved
        assert!(
            ad.attribution
                .contains(&AttributionMechanism::KyrisPathShim)
        );
        assert!(!ad.agentpact_native_attribution);
        // markers
        assert!(ad.markers.contains(&"kyris hook check".to_string()));
        assert!(ad.markers.contains(&"kyris-mcp".to_string()));
        // no settings (cline has no native_ask → no approval_prompt)
        assert!(ad.settings.is_empty());
    }

    #[test]
    fn testClineSurfacesAndMechanisms() {
        let m = parse_and_validate(super::super::documents::CLINE, "cline/cline").unwrap();
        let ad = m.adaptation.unwrap();
        let exec = ad.surfaces.execution.expect("execution surface");
        assert_eq!(exec.mechanisms, vec![ExecutionMechanism::LiveHookAdapter]);
        let tool = ad.surfaces.tool.expect("tool surface");
        assert_eq!(tool.mechanisms, vec![ToolMechanism::McpWrapping]);
        assert_eq!(tool.mcp[0].servers_key, vec!["mcpServers".to_string()]);
        let mr = ad.surfaces.model_routing.expect("model_routing surface");
        assert_eq!(mr.kind, RoutingKind::Config);
        assert_eq!(mr.mechanisms, vec![BurnControlMechanism::ConfigRewrite]);
    }

    #[test]
    fn testClineHookProtocolRoundTrips() {
        let m = parse_and_validate(super::super::documents::CLINE, "cline/cline").unwrap();
        let hp = m.adaptation.unwrap().hook_protocol.expect("hook protocol");
        assert_eq!(hp.runtime.agent_hook_timeout_secs, 120);
        assert!(!hp.runtime.native_backstop);
        // apply_patch maps to the apply_patch action (Finding 10)
        let ap = hp
            .tool_mappings
            .iter()
            .find(|t| t.tool_name == "apply_patch")
            .expect("apply_patch mapping");
        assert_eq!(ap.action, "apply_patch");
        let mtn = hp.mcp_tool_naming.expect("cline declares mcp tool naming");
        assert_eq!(mtn.server_separator, "__");
        assert!(mtn.collapse_sanitize_runs);
    }

    #[test]
    fn testClineConfigureOpsShape() {
        let m = parse_and_validate(super::super::documents::CLINE, "cline/cline").unwrap();
        let ad = m.adaptation.unwrap();
        // execution installs the bridge template
        let exec = ad.surfaces.execution.unwrap();
        assert!(matches!(
            exec.configure.first(),
            Some(ConfigureOp::InstallFile { dest, .. }) if dest == "hook"
        ));
        // tool routes mcp
        let tool = ad.surfaces.tool.unwrap();
        assert!(matches!(
            tool.configure.first(),
            Some(ConfigureOp::RouteMcp)
        ));
        // model_routing writes the anthropic block via set_key ops
        let mr = ad.surfaces.model_routing.unwrap();
        assert!(
            mr.configure
                .iter()
                .any(|op| matches!(op, ConfigureOp::SetKey { .. }))
        );
    }
}
