// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::capabilities::NativeCapabilityDeclaration;
use super::probe::ProbeResult;
use super::profile::{CoverageCeiling, NativeEvidence};

pub trait AgentDescriptor {
    fn id(&self) -> &'static str;
    /// Canonical `vendor/product` agent id — the form agentpact's attribution
    /// emits into governance events (see agentpact `defaults/agents.yaml`).
    /// `id()` is the bare kyris CLI/registry handle (`claude-code`); this is the
    /// form that must land in the timeline `agent` field — both the
    /// `x-kyris-agent-id` header kyrisd writes onto a gateway record and the
    /// `attribution.resolve` result — so kyrisd-only records unify with
    /// governance events instead of appearing as a second, differently-named
    /// agent. Keep this match in sync with agentpact's `agents.yaml`.
    fn canonical_id(&self) -> &'static str {
        canonical_agent_id(self.id())
    }
    fn is_installed(&self) -> bool;
    fn probe(&self) -> ProbeResult;
    fn native_evidence(&self) -> NativeEvidence {
        NativeEvidence::default()
    }
    fn kyris_content_markers(&self) -> Vec<String>;
    /// Declares how an env-routed (`EnvVarProxy`) agent is pointed at kyrisd:
    /// which provider base-URL env vars to repoint, any auth-skip flags, and the
    /// provider CLI's custom-headers env var (+ multi-header separator) that
    /// carries kyrisd's gate secret and agent-id attribution. `None` (the
    /// default) → the agent is config-routed or has no burn-control surface, so
    /// `env_exports` is empty. This is the single declarative source for env
    /// routing; agents supply data, not construction code.
    fn provider_routing(&self) -> Option<ProviderRouting> {
        None
    }
    /// Routing env written to `~/.kyris/env/<id>.sh` and delivered on every
    /// launch. Built uniformly from [`Self::provider_routing`]: every base-URL
    /// var is repointed at kyrisd, the auth-skip flags are set verbatim, and the
    /// gate secret + agent-id ride in the agent's custom-headers env var. The
    /// agent's OWN provider credential (subscription OAuth or the user's API key)
    /// is deliberately NOT set, so it flows through to the provider untouched for
    /// kyrisd to forward and classify included-vs-overage. Override only for a
    /// routing shape this declarative form cannot express.
    fn env_exports(&self, base_url: &str, inbound_key: &str) -> Vec<(String, String)> {
        let Some(routing) = self.provider_routing() else {
            return Vec::new();
        };
        let mut exports: Vec<(String, String)> = routing
            .base_url_vars
            .iter()
            .map(|var| (var.clone(), base_url.to_string()))
            .collect();
        exports.extend(
            routing
                .auth_skip_flags
                .iter()
                .map(|(var, val)| (var.clone(), val.clone())),
        );
        exports.push((
            routing.custom_headers_var.clone(),
            format!(
                "x-kyris-inbound: {inbound_key}{}x-kyris-agent-id: {}",
                routing.header_separator,
                self.canonical_id()
            ),
        ));
        exports
    }
    fn integration_plan(&self) -> AgentIntegrationPlan;
    fn expected_surfaces(&self) -> (bool, bool, bool) {
        self.integration_plan().expected_surfaces()
    }
    /// Environment variable carrying the agent's FIXED launch/project directory
    /// into its hook subprocess (e.g. `CLAUDE_PROJECT_DIR`). When set,
    /// `kyris hook check` uses it as the permitted-domain anchor instead of the
    /// hook payload's `cwd` — which for some agents (notably Claude Code) is the
    /// LIVE working directory that moves when the agent runs `cd`, and so must
    /// not define the workspace boundary. `None` → fall back to the payload
    /// `cwd` (already fixed at session start for agents like Codex and Gemini).
    /// See `crate::hook_cmd::derive_session_cwd`.
    fn launch_dir_env(&self) -> Option<String> {
        None
    }
    /// Per-surface design ceiling (exec, tool, burn). `Some(Compiled)` means
    /// the agent has no path beyond compiled-policy for that surface — so
    /// realizing Compiled is `ok`, not a degradation. Default: `None` for all
    /// surfaces (any Compiled outcome is treated as a degradation).
    fn surface_design_ceilings(
        &self,
    ) -> (
        Option<CoverageCeiling>,
        Option<CoverageCeiling>,
        Option<CoverageCeiling>,
    ) {
        self.integration_plan().surface_design_ceilings()
    }
    fn configure_execution_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn configure_tool_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    /// Optional agent-specific tool filter applied to a JSON MCP config by
    /// `configure::configure_json_mcp_tool_surface`, on top of the shared MCP
    /// rewrite. Returns whether `settings` changed. Default: nothing (the
    /// runtime wrap/routing still enforces tool denial — see configure.rs).
    fn apply_extra_tool_filters(&self, _settings: &mut serde_json::Value) -> bool {
        false
    }
    fn configure_burn_control_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        Ok(())
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        Ok(())
    }
    /// Manifest-INDEPENDENT removal of any kyris residue left in this agent's
    /// config files (stale credentials, kyris headers/baseURL, plugin/hook
    /// registrations, kyris-installed script files). Runs after the surface
    /// undos as a backstop so `uninstall`/`disconnect` leave nothing behind even
    /// when the manifest is stale or never recorded an edit. Returns the
    /// human-readable changes made. Best-effort; default is a no-op.
    fn scrub_residue(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        None
    }
    /// Every config location whose MCP servers kyris must route. Most agents
    /// have one; Claude Code has three scopes (`~/.claude.json` user-level,
    /// `~/.claude.json` per-project local entries, and a project `.mcp.json`),
    /// so the contract is plural — wrapping only one scope silently leaves the
    /// others ungoverned. Implementations may read the filesystem to enumerate
    /// dynamic locations (e.g. per-project keys).
    fn mcp_configs(&self) -> Vec<McpConfigLocation> {
        Vec::new()
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    /// Keys accepted by `kyris agent setup <agent> --set KEY=VALUE`, each with a
    /// short description. Any `--set` key not listed here is rejected fail-fast
    /// rather than silently stored and ignored. Default: none.
    fn supported_settings(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

// Owned, not `Copy`: the plan can be built from a parsed JSON document (an agent
// `adaptation` profile) at runtime, so the mechanism/attribution lists are owned
// `Vec`s rather than `&'static` slices baked into the binary. Clone, not Copy,
// for the same reason (a `Vec` owns heap memory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIntegrationPlan {
    pub execution: SurfaceIntegration<ExecutionMechanism>,
    pub tool: SurfaceIntegration<ToolMechanism>,
    pub burn_control: SurfaceIntegration<BurnControlMechanism>,
    pub attribution: Vec<AttributionMechanism>,
    pub agentpact_native_attribution: bool,
}

impl AgentIntegrationPlan {
    pub fn expected_surfaces(&self) -> (bool, bool, bool) {
        (
            !self.execution.is_none(),
            !self.tool.is_none(),
            !self.burn_control.is_none(),
        )
    }

    pub fn surface_design_ceilings(
        &self,
    ) -> (
        Option<CoverageCeiling>,
        Option<CoverageCeiling>,
        Option<CoverageCeiling>,
    ) {
        (
            self.execution.ceiling(),
            self.tool.ceiling(),
            self.burn_control.ceiling(),
        )
    }

    pub fn requires_path_shim(&self) -> bool {
        !self.agentpact_native_attribution
            && self
                .attribution
                .contains(&AttributionMechanism::KyrisPathShim)
    }

    pub fn has_adapted_execution(&self) -> bool {
        matches!(self.execution, SurfaceIntegration::Adapted { .. })
    }

    pub fn has_adapted_tool(&self) -> bool {
        matches!(self.tool, SurfaceIntegration::Adapted { .. })
    }

    pub fn has_adapted_burn_control(&self) -> bool {
        matches!(self.burn_control, SurfaceIntegration::Adapted { .. })
    }

    pub fn with_native_capabilities(mut self, capabilities: NativeCapabilityDeclaration) -> Self {
        if capabilities.execution {
            self.execution = SurfaceIntegration::AgentPactNative;
        }
        if capabilities.tool {
            self.tool = SurfaceIntegration::AgentPactNative;
        }
        if capabilities.burn_control {
            self.burn_control = SurfaceIntegration::AgentPactNative;
        }
        if capabilities.attribution {
            self.agentpact_native_attribution = true;
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SurfaceIntegration<M> {
    None,
    AgentPactNative,
    Adapted {
        mechanisms: Vec<M>,
        ceiling: Option<CoverageCeiling>,
    },
}

impl<M> SurfaceIntegration<M> {
    pub fn adapted(mechanisms: Vec<M>) -> Self {
        Self::Adapted {
            mechanisms,
            ceiling: None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn ceiling(&self) -> Option<CoverageCeiling> {
        match self {
            Self::Adapted { ceiling, .. } => *ceiling,
            Self::None | Self::AgentPactNative => None,
        }
    }
}

// Per-surface mechanism enums are the SINGLE vocabulary for each surface: used
// by both the plan (`SurfaceIntegration<M>`) and the observed state
// (`SurfaceState<M>`). There is no separate "observed" enum, so a
// correctly-configured surface can never render an obs/plan label skew. The
// per-surface typing also keeps it a compile error to name a tool mechanism in
// the execution slot, etc. `MechanismLabel` is the one place each mechanism's
// short/detail strings are defined — shared by `display.rs` and `status.rs`.

/// Rendering for a surface mechanism: `short` is the compact status label
/// (e.g. "hook", "policy", "mcp", "proxy", "config", "provider"), `detail` the
/// longer human form used in the detail view (e.g. "compiled policy").
pub trait MechanismLabel {
    fn short(&self) -> &'static str;
    fn detail(&self) -> &'static str;
    /// True for "in-band" / live mediation (live hook, MCP wrap, env proxy) — as
    /// opposed to static mechanisms (compiled policy, config rewrite, kyrisd
    /// model provider) that enforce out-of-band and need a re-run of setup to
    /// update. Single source for status's `+`/`~` marker and scan's
    /// degraded-surface detection.
    fn is_in_band(&self) -> bool;
}

/// Render a plan surface for display: "none", "native", or the adapted
/// mechanisms' short labels joined by "+". Shared by every renderer so the plan
/// side and the observed side (which also uses `MechanismLabel::short`) cannot
/// drift apart.
pub fn plan_label<M: MechanismLabel>(plan: &SurfaceIntegration<M>) -> String {
    match plan {
        SurfaceIntegration::None => "none".to_string(),
        SurfaceIntegration::AgentPactNative => "native".to_string(),
        SurfaceIntegration::Adapted { mechanisms, .. } => mechanisms
            .iter()
            .map(MechanismLabel::short)
            .collect::<Vec<_>>()
            .join("+"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ExecutionMechanism {
    // Stable on-disk string predates the `Adapter` suffix; keep it so profiles
    // written before the vocabulary unification still deserialize.
    #[serde(rename = "live_hook")]
    LiveHookAdapter,
    ShellHook,
    CompiledPolicy,
}

impl MechanismLabel for ExecutionMechanism {
    fn short(&self) -> &'static str {
        match self {
            Self::LiveHookAdapter => "hook",
            Self::ShellHook => "shell",
            Self::CompiledPolicy => "policy",
        }
    }
    fn detail(&self) -> &'static str {
        match self {
            Self::LiveHookAdapter => "hook",
            Self::ShellHook => "shell hook",
            Self::CompiledPolicy => "compiled policy",
        }
    }
    fn is_in_band(&self) -> bool {
        match self {
            Self::LiveHookAdapter | Self::ShellHook => true,
            Self::CompiledPolicy => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum ToolMechanism {
    #[serde(rename = "live_hook")]
    LiveHookAdapter,
    McpWrapping,
}

impl MechanismLabel for ToolMechanism {
    fn short(&self) -> &'static str {
        match self {
            Self::LiveHookAdapter => "hook",
            Self::McpWrapping => "mcp",
        }
    }
    fn detail(&self) -> &'static str {
        match self {
            Self::LiveHookAdapter => "hook",
            Self::McpWrapping => "mcp wrapper",
        }
    }
    fn is_in_band(&self) -> bool {
        match self {
            Self::LiveHookAdapter | Self::McpWrapping => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum BurnControlMechanism {
    AgentPactUsageReport,
    KyrisdModelProvider,
    EnvVarProxy,
    ConfigRewrite,
}

impl MechanismLabel for BurnControlMechanism {
    fn short(&self) -> &'static str {
        match self {
            Self::AgentPactUsageReport => "usage",
            Self::KyrisdModelProvider => "provider",
            Self::EnvVarProxy => "proxy",
            Self::ConfigRewrite => "config",
        }
    }
    fn detail(&self) -> &'static str {
        match self {
            Self::AgentPactUsageReport => "usage report",
            Self::KyrisdModelProvider => "kyrisd model provider",
            Self::EnvVarProxy => "env shim",
            Self::ConfigRewrite => "config rewrite",
        }
    }
    fn is_in_band(&self) -> bool {
        match self {
            Self::EnvVarProxy | Self::AgentPactUsageReport => true,
            Self::KyrisdModelProvider | Self::ConfigRewrite => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum AttributionMechanism {
    AgentPactNative,
    KyrisPathShim,
    ShellEnvironmentPolicy,
    NativeHookPayload,
    ProcessLineage,
    PeerProcessObserved,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum McpConfigFormat {
    /// Owned segments, not `&'static str`: Claude Code's local-scope path is
    /// `projects.<absolute project dir>.mcpServers` — a runtime value.
    Json { servers_path: Vec<String> },
    Toml {
        // Owned (not `&'static`) so it can come from a parsed JSON document.
        servers_key: String,
    },
}

#[derive(Debug, Clone)]
pub struct McpConfigLocation {
    pub path: std::path::PathBuf,
    pub format: McpConfigFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMapping {
    pub tool_name: String,
    pub action: String,
    pub detail_key: Option<String>,
}

/// What the agent does when a hook misses its kill deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookTimeoutPosture {
    /// The agent abandons the hook and PROCEEDS with the tool call (codex:
    /// timeout → Failed → not blocked; cline: SIGKILL then proceed). kyris must
    /// answer strictly inside the window or the command runs unguarded.
    FailOpen,
    /// The agent abandons the hook and blocks the tool call. No supported agent
    /// is verified fail-closed today; declared for completeness so a future
    /// agent states it explicitly instead of inheriting an assumption.
    FailClosed,
}

/// The live-hook RUNTIME contract — the per-agent semantics the shared decision
/// engine (`kyris hook check`) must honor, beyond the payload shapes in
/// [`HookProtocol`]. These are the properties that silently diverge per agent
/// (review gaps G1–G3): every live-hook agent declares them explicitly and the
/// registry invariant tests lock them, so one shared code path cannot be
/// fail-safe on one agent and fail-open on another invisibly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRuntime {
    /// Seconds after which the AGENT kills or abandons the hook process — the
    /// EFFECTIVE deadline after kyris's configuration (gemini's 60s default is
    /// pinned to 600s at install; cline's 120s is not configurable). The
    /// install-time pin and the JS bridge/plugin spawn timeouts derive from
    /// this value — it is the single source for the agent's deadline.
    pub agent_hook_timeout_secs: u64,
    /// What the agent does after that deadline (see [`HookTimeoutPosture`]).
    /// Informational today: every supported agent is fail-open, and
    /// [`Self::poll_deadline`] conservatively returns inside the window for
    /// BOTH postures — resolving (clean deny + pending cleanup) beats being
    /// killed mid-poll even on a fail-closed agent. Declared so the
    /// verified-upstream fact is recorded per agent rather than assumed.
    pub on_timeout: HookTimeoutPosture,
    /// Whether the agent's OWN permission system still gates a tool when kyris
    /// answers "no decision" (`EmptyStdout`). True for claude/codex/gemini
    /// (their native approval ladders run after the hook). False where there is
    /// no gate behind kyris — cline's CLI auto-approves by default, and
    /// opencode's native permissions are set permissive BY KYRIS so the plugin
    /// is the sole gate. When false, a defer is a SILENT ALLOW, so the engine
    /// denies (with an actionable reason) instead of deferring — for unmapped
    /// tools and for daemon-unavailable alike.
    pub native_backstop: bool,
    /// Whether the declared `allow_response` actually suppresses the agent's
    /// own permission prompt. True only for Claude Code's JSON
    /// `permissionDecision: allow`. Gemini parses its JSON allow but its
    /// scheduler ignores the decision (policy/confirmation still run), and an
    /// `EmptyStdout` allow never suppresses anything. Drives the `agent_prompt`
    /// audit field — without it the audit claims "none" (no agent prompt) for
    /// agents that will in fact prompt again.
    pub allow_suppresses_agent_prompt: bool,
}

impl HookRuntime {
    /// Safety margin between kyris resolving an approval and the agent's hook
    /// deadline: the resolver must deny, clean up the pending entry, and emit
    /// the agent response before the agent kills the hook.
    pub const RESPONSE_MARGIN_SECS: u64 = 10;

    /// How long the no-TTY approval resolver may poll for this agent: this
    /// agent's own hook deadline minus [`Self::RESPONSE_MARGIN_SECS`], so the
    /// resolver always returns (clean deny + pending cleanup) before the
    /// agent kills the hook. For 600s-deadline agents this is the historical
    /// 590s; for cline (120s, fail-open) it is 110s; for codex — whose
    /// per-hook `timeout` kyris pins to a week so an approval can wait
    /// effectively forever — it is just under that week. The rest of the
    /// approval chain is sized per-request from this value (agentpactd's
    /// `approval_ttl_secs` hint, kyrisd's per-hold `ttl_seconds`), so a
    /// larger declared window propagates automatically.
    #[must_use]
    pub fn poll_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.agent_hook_timeout_secs
                .saturating_sub(Self::RESPONSE_MARGIN_SECS),
        )
    }

    /// Spawn timeout (ms) for the JS bridge/plugin's `spawnSync` of
    /// `kyris hook check` — the backstop if the engine itself hangs. Sits
    /// between [`Self::poll_deadline`] (the engine's own deadline) and the
    /// agent's kill deadline, so the bridge can still emit a clean DENY before
    /// a fail-open agent abandons the hook and runs the command.
    #[must_use]
    pub fn bridge_spawn_timeout_ms(&self) -> u64 {
        self.agent_hook_timeout_secs
            .saturating_sub(Self::RESPONSE_MARGIN_SECS / 2)
            * 1000
    }
}

/// How MCP tools appear in this agent's hook payloads:
/// `sanitize(server) + separator + sanitize(tool)`, where sanitize replaces
/// characters outside `[a-zA-Z0-9_-]` with `_`. Declared so the hook engine can
/// recognize an unmapped tool name as an MCP tool of a kyris-routed server —
/// governed at the TOOL surface (kyris-mcp wrap / kyrisd `/mcp/` routing) — and
/// not deny it under the no-backstop posture. Only consulted for
/// `native_backstop: false` agents; backstopped agents keep the plain
/// warn-and-defer path for unmapped names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolNaming {
    /// Separator between the sanitized server name and the tool name
    /// (opencode: `"_"`; cline: `"__"`).
    pub server_separator: String,
    /// Whether runs of invalid characters collapse into ONE underscore (cline's
    /// `[^a-zA-Z0-9_-]+` regex) or map one-to-one (opencode's per-character
    /// replace).
    pub collapse_sanitize_runs: bool,
}

impl McpToolNaming {
    // Iterates Rust chars; the agents' JS replaces operate per UTF-16 code
    // unit, so a non-BMP char in a server name sanitizes to TWO underscores
    // upstream vs one here. The mismatch direction is fail-safe (no exemption
    // → deny); ASCII server names — the practical universe — are identical.
    fn sanitize(&self, name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        let mut last_was_replaced = false;
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                out.push(ch);
                last_was_replaced = false;
            } else if !(self.collapse_sanitize_runs && last_was_replaced) {
                out.push('_');
                last_was_replaced = true;
            }
        }
        out
    }

    /// Whether `tool` is named like an MCP tool of `server` under this agent's
    /// naming scheme. Prefix-only: the tool part is the server's business.
    /// Callers resolving ambiguity between servers must pick the LONGEST
    /// sanitized match (see `is_kyris_routed_mcp_tool` in `hook_cmd`).
    #[must_use]
    pub fn tool_belongs_to_server(&self, tool: &str, server: &str) -> bool {
        let prefix = format!("{}{}", self.sanitize(server), self.server_separator);
        tool.len() > prefix.len() && tool.starts_with(&prefix)
    }

    /// Length of the server's sanitized form — the tie-breaker for ambiguous
    /// prefix matches across servers.
    #[must_use]
    pub fn sanitized_len(&self, server: &str) -> usize {
        self.sanitize(server).len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookProtocol {
    pub tool_name_field: String,
    pub detail_fields: Vec<String>,
    /// Tools that route through `agentpactd` for policy enforcement
    /// (Bash → execute, Read → read, MCP servers → call, …).
    pub tool_mappings: Vec<ToolMapping>,
    /// Tools that are allowed without contacting `agentpactd` — LLM
    /// coordination primitives with no governable side effect
    /// (`AskUserQuestion`, `TodoWrite`, `ExitPlanMode`, etc.). Skipping the
    /// daemon is required because the daemon contract for `action=call`
    /// demands `context.mcp_server`, which these tools cannot supply. In
    /// enforce mode these emit the agent's NATIVE allow shape — suppressing its
    /// own prompt — so only list tools where frictionless execution is the
    /// intended outcome.
    /// Tools not in this list, `agent_owned_tools`, or `tool_mappings` are
    /// *unmapped*: kyris emits a stderr warning and (for backstopped agents)
    /// defers to the agent's own permission system (the `EmptyStdout` "no
    /// decision" shape), behaving as if it were not installed — it never
    /// suppresses the agent's prompt for an unknown tool.
    pub pass_through_tools: Vec<String>,
    /// Tools kyris DELIBERATELY leaves to the agent's own permission system:
    /// known, classified, but neither governed (no agentpactd mapping fits)
    /// nor blessed (suppressing the agent's native prompt would remove a real
    /// control — e.g. Claude Code's `WebFetch` domain rules, `SendMessage`
    /// session targeting, `SlashCommand` allowed-tools grants). Emits
    /// `EmptyStdout` with no unmapped warning; audited as `agent_owned`.
    /// Meaningless without a native backstop (it would be a silent allow) —
    /// locked by `testAgentOwnedToolsRequireNativeBackstop`.
    pub agent_owned_tools: Vec<String>,
    pub default_action: String,
    pub allow_response: AllowResponse,
    /// Per-agent runtime semantics the decision engine must honor (timeout
    /// window, defer posture, allow effect). Required — every live-hook agent
    /// states these explicitly; the registry tests lock the declared values.
    pub runtime: HookRuntime,
    /// The agent's native-approval hook integration, when the agent has a
    /// second hook event consulted exactly where it would PROMPT the user
    /// (Codex's `PermissionRequest`). `Some(body)` = the JSON to emit when
    /// kyris answers "allow" (suppressing the native prompt); abstain is empty
    /// stdout. `None` = the agent has no such event; the engine abstains if it
    /// ever sees one. This is the allow-path completion that PreToolUse-style
    /// hooks cannot provide (codex parses a JSON allow there as Failed) — it
    /// eliminates the kyris-approves-then-agent-prompts-again double prompt.
    pub permission_request_allow: Option<serde_json::Value>,
    /// How MCP tools are named in hook payloads, for agents whose unmapped
    /// tools must not be denied when they are wrap-governed MCP tools. `None`
    /// for backstopped agents (unmapped defers to the agent's own prompt).
    pub mcp_tool_naming: Option<McpToolNaming>,
    /// How this agent shows an `ask` verdict through its OWN native approval
    /// prompt, when the `approval_prompt` setting opts into native mode
    /// (kyris popup is the default). `None` = the agent has no per-call native
    /// ask channel its hook can drive (opencode/cline: their hooks gate only
    /// per-tool-name, with no per-call "ask" signal), so native mode is
    /// unavailable and the kyris pending-approval popup is always used. See
    /// [`AskResponse`].
    pub native_ask: Option<AskResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowResponse {
    EmptyStdout,
    Json { body: serde_json::Value },
}

/// How kyris asks the human through the AGENT's own native approval prompt for
/// an `ask` verdict, instead of holding the kyris pending-approval popup. The
/// agent's native prompt is in-band (no terminal corruption) and waits for the
/// user with no hook-kill deadline — unlike a synchronous kyris hold, which
/// races the agent's hook timeout (codex 600s) and freezes the agent's turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskResponse {
    /// Emit this JSON (exit 0) at the governance hook to make the agent show its
    /// own prompt: Claude Code's `PreToolUse` `permissionDecision: "ask"`,
    /// Gemini's `{"decision": "ask"}`. Single-phase — this hook IS the ask.
    NativePrompt { body: serde_json::Value },
    /// Abstain (empty stdout, exit 0) at the governance hook and let the agent's
    /// SEPARATE native-approval hook drive the prompt: codex's `PreToolUse`
    /// cannot emit "ask" (it parses a JSON allow as Failed), so the ask is
    /// delegated to
    /// the `PermissionRequest` hook (`permission_request_allow`), which abstains
    /// for an unvouched request so codex's own prompt appears. Requires the agent
    /// to route governed commands to its approval ladder (codex
    /// `approval_policy = "untrusted"`); see `run_permission_request`.
    DeferToNativeApproval,
}

/// Which approval UX a native-capable agent uses for an `ask` verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    /// The agent's own native prompt (via [`AskResponse`]). Opt-in
    /// (`approval_prompt=native`) for agents that declare `native_ask`;
    /// dormant otherwise. Trades away the popup's audit trail, "Always"
    /// persistence, per-segment decisions, and walk-away approval.
    Native,
    /// kyris's out-of-band pending-approval popup (the synchronous hold) —
    /// the default for every agent, and the only option for agents without a
    /// `native_ask` channel.
    KyrisPopup,
}

/// `kyris agent setup <agent> --set approval_prompt=native|kyris` — selects the
/// approval UX for an `ask`. Stored in the agent profile's `agent_specific`.
pub const APPROVAL_PROMPT_SETTING: &str = "approval_prompt";

/// Description for [`APPROVAL_PROMPT_SETTING`] in `supported_settings`.
pub const APPROVAL_PROMPT_SETTING_DESC: &str = "Approval UX for an `ask`: `kyris` (kyris's pending-approval popup — \
     default) or `native` (the agent's own prompt)";

/// Resolve the approval UX for an agent. The default is
/// [`ApprovalMode::KyrisPopup`] for every agent: the popup is the only mode
/// that records the human's decision in agentpact's event log, persists
/// "Always" into policy, approves per-segment, and supports walk-away /
/// cross-device resolution. Native mode hands the ask to the agent's own
/// prompt and never learns the outcome (and on codex its safe-command list
/// can skip the prompt entirely), so it is opt-in:
/// `kyris agent setup <agent> --set approval_prompt=native`, honored only
/// for agents that declare a `native_ask` channel. The native machinery
/// stays in place — dormant, not removed.
#[must_use]
pub fn resolve_approval_mode(agent_id: &str, native_capable: bool) -> ApprovalMode {
    if !native_capable {
        return ApprovalMode::KyrisPopup;
    }
    // Single source of truth: the persisted `approval_prompt` agent-profile
    // setting (`kyris agent setup <agent> --set approval_prompt=native|kyris`).
    let setting = crate::state::load_agent_profile(agent_id)
        .ok()
        .flatten()
        .and_then(|p| p.agent_specific.get(APPROVAL_PROMPT_SETTING).cloned());
    match setting.as_deref() {
        Some("native") => ApprovalMode::Native,
        // Default (incl. an unrecognized value) is the kyris popup.
        _ => ApprovalMode::KyrisPopup,
    }
}

/// Declarative routing for an env-routed (`EnvVarProxy`) agent — consumed by
/// [`AgentDescriptor::env_exports`]'s default impl. All cross-agent variation
/// (provider base-URL var names, auth-skip flags, the custom-headers env var and
/// its multi-header separator) lives here as data, so adding an env-routed agent
/// is one [`AgentDescriptor::provider_routing`] declaration with no construction
/// code. The agent's own provider credential is never part of this — it flows
/// through to the provider untouched (see `env_exports`).
// Owned (not `&'static`) so it can be built from a parsed JSON `model_routing`
// surface as well as from a source literal.
pub struct ProviderRouting {
    /// Provider base-URL env vars to repoint at kyrisd (each set to `base_url`).
    pub base_url_vars: Vec<String>,
    /// Provider auth-skip flags set verbatim (e.g. `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1`).
    pub auth_skip_flags: Vec<(String, String)>,
    /// The provider CLI's custom-headers env var carrying the gate secret +
    /// agent-id (Claude Code: `ANTHROPIC_CUSTOM_HEADERS`; Gemini CLI:
    /// `GEMINI_CLI_CUSTOM_HEADERS`).
    pub custom_headers_var: String,
    /// Separator the CLI's parser expects between multiple headers in that var
    /// (Claude Code: `"\n"`; Gemini CLI: `", "`).
    pub header_separator: String,
}

/// Map a bare kyris registry handle (`claude-code`) to the canonical
/// `vendor/product` id agentpact attribution emits. Unknown ids pass through
/// unchanged. Single source for both `AgentDescriptor::canonical_id` and the
/// generic engine's document validation. Keep in sync with agentpact `agents.yaml`.
#[must_use]
pub fn canonical_agent_id(id: &'static str) -> &'static str {
    match id {
        "claude-code" => "anthropic/claude-code",
        "codex-cli" => "openai/codex-cli",
        "gemini-cli" => "google/gemini-cli",
        "opencode" => "opencode/opencode",
        "cline" => "cline/cline",
        other => other,
    }
}

pub fn which_exists(cmd: &str) -> bool {
    crate::state::find_in_path(cmd).is_some()
}

/// The five supported agents, by bare registry id.
const AGENT_IDS: [&str; 5] = [
    "claude-code",
    "codex-cli",
    "gemini-cli",
    "cline",
    "opencode",
];

/// Build a descriptor. Every supported agent is now defined by its in-code
/// `AgentCapabilities` document and run through the generic engine
/// (`GenericAgent`); codex's irreducible realization is delegated from its
/// document to the `codex-cli` handler inside `GenericAgent`.
fn descriptor_for(id: &'static str) -> Box<dyn AgentDescriptor> {
    assert!(
        super::documents::for_agent(id).is_some(),
        "no in-code AgentCapabilities document for agent {id}"
    );
    Box::new(super::generic::GenericAgent::new(id))
}

pub fn all_agents() -> Vec<Box<dyn AgentDescriptor>> {
    AGENT_IDS.into_iter().map(descriptor_for).collect()
}

pub fn agent_by_id(id: &str) -> Option<Box<dyn AgentDescriptor>> {
    AGENT_IDS.into_iter().find(|&x| x == id).map(descriptor_for)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testAllAgentsReturnsFive() {
        assert_eq!(all_agents().len(), 5);
    }

    #[test]
    fn testAgentByIdKnown() {
        assert!(agent_by_id("claude-code").is_some());
        assert!(agent_by_id("codex-cli").is_some());
        assert!(agent_by_id("gemini-cli").is_some());
        assert!(agent_by_id("cline").is_some());
        assert!(agent_by_id("opencode").is_some());
    }

    #[test]
    fn testAgentByIdUnknown() {
        assert!(agent_by_id("nonexistent").is_none());
    }

    #[test]
    fn testCanonicalIdsMatchAgentpactVendorProduct() {
        // Lock the kyris bare-id → agentpact `vendor/product` mapping. These MUST
        // equal the `agent_id` values in agentpact `defaults/agents.yaml`, or the
        // `agent` field on gateway records (which carry `canonical_id()` via the
        // `x-kyris-agent-id` header) will not unify with governance events.
        let expect = [
            ("claude-code", "anthropic/claude-code"),
            ("codex-cli", "openai/codex-cli"),
            ("gemini-cli", "google/gemini-cli"),
            ("opencode", "opencode/opencode"),
            ("cline", "cline/cline"),
        ];
        for (bare, canonical) in expect {
            let agent = agent_by_id(bare).expect("known agent");
            assert_eq!(agent.canonical_id(), canonical, "canonical_id for {bare}");
            // Canonical form is namespaced and embeds the bare product id.
            assert!(agent.canonical_id().contains('/'));
            assert!(agent.canonical_id().ends_with(bare));
        }
    }

    #[test]
    fn testEachAdaptedMechanismHasItsDeliveryCompanion() {
        // A surface declared `Adapted(<mechanism>)` is only realizable if the
        // descriptor also provides the companion declaration that mechanism's
        // delivery path consumes. Without this, a plan can over-promise — declare
        // a surface adapted while the actual delivery scaffolding is missing — and
        // the agent ends up silently ungoverned on that surface (the default
        // `configure_*_surface` is a no-op, and `prestage` writes nothing if
        // `env_exports` is empty). This locks plan→delivery wiring per mechanism.
        //
        // Note the mapping is mechanism → *delivery artifact*, not mechanism →
        // configure method: EnvVarProxy burn-control is delivered by prestage via
        // `env_exports`, so claude/gemini intentionally leave
        // `configure_burn_control_surface` as the default. Behavioral proof that a
        // configure body actually enforces lives in the cross-repo e2e suite
        // (run-agent + assert-event-log); this is the cheap structural guard.
        for agent in all_agents() {
            let plan = agent.integration_plan();
            let id = agent.id();

            if let SurfaceIntegration::Adapted { mechanisms, .. } = plan.execution {
                for m in mechanisms {
                    match m {
                        ExecutionMechanism::LiveHookAdapter => assert!(
                            agent.hook_protocol().is_some(),
                            "{id}: execution declares LiveHookAdapter but hook_protocol() is None \
                             — the installed hook would have no protocol to interpret tool payloads"
                        ),
                        // CompiledPolicy writes a policy file directly in
                        // configure_execution_surface and ShellHook is shell-rc
                        // based; neither has a separate companion declaration.
                        ExecutionMechanism::CompiledPolicy | ExecutionMechanism::ShellHook => {}
                    }
                }
            }

            if let SurfaceIntegration::Adapted { mechanisms, .. } = plan.tool {
                for m in mechanisms {
                    match m {
                        ToolMechanism::McpWrapping => assert!(
                            !agent.mcp_configs().is_empty(),
                            "{id}: tool declares McpWrapping but mcp_configs() is empty — the MCP \
                             rewrite has no config location to wrap"
                        ),
                        ToolMechanism::LiveHookAdapter => assert!(
                            agent.hook_protocol().is_some(),
                            "{id}: tool declares LiveHookAdapter but hook_protocol() is None"
                        ),
                    }
                }
            }

            if let SurfaceIntegration::Adapted { mechanisms, .. } = plan.burn_control {
                for m in mechanisms {
                    match m {
                        BurnControlMechanism::EnvVarProxy => assert!(
                            !agent
                                .env_exports("http://127.0.0.1:4710", "sk-kyris-test")
                                .is_empty(),
                            "{id}: burn-control declares EnvVarProxy but env_exports() is empty — \
                             prestage would write no env file, so nothing redirects the agent"
                        ),
                        BurnControlMechanism::ConfigRewrite
                        | BurnControlMechanism::KyrisdModelProvider => assert!(
                            !agent.burn_control_config_paths().is_empty(),
                            "{id}: burn-control declares a config rewrite but \
                             burn_control_config_paths() is empty — there is no file to rewrite"
                        ),
                        BurnControlMechanism::AgentPactUsageReport => {}
                    }
                }
            }
        }
    }

    #[test]
    fn testEnvExportingAgentsRequirePathShim() {
        // The PATH shim is the robust, shell-independent vehicle that delivers an
        // agent's `~/.kyris/env/<id>.sh` file on every launch (see shim.rs). Any
        // agent that ships `env_exports` MUST therefore also require the shim —
        // otherwise its base-URL/key redirect would only reach the agent through
        // shell-RC sourcing, which fish and GUI launches never do. Lock the
        // invariant so a new agent cannot silently regress burn-control delivery.
        for agent in all_agents() {
            let exports = agent.env_exports("http://127.0.0.1:4710", "sk-kyris-test");
            if !exports.is_empty() {
                assert!(
                    agent.integration_plan().requires_path_shim(),
                    "{} ships env_exports but does not require a PATH shim — its env \
                     file would not reach the agent under fish/GUI launches",
                    agent.id()
                );
            }
        }
    }

    #[test]
    fn testAllAgentsHaveUniqueIds() {
        let agents = all_agents();
        let mut ids: Vec<&str> = agents.iter().map(|a| a.id()).collect();
        let len_before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), len_before);
    }

    #[test]
    fn testExpectedSurfacesAllAgents() {
        let expected: &[(&str, (bool, bool, bool))] = &[
            ("claude-code", (true, true, true)),
            ("codex-cli", (true, true, true)),
            ("gemini-cli", (true, true, true)),
            ("cline", (true, true, true)),
            ("opencode", (true, true, true)),
        ];
        for (id, surfaces) in expected {
            let agent = agent_by_id(id).unwrap_or_else(|| panic!("missing agent: {id}"));
            assert_eq!(
                agent.expected_surfaces(),
                *surfaces,
                "expected_surfaces mismatch for {id}"
            );
        }
    }

    #[test]
    fn testEveryAgentDeclaresExpectedSurfaces() {
        for agent in all_agents() {
            let (exec, tool, burn) = agent.expected_surfaces();
            assert!(
                exec || tool || burn,
                "{} declares no expected surfaces",
                agent.id()
            );
        }
    }

    #[test]
    fn testEveryAgentHasMcpConfigOrHookProtocol() {
        for agent in all_agents() {
            let has_mcp = !agent.mcp_configs().is_empty();
            let has_hook = agent.hook_protocol().is_some();
            assert!(
                has_mcp || has_hook,
                "{} has neither mcp_configs nor hook_protocol",
                agent.id()
            );
        }
    }

    #[test]
    fn testPermissionRequestIntegrationIsDeclaredDeliberately() {
        // The native-approval consultation can SUPPRESS the agent's own prompt
        // — it must exist only where verified (codex), require a backstop
        // (otherwise there is no native prompt to answer), and emit codex's
        // exact contract shape.
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            match agent.id() {
                "codex-cli" => {
                    let body = proto
                        .permission_request_allow
                        .expect("codex declares the PermissionRequest integration");
                    assert_eq!(
                        body["hookSpecificOutput"]["decision"]["behavior"], "allow",
                        "codex allow body must carry decision.behavior=allow"
                    );
                    assert!(proto.runtime.native_backstop);
                }
                _ => assert!(
                    proto.permission_request_allow.is_none(),
                    "{}: declares a PermissionRequest integration that was never \
                     verified against its upstream",
                    agent.id()
                ),
            }
        }
    }

    #[test]
    fn testAgentOwnedToolsRequireNativeBackstop() {
        // "Leave it to the agent's own permission system" is only a real
        // posture when one exists; on a no-backstop agent an agent_owned entry
        // would be a silent allow — the exact hole G1 closed.
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            if !proto.agent_owned_tools.is_empty() {
                assert!(
                    proto.runtime.native_backstop,
                    "{}: declares agent_owned_tools without a native backstop",
                    agent.id()
                );
            }
        }
    }

    #[test]
    fn testToolClassificationsAreDisjoint() {
        // A tool in two categories would make the decision order-dependent.
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            let mapped: Vec<&str> = proto
                .tool_mappings
                .iter()
                .map(|m| m.tool_name.as_str())
                .collect();
            for t in &proto.pass_through_tools {
                assert!(
                    !mapped.contains(&t.as_str()) && !proto.agent_owned_tools.contains(t),
                    "{}: '{t}' appears in multiple tool categories",
                    agent.id()
                );
            }
            for t in &proto.agent_owned_tools {
                assert!(
                    !mapped.contains(&t.as_str()),
                    "{}: '{t}' is both mapped and agent_owned",
                    agent.id()
                );
            }
        }
    }

    #[test]
    fn testEveryAgentDeclaresExplicitIntegrationPlan() {
        for agent in all_agents() {
            let plan = agent.integration_plan();
            assert!(
                !plan.execution.is_none(),
                "{} has no declared execution integration",
                agent.id()
            );
            assert!(
                !plan.tool.is_none(),
                "{} has no declared tool integration",
                agent.id()
            );
            assert!(
                !plan.burn_control.is_none(),
                "{} has no declared burn-control integration",
                agent.id()
            );
            assert!(
                plan.agentpact_native_attribution || !plan.attribution.is_empty(),
                "{} has no declared attribution integration",
                agent.id()
            );
        }
    }

    #[test]
    fn testPathShimComesFromAttributionPlan() {
        let expect = [
            ("claude-code", true),
            // Codex needs the shim for more than attribution: it is the only
            // mechanism that marks codex's HOOK children as governed
            // (shell_environment_policy covers exec children only) — without
            // it the kyris hook spawn reaches the shell gate unmarked.
            ("codex-cli", true),
            ("gemini-cli", true),
            ("cline", true),
            ("opencode", true),
        ];
        for (id, requires_shim) in expect {
            let agent = agent_by_id(id).expect("known agent");
            assert_eq!(
                agent.integration_plan().requires_path_shim(),
                requires_shim,
                "path-shim attribution mismatch for {id}"
            );
        }
    }

    #[test]
    fn testHookRuntimeContractsMatchVerifiedUpstreamBehavior() {
        // Lock the per-agent runtime contracts to the upstream-verified facts
        // (agent-interface review, G1–G3). Changing one of these is a statement
        // about the AGENT's behavior — re-verify against its source first.
        // (timeout_secs, native_backstop, allow_suppresses_agent_prompt)
        let expect = [
            // Claude: 600s default PreToolUse timeout; native permission ladder
            // backstops defers; JSON permissionDecision:allow suppresses its prompt.
            ("claude-code", 600, true, true),
            // Codex: per-hook `timeout` PINNED to a week at install (the pin
            // derives from this declaration; codex honors explicit values
            // uncapped) so a popup ask can wait effectively forever; approval
            // ladder backstops; EmptyStdout never suppresses (codex parses
            // JSON allow as Failed).
            ("codex-cli", 7 * 24 * 60 * 60, true, false),
            // Gemini: 60s default PINNED to 600s at install (the pin derives from
            // this declaration); policy/confirmation backstop defers; its JSON
            // allow is parsed but does NOT suppress the native prompt.
            ("gemini-cli", 600, true, false),
            // Cline: 120s hard kill then PROCEED (not configurable); CLI
            // auto-approves by default → no backstop.
            ("cline", 120, false, false),
            // OpenCode: no upstream hook timeout — the plugin's own spawn bound
            // (derived from this) is the effective deadline; kyris sets native
            // permissions to allow-all → no backstop.
            ("opencode", 600, false, false),
        ];
        for (id, timeout, backstop, suppresses) in expect {
            let proto = agent_by_id(id)
                .expect("known agent")
                .hook_protocol()
                .unwrap_or_else(|| panic!("{id} declares no hook protocol"));
            assert_eq!(
                proto.runtime.agent_hook_timeout_secs, timeout,
                "hook timeout for {id}"
            );
            assert_eq!(
                proto.runtime.native_backstop, backstop,
                "native_backstop for {id}"
            );
            assert_eq!(
                proto.runtime.allow_suppresses_agent_prompt, suppresses,
                "allow_suppresses_agent_prompt for {id}"
            );
        }
    }

    #[test]
    fn testPollDeadlineFitsInsideEveryAgentsHookTimeout() {
        // G3: the no-TTY approval resolver must return strictly before the
        // agent's hook deadline — on a FailOpen agent, outliving it means the
        // unanswered command RUNS. Also keep a sane floor: below ~60s a human
        // can't realistically answer and the agent needs a different strategy.
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            let deadline = proto.runtime.poll_deadline();
            assert!(
                deadline.as_secs() + HookRuntime::RESPONSE_MARGIN_SECS
                    <= proto.runtime.agent_hook_timeout_secs,
                "{}: poll deadline {}s does not clear the {}s hook timeout by the margin",
                agent.id(),
                deadline.as_secs(),
                proto.runtime.agent_hook_timeout_secs,
            );
            assert!(
                deadline.as_secs() >= 60,
                "{}: poll deadline {}s is too short for a human approval — \
                 this agent needs a different ask strategy, not a shorter poll",
                agent.id(),
                deadline.as_secs()
            );
        }
    }

    #[test]
    fn testAllowSuppressionRequiresJsonAllowShape() {
        // An EmptyStdout allow is by definition "no decision" to the agent — it
        // cannot suppress anything. Declaring suppression with that shape would
        // make the agent_prompt audit lie.
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            if proto.runtime.allow_suppresses_agent_prompt {
                assert!(
                    matches!(proto.allow_response, AllowResponse::Json { .. }),
                    "{}: declares allow-suppression with an EmptyStdout allow shape",
                    agent.id()
                );
            }
        }
    }

    #[test]
    fn testNativeAskInvariants() {
        // A native ask delegates the decision to the agent's OWN approval
        // machinery, so it is only sound where the agent has a native backstop;
        // and the deferral variant needs the separate native-approval hook to
        // actually render the prompt (codex's PermissionRequest).
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            if let Some(ask) = &proto.native_ask {
                assert!(
                    proto.runtime.native_backstop,
                    "{}: declares native_ask without a native backstop",
                    agent.id()
                );
                if matches!(ask, AskResponse::DeferToNativeApproval) {
                    assert!(
                        proto.permission_request_allow.is_some(),
                        "{}: DeferToNativeApproval needs a permission_request_allow integration",
                        agent.id()
                    );
                }
            }
        }
    }

    #[test]
    fn testNativeAskAgentsDeclareApprovalPromptSetting() {
        // A native-capable agent must accept `--set approval_prompt=...` so the
        // toggle is reachable; agents without a native ask must NOT advertise it.
        for agent in all_agents() {
            let native = agent.hook_protocol().and_then(|p| p.native_ask).is_some();
            let advertises = agent
                .supported_settings()
                .iter()
                .any(|(k, _)| k.as_str() == APPROVAL_PROMPT_SETTING);
            assert_eq!(
                native,
                advertises,
                "{}: native_ask={native} but approval_prompt setting advertised={advertises}",
                agent.id()
            );
        }
    }

    #[test]
    fn testNoBackstopAgentsDeclareMcpToolNaming() {
        // G1: for a no-backstop agent, unmapped tools are DENIED. MCP tools of
        // kyris-routed servers reach the hook under generated names and are
        // governed at the tool surface — without a naming declaration the deny
        // would break every wrapped MCP server for that agent.
        for agent in all_agents() {
            let Some(proto) = agent.hook_protocol() else {
                continue;
            };
            if !proto.runtime.native_backstop && !agent.mcp_configs().is_empty() {
                assert!(
                    proto.mcp_tool_naming.is_some(),
                    "{}: no native backstop and an MCP config, but no mcp_tool_naming — \
                     wrapped MCP tools would be denied at the hook",
                    agent.id()
                );
            }
        }
    }

    #[test]
    fn testMcpToolNamingMatchesUpstreamSchemes() {
        // opencode: sanitize(client) + "_" + sanitize(tool), per-char replace
        // (mcp/index.ts: s.replace(/[^a-zA-Z0-9_-]/g, "_")).
        let opencode = McpToolNaming {
            server_separator: "_".to_string(),
            collapse_sanitize_runs: false,
        };
        assert!(opencode.tool_belongs_to_server("my_srv_read_file", "my srv"));
        assert!(opencode.tool_belongs_to_server("a__b_tool", "a.&b"));
        assert!(!opencode.tool_belongs_to_server("other_read", "my srv"));
        // Bare server name with no tool part must not match.
        assert!(!opencode.tool_belongs_to_server("my_srv_", "my srv"));

        // cline: serverName + "__" + toolName, runs collapse
        // (name-transform.ts: /[^a-zA-Z0-9_-]+/g).
        let cline = McpToolNaming {
            server_separator: "__".to_string(),
            collapse_sanitize_runs: true,
        };
        assert!(cline.tool_belongs_to_server("a_b__read_file", "a.&b"));
        assert!(!cline.tool_belongs_to_server("a_b_read_file", "a b"));
    }

    #[test]
    fn testAgentPactNativePlanIsFirstClass() {
        let plan = AgentIntegrationPlan {
            execution: SurfaceIntegration::AgentPactNative,
            tool: SurfaceIntegration::AgentPactNative,
            burn_control: SurfaceIntegration::AgentPactNative,
            attribution: vec![AttributionMechanism::AgentPactNative],
            agentpact_native_attribution: true,
        };

        assert_eq!(plan.expected_surfaces(), (true, true, true));
        assert!(!plan.requires_path_shim());
        assert!(!plan.has_adapted_execution());
        assert!(!plan.has_adapted_tool());
        assert!(!plan.has_adapted_burn_control());
        assert_eq!(plan.surface_design_ceilings(), (None, None, None));
    }

    #[test]
    fn testPartialNativePlanOnlyAdaptsRemainingSurfaces() {
        let plan = AgentIntegrationPlan {
            execution: SurfaceIntegration::AgentPactNative,
            tool: SurfaceIntegration::adapted(vec![ToolMechanism::McpWrapping]),
            burn_control: SurfaceIntegration::adapted(vec![
                BurnControlMechanism::KyrisdModelProvider,
            ]),
            attribution: vec![AttributionMechanism::AgentPactNative],
            agentpact_native_attribution: true,
        };

        assert_eq!(plan.expected_surfaces(), (true, true, true));
        assert!(!plan.has_adapted_execution());
        assert!(plan.has_adapted_tool());
        assert!(plan.has_adapted_burn_control());
        assert!(!plan.requires_path_shim());
    }

    #[test]
    fn testNativeCapabilityDeclarationOverlaysOnlyDeclaredSurfaces() {
        let plan = AgentIntegrationPlan {
            execution: SurfaceIntegration::adapted(vec![ExecutionMechanism::LiveHookAdapter]),
            tool: SurfaceIntegration::adapted(vec![ToolMechanism::McpWrapping]),
            burn_control: SurfaceIntegration::adapted(vec![BurnControlMechanism::EnvVarProxy]),
            attribution: vec![AttributionMechanism::KyrisPathShim],
            agentpact_native_attribution: false,
        }
        .with_native_capabilities(NativeCapabilityDeclaration {
            execution: true,
            tool: false,
            burn_control: true,
            attribution: true,
        });

        assert_eq!(plan.execution, SurfaceIntegration::AgentPactNative);
        assert!(plan.has_adapted_tool());
        assert_eq!(plan.burn_control, SurfaceIntegration::AgentPactNative);
        assert!(plan.agentpact_native_attribution);
        assert!(!plan.requires_path_shim());
    }
}
