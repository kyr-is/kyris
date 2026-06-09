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
        match self.id() {
            "claude-code" => "anthropic/claude-code",
            "codex-cli" => "openai/codex-cli",
            "gemini-cli" => "google/gemini-cli",
            "opencode" => "opencode/opencode",
            "cline" => "cline/cline",
            other => other,
        }
    }
    fn display_name(&self) -> &'static str;
    fn is_installed(&self) -> bool;
    fn probe(&self) -> ProbeResult;
    fn native_evidence(&self) -> NativeEvidence {
        NativeEvidence::default()
    }
    fn kyris_content_markers(&self) -> &'static [&'static str];
    fn env_exports(&self, base_url: &str, inbound_key: &str) -> Vec<(String, String)>;
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
    fn launch_dir_env(&self) -> Option<&'static str> {
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
    fn hook_protocol(&self) -> Option<HookProtocol> {
        None
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        None
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    /// Keys accepted by `kyris agents setup <agent> --set KEY=VALUE`, each with a
    /// short description. Any `--set` key not listed here is rejected fail-fast
    /// rather than silently stored and ignored. Default: none.
    fn supported_settings(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentIntegrationPlan {
    pub execution: SurfaceIntegration<ExecutionMechanism>,
    pub tool: SurfaceIntegration<ToolMechanism>,
    pub burn_control: SurfaceIntegration<BurnControlMechanism>,
    pub attribution: &'static [AttributionMechanism],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SurfaceIntegration<M: 'static> {
    None,
    AgentPactNative,
    Adapted {
        mechanisms: &'static [M],
        ceiling: Option<CoverageCeiling>,
    },
}

impl<M: 'static> SurfaceIntegration<M> {
    pub fn adapted(mechanisms: &'static [M]) -> Self {
        Self::Adapted {
            mechanisms,
            ceiling: None,
        }
    }

    pub fn adapted_with_ceiling(mechanisms: &'static [M], ceiling: CoverageCeiling) -> Self {
        Self::Adapted {
            mechanisms,
            ceiling: Some(ceiling),
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
pub fn plan_label<M: MechanismLabel>(plan: SurfaceIntegration<M>) -> String {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Json { servers_path: Vec<&'static str> },
    Toml { servers_key: &'static str },
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailPassThrough {
    pub action: String,
    pub detail_contains: Vec<String>,
    pub reason: String,
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
    /// demands `context.mcp_server`, which these tools cannot supply.
    /// Tools not in this list and not in `tool_mappings` are *unmapped*: kyris
    /// emits a stderr warning and defers to the agent's own permission system
    /// (the `EmptyStdout` "no decision" shape), behaving as if it were not
    /// installed — it never suppresses the agent's prompt for an unknown tool.
    pub pass_through_tools: Vec<String>,
    /// Agent-internal invocations that reuse a governable tool shape but are
    /// not the user's requested side effect. Example: Codex restores an
    /// internal shell snapshot by issuing a Bash command before the real command.
    pub detail_pass_throughs: Vec<DetailPassThrough>,
    pub default_action: String,
    pub allow_response: AllowResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowResponse {
    EmptyStdout,
    Json { body: serde_json::Value },
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum PrimaryProvider {
    OpenAI,
    Google,
}

pub fn provider_env_exports(
    provider: PrimaryProvider,
    base_url: &str,
    inbound_key: &str,
) -> Vec<(String, String)> {
    match provider {
        PrimaryProvider::OpenAI => vec![
            ("OPENAI_BASE_URL".to_string(), format!("{base_url}/v1")),
            ("OPENAI_API_KEY".to_string(), inbound_key.to_string()),
        ],
        PrimaryProvider::Google => vec![
            ("GOOGLE_GEMINI_BASE_URL".to_string(), base_url.to_string()),
            ("GEMINI_API_KEY".to_string(), inbound_key.to_string()),
            (
                "GEMINI_API_KEY_AUTH_MECHANISM".to_string(),
                "bearer".to_string(),
            ),
        ],
    }
}

pub fn which_exists(cmd: &str) -> bool {
    crate::state::find_in_path(cmd).is_some()
}

macro_rules! agent_registry {
    ($($id:literal => $mod:ident::$ty:ident),* $(,)?) => {
        pub fn all_agents() -> Vec<Box<dyn AgentDescriptor>> {
            vec![$(Box::new(super::$mod::$ty)),*]
        }
        pub fn agent_by_id(id: &str) -> Option<Box<dyn AgentDescriptor>> {
            match id {
                $($id => Some(Box::new(super::$mod::$ty)),)*
                _ => None,
            }
        }
    };
}

agent_registry! {
    "claude-code"  => claude_code::ClaudeCode,
    "codex-cli"    => codex_cli::CodexCli,
    "gemini-cli"   => gemini_cli::GeminiCli,
    "cline"        => cline::Cline,
    "opencode"     => opencode::OpenCode,
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
        // configure body actually enforces lives in kyris-internal e2e
        // (run-agent + assert-event-log); this is the cheap structural guard.
        for agent in all_agents() {
            let plan = agent.integration_plan();
            let id = agent.id();

            if let SurfaceIntegration::Adapted { mechanisms, .. } = plan.execution {
                for &m in mechanisms {
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
                for &m in mechanisms {
                    match m {
                        ToolMechanism::McpWrapping => assert!(
                            agent.mcp_config().is_some(),
                            "{id}: tool declares McpWrapping but mcp_config() is None — the MCP \
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
                for &m in mechanisms {
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
            let has_mcp = agent.mcp_config().is_some();
            let has_hook = agent.hook_protocol().is_some();
            assert!(
                has_mcp || has_hook,
                "{} has neither mcp_config nor hook_protocol",
                agent.id()
            );
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
            ("codex-cli", false),
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
    fn testAgentPactNativePlanIsFirstClass() {
        let plan = AgentIntegrationPlan {
            execution: SurfaceIntegration::AgentPactNative,
            tool: SurfaceIntegration::AgentPactNative,
            burn_control: SurfaceIntegration::AgentPactNative,
            attribution: &[AttributionMechanism::AgentPactNative],
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
            tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
            burn_control: SurfaceIntegration::adapted(&[BurnControlMechanism::KyrisdModelProvider]),
            attribution: &[AttributionMechanism::AgentPactNative],
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
            execution: SurfaceIntegration::adapted(&[ExecutionMechanism::LiveHookAdapter]),
            tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
            burn_control: SurfaceIntegration::adapted(&[BurnControlMechanism::EnvVarProxy]),
            attribution: &[AttributionMechanism::KyrisPathShim],
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
