// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `GenericAgent` — the single, agent-agnostic `AgentDescriptor` implementation
//! that reads a parsed [`AgentManifest`] and drives the generic [`engine`]. It
//! replaces the per-agent Rust descriptors: an agent is its JSON document plus
//! (for adapted agents) a bridge-script template asset. Behavior methods
//! (`configure_*`, `undo_*`, `probe`) interpret the document's bounded op
//! vocabulary, reusing the existing shared write/probe/restore helpers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::adaptation::{AdaptationProfile, ConfigureOp, Discovery, FileFormat, ProbeRule, UndoOp};
use super::manifest::{self, AgentManifest};
use super::probe::{self, ProbeResult, fingerprint, not_detected};
use super::profile::{NativeEvidence, SurfaceState};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, HookProtocol, McpConfigFormat, McpConfigLocation,
    ProviderRouting, SurfaceIntegration, ToolMechanism, canonical_agent_id,
};
use super::{documents, engine};
use crate::config_writer::WellFormedJsonValidator;
use crate::integration::{read_json_value, write_json_value};

/// A batch of `set_key` ops (key path + JSON value) accumulated for one config
/// file, so all writes to that file happen in a single read-modify-write.
type SetKeyBatch = Vec<(Vec<String>, Value)>;

/// Whether two paths name the same file. Compares canonical paths when both
/// resolve — so a `walk_up_optional` result and a static `~/…` path that point at
/// the same file compare equal — falling back to a literal comparison otherwise.
fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    matches!(
        (a.canonicalize(), b.canonicalize()),
        (Ok(ca), Ok(cb)) if ca == cb
    )
}

pub struct GenericAgent {
    id: &'static str,
    manifest: AgentManifest,
}

impl GenericAgent {
    /// Build the agent from its in-code document. Panics if the document is
    /// missing or invalid — these are compile-time-tested constants, so a
    /// failure is a programmer error, surfaced loudly.
    #[must_use]
    pub fn new(id: &'static str) -> Self {
        let doc = documents::for_agent(id)
            .unwrap_or_else(|| panic!("no in-code AgentCapabilities document for agent {id}"));
        let manifest = manifest::parse_and_validate(doc, canonical_agent_id(id))
            .unwrap_or_else(|e| panic!("in-code document for {id} is invalid: {e}"));
        Self { id, manifest }
    }

    fn profile(&self) -> &AdaptationProfile {
        self.manifest
            .adaptation
            .as_ref()
            .unwrap_or_else(|| panic!("{} document declares no adaptation profile", self.id))
    }

    /// Resolve a named config file to its path. Walk-up discovery is anchored at
    /// the current working directory; `sibling_of` is resolved here (it needs the
    /// referenced file's path).
    fn config_path(&self, name: &str) -> Result<PathBuf, String> {
        let cf = self
            .profile()
            .config_files
            .get(name)
            .ok_or_else(|| format!("{}: unknown config file '{name}'", self.id))?;
        if let Discovery::SiblingOf {
            file,
            name: sibling,
        } = &cf.discovery
        {
            let base = self.config_path(file)?;
            let parent = base.parent().ok_or_else(|| {
                format!("{}: cannot resolve parent of {}", self.id, base.display())
            })?;
            return Ok(parent.join(sibling));
        }
        engine::resolve_config_path(&cf.discovery, std::env::current_dir().ok().as_deref())
    }

    fn config_format(&self, name: &str) -> FileFormat {
        self.profile()
            .config_files
            .get(name)
            .map_or(FileFormat::Json, |cf| cf.format)
    }

    /// The daemon-side realization handler for an agent whose probe/configure/undo
    /// is too irreducible for data ops (codex). DATA methods (plan, hook protocol,
    /// markers, mcp configs, settings) still come from the document; only the
    /// realization is delegated. `None` for the fully data-driven agents.
    fn native_delegate(&self) -> Option<Box<dyn AgentDescriptor>> {
        match self.profile().delegate.as_deref() {
            None => None,
            Some("codex-cli") => Some(Box::new(super::codex_cli::CodexCli)),
            Some(other) => panic!("{}: unknown realization delegate '{other}'", self.id),
        }
    }

    fn component(&self, surface: &str) -> String {
        format!("{}:{}", self.id, surface)
    }

    /// Execute a surface's `configure` op list. `component` scopes the managed
    /// writes; `set_key` ops are batched per file (one read-modify-write).
    #[allow(clippy::too_many_lines)] // a flat op-dispatch table, not branching logic
    fn run_configure(
        &self,
        ops: &[ConfigureOp],
        component: &str,
        base_url: &str,
        inbound_key: &str,
        agent_specific: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let canonical = self.canonical_id();
        let ctx = engine::SubstCtx {
            base_url,
            inbound_key,
            agent_id: canonical,
        };
        let spawn = self
            .profile()
            .hook_protocol
            .as_ref()
            .map_or(0, |hp| hp.runtime.bridge_spawn_timeout_ms());

        let mut changes = Vec::new();
        let mut set_keys_by_file: Vec<(String, SetKeyBatch)> = Vec::new();
        // Paths an `install_hook` registered a hook INTO this run. A
        // `remove_legacy_hook` whose file resolves to one of these is NOT a
        // separate legacy/secondary file — it's the file we just installed into,
        // so removing "the legacy hook" (matched by the same marker) would delete
        // the hook we just added. This happens for gemini when setup runs from a
        // cwd under HOME: `workspace_settings` (`walk_up_optional .gemini/settings.json`)
        // walks up and resolves to the user `~/.gemini/settings.json`.
        let mut installed_hook_paths: Vec<PathBuf> = Vec::new();
        for op in ops {
            match op {
                ConfigureOp::InstallFile {
                    template,
                    dest,
                    mode,
                } => {
                    let dest_path = self.config_path(dest)?;
                    changes.extend(engine::install_template(
                        template,
                        &dest_path,
                        mode.as_deref(),
                        spawn,
                        component,
                    )?);
                }
                ConfigureOp::RouteMcp => {
                    changes.extend(super::configure::configure_json_mcp_tool_surface(
                        self,
                        base_url,
                        inbound_key,
                    )?);
                }
                ConfigureOp::SetKey { file, path, value } => {
                    let entry = (path.clone(), value.clone());
                    match set_keys_by_file.iter_mut().find(|(f, _)| f == file) {
                        Some((_, v)) => v.push(entry),
                        None => set_keys_by_file.push((file.clone(), vec![entry])),
                    }
                }
                ConfigureOp::InstallPlugin { dest, register_in } => {
                    let plugin_path = self.config_path(dest)?;
                    let config_path = self.config_path(register_in)?;
                    changes.extend(super::configure::install_plugin_hook_adapter(
                        self.id(),
                        component,
                        &plugin_path,
                        &config_path,
                    )?);
                }
                ConfigureOp::RequireWritable { file } => {
                    engine::require_writable(&self.config_path(file)?)?;
                }
                ConfigureOp::SetGovernedPermissions { file } => {
                    let path = self.config_path(file)?;
                    changes.extend(engine::set_governed_permissions(
                        &path,
                        self.config_format(file),
                        component,
                    )?);
                }
                ConfigureOp::StripKeyIfEqualsInbound { file, path } => {
                    let p = self.config_path(file)?;
                    changes.extend(engine::strip_key_if_equals(
                        &p,
                        self.config_format(file),
                        path,
                        inbound_key,
                        component,
                    )?);
                }
                ConfigureOp::InstallHook {
                    script,
                    register_in,
                    events,
                    nested,
                    hook_timeout,
                } => {
                    let script_path = self.config_path(script)?;
                    let settings_path = self.config_path(register_in)?;
                    installed_hook_paths.push(settings_path.clone());
                    let event_refs: Vec<&str> = events.iter().map(String::as_str).collect();
                    changes.extend(super::configure::install_live_hook_adapter(
                        self.id(),
                        component,
                        &event_refs,
                        &script_path,
                        &settings_path,
                        *nested,
                        *hook_timeout,
                    )?);
                }
                ConfigureOp::McpDerivedDenies { file } => {
                    let names = super::configure::mcp_server_names_from_agent(self);
                    let path = self.config_path(file)?;
                    let mut settings = if path.exists() {
                        read_json_value(&path)?
                    } else {
                        Value::Object(serde_json::Map::new())
                    };
                    if super::configure::apply_claude_mcp_tool_denies(&mut settings, &names) {
                        write_json_value(&path, &settings, component, &WellFormedJsonValidator)?;
                        changes.push(format!("applied MCP tool policy in {}", path.display()));
                    }
                }
                ConfigureOp::WriteCompiledPolicy { dest } => {
                    let dest_path = self.config_path(dest)?;
                    changes.extend(engine::write_compiled_policy(&dest_path, component)?);
                }
                ConfigureOp::EnsureRoutableAuth { file } => {
                    let path = self.config_path(file)?;
                    changes.extend(engine::ensure_routable_auth(
                        &path,
                        self.config_format(file),
                        component,
                    )?);
                }
                ConfigureOp::SetSettingFromInput { file, path, input } => {
                    if let Some(value) = agent_specific.get(input) {
                        let p = self.config_path(file)?;
                        changes.extend(engine::set_setting_from_input(
                            &p,
                            self.config_format(file),
                            path,
                            value,
                            component,
                        )?);
                    }
                }
                ConfigureOp::RemoveLegacyHook {
                    file,
                    event,
                    marker,
                } => {
                    // The file may not resolve (walk-up-optional miss) or exist —
                    // a legacy migration is a no-op then. Also skip when it
                    // resolved to a file an install_hook just registered into this
                    // run (same-file self-destruct, see `installed_hook_paths`).
                    if let Ok(path) = self.config_path(file)
                        && path.exists()
                        && !installed_hook_paths.iter().any(|p| same_file(p, &path))
                    {
                        let mut config = engine::read_config(&path, self.config_format(file))?;
                        if crate::integration::remove_json_command_hook(&mut config, event, marker)
                        {
                            write_json_value(&path, &config, component, &WellFormedJsonValidator)?;
                            changes.push(format!(
                                "removed legacy {event} hook from {}",
                                path.display()
                            ));
                        }
                    }
                }
            }
        }
        for (file, ops) in &set_keys_by_file {
            let path = self.config_path(file)?;
            changes.extend(engine::apply_json_set_keys(&path, ops, &ctx, component)?);
        }
        Ok(changes)
    }

    fn run_undo(&self, ops: &[UndoOp]) -> Result<(), String> {
        for op in ops {
            match op {
                UndoOp::ManifestRestore {
                    file,
                    scope,
                    delete_if_unmanaged,
                } => {
                    let path = self.config_path(file)?;
                    engine::restore(&path, scope, *delete_if_unmanaged)?;
                }
                UndoOp::UndoMcp => super::configure::undo_json_mcp_tool_surface(self)?,
                UndoOp::DeleteEnvFile => {
                    let env_file = crate::state::env_dir()?.join(format!("{}.sh", self.id));
                    super::undo::remove_file_if_exists(&env_file)?;
                }
                UndoOp::RestoreComponent { scope } => {
                    for path in crate::state::restore_manifest_component(scope)? {
                        println!("Reverted {}", path.display());
                    }
                }
                UndoOp::DeleteFile { file } => {
                    super::undo::remove_file_if_exists(&self.config_path(file)?)?;
                }
            }
        }
        Ok(())
    }

    /// Expand a `nested_scope` MCP source: a `servers_key` with a `"*"` segment
    /// enumerated over the parent object's keys, one location per child that has
    /// a non-empty servers object (Claude's `projects.*.mcpServers`).
    fn expand_nested_mcp(path: &Path, servers_key: &[String]) -> Vec<McpConfigLocation> {
        let Some(star) = servers_key.iter().position(|s| s == "*") else {
            return Vec::new();
        };
        let (prefix, rest) = servers_key.split_at(star);
        let suffix = &rest[1..];
        let Ok(config) = read_json_value(path) else {
            return Vec::new();
        };
        let Some(parent) = json_get(&config, prefix).and_then(Value::as_object) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (key, entry) in parent {
            let has_servers = json_get(entry, suffix)
                .and_then(Value::as_object)
                .is_some_and(|m| !m.is_empty());
            if has_servers {
                let mut servers_path: Vec<String> = prefix.to_vec();
                servers_path.push(key.clone());
                servers_path.extend(suffix.iter().cloned());
                out.push(McpConfigLocation {
                    path: path.to_path_buf(),
                    format: McpConfigFormat::Json { servers_path },
                });
            }
        }
        out
    }

    fn probe_rule_matches(&self, rule: &ProbeRule) -> bool {
        match rule {
            ProbeRule::FileExists { file } => self.config_path(file).is_ok_and(|p| p.exists()),
            ProbeRule::ContainsMarker { file, marker } => self
                .config_path(file)
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .is_some_and(|c| c.contains(marker.as_str())),
            ProbeRule::McpWrap => probe::mcp_locations_status(self).0,
            ProbeRule::KeyEqualsKyrisd { file, path, suffix } => {
                let Some(base) = probe::kyrisd_base_url() else {
                    return false;
                };
                let expected = suffix
                    .as_ref()
                    .map_or_else(|| base.clone(), |s| format!("{base}{s}"));
                self.config_path(file)
                    .ok()
                    .and_then(|p| read_json_value(&p).ok())
                    .and_then(|v| json_get(&v, path).and_then(|x| x.as_str().map(String::from)))
                    == Some(expected)
            }
            ProbeRule::ArrayContains { file, path, value } => {
                let Ok(p) = self.config_path(file) else {
                    return false;
                };
                let Ok(v) = engine::read_config(&p, self.config_format(file)) else {
                    return false;
                };
                json_get(&v, path)
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|s| s.contains(value.as_str()))
                    })
            }
            ProbeRule::EnvPointsKyrisd { var } => {
                // The env file and PATH shim are keyed by the SHORT registry id
                // (`claude-code.sh`), as the install/undo paths write them
                // (prestage `{agent.id()}.sh`, shim `shim_delivers_env`). The
                // canonical `vendor/product` id would look for a never-written
                // `anthropic/claude-code.sh` and under-report burn as off.
                probe::env_routes_to_kyrisd(self.id, var)
            }
            ProbeRule::All { rules } => rules.iter().all(|r| self.probe_rule_matches(r)),
            ProbeRule::CompiledPolicyLoadable { file } => self
                .config_path(file)
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .is_some_and(|c| crate::compile_policy::gemini_policy_file_is_loadable(&c)),
            ProbeRule::AuthRoutable { file, alt_file } => {
                // The effective selection: `alt_file` (workspace) wins over `file`
                // (user) when present.
                let sel_type = |name: &String| -> Option<String> {
                    self.config_path(name)
                        .ok()
                        .and_then(|p| read_json_value(&p).ok())
                        .and_then(|v| {
                            v.get("security")
                                .and_then(|s| s.get("auth"))
                                .and_then(|a| a.get("selectedType"))
                                .and_then(|t| t.as_str().map(String::from))
                        })
                };
                alt_file
                    .as_ref()
                    .and_then(sel_type)
                    .or_else(|| sel_type(file))
                    .is_some_and(|t| engine::is_routable_auth_type(&t))
            }
            ProbeRule::HookScriptMatches { file } => self
                .config_path(file)
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .is_some_and(|actual| actual == super::configure::hook_script_source(self.id())),
        }
    }
}

fn json_get<'a>(v: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    Some(cur)
}

impl AgentDescriptor for GenericAgent {
    fn id(&self) -> &'static str {
        self.id
    }

    fn is_installed(&self) -> bool {
        engine::is_detected(self.profile())
    }

    fn kyris_content_markers(&self) -> Vec<String> {
        self.profile().markers.clone()
    }

    fn native_evidence(&self) -> NativeEvidence {
        // Discover native support by running the agent's `agentpact` command, but
        // only when its document opts in (an agent that ships the command). The
        // result feeds the same native-evidence → promotion pipeline the runtime
        // burn-control breadcrumb uses, so a declared-native surface is promoted
        // and its adaptation undone — no integration_plan coupling, no per-action
        // subprocess (this runs at setup/reconcile only). §13.3.
        let p = self.profile();
        if !p.live_query {
            return NativeEvidence::default();
        }
        let Some(native) = engine::query_live_capabilities(&p.detect.binaries, self.canonical_id())
        else {
            return NativeEvidence::default();
        };
        let now = chrono::Utc::now();
        NativeEvidence {
            execution: native.execution.then_some(now),
            tool: native.tool.then_some(now),
            burn_control: native.burn_control.then_some(now),
        }
    }

    fn supported_settings(&self) -> Vec<(String, String)> {
        self.profile()
            .settings
            .iter()
            .map(|s| (s.key.clone(), s.description.clone()))
            .collect()
    }

    fn integration_plan(&self) -> AgentIntegrationPlan {
        let p = self.profile();
        let execution = p
            .surfaces
            .execution
            .as_ref()
            .map_or(SurfaceIntegration::None, |s| {
                SurfaceIntegration::adapted(s.mechanisms.clone())
            });
        let tool = p
            .surfaces
            .tool
            .as_ref()
            .map_or(SurfaceIntegration::None, |s| {
                SurfaceIntegration::adapted(s.mechanisms.clone())
            });
        let burn_control = p
            .surfaces
            .model_routing
            .as_ref()
            .map_or(SurfaceIntegration::None, |s| {
                SurfaceIntegration::adapted(s.mechanisms.clone())
            });
        AgentIntegrationPlan {
            execution,
            tool,
            burn_control,
            attribution: p.attribution.clone(),
            agentpact_native_attribution: p.agentpact_native_attribution,
        }
        // Overlay the in-code native declaration (all-false today) the same way
        // the file-based path did — generic, no per-agent code.
        .with_native_capabilities(self.manifest.native_capabilities())
    }

    fn hook_protocol(&self) -> Option<HookProtocol> {
        self.profile().hook_protocol.clone()
    }

    fn launch_dir_env(&self) -> Option<String> {
        self.profile().launch_dir.clone()
    }

    fn provider_routing(&self) -> Option<ProviderRouting> {
        let env = self
            .profile()
            .surfaces
            .model_routing
            .as_ref()?
            .env
            .as_ref()?;
        Some(ProviderRouting {
            base_url_vars: env.base_url_vars.clone(),
            auth_skip_flags: env.auth_skip_flags.clone(),
            custom_headers_var: env.custom_headers_var.clone(),
            header_separator: env.header_separator.clone(),
        })
    }

    fn mcp_configs(&self) -> Vec<McpConfigLocation> {
        let Some(tool) = self.profile().surfaces.tool.as_ref() else {
            return Vec::new();
        };
        let mut locations = Vec::new();
        for source in &tool.mcp {
            // A source whose file doesn't resolve (e.g. walk_up_optional
            // `.mcp.json` not found) is skipped.
            let Ok(path) = self.config_path(&source.config) else {
                continue;
            };
            if source.nested_scope {
                locations.extend(Self::expand_nested_mcp(&path, &source.servers_key));
            } else {
                let format = match self.config_format(&source.config) {
                    FileFormat::Toml => McpConfigFormat::Toml {
                        servers_key: source.servers_key.join("."),
                    },
                    _ => McpConfigFormat::Json {
                        servers_path: source.servers_key.clone(),
                    },
                };
                locations.push(McpConfigLocation { path, format });
            }
        }
        // Dedupe identical (path, servers_path) entries — gemini's user and
        // walk-up workspace sources collapse when cwd is the home dir.
        let mut seen: Vec<(PathBuf, Vec<String>)> = Vec::new();
        locations.retain(|l| {
            let servers_path = match &l.format {
                McpConfigFormat::Json { servers_path } => servers_path.clone(),
                McpConfigFormat::Toml { servers_key } => vec![servers_key.clone()],
            };
            let key = (l.path.clone(), servers_path);
            if seen.contains(&key) {
                false
            } else {
                seen.push(key);
                true
            }
        });
        locations
    }

    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        if let Some(d) = self.native_delegate() {
            return d.burn_control_config_paths();
        }
        let Some(mr) = self.profile().surfaces.model_routing.as_ref() else {
            return Vec::new();
        };
        let mut names: Vec<String> = Vec::new();
        for op in &mr.configure {
            if let ConfigureOp::SetKey { file, .. } = op
                && !names.contains(file)
            {
                names.push(file.clone());
            }
        }
        names
            .iter()
            .filter_map(|n| self.config_path(n).ok())
            .collect()
    }

    fn probe(&self) -> ProbeResult {
        if let Some(d) = self.native_delegate() {
            return d.probe();
        }
        let p = self.profile();
        if !engine::is_detected(p) {
            return not_detected();
        }

        let execution = p
            .surfaces
            .execution
            .as_ref()
            .map_or_else(SurfaceState::none, |s| {
                if s.probe.iter().any(|r| self.probe_rule_matches(r)) {
                    s.mechanisms
                        .first()
                        .map_or_else(SurfaceState::none, |&m| SurfaceState::adapted(m))
                } else if let Some(fb) = s.fallback.as_ref()
                    && fb.probe.iter().any(|r| self.probe_rule_matches(r))
                {
                    let state = SurfaceState::adapted(fb.mechanism);
                    match fb.ceiling {
                        Some(c) => state.with_ceiling(c),
                        None => state,
                    }
                } else {
                    SurfaceState::none()
                }
            });

        // Tool surface has the MCP not-applicable nuance (no servers configured →
        // nothing to mediate), distinct from "configured but unwrapped".
        let tool = if p.surfaces.tool.is_some() {
            let (has_wrap, has_servers) = probe::mcp_locations_status(self);
            if has_wrap {
                SurfaceState::adapted(ToolMechanism::McpWrapping)
            } else if has_servers {
                SurfaceState::none()
            } else {
                SurfaceState::not_applicable()
            }
        } else {
            SurfaceState::none()
        };

        let burn_control = p
            .surfaces
            .model_routing
            .as_ref()
            .map_or_else(SurfaceState::none, |s| {
                if s.probe.iter().any(|r| self.probe_rule_matches(r)) {
                    s.mechanisms
                        .first()
                        .map_or_else(SurfaceState::none, |&m| SurfaceState::adapted(m))
                } else {
                    SurfaceState::none()
                }
            });

        // Managed files for drift detection: every declared config file that
        // currently carries a kyris marker. Conditional on the marker so a file
        // the agent itself rewrites constantly (e.g. ~/.claude.json) does not
        // hash-drift into an endless repair loop when kyris content is absent.
        let mut managed_files = Vec::new();
        let mut seen: Vec<PathBuf> = Vec::new();
        for name in p.config_files.keys() {
            let Ok(path) = self.config_path(name) else {
                continue;
            };
            if seen.contains(&path) {
                continue;
            }
            seen.push(path.clone());
            let has_marker = std::fs::read_to_string(&path)
                .is_ok_and(|c| p.markers.iter().any(|m| c.contains(m.as_str())));
            if has_marker && let Some(fp) = fingerprint(&path) {
                managed_files.push(fp);
            }
        }

        ProbeResult {
            detected: true,
            execution,
            tool,
            burn_control,
            managed_files,
        }
    }

    fn configure_execution_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        agent_specific: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        if let Some(d) = self.native_delegate() {
            return d.configure_execution_surface(base_url, inbound_key, agent_specific);
        }
        match self.profile().surfaces.execution.as_ref() {
            Some(s) => self.run_configure(
                &s.configure,
                &self.component("execution"),
                base_url,
                inbound_key,
                agent_specific,
            ),
            None => Ok(Vec::new()),
        }
    }

    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        agent_specific: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        if let Some(d) = self.native_delegate() {
            return d.configure_tool_surface(base_url, inbound_key, agent_specific);
        }
        match self.profile().surfaces.tool.as_ref() {
            Some(s) => self.run_configure(
                &s.configure,
                &self.component("tool"),
                base_url,
                inbound_key,
                agent_specific,
            ),
            None => Ok(Vec::new()),
        }
    }

    fn configure_burn_control_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        agent_specific: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        if let Some(d) = self.native_delegate() {
            return d.configure_burn_control_surface(base_url, inbound_key, agent_specific);
        }
        match self.profile().surfaces.model_routing.as_ref() {
            Some(s) => self.run_configure(
                &s.configure,
                &self.component("burn-control"),
                base_url,
                inbound_key,
                agent_specific,
            ),
            None => Ok(Vec::new()),
        }
    }

    fn apply_extra_tool_filters(&self, settings: &mut Value) -> bool {
        match self
            .profile()
            .surfaces
            .tool
            .as_ref()
            .and_then(|t| t.exclude_tools.as_ref())
        {
            Some(key) => {
                let refs: Vec<&str> = key.iter().map(String::as_str).collect();
                super::configure::apply_json_tool_filters(settings, &refs)
            }
            None => false,
        }
    }

    fn undo_execution_surface(&self) -> Result<(), String> {
        if let Some(d) = self.native_delegate() {
            return d.undo_execution_surface();
        }
        match self.profile().surfaces.execution.as_ref() {
            Some(s) => self.run_undo(&s.undo),
            None => Ok(()),
        }
    }

    fn undo_tool_surface(&self) -> Result<(), String> {
        if let Some(d) = self.native_delegate() {
            return d.undo_tool_surface();
        }
        match self.profile().surfaces.tool.as_ref() {
            Some(s) => self.run_undo(&s.undo),
            None => Ok(()),
        }
    }

    fn undo_burn_control_surface(&self) -> Result<(), String> {
        if let Some(d) = self.native_delegate() {
            return d.undo_burn_control_surface();
        }
        match self.profile().surfaces.model_routing.as_ref() {
            Some(s) => self.run_undo(&s.undo),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shipped agent document parses, validates (`GenericAgent::new`
    /// panics otherwise), and yields a usable descriptor: an id, a hook
    /// protocol, markers, and all three governance surfaces present. The
    /// byte-for-byte faithfulness of each document to its former hand-written
    /// descriptor was proven by the equivalence tests during the migration; the
    /// documents are now the source of truth, validated here + by the registry
    /// invariants + the kyris-internal e2e suite.
    #[test]
    fn testAllAgentDocumentsLoad() {
        for id in [
            "cline",
            "opencode",
            "claude-code",
            "gemini-cli",
            "codex-cli",
        ] {
            let agent = GenericAgent::new(id);
            assert_eq!(agent.id(), id);
            assert_eq!(agent.canonical_id(), canonical_agent_id(id));
            assert!(
                agent.hook_protocol().is_some(),
                "{id}: missing hook protocol"
            );
            assert!(
                !agent.kyris_content_markers().is_empty(),
                "{id}: no kyris content markers"
            );
            let (exec, tool, burn) = agent.integration_plan().expected_surfaces();
            assert!(
                exec && tool && burn,
                "{id}: all three governance surfaces should be declared"
            );
        }
    }

    /// codex delegates its realization (probe/configure/undo) to the codex-cli
    /// handler; this verifies the document's DATA (plan, hook protocol, markers,
    /// settings, MCP/TOML location) matches the hand-written `CodexCli` delegate.
    #[test]
    fn testGenericCodexMatchesDelegate() {
        use crate::agents::codex_cli::CodexCli;
        let generic = GenericAgent::new("codex-cli");
        let hand = CodexCli;

        assert_eq!(generic.id(), hand.id());
        assert_eq!(generic.canonical_id(), hand.canonical_id());
        assert_eq!(
            generic.kyris_content_markers(),
            hand.kyris_content_markers()
        );
        assert_eq!(generic.integration_plan(), hand.integration_plan());
        assert_eq!(generic.launch_dir_env(), hand.launch_dir_env());
        assert_eq!(generic.supported_settings(), hand.supported_settings());

        let to_json = |a: &dyn AgentDescriptor| {
            serde_json::to_value(a.hook_protocol().expect("hook protocol")).unwrap()
        };
        assert_eq!(to_json(&generic), to_json(&hand));

        let gc = generic.mcp_configs();
        let hc = hand.mcp_configs();
        assert_eq!(gc.len(), hc.len());
        assert_eq!(gc[0].path, hc[0].path);
    }

    /// `same_file` equates two distinct path spellings of one file (the
    /// `walk_up_optional` result vs the static `~/…` path that resolve to the
    /// same `~/.gemini/settings.json`), which is what lets the install/remove
    /// self-destruct guard fire.
    #[test]
    fn testSameFileEquatesDistinctSpellingsOfOneFile() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("settings.json");
        std::fs::write(&real, "{}").unwrap();
        // A second spelling via a redundant `.` component — canonicalizes equal.
        let aliased = dir.path().join(".").join("settings.json");
        assert!(same_file(&real, &aliased));
        // A genuinely different file does not match.
        let other = dir.path().join("other.json");
        std::fs::write(&other, "{}").unwrap();
        assert!(!same_file(&real, &other));
    }

    /// The self-destruct guard depends on ordering: `install_hook` must run
    /// before `remove_legacy_hook` so the installed path is recorded before the
    /// legacy removal checks it. Gemini is the agent that hits the collision
    /// (its `workspace_settings` walk-up can resolve to the user settings file),
    /// so pin its op order and that a legacy removal is actually present.
    #[test]
    fn testGeminiInstallsHookBeforeLegacyRemoval() {
        let agent = GenericAgent::new("gemini-cli");
        let exec = agent
            .profile()
            .surfaces
            .execution
            .as_ref()
            .expect("gemini execution surface");
        let install_idx = exec
            .configure
            .iter()
            .position(|op| matches!(op, ConfigureOp::InstallHook { .. }))
            .expect("gemini installs a hook");
        let remove_idx = exec
            .configure
            .iter()
            .position(|op| matches!(op, ConfigureOp::RemoveLegacyHook { .. }))
            .expect("gemini removes a legacy hook");
        assert!(
            install_idx < remove_idx,
            "install_hook must precede remove_legacy_hook so the guard records the \
             installed path first (else the legacy removal can delete the new hook)"
        );
    }
}
