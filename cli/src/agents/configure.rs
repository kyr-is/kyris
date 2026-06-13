// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{
    ensure_json_array_contains, ensure_json_command_hook, read_json_value, write_json_value,
};
use crate::lifecycle::log::InstallLog;
use crate::state::{load_or_init_config, write_managed_file};

use super::registry;

pub(super) fn hook_script_source(agent_id: &str) -> String {
    // Discover the kyris binary at runtime instead of hardcoding a single
    // path. Preserves the original design's preference for the managed copy
    // at ~/.kyris/bin/kyris (writeable by `kyris install`, stable across
    // PATH changes) but falls back to common install locations when the
    // managed copy doesn't exist — covers install.sh-only users who never
    // ran `kyris install`, brew installs, and post-cleanup re-installs.
    //
    // PATH lookup is last because PATH could be attacker-influenced in
    // some hook-invocation contexts; a real kyris binary at a well-known
    // absolute path is preferred to whatever PATH resolves to.
    //
    // Fail-open with a stderr warning when no kyris is reachable: matches
    // AgentPact §11.1's "not installed" state (agent runs ungoverned).
    let template = r#"#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

export KYRIS_GOVERNED_SUBPROCESS="__AGENT_ID__"

KYRIS_BIN=""
for candidate in \
  "$HOME/.kyris/bin/kyris" \
  "$HOME/.local/bin/kyris" \
  "/opt/homebrew/bin/kyris" \
  "/usr/local/bin/kyris"; do
  if [ -x "$candidate" ]; then
    KYRIS_BIN="$candidate"
    break
  fi
done
if [ -z "$KYRIS_BIN" ] && command -v kyris >/dev/null 2>&1; then
  KYRIS_BIN="$(command -v kyris)"
fi
if [ -z "$KYRIS_BIN" ]; then
  echo "[agentpact-hook] kyris binary not found; skipping governance check" >&2
  exit 0
fi

exec "$KYRIS_BIN" hook check --agent __AGENT_ID__
"#;
    template.replace("__AGENT_ID__", agent_id)
}

pub(super) fn shell_command(path: &std::path::Path) -> String {
    // POSIX single-quote escaping: the only character that cannot appear
    // inside single-quoted strings is the single-quote itself, which we
    // escape by ending the quote, inserting a literal \', and reopening.
    let escaped = path.display().to_string().replace('\'', "'\\''");
    format!("bash '{escaped}'")
}

pub(super) fn install_live_hook_adapter(
    agent_id: &str,
    component: &str,
    // One registration per hook EVENT, same script for all (the engine
    // branches on the payload's hook_event_name) — codex registers both
    // PreToolUse and PermissionRequest; claude/gemini one event each.
    hook_phases: &[&str],
    script_path: &std::path::Path,
    hooks_file_path: &std::path::Path,
    nested: bool,
    // Per-hook timeout in the agent's units; see `ensure_json_command_hook`.
    // Set it when the agent's default hook timeout is below kyris's ~590s
    // no-TTY approval window (e.g. Gemini's 60s default).
    hook_timeout: Option<i64>,
) -> Result<Vec<String>, String> {
    let script_source = hook_script_source(agent_id);
    let mut changes = Vec::new();

    // Hook script is opaque shell — no schema to validate against.
    if write_managed_file(
        script_path,
        &script_source,
        component,
        Some(0o755),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", script_path.display()));
    }

    let mut hooks = read_json_value(hooks_file_path)?;
    let mut hooks_changed = false;
    for hook_phase in hook_phases {
        hooks_changed |= ensure_json_command_hook(
            &mut hooks,
            hook_phase,
            &shell_command(script_path),
            nested,
            hook_timeout,
        );
    }
    if hooks_changed {
        // Hooks file format varies per agent (claude/cline/codex/gemini have
        // different shapes); well-formedness is the safe baseline. Per-agent
        // shape validators can be added incrementally.
        write_json_value(hooks_file_path, &hooks, component, &WellFormedJsonValidator)?;
        changes.push(format!("updated {}", hooks_file_path.display()));
    }

    Ok(changes)
}

/// The JS plugin that delivers the live-hook adapter for agents whose
/// extension point is an in-process plugin (e.g. opencode) rather than a native
/// shell-script hook. It is the plugin-delivery twin of [`hook_script_source`]:
/// a GENERIC, agent-id-templated bridge that, on every tool call, asks the SAME
/// shared decision engine (`kyris hook check --agent <id>` → agentpactd) and
/// blocks the tool by throwing when governance denies. Reusable by any future
/// plugin-hook agent — the agent id and the spawn timeout (from the agent's
/// declared `HookRuntime`) are substituted.
pub(super) fn plugin_hook_source(agent_id: &str) -> Result<String, String> {
    let spawn_timeout_ms = registry::agent_by_id(agent_id)
        .and_then(|a| a.hook_protocol())
        .map(|p| p.runtime.bridge_spawn_timeout_ms())
        .ok_or_else(|| {
            format!("{agent_id} declares no hook protocol — cannot derive the plugin spawn timeout")
        })?;
    let template = r#"// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
// Generated by Kyris — AgentPact live governance for __AGENT_ID__.
// On every tool call, ask `kyris hook check` (→ agentpactd) for a decision and
// block the tool (throw) when governance denies it. This is the plugin-delivery
// twin of the native shell-hook adapter; the decision engine is shared.
//
// The check runs via ASYNC spawn (not spawnSync): this plugin runs INSIDE the
// long-lived opencode server process, so a synchronous wait during a kyris
// approval hold would freeze every session, the HTTP API, and abort delivery
// for the whole hold window. The hook is awaited, so the event loop stays free.
import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { homedir } from "node:os"

// Prefer the managed copy, then well-known absolute install paths, then PATH —
// mirrors the shell adapter's resolution (a real binary at a known path is
// preferred to whatever PATH resolves to).
function kyrisBin() {
  for (const candidate of [
    homedir() + "/.kyris/bin/kyris",
    homedir() + "/.local/bin/kyris",
    "/opt/homebrew/bin/kyris",
    "/usr/local/bin/kyris",
  ]) {
    if (existsSync(candidate)) return candidate
  }
  return "kyris"
}

const KYRIS_BIN = kyrisBin()

// Resolve to {status} on a clean exit, {timedOut} if the engine outran the
// deadline (we SIGKILL it), or {error} if the binary could not run at all.
function runKyrisCheck(payload, cwd) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(KYRIS_BIN, ["hook", "check", "--agent", "__AGENT_ID__"], {
        cwd,
        env: { ...process.env, KYRIS_GOVERNED_SUBPROCESS: "__AGENT_ID__" },
      })
    } catch (e) {
      resolve({ error: e })
      return
    }
    let stdout = "", stderr = "", settled = false
    const finish = (r) => { if (!settled) { settled = true; clearTimeout(timer); resolve(r) } }
    const timer = setTimeout(() => { try { child.kill("SIGKILL") } catch {} finish({ timedOut: true }) }, __SPAWN_TIMEOUT_MS__)
    child.on("error", (e) => finish({ error: e })) // ENOENT etc. (fires async)
    child.stdout.on("data", (d) => { stdout += d })
    child.stderr.on("data", (d) => { stderr += d })
    child.on("close", (status) => finish({ status, stdout, stderr }))
    // A write to a dead child surfaces an ASYNC 'error' on the stdin stream that
    // a try/catch cannot catch; without this handler it would throw inside the
    // opencode server event loop. Fail open (a dead child → not-installed).
    child.stdin.on("error", (e) => finish({ error: e }))
    try { child.stdin.write(payload); child.stdin.end() } catch (e) { finish({ error: e }) }
  })
}

export const KyrisGovernance = async (input) => {
  // `cwd` is the permitted-domain anchor agentpactd resolves policy from
  // (opencode has no launch-dir env var, so it must ride in the payload). It
  // lives on the plugin-factory input (PluginInput.directory), NOT the per-hook
  // input.
  const cwd = input.directory
  return {
    "tool.execute.before": async (inp, out) => {
      const payload = JSON.stringify({ tool_name: inp.tool, tool_input: out?.args ?? {}, cwd })
      const res = await runKyrisCheck(payload, cwd)
      // A hung engine fails CLOSED: this agent has no native permission backstop
      // behind the plugin, so an unresolved check must become a deny, not a
      // silent allow. Only a missing/unrunnable binary fails open ("kyris not
      // installed → ungoverned", matching the shell adapter).
      if (res.timedOut) throw new Error("kyris governance check timed out before a decision")
      if (res.error) return
      // exit 0 = allow; nonzero (2 = deny) blocks this one tool call. The reason
      // arrives on stderr as "[agentpact] <reason>".
      if (res.status !== 0) {
        const reason = (res.stderr || res.stdout || "").trim().replace(/^\[agentpact\]\s*/, "")
        throw new Error(reason || "blocked by kyris governance")
      }
    },
  }
}
"#;
    Ok(template
        .replace("__AGENT_ID__", agent_id)
        .replace("__SPAWN_TIMEOUT_MS__", &spawn_timeout_ms.to_string()))
}

/// Install the live-hook adapter for a PLUGIN-hook agent: write the generic
/// kyris governance plugin and register it in the agent's config `plugin` array.
/// Plugin-delivery twin of [`install_live_hook_adapter`]; pairs with the agent's
/// `hook_protocol()` and the shared `kyris hook check` engine.
pub(super) fn install_plugin_hook_adapter(
    agent_id: &str,
    component: &str,
    plugin_path: &std::path::Path,
    config_path: &std::path::Path,
) -> Result<Vec<String>, String> {
    let mut changes = Vec::new();

    if write_managed_file(
        plugin_path,
        &plugin_hook_source(agent_id)?,
        component,
        Some(0o644),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", plugin_path.display()));
    }

    let mut config = if config_path.exists() {
        read_json_value(config_path)?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    let plugin_spec = plugin_path.to_string_lossy();
    if ensure_json_array_contains(&mut config, &["plugin"], &plugin_spec) {
        write_json_value(config_path, &config, component, &WellFormedJsonValidator)?;
        changes.push(format!(
            "registered kyris governance plugin in {}",
            config_path.display()
        ));
    }

    Ok(changes)
}

/// Full setup: prestage + configure every adapted surface, then verify kyrisd
/// is reachable.
///
/// All changes are KEPT even when the kyrisd health check fails. The developer
/// explicitly asked for this configuration; the config rewrites that route
/// through kyrisd (base URLs/keys, MCP URL rewrites) take effect the moment
/// kyrisd comes up, so there is nothing to gain by discarding them. We instead
/// apply everything and return an actionable error telling the user to start
/// kyrisd — the surfaces are already in place. Execution-surface changes need
/// only agentpactd and are likewise committed unconditionally.
///
/// An earlier version rolled burn-control changes back on health-check failure;
/// that was deliberately removed. Do not reintroduce it — the kept-changes
/// contract is pinned by `tests/setup_rollback.rs`.
/// Reject any `--set` key the agent does not declare in `supported_settings`,
/// before any side effects run. Without this, an unknown key (e.g. a
/// `max-budget-usd` claude doesn't consume) would be stored and printed as
/// "set …" yet do nothing — false confidence.
fn validate_agent_settings(
    agent: &dyn registry::AgentDescriptor,
    agent_specific: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let supported = agent.supported_settings();
    for key in agent_specific.keys() {
        if !supported.iter().any(|(k, _)| k == key) {
            let detail = if supported.is_empty() {
                format!("{} accepts no --set settings.", agent.id())
            } else {
                let list = supported
                    .iter()
                    .map(|(k, d)| format!("  {k} — {d}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!("Valid --set keys for {}:\n{list}", agent.id())
            };
            return Err(format!(
                "Unknown --set key '{key}' for {}. {detail}",
                agent.id()
            ));
        }
    }
    Ok(())
}

pub fn setup_agent(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    validate_agent_settings(agent.as_ref(), agent_specific)?;

    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    let mut changes = super::prestage::prestage_agent(agent_id)?;

    if agent.is_installed() {
        let plan = agent.integration_plan();
        if plan.requires_path_shim() {
            changes.extend(super::shim::install_shim(agent_id)?);
        }
        if plan.has_adapted_execution() {
            changes.extend(agent.configure_execution_surface(
                &base_url,
                inbound_key,
                agent_specific,
            )?);
        }
        if plan.has_adapted_tool() {
            changes.extend(agent.configure_tool_surface(&base_url, inbound_key, agent_specific)?);
        }
        if plan.has_adapted_burn_control() {
            changes.extend(agent.configure_burn_control_surface(
                &base_url,
                inbound_key,
                agent_specific,
            )?);
        }

        // Execution and tool governance route decisions through agentpactd, so
        // verify it too — otherwise setup would report success while command/MCP
        // governance is silently dormant (the hook fails open → ungoverned).
        let needs_agentpactd = plan.has_adapted_execution() || plan.has_adapted_tool();
        verify_governance_daemons(&base_url, agent_id, needs_agentpactd)?;
    } else {
        // Not installed: only prestaged (no governance surfaces yet), so just
        // kyrisd needs to be reachable for the routing env to work once detected.
        verify_governance_daemons(&base_url, agent_id, false)?;
    }

    clear_disabled_flag(agent_id)?;

    if !agent_specific.is_empty() {
        save_agent_specific(agent_id, agent_specific)?;
        for (k, v) in agent_specific {
            changes.push(format!("set {k}={v}"));
        }
    }

    if changes.is_empty() {
        println!("No changes needed for {agent_id}.");
    } else {
        if !agent.is_installed() {
            println!(
                "{agent_id} not installed — prestaged only. \
                 Configure will run automatically when the agent is detected."
            );
        }
        println!("Applied setup for {agent_id}:");
        for change in &changes {
            println!("  {change}");
        }
    }

    Ok(())
}

/// Configure agent-owned files only. Used by reconcile auto-configure.
/// Prestage must have already run. If kyrisd is unreachable, returns an
/// error — the caller must ensure kyrisd is ready before calling this.
///
/// When `skip_burn_control` is true, burn-control configuration is skipped.
/// Execution and tool surfaces still run; used after native promotion removes
/// burn-control artifacts without disabling MCP/tool mediation.
pub fn configure_agent(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
    skip_burn_control: bool,
    log: Option<&InstallLog>,
) -> Result<(), String> {
    configure_agent_surfaces(
        agent_id,
        agent_specific,
        false,
        false,
        skip_burn_control,
        log,
    )
}

pub(super) fn configure_agent_surfaces(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
    skip_execution: bool,
    skip_tool: bool,
    skip_burn_control: bool,
    log: Option<&InstallLog>,
) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    if !agent.is_installed() {
        return Err(format!("{agent_id} is not installed."));
    }

    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    let mut changes = Vec::new();
    let plan = agent.integration_plan();
    if plan.requires_path_shim() {
        changes.extend(super::shim::install_shim(agent_id)?);
    }
    if !skip_execution && plan.has_adapted_execution() {
        changes.extend(agent.configure_execution_surface(
            &base_url,
            inbound_key,
            agent_specific,
        )?);
    }
    if !skip_tool && plan.has_adapted_tool() {
        changes.extend(agent.configure_tool_surface(&base_url, inbound_key, agent_specific)?);
    }

    if !skip_burn_control && plan.has_adapted_burn_control() {
        changes.extend(agent.configure_burn_control_surface(
            &base_url,
            inbound_key,
            agent_specific,
        )?);

        if let Err(error) = verify_kyrisd_health(&base_url) {
            return Err(format!(
                "kyrisd unreachable ({error}). \
                 Bring kyrisd up (try `launchctl kickstart gui/$UID/is.kyr.kyrisd` or reinstall), then re-run `kyris agents setup {agent_id}`."
            ));
        }
    }

    if changes.is_empty() {
        println!("No changes needed for {agent_id}.");
        if let Some(l) = log {
            l.info(&format!("{agent_id}: no changes needed"));
        }
    } else {
        println!("Configured {agent_id}:");
        if let Some(l) = log {
            l.info(&format!("configured {agent_id}"));
        }
        for change in &changes {
            println!("  {change}");
            if let Some(l) = log {
                l.info(&format!("  {agent_id} {change}"));
            }
        }
    }

    Ok(())
}

fn clear_disabled_flag(agent_id: &str) -> Result<(), String> {
    if let Some(mut profile) = crate::state::load_agent_profile(agent_id)?
        && profile.disabled
    {
        profile.disabled = false;
        crate::state::save_agent_profile(&profile)?;
    }
    Ok(())
}

fn save_agent_specific(
    agent_id: &str,
    settings: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let mut profile = crate::state::load_agent_profile(agent_id)?
        .unwrap_or_else(|| super::profile::AgentProfile::new_empty(agent_id));
    profile
        .agent_specific
        .extend(settings.iter().map(|(k, v)| (k.clone(), v.clone())));
    crate::state::save_agent_profile(&profile)
}

#[derive(Debug, Clone, Default)]
pub struct McpRewriteResult {
    pub changed: bool,
    pub http_rewrites: Vec<(String, String)>,
}

impl McpRewriteResult {
    fn unchanged() -> Self {
        Self::default()
    }
}

/// Walk one MCP config location and collect the names of servers matching the
/// per-format predicates. Missing file / missing path → empty (clean no-op).
fn mcp_server_names_at(
    location: &super::registry::McpConfigLocation,
    json_keep: &dyn Fn(&serde_json::Value) -> bool,
    toml_keep: &dyn Fn(&toml::Value) -> bool,
) -> Vec<String> {
    match &location.format {
        super::registry::McpConfigFormat::Json { servers_path } => {
            let Ok(val) = crate::integration::read_json_value(&location.path) else {
                return Vec::new();
            };
            let mut cur = &val;
            for key in servers_path {
                match cur.get(key) {
                    Some(v) => cur = v,
                    None => return Vec::new(),
                }
            }
            cur.as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(_, server)| json_keep(server))
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
        super::registry::McpConfigFormat::Toml { servers_key } => {
            let Ok(val) = crate::integration::read_toml_value(&location.path) else {
                return Vec::new();
            };
            val.get(servers_key)
                .and_then(toml::Value::as_table)
                .map(|t| {
                    t.iter()
                        .filter(|(_, server)| toml_keep(server))
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
    }
}

/// Union of matching server names across ALL of the agent's MCP config
/// locations, sorted and deduped (the same name can appear in several scopes).
fn mcp_server_names_matching(
    agent: &dyn super::registry::AgentDescriptor,
    json_keep: &dyn Fn(&serde_json::Value) -> bool,
    toml_keep: &dyn Fn(&toml::Value) -> bool,
) -> Vec<String> {
    let mut names: Vec<String> = agent
        .mcp_configs()
        .iter()
        .flat_map(|location| mcp_server_names_at(location, json_keep, toml_keep))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Collect the MCP server names currently registered in any of the agent's
/// config locations.
///
/// Called at the start of tool-surface undo, before `restore_manifest_entry`
/// restores the file(s) to their pre-kyris state, so we can identify which
/// upstream entries to remove from `kyrisd.yaml`.
pub fn mcp_server_names_from_agent(agent: &dyn super::registry::AgentDescriptor) -> Vec<String> {
    mcp_server_names_matching(agent, &|_| true, &|_| true)
}

/// Names of MCP servers in the agent's config that ARE routed through kyris —
/// a stdio server wrapped by `kyris-mcp`, or an HTTP server whose `url` points
/// at kyrisd's `/mcp/` routing. The hook engine uses this to recognize an
/// unmapped hook tool name as an MCP tool that is already governed at the TOOL
/// surface, so the no-backstop deny posture (G1) does not break wrapped MCP
/// servers. Servers NOT in this list get no such blessing — an unwrapped
/// server's tools are ungoverned everywhere and deny is the honest outcome.
pub fn kyris_routed_mcp_server_names(agent: &dyn super::registry::AgentDescriptor) -> Vec<String> {
    let kyrisd_mcp_prefix = crate::state::load_config()
        .ok()
        .map(|c| format!("{}/mcp/", c.base_url()));
    let url_is_routed = move |url: Option<&str>| {
        url.zip(kyrisd_mcp_prefix.as_deref())
            .is_some_and(|(u, prefix)| u.starts_with(prefix))
    };
    mcp_server_names_matching(
        agent,
        &|server| {
            let fields = json_mcp_fields(server);
            !json_mcp_server_unwrapped(server)
                && (fields.get("command").is_some()
                    || url_is_routed(fields.get("url").and_then(serde_json::Value::as_str)))
        },
        &|server| {
            !toml_mcp_server_unwrapped(server)
                && (server.get("command").is_some()
                    || url_is_routed(server.get("url").and_then(toml::Value::as_str)))
        },
    )
}

/// Names of MCP servers in the agent's config that are NOT yet routed through
/// kyris — a stdio server whose `command` isn't `kyris-mcp`. Surfaces config
/// drift (e.g. an MCP server added *after* `kyris agents setup`, which the
/// configure-time rewrite never saw) so `kyris status` can prompt a reconcile.
/// URL/HTTP servers are out of scope here.
pub fn unwrapped_mcp_server_names(agent: &dyn super::registry::AgentDescriptor) -> Vec<String> {
    mcp_server_names_matching(
        agent,
        &json_mcp_server_unwrapped,
        &toml_mcp_server_unwrapped,
    )
}

/// A stdio MCP server is "unwrapped" when it has a `command` that isn't
/// `kyris-mcp` (string form or array-first form). Servers with no `command`
/// (URL/HTTP) are not flagged. Reads through `json_mcp_fields` so cline's
/// nested `transport.command` is detected, not just the flat form.
fn json_mcp_server_unwrapped(server: &serde_json::Value) -> bool {
    match json_mcp_fields(server).get("command") {
        Some(serde_json::Value::String(cmd)) => cmd != "kyris-mcp",
        Some(serde_json::Value::Array(cmd)) => {
            cmd.first().and_then(serde_json::Value::as_str) != Some("kyris-mcp")
        }
        _ => false,
    }
}

fn toml_mcp_server_unwrapped(server: &toml::Value) -> bool {
    match server.get("command").and_then(toml::Value::as_str) {
        Some(cmd) => cmd != "kyris-mcp",
        None => false,
    }
}

/// Remove named MCP upstream entries from `kyrisd.yaml`.
///
/// Called during agent tool-surface undo to reverse the
/// `upsert_mcp_upstreams` call that happened during tool-surface setup. Server
/// names not present in `kyrisd.yaml` are silently skipped (idempotent).
pub fn remove_mcp_upstreams(names: &[String]) -> Result<(), String> {
    if names.is_empty() {
        return Ok(());
    }
    let Ok(mut config) = crate::state::load_config() else {
        return Ok(()); // config absent — nothing to clean
    };
    let before = config.mcp.servers.len();
    config.mcp.servers.retain(|s| !names.contains(&s.name));
    if config.mcp.servers.len() == before {
        return Ok(()); // no matching entries found
    }
    if config.mcp.servers.is_empty() {
        config.mcp.enabled = false;
    }
    crate::state::save_config(&config)
}

/// Shared configure flow for agents whose MCP servers live in JSON config(s)
/// (claude, gemini, cline, opencode): route every MCP server through kyris
/// (`rewrite_json_mcp_servers`) at EVERY declared location, apply the agent's
/// optional extra tool filter (`apply_extra_tool_filters`), write back only
/// files that changed, and register any HTTP upstreams. Several locations may
/// share one FILE (Claude Code's user scope and per-project local scopes both
/// live in `~/.claude.json`), so locations are grouped by path and each file
/// gets one read-modify-write. Codex (TOML) keeps its own
/// `configure_tool_surface`. `read_json_value` returns `{}` for a missing
/// file, so a not-yet-created config is a clean no-op (no write).
pub fn configure_json_mcp_tool_surface(
    agent: &dyn super::registry::AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let component = format!("{}:tool", agent.id());
    let mut changes = Vec::new();
    let mut all_http_rewrites: Vec<(String, String)> = Vec::new();

    // Group JSON locations by file, preserving declaration order.
    let mut files: Vec<(std::path::PathBuf, Vec<Vec<String>>)> = Vec::new();
    for location in agent.mcp_configs() {
        let super::registry::McpConfigFormat::Json { servers_path } = location.format else {
            continue;
        };
        match files.iter_mut().find(|(p, _)| *p == location.path) {
            Some((_, paths)) => paths.push(servers_path),
            None => files.push((location.path, vec![servers_path])),
        }
    }

    // Fail fast on a cross-scope upstream conflict BEFORE any rewrite:
    // kyrisd.yaml keys upstreams by bare server name, so the same HTTP server
    // name in two scopes with different upstream URLs would silently route the
    // agent's effective server to whichever scope was processed last.
    reject_conflicting_http_upstreams(agent.id(), &files, base_url)?;

    for (path, server_paths) in files {
        let mut settings = read_json_value(&path)?;
        let mut file_changed = false;
        for servers_path in &server_paths {
            let mcp_result = rewrite_json_mcp_servers(
                &mut settings,
                servers_path,
                base_url,
                inbound_key,
                agent.canonical_id(),
            );
            file_changed |= mcp_result.changed;
            all_http_rewrites.extend(mcp_result.http_rewrites);
        }
        let extra_changed = agent.apply_extra_tool_filters(&mut settings);

        if file_changed || extra_changed {
            write_json_value(&path, &settings, &component, &WellFormedJsonValidator)?;
            if file_changed {
                changes.push(format!("rewrote MCP servers in {}", path.display()));
            }
            if extra_changed {
                changes.push(format!("applied MCP tool policy in {}", path.display()));
            }
        }
    }

    if !all_http_rewrites.is_empty() {
        upsert_mcp_upstreams(&all_http_rewrites)?;
        changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
    }
    Ok(changes)
}

/// Error when the same HTTP MCP server NAME appears in several scopes with
/// DIFFERENT (not-yet-routed) upstream URLs. Already-routed entries (url at
/// kyrisd's `/mcp/` prefix) are skipped — their original upstream lives in
/// `kyrisd.yaml` and a same-name unrouted twin will simply update it.
fn reject_conflicting_http_upstreams(
    agent_id: &str,
    files: &[(std::path::PathBuf, Vec<Vec<String>>)],
    base_url: &str,
) -> Result<(), String> {
    let routed_prefix = format!("{base_url}/mcp/");
    let mut upstreams: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (path, server_paths) in files {
        let Ok(value) = read_json_value(path) else {
            continue;
        };
        for servers_path in server_paths {
            let mut cur = Some(&value);
            for key in servers_path {
                cur = cur.and_then(|v| v.get(key));
            }
            let Some(servers) = cur.and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, server) in servers {
                // Read through cline's transport nesting (no-op for flat shapes).
                let Some(url) = json_mcp_fields(server).get("url").and_then(|v| v.as_str()) else {
                    continue;
                };
                if url.starts_with(&routed_prefix) {
                    continue;
                }
                if let Some(existing) = upstreams.get(name) {
                    if existing != url {
                        return Err(format!(
                            "MCP server '{name}' appears in multiple {agent_id} config scopes \
                             with different upstream URLs ({existing} vs {url}); kyrisd routes \
                             by server name, so one scope would silently reach the other's \
                             upstream. Rename one of the servers, then re-run \
                             `kyris agents setup {agent_id}`."
                        ));
                    }
                } else {
                    upstreams.insert(name.clone(), url.to_string());
                }
            }
        }
    }
    Ok(())
}

/// Shared tool-surface undo for JSON-MCP agents: remove the MCP upstreams from
/// `kyrisd.yaml` (while the server names are still readable from the agent
/// config), then restore every file the tool-surface setup RECORDED in the
/// manifest. Manifest-driven, not enumeration-driven: some locations are
/// discovered relative to the setup-time cwd (Claude Code's `.mcp.json`), so
/// an undo run from elsewhere would never re-enumerate them — the manifest is
/// the only complete record of what setup touched. (The upstream-name
/// collection above is still enumeration-based and therefore best-effort for
/// such locations; a stale `kyrisd.yaml` upstream entry is inert, unlike a
/// stranded wrap.)
pub fn undo_json_mcp_tool_surface(
    agent: &dyn super::registry::AgentDescriptor,
) -> Result<(), String> {
    let mcp_names = mcp_server_names_from_agent(agent);
    remove_mcp_upstreams(&mcp_names)?;
    let component = format!("{}:tool", agent.id());
    for path in crate::state::restore_manifest_component(&component)? {
        println!("Reverted {}", path.display());
    }
    Ok(())
}

pub fn upsert_mcp_upstreams(rewrites: &[(String, String)]) -> Result<bool, String> {
    if rewrites.is_empty() {
        return Ok(false);
    }
    let mut config = crate::state::load_or_init_config()?;
    let mut changed = false;
    for (name, upstream) in rewrites {
        let exists = config.mcp.servers.iter().any(|s| s.name == *name);
        if exists {
            let entry = config
                .mcp
                .servers
                .iter_mut()
                .find(|s| s.name == *name)
                .expect("just confirmed exists");
            if entry.upstream != *upstream {
                entry.upstream.clone_from(upstream);
                changed = true;
            }
        } else {
            config
                .mcp
                .servers
                .push(kyris_core::config::McpServerConfig {
                    name: name.clone(),
                    upstream: upstream.clone(),
                    working_dir: None,
                });
            changed = true;
        }
    }
    if changed {
        if !config.mcp.enabled {
            config.mcp.enabled = true;
        }
        crate::state::save_config(&config)?;
    }
    Ok(changed)
}

/// Ensure a wrap-args list carries `--agent <agent_id>` among the leading
/// flags (after `wrap`/`--server`), inserting it when absent — both for
/// freshly wrapped servers and as an idempotent upgrade of wraps written
/// before the flag existed. Returns whether the list changed. Generic over the
/// config value type via the to/from-string closures (`serde_json` / `toml`).
fn ensure_wrap_agent_flag<V>(
    args: &mut Vec<V>,
    agent_id: &str,
    as_str: impl Fn(&V) -> Option<&str>,
    from_str: impl Fn(&str) -> V,
) -> bool {
    // Skip the leading "wrap" and any flag pairs to find the insertion point.
    let mut i = usize::from(args.first().and_then(&as_str) == Some("wrap"));
    while i < args.len() {
        match as_str(&args[i]) {
            Some("--agent") => return false,
            Some("--server") => i += 2,
            _ => break,
        }
    }
    let insert_at = i.min(args.len());
    args.insert(insert_at, from_str(agent_id));
    args.insert(insert_at, from_str("--agent"));
    true
}

pub fn rewrite_codex_mcp_servers(
    config: &mut toml::Value,
    base_url: &str,
    inbound_key: &str,
    agent_id: &str,
) -> McpRewriteResult {
    let Some(root) = config.as_table_mut() else {
        return McpRewriteResult::unchanged();
    };
    let Some(servers) = root
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
    else {
        return McpRewriteResult::unchanged();
    };

    let mut changed = false;
    let mut http_rewrites = Vec::new();
    for (name, server_value) in servers {
        let Some(server) = server_value.as_table_mut() else {
            continue;
        };

        if let Some(command) = server.get("command").and_then(toml::Value::as_str) {
            if command == "kyris-mcp" {
                // Already wrapped — idempotent upgrade: stamp the agent flag
                // onto wraps written before it existed.
                if let Some(args) = server.get_mut("args").and_then(toml::Value::as_array_mut)
                    && ensure_wrap_agent_flag(args, agent_id, toml::Value::as_str, |s| {
                        toml::Value::String(s.to_string())
                    })
                {
                    changed = true;
                }
                continue;
            }

            let original_args = server
                .get("args")
                .and_then(toml::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut wrapped_args = vec![
                toml::Value::String("wrap".to_string()),
                toml::Value::String("--server".to_string()),
                toml::Value::String(name.clone()),
                toml::Value::String("--agent".to_string()),
                toml::Value::String(agent_id.to_string()),
                toml::Value::String(command.to_string()),
            ];
            wrapped_args.extend(original_args);

            server.insert(
                "command".to_string(),
                toml::Value::String("kyris-mcp".to_string()),
            );
            server.insert("args".to_string(), toml::Value::Array(wrapped_args));
            changed = true;
            continue;
        }

        if let Some(url) = server.get("url").and_then(toml::Value::as_str) {
            let routed_url = format!("{base_url}/mcp/{name}/");
            if url != routed_url {
                let original_url = url.to_string();
                server.insert("url".to_string(), toml::Value::String(routed_url));
                changed = true;
                http_rewrites.push((name.clone(), original_url));
            }

            let headers = server
                .entry("http_headers".to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if !headers.is_table() {
                *headers = toml::Value::Table(toml::Table::new());
            }
            let auth_value = format!("Bearer {inbound_key}");
            let headers_table = headers.as_table_mut().expect("converted to TOML table");
            for (header, value) in [
                ("Authorization", auth_value.as_str()),
                // Attribution for kyrisd's /mcp/ routing (tool-surface live
                // evidence) — the wrap's `--agent` twin for HTTP servers.
                ("x-kyris-agent-id", agent_id),
            ] {
                if headers_table.get(header).and_then(toml::Value::as_str) != Some(value) {
                    headers_table
                        .insert(header.to_string(), toml::Value::String(value.to_string()));
                    changed = true;
                }
            }
        }
    }

    McpRewriteResult {
        changed,
        http_rewrites,
    }
}

/// The sub-value of a JSON MCP server entry that carries `command`/`args`/`url`.
/// Cline's `cline mcp add` wizard nests these under a `transport` object
/// (`{transport:{type:"stdio",command,args}}`); every other agent (and cline's
/// legacy flat form) keeps them at the top level. Returns the `transport`
/// object when present, else the server itself — so the rewrite, probes, and
/// drift detectors all see the real command/url regardless of shape. A no-op
/// for agents that never use `transport`.
pub(crate) fn json_mcp_fields(server: &serde_json::Value) -> &serde_json::Value {
    server
        .get("transport")
        .filter(|t| t.is_object())
        .unwrap_or(server)
}

#[allow(clippy::too_many_lines)]
pub fn rewrite_json_mcp_servers(
    config: &mut serde_json::Value,
    servers_path: &[String],
    base_url: &str,
    inbound_key: &str,
    agent_id: &str,
) -> McpRewriteResult {
    let mut cursor = config.as_object_mut();
    for key in servers_path {
        cursor = cursor
            .and_then(|obj| obj.get_mut(key))
            .and_then(|v| v.as_object_mut());
    }
    let Some(servers) = cursor else {
        return McpRewriteResult::unchanged();
    };

    let ensure_json_agent_flag = |args: &mut Vec<serde_json::Value>| {
        ensure_wrap_agent_flag(args, agent_id, serde_json::Value::as_str, |s| {
            serde_json::json!(s)
        })
    };

    let mut changed = false;
    let mut http_rewrites = Vec::new();
    for (name, server_value) in servers.iter_mut() {
        let Some(server) = server_value.as_object_mut() else {
            continue;
        };
        // Operate on the `transport` sub-object for cline's nested shape; the
        // top-level map otherwise (see `json_mcp_fields`).
        let server = if server
            .get("transport")
            .is_some_and(serde_json::Value::is_object)
        {
            server
                .get_mut("transport")
                .and_then(serde_json::Value::as_object_mut)
                .expect("just checked it is an object")
        } else {
            server
        };

        if let Some(command) = server
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if command == "kyris-mcp" {
                // Already wrapped — idempotent upgrade: stamp the agent flag
                // onto wraps written before it existed.
                if let Some(args) = server.get_mut("args").and_then(|v| v.as_array_mut())
                    && ensure_json_agent_flag(args)
                {
                    changed = true;
                }
                continue;
            }

            let original_args = server
                .get("args")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut wrapped_args = vec![
                serde_json::json!("wrap"),
                serde_json::json!("--server"),
                serde_json::json!(name),
                serde_json::json!("--agent"),
                serde_json::json!(agent_id),
                serde_json::json!(command),
            ];
            wrapped_args.extend(original_args);

            server.insert("command".to_string(), serde_json::json!("kyris-mcp"));
            server.insert("args".to_string(), serde_json::Value::Array(wrapped_args));
            changed = true;
            continue;
        }

        if let Some(cmd_array) = server.get("command").and_then(|v| v.as_array()).cloned() {
            let first = cmd_array
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if first == "kyris-mcp" {
                // Array-command wrap: the flags live in the command list itself
                // (after "kyris-mcp"); upgrade in place.
                if let Some(cmd) = server.get_mut("command").and_then(|v| v.as_array_mut()) {
                    let mut tail: Vec<serde_json::Value> = cmd.drain(1..).collect();
                    let tail_changed = ensure_json_agent_flag(&mut tail);
                    cmd.extend(tail);
                    if tail_changed {
                        changed = true;
                    }
                }
                continue;
            }

            let mut wrapped = vec![
                serde_json::json!("kyris-mcp"),
                serde_json::json!("wrap"),
                serde_json::json!("--server"),
                serde_json::json!(name),
                serde_json::json!("--agent"),
                serde_json::json!(agent_id),
            ];
            wrapped.extend(cmd_array);

            server.insert("command".to_string(), serde_json::Value::Array(wrapped));
            changed = true;
            continue;
        }

        if let Some(url) = server.get("url").and_then(|v| v.as_str()).map(String::from) {
            let routed_url = format!("{base_url}/mcp/{name}/");
            if url != routed_url {
                server.insert("url".to_string(), serde_json::json!(routed_url));
                changed = true;
                http_rewrites.push((name.clone(), url));
            }

            let headers = server
                .entry("headers")
                .or_insert_with(|| serde_json::json!({}));
            if !headers.is_object() {
                *headers = serde_json::json!({});
            }
            let auth_value = format!("Bearer {inbound_key}");
            let headers_obj = headers.as_object_mut().expect("converted to JSON object");
            for (header, value) in [
                ("Authorization", auth_value.as_str()),
                // Attribution for kyrisd's /mcp/ routing (tool-surface live
                // evidence) — the wrap's `--agent` twin for HTTP servers.
                ("x-kyris-agent-id", agent_id),
            ] {
                if headers_obj.get(header).and_then(|v| v.as_str()) != Some(value) {
                    headers_obj.insert(header.to_string(), serde_json::json!(value));
                    changed = true;
                }
            }
        }
    }

    McpRewriteResult {
        changed,
        http_rewrites,
    }
}

// ── MCP tool-deny filters ────────────────────────────────────────────────
//
// These apply the policy's per-(server, tool) DENY entries to an agent's config
// so the model is steered away from denied MCP tools *upfront*. This is
// SUPPLEMENTARY, not the enforcement boundary: every MCP `tools/call` is already
// mediated at runtime — stdio servers through the `kyris-mcp wrap` (which checks
// agentpactd) and HTTP servers through kyrisd's `/mcp/{name}/` routing
// (`daemon::mcp_routing::policy::check_permission`). So tool denial is enforced
// for ALL agents regardless of these filters; the filters only spare the agent a
// wasted round-trip on a tool it will be denied anyway.
//
// They are applied per agent according to what its config can natively express:
//   - codex   → `disabled_tools` per `[mcp_servers.<name>]`  (apply_toml_tool_filters)
//   - gemini  → `excludeTools` per `mcpServers.<name>`        (apply_json_tool_filters)
//   - claude  → global `permissions.deny` via `mcp__<server>__<tool>` matchers
//               (apply_claude_mcp_tool_denies) — claude has no per-server field
//   - cline / opencode → no native per-server tool-denylist field; they rely on
//               the runtime wrap/routing backstop above (documented at their
//               `configure_tool_surface`).

pub(super) fn apply_toml_tool_filters(config: &mut toml::Value) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    if filters.is_empty() {
        return false;
    }

    let Some(servers) = config
        .as_table_mut()
        .and_then(|t| t.get_mut("mcp_servers"))
        .and_then(toml::Value::as_table_mut)
    else {
        return false;
    };

    let mut changed = false;
    for (server_name, denied_tools) in &filters {
        let Some(server) = servers
            .get_mut(server_name)
            .and_then(toml::Value::as_table_mut)
        else {
            continue;
        };
        let new_val = toml::Value::Array(
            denied_tools
                .iter()
                .map(|t| toml::Value::String(t.clone()))
                .collect(),
        );
        if server.get("disabled_tools") != Some(&new_val) {
            server.insert("disabled_tools".to_string(), new_val);
            changed = true;
        }
    }
    changed
}

pub(super) fn apply_json_tool_filters(
    config: &mut serde_json::Value,
    servers_path: &[&str],
) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    if filters.is_empty() {
        return false;
    }

    let mut cursor = config.as_object_mut();
    for key in servers_path {
        cursor = cursor
            .and_then(|obj| obj.get_mut(*key))
            .and_then(|v| v.as_object_mut());
    }
    let Some(servers) = cursor else {
        return false;
    };

    let mut changed = false;
    for (server_name, denied_tools) in &filters {
        let Some(server) = servers.get_mut(server_name).and_then(|v| v.as_object_mut()) else {
            continue;
        };
        let new_val: serde_json::Value = denied_tools.clone().into();
        if server.get("excludeTools") != Some(&new_val) {
            server.insert("excludeTools".to_string(), new_val);
            changed = true;
        }
    }
    changed
}

/// Claude has no per-MCP-server tool-denylist field, but it CAN deny individual
/// MCP tools via the documented global `permissions.deny` matcher
/// `mcp__<server>__<tool>`. Add a deny entry for every policy-denied tool on a
/// PRESENT server (matching the gemini/codex behavior of only touching servers
/// that exist). The deny entries live in `settings.json` while the servers live
/// in `~/.claude.json`/`.mcp.json`, so the caller supplies the present-server
/// names (from `mcp_server_names_from_agent`) rather than this function reading
/// them out of `settings`. Idempotent: existing entries are preserved and
/// duplicates are not added. ADD-ONLY by design, unlike the codex/gemini
/// filters which replace their dedicated per-server fields: `permissions.deny`
/// is shared with user-authored rules, so kyris never removes entries (a
/// policy-dropped deny lingers until `kyris agents undo` restores the file —
/// supplementary steering only; runtime enforcement is the wrap/routing).
/// Returns whether `settings` changed.
pub(super) fn apply_claude_mcp_tool_denies(
    settings: &mut serde_json::Value,
    present_servers: &[String],
) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    add_mcp_tool_denies(settings, &filters, present_servers)
}

/// Pure core of [`apply_claude_mcp_tool_denies`], split out so it can be tested
/// with synthetic filters (the public entry reads the policy from disk).
fn add_mcp_tool_denies(
    settings: &mut serde_json::Value,
    filters: &std::collections::HashMap<String, Vec<String>>,
    present_servers: &[String],
) -> bool {
    if filters.is_empty() {
        return false;
    }

    let present: std::collections::BTreeSet<&str> =
        present_servers.iter().map(String::as_str).collect();

    let mut wanted: Vec<String> = Vec::new();
    for (server, tools) in filters {
        if present.contains(server.as_str()) {
            for tool in tools {
                wanted.push(format!("mcp__{server}__{tool}"));
            }
        }
    }
    if wanted.is_empty() {
        return false;
    }

    let Some(root) = settings.as_object_mut() else {
        return false;
    };
    let permissions = root
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}));
    // Don't clobber a non-object `permissions` the user may have set.
    let Some(permissions) = permissions.as_object_mut() else {
        return false;
    };
    let deny = permissions
        .entry("deny")
        .or_insert_with(|| serde_json::json!([]));
    let Some(deny_arr) = deny.as_array_mut() else {
        return false;
    };

    let existing: std::collections::BTreeSet<String> = deny_arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let mut changed = false;
    for entry in wanted {
        if !existing.contains(&entry) {
            deny_arr.push(serde_json::Value::String(entry));
            changed = true;
        }
    }
    changed
}

/// Poll `/healthz` until kyrisd responds successfully or `timeout_secs` elapses.
/// Returns `true` if kyrisd became healthy within the timeout.
pub fn wait_for_kyrisd_ready(base_url: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if verify_kyrisd_health(base_url).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn verify_kyrisd_health(base_url: &str) -> Result<(), String> {
    let url = format!("{base_url}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime: {e}"))?;

    runtime.block_on(async {
        let response = reqwest::get(&url)
            .await
            .map_err(|e| format!("kyrisd is not reachable at {url}: {e}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "kyrisd health check failed at {url}: {}",
                response.status()
            ))
        }
    })
}

/// Resolve the agentpactd socket the same way `kyris status` does
/// (`AGENTPACT_SOCK` override, else `~/.agentpact/agentpact.sock`).
fn agentpactd_socket_path() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn agentpactd_reachable() -> bool {
    agentpactd_reachable_at(&agentpactd_socket_path())
}

/// True iff agentpactd answers a `daemon.health` probe at `socket_path`
/// (a real round-trip, not just a socket connect).
fn agentpactd_reachable_at(socket_path: &str) -> bool {
    kyris_agentpact_client::probe_daemon_health(socket_path, std::time::Duration::from_secs(2))
}

/// Pure builder for the "governance not active" setup error. Returns `None`
/// when every required daemon is reachable. Split out so the message/decision
/// logic is testable without live daemons.
fn governance_daemons_error(
    agent_id: &str,
    kyrisd_problem: Option<String>,
    agentpactd_down: bool,
) -> Option<String> {
    let mut down: Vec<String> = Vec::new();
    if let Some(problem) = kyrisd_problem {
        down.push(format!(
            "kyrisd unreachable ({problem}) — model routing / burn-control will not work \
             (try `launchctl kickstart gui/$UID/is.kyr.kyrisd` or reinstall)"
        ));
    }
    if agentpactd_down {
        down.push(
            "agentpactd unreachable — command & MCP governance will not enforce; the agent \
             would run UNGOVERNED (start agentpactd or reinstall)"
                .to_string(),
        );
    }
    if down.is_empty() {
        return None;
    }
    Some(format!(
        "{agent_id} configured, but governance is NOT active:\n  - {}\n\
         The configuration is in place — re-run `kyris agents setup {agent_id}` once the daemon(s) are up.",
        down.join("\n  - ")
    ))
}

/// Verify the daemons the just-configured surfaces depend on: kyrisd always
/// (routing/burn), and agentpactd when `check_agentpactd` (execution/tool
/// governance). Changes are already applied (kept-changes contract); this only
/// decides whether to report success or an actionable error.
fn verify_governance_daemons(
    base_url: &str,
    agent_id: &str,
    check_agentpactd: bool,
) -> Result<(), String> {
    let kyrisd_problem = verify_kyrisd_health(base_url).err();
    let agentpactd_down = check_agentpactd && !agentpactd_reachable();
    match governance_daemons_error(agent_id, kyrisd_problem, agentpactd_down) {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn testHookScriptMarksGovernedSubprocessBeforeShellWork() {
        let script = hook_script_source("codex-cli");
        let marker = r#"export KYRIS_GOVERNED_SUBPROCESS="codex-cli""#;
        let marker_idx = script.find(marker).expect("hook script exports marker");
        let lookup_idx = script
            .find("KYRIS_BIN=\"\"")
            .expect("hook script resolves kyris");
        assert!(
            marker_idx < lookup_idx,
            "hook script must mark itself before shell work so shell governance does not recursively prompt"
        );
    }

    #[test]
    fn testJsonMcpServerUnwrappedDetection() {
        // Wrapped (string + array forms) → not flagged.
        assert!(!json_mcp_server_unwrapped(
            &serde_json::json!({"command": "kyris-mcp"})
        ));
        assert!(!json_mcp_server_unwrapped(
            &serde_json::json!({"command": ["kyris-mcp", "wrap"]})
        ));
        // Unwrapped stdio (added after setup) → flagged.
        assert!(json_mcp_server_unwrapped(
            &serde_json::json!({"command": "npx"})
        ));
        assert!(json_mcp_server_unwrapped(
            &serde_json::json!({"command": ["npx", "-y", "srv"]})
        ));
        // URL/HTTP server (no command) → not flagged.
        assert!(!json_mcp_server_unwrapped(
            &serde_json::json!({"url": "https://example.com/mcp"})
        ));
    }

    #[test]
    fn testTomlMcpServerUnwrappedDetection() {
        let wrapped: toml::Value = toml::from_str("command = \"kyris-mcp\"").unwrap();
        assert!(!toml_mcp_server_unwrapped(&wrapped));
        let unwrapped: toml::Value = toml::from_str("command = \"npx\"").unwrap();
        assert!(toml_mcp_server_unwrapped(&unwrapped));
        let url: toml::Value = toml::from_str("url = \"https://example.com/mcp\"").unwrap();
        assert!(!toml_mcp_server_unwrapped(&url));
    }

    #[test]
    fn testGovernanceDaemonsErrorNoneWhenAllUp() {
        assert!(governance_daemons_error("claude-code", None, false).is_none());
    }

    #[test]
    fn testGovernanceDaemonsErrorFlagsAgentpactdDown() {
        let msg = governance_daemons_error("claude-code", None, true).expect("error");
        assert!(msg.contains("agentpactd unreachable"), "{msg}");
        assert!(msg.contains("UNGOVERNED"), "{msg}");
        assert!(msg.contains("governance is NOT active"), "{msg}");
    }

    #[test]
    fn testGovernanceDaemonsErrorFlagsBothDown() {
        let msg =
            governance_daemons_error("codex-cli", Some("dead".to_string()), true).expect("error");
        // Existing tests assert the "kyrisd unreachable" substring — keep it.
        assert!(msg.contains("kyrisd unreachable"), "{msg}");
        assert!(msg.contains("agentpactd unreachable"), "{msg}");
    }

    #[test]
    fn testAgentpactdReachableFalseForMissingSocket() {
        assert!(!agentpactd_reachable_at(
            "/tmp/kyris-test-nonexistent-agentpact.sock"
        ));
    }

    #[test]
    fn testValidateAgentSettingsRejectsUnknownKey() {
        // opencode advertises no --set settings (no native-ask toggle), so the
        // rejection names the "accepts no settings" branch. (claude/codex/gemini
        // now advertise `approval_prompt`.)
        let agent = registry::agent_by_id("opencode").unwrap();
        let settings = HashMap::from([("max-budget-usd".to_string(), "50".to_string())]);
        let err = validate_agent_settings(agent.as_ref(), &settings).expect_err("should reject");
        assert!(err.contains("Unknown --set key 'max-budget-usd'"), "{err}");
        assert!(err.contains("accepts no --set settings"), "{err}");
    }

    #[test]
    fn testValidateAgentSettingsAcceptsKnownKeyAndListsOnUnknown() {
        let agent = registry::agent_by_id("gemini-cli").unwrap();
        // Known key passes.
        let ok = HashMap::from([("maxSessionTurns".to_string(), "100".to_string())]);
        assert!(validate_agent_settings(agent.as_ref(), &ok).is_ok());
        // Unknown key is rejected and the error lists the valid key(s).
        let bad = HashMap::from([("nope".to_string(), "1".to_string())]);
        let err = validate_agent_settings(agent.as_ref(), &bad).expect_err("should reject");
        assert!(err.contains("Unknown --set key 'nope'"), "{err}");
        assert!(err.contains("maxSessionTurns"), "{err}");
    }

    #[test]
    fn testValidateAgentSettingsEmptyIsOk() {
        let agent = registry::agent_by_id("claude-code").unwrap();
        assert!(validate_agent_settings(agent.as_ref(), &HashMap::new()).is_ok());
    }

    #[test]
    fn testClaudeMcpDeniesAddsPresentServerToolsToPermissionsDeny() {
        // The denies land in settings.json; the present-server list comes from
        // the MCP store files (~/.claude.json / .mcp.json) via the caller.
        let mut settings = serde_json::json!({});
        let filters = HashMap::from([
            (
                "fs".to_string(),
                vec!["write".to_string(), "delete".to_string()],
            ),
            // A server NOT present in any scope must be skipped.
            ("other".to_string(), vec!["x".to_string()]),
        ]);

        assert!(add_mcp_tool_denies(
            &mut settings,
            &filters,
            &["fs".to_string()]
        ));
        let deny: Vec<&str> = settings["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(deny.contains(&"mcp__fs__write"));
        assert!(deny.contains(&"mcp__fs__delete"));
        assert!(!deny.iter().any(|d| d.contains("other")));
    }

    #[test]
    fn testClaudeMcpDeniesIsIdempotentAndPreservesExisting() {
        let mut settings = serde_json::json!({
            "permissions": { "deny": ["Bash(rm *)", "mcp__fs__write"] }
        });
        let filters = HashMap::from([("fs".to_string(), vec!["write".to_string()])]);

        // Already present → no change.
        assert!(!add_mcp_tool_denies(
            &mut settings,
            &filters,
            &["fs".to_string()]
        ));
        let deny = settings["permissions"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 2, "must not duplicate or drop existing entries");
        assert!(deny.iter().any(|v| v == "Bash(rm *)"));
    }

    #[test]
    fn testClaudeMcpDeniesEmptyFiltersNoOp() {
        let mut settings = serde_json::json!({});
        assert!(!add_mcp_tool_denies(
            &mut settings,
            &HashMap::new(),
            &["fs".to_string()]
        ));
        assert!(settings.get("permissions").is_none());
    }

    #[test]
    fn testRewriteCodexMcpServers() {
        let mut config: toml::Value = toml::from_str("[mcp_servers.filesystem]\ncommand = \"npx\"\nargs = [\"-y\", \"server\"]\n\n[mcp_servers.remote]\nurl = \"https://example.com/mcp\"\n")
        .expect("parse");

        let result = rewrite_codex_mcp_servers(
            &mut config,
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "openai/codex-cli",
        );
        assert!(result.changed);
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string()),]
        );

        let servers = config["mcp_servers"].as_table().expect("mcp_servers");
        assert_eq!(servers["filesystem"]["command"].as_str(), Some("kyris-mcp"));
        let args: Vec<&str> = servers["filesystem"]["args"]
            .as_array()
            .expect("args")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect();
        assert_eq!(
            args,
            vec![
                "wrap",
                "--server",
                "filesystem",
                "--agent",
                "openai/codex-cli",
                "npx",
                "-y",
                "server"
            ]
        );
        assert_eq!(
            servers["remote"]["url"].as_str(),
            Some("http://127.0.0.1:4710/mcp/remote/")
        );
        assert_eq!(
            servers["remote"]["http_headers"]["x-kyris-agent-id"].as_str(),
            Some("openai/codex-cli")
        );
    }

    #[test]
    fn testRewriteJsonMcpServersClineNestedTransport() {
        // Cline's `cline mcp add` wizard nests command/args under `transport`
        // (review Finding 15). The rewrite must descend into it — wrapping the
        // top level would miss every wizard-written server.
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "fs": {
                    "transport": {"type": "stdio", "command": "uvx", "args": ["fs-mcp"]}
                },
                "remote": {
                    "transport": {"type": "streamableHttp", "url": "https://example.com/mcp"}
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "cline/cline",
        );
        assert!(result.changed);
        let fs = &config["mcpServers"]["fs"]["transport"];
        assert_eq!(fs["command"], "kyris-mcp");
        assert_eq!(fs["type"], "stdio", "transport type preserved");
        assert_eq!(
            fs["args"],
            serde_json::json!([
                "wrap",
                "--server",
                "fs",
                "--agent",
                "cline/cline",
                "uvx",
                "fs-mcp"
            ])
        );
        let remote = &config["mcpServers"]["remote"]["transport"];
        assert_eq!(remote["url"], "http://127.0.0.1:4710/mcp/remote/");
        assert_eq!(remote["headers"]["x-kyris-agent-id"], "cline/cline");
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string())]
        );

        // Drift/routed detectors see the nested form too.
        assert!(!super::json_mcp_server_unwrapped(
            &config["mcpServers"]["fs"]
        ));

        // Idempotent: a second pass on the now-wrapped nested servers is a
        // no-op (the --agent flag is already present in transport.args).
        let again = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "cline/cline",
        );
        assert!(!again.changed, "re-wrap of a nested server must be a no-op");
    }

    #[test]
    fn testRewriteJsonMcpServers() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "server"]
                },
                "remote": {
                    "url": "https://example.com/mcp"
                }
            }
        });

        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "anthropic/claude-code",
        );
        assert!(result.changed);
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string()),]
        );

        let servers = config["mcpServers"].as_object().expect("mcpServers");
        assert_eq!(servers["filesystem"]["command"], "kyris-mcp");
        assert_eq!(
            servers["filesystem"]["args"],
            serde_json::json!([
                "wrap",
                "--server",
                "filesystem",
                "--agent",
                "anthropic/claude-code",
                "npx",
                "-y",
                "server"
            ])
        );
        assert_eq!(
            servers["remote"]["url"],
            "http://127.0.0.1:4710/mcp/remote/"
        );
        assert_eq!(
            servers["remote"]["headers"]["Authorization"],
            "Bearer sk-kyris-test"
        );
        assert_eq!(
            servers["remote"]["headers"]["x-kyris-agent-id"],
            "anthropic/claude-code"
        );
    }

    #[test]
    fn testRewriteJsonMcpServersArrayCommand() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcp": {
                "filesystem": {
                    "command": ["npx", "-y", "my-mcp-server"]
                }
            }
        });

        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcp".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "opencode/opencode",
        );
        assert!(result.changed);
        assert!(result.http_rewrites.is_empty());

        let cmd = config["mcp"]["filesystem"]["command"]
            .as_array()
            .expect("command is array");
        assert_eq!(cmd[0], "kyris-mcp");
        assert_eq!(cmd[1], "wrap");
        assert_eq!(cmd[2], "--server");
        assert_eq!(cmd[3], "filesystem");
        assert_eq!(cmd[4], "--agent");
        assert_eq!(cmd[5], "opencode/opencode");
        assert_eq!(cmd[6], "npx");
        assert_eq!(cmd[7], "-y");
        assert_eq!(cmd[8], "my-mcp-server");
    }

    #[test]
    fn testRewriteJsonMcpServersArrayCommandAlreadyWrapped() {
        // Fully current wrap (has --agent) → untouched. A pre-upgrade wrap
        // (no --agent) → upgraded in place, nothing else rewritten.
        let mut config: serde_json::Value = serde_json::json!({
            "mcp": {
                "current": {
                    "command": ["kyris-mcp", "wrap", "--server", "current",
                                "--agent", "opencode/opencode", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcp".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "opencode/opencode",
        );
        assert!(!result.changed);

        let mut legacy: serde_json::Value = serde_json::json!({
            "mcp": {
                "legacy": {
                    "command": ["kyris-mcp", "wrap", "--server", "legacy", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut legacy,
            &["mcp".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "opencode/opencode",
        );
        assert!(result.changed, "pre-upgrade wrap gains the --agent flag");
        assert_eq!(
            legacy["mcp"]["legacy"]["command"],
            serde_json::json!([
                "kyris-mcp",
                "wrap",
                "--server",
                "legacy",
                "--agent",
                "opencode/opencode",
                "npx"
            ])
        );
    }

    #[test]
    fn testRewriteJsonMcpServersSkipsAlreadyWrapped() {
        // Fully current wrap → no change; pre-upgrade wrap → only the
        // --agent flag is added (never re-wrapped).
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "wrapped": {
                    "command": "kyris-mcp",
                    "args": ["wrap", "--server", "wrapped",
                             "--agent", "anthropic/claude-code", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "anthropic/claude-code",
        );
        assert!(!result.changed);
        assert!(result.http_rewrites.is_empty());

        let mut legacy: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "wrapped": {
                    "command": "kyris-mcp",
                    "args": ["wrap", "--server", "wrapped", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut legacy,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "anthropic/claude-code",
        );
        assert!(result.changed);
        assert_eq!(
            legacy["mcpServers"]["wrapped"]["args"],
            serde_json::json!([
                "wrap",
                "--server",
                "wrapped",
                "--agent",
                "anthropic/claude-code",
                "npx"
            ])
        );
    }

    #[test]
    fn testRewriteCodexMcpServersIdempotent() {
        let mut config: toml::Value = toml::from_str(
            "[mcp_servers.remote]\nurl = \"http://127.0.0.1:4710/mcp/remote/\"\n\n[mcp_servers.remote.http_headers]\nAuthorization = \"Bearer sk-kyris-test\"\n\"x-kyris-agent-id\" = \"openai/codex-cli\"\n"
        ).expect("parse");

        let result = rewrite_codex_mcp_servers(
            &mut config,
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "openai/codex-cli",
        );
        assert!(!result.changed);
        assert!(result.http_rewrites.is_empty());
    }
}
