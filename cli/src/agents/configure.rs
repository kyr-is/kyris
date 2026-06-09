// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{
    ensure_json_command_hook, read_json_value, set_json_string_path, write_json_value,
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
    hook_phase: &str,
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
    if ensure_json_command_hook(
        &mut hooks,
        hook_phase,
        &shell_command(script_path),
        nested,
        hook_timeout,
    ) {
        // Hooks file format varies per agent (claude/cline/codex/gemini have
        // different shapes); well-formedness is the safe baseline. Per-agent
        // shape validators can be added incrementally.
        write_json_value(hooks_file_path, &hooks, component, &WellFormedJsonValidator)?;
        changes.push(format!("updated {}", hooks_file_path.display()));
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

pub(super) fn apply_json_config_rewrites(
    config_path: &std::path::Path,
    rewrites: &[(&[&str], &str)],
    component: &str,
) -> Result<Vec<String>, String> {
    let mut config = read_json_value(config_path)?;
    let mut config_changed = false;
    for (path, value) in rewrites {
        if set_json_string_path(&mut config, path, value) {
            config_changed = true;
        }
    }
    let mut changes = Vec::new();
    if config_changed {
        write_json_value(config_path, &config, component, &WellFormedJsonValidator)?;
        changes.push(format!("updated {}", config_path.display()));
    }
    Ok(changes)
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

/// Collect the MCP server names currently registered in an agent's config.
///
/// Called at the start of tool-surface undo, before `restore_manifest_entry`
/// restores the file to its pre-kyris state, so we can identify which upstream
/// entries to remove from `kyrisd.yaml`.
pub fn mcp_server_names_from_agent(agent: &dyn super::registry::AgentDescriptor) -> Vec<String> {
    let Some(mcp_cfg) = agent.mcp_config() else {
        return Vec::new();
    };
    match mcp_cfg.format {
        super::registry::McpConfigFormat::Json { servers_path } => {
            let Ok(val) = crate::integration::read_json_value(&mcp_cfg.path) else {
                return Vec::new();
            };
            let mut cur = &val;
            for key in &servers_path {
                match cur.get(key) {
                    Some(v) => cur = v,
                    None => return Vec::new(),
                }
            }
            cur.as_object()
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default()
        }
        super::registry::McpConfigFormat::Toml { servers_key } => {
            let Ok(val) = crate::integration::read_toml_value(&mcp_cfg.path) else {
                return Vec::new();
            };
            val.get(servers_key)
                .and_then(|v| v.as_table())
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default()
        }
    }
}

/// Names of MCP servers in the agent's config that are NOT yet routed through
/// kyris — a stdio server whose `command` isn't `kyris-mcp`. Surfaces config
/// drift (e.g. an MCP server added *after* `kyris agents setup`, which the
/// configure-time rewrite never saw) so `kyris status` can prompt a reconcile.
/// URL/HTTP servers are out of scope here.
pub fn unwrapped_mcp_server_names(agent: &dyn super::registry::AgentDescriptor) -> Vec<String> {
    let Some(mcp_cfg) = agent.mcp_config() else {
        return Vec::new();
    };
    let mut names: Vec<String> = match mcp_cfg.format {
        super::registry::McpConfigFormat::Json { servers_path } => {
            let Ok(val) = crate::integration::read_json_value(&mcp_cfg.path) else {
                return Vec::new();
            };
            let mut cur = &val;
            for key in &servers_path {
                match cur.get(key) {
                    Some(v) => cur = v,
                    None => return Vec::new(),
                }
            }
            cur.as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(_, server)| json_mcp_server_unwrapped(server))
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
        super::registry::McpConfigFormat::Toml { servers_key } => {
            let Ok(val) = crate::integration::read_toml_value(&mcp_cfg.path) else {
                return Vec::new();
            };
            val.get(servers_key)
                .and_then(toml::Value::as_table)
                .map(|t| {
                    t.iter()
                        .filter(|(_, server)| toml_mcp_server_unwrapped(server))
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
    };
    names.sort();
    names
}

/// A stdio MCP server is "unwrapped" when it has a `command` that isn't
/// `kyris-mcp` (string form or array-first form). Servers with no `command`
/// (URL/HTTP) are not flagged.
fn json_mcp_server_unwrapped(server: &serde_json::Value) -> bool {
    match server.get("command") {
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

/// Shared configure flow for agents whose MCP servers live in a JSON config
/// (claude, gemini, cline, opencode): route every MCP server through kyris
/// (`rewrite_json_mcp_servers`), apply the agent's optional extra tool filter
/// (`apply_extra_tool_filters`), write back only if something changed, and
/// register any HTTP upstreams. Codex (TOML) keeps its own `configure_tool_surface`.
/// `read_json_value` returns `{}` for a missing file, so a not-yet-created config
/// is a clean no-op (no write).
pub fn configure_json_mcp_tool_surface(
    agent: &dyn super::registry::AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let Some(mcp_cfg) = agent.mcp_config() else {
        return Ok(Vec::new());
    };
    let super::registry::McpConfigFormat::Json { servers_path } = mcp_cfg.format else {
        return Ok(Vec::new());
    };
    let path = mcp_cfg.path;
    let component = format!("{}:tool", agent.id());

    let mut settings = read_json_value(&path)?;
    let mcp_result = rewrite_json_mcp_servers(&mut settings, &servers_path, base_url, inbound_key);
    let extra_changed = agent.apply_extra_tool_filters(&mut settings);

    let mut changes = Vec::new();
    if mcp_result.changed || extra_changed {
        write_json_value(&path, &settings, &component, &WellFormedJsonValidator)?;
        if mcp_result.changed {
            changes.push(format!("rewrote MCP servers in {}", path.display()));
        }
        if extra_changed {
            changes.push(format!("applied MCP tool policy in {}", path.display()));
        }
    }
    if !mcp_result.http_rewrites.is_empty() {
        upsert_mcp_upstreams(&mcp_result.http_rewrites)?;
        changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
    }
    Ok(changes)
}

/// Shared tool-surface undo for JSON-MCP agents: remove the MCP upstreams from
/// `kyrisd.yaml` (while the server names are still readable from the agent
/// config) then restore the agent config to its pre-kyris state.
pub fn undo_json_mcp_tool_surface(
    agent: &dyn super::registry::AgentDescriptor,
) -> Result<(), String> {
    let mcp_names = mcp_server_names_from_agent(agent);
    remove_mcp_upstreams(&mcp_names)?;
    if let Some(mcp_cfg) = agent.mcp_config() {
        let component = format!("{}:tool", agent.id());
        if crate::state::restore_manifest_entry_component(&mcp_cfg.path, &component)? {
            println!("Reverted {}", mcp_cfg.path.display());
        }
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

pub fn rewrite_codex_mcp_servers(
    config: &mut toml::Value,
    base_url: &str,
    inbound_key: &str,
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
            if headers_table
                .get("Authorization")
                .and_then(toml::Value::as_str)
                != Some(auth_value.as_str())
            {
                headers_table.insert("Authorization".to_string(), toml::Value::String(auth_value));
                changed = true;
            }
        }
    }

    McpRewriteResult {
        changed,
        http_rewrites,
    }
}

pub fn rewrite_json_mcp_servers(
    config: &mut serde_json::Value,
    servers_path: &[&str],
    base_url: &str,
    inbound_key: &str,
) -> McpRewriteResult {
    let mut cursor = config.as_object_mut();
    for key in servers_path {
        cursor = cursor
            .and_then(|obj| obj.get_mut(*key))
            .and_then(|v| v.as_object_mut());
    }
    let Some(servers) = cursor else {
        return McpRewriteResult::unchanged();
    };

    let mut changed = false;
    let mut http_rewrites = Vec::new();
    for (name, server_value) in servers.iter_mut() {
        let Some(server) = server_value.as_object_mut() else {
            continue;
        };

        if let Some(command) = server
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if command == "kyris-mcp" {
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
                continue;
            }

            let mut wrapped = vec![
                serde_json::json!("kyris-mcp"),
                serde_json::json!("wrap"),
                serde_json::json!("--server"),
                serde_json::json!(name),
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
            if headers_obj.get("Authorization").and_then(|v| v.as_str())
                != Some(auth_value.as_str())
            {
                headers_obj.insert("Authorization".to_string(), serde_json::json!(auth_value));
                changed = true;
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
/// server present in this config (matching the gemini/codex behavior of only
/// touching servers that exist). Idempotent: existing entries are preserved and
/// duplicates are not added. Returns whether `settings` changed.
pub(super) fn apply_claude_mcp_tool_denies(settings: &mut serde_json::Value) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    add_mcp_tool_denies(settings, &filters)
}

/// Pure core of [`apply_claude_mcp_tool_denies`], split out so it can be tested
/// with synthetic filters (the public entry reads the policy from disk).
fn add_mcp_tool_denies(
    settings: &mut serde_json::Value,
    filters: &std::collections::HashMap<String, Vec<String>>,
) -> bool {
    if filters.is_empty() {
        return false;
    }

    let present: std::collections::BTreeSet<String> = settings
        .get("mcpServers")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let mut wanted: Vec<String> = Vec::new();
    for (server, tools) in filters {
        if present.contains(server) {
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
        let agent = registry::agent_by_id("claude-code").unwrap();
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
        let mut settings = serde_json::json!({
            "mcpServers": { "fs": { "command": "kyris-mcp" } }
        });
        let filters = HashMap::from([
            (
                "fs".to_string(),
                vec!["write".to_string(), "delete".to_string()],
            ),
            // A server NOT present in this config must be skipped.
            ("other".to_string(), vec!["x".to_string()]),
        ]);

        assert!(add_mcp_tool_denies(&mut settings, &filters));
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
            "mcpServers": { "fs": {} },
            "permissions": { "deny": ["Bash(rm *)", "mcp__fs__write"] }
        });
        let filters = HashMap::from([("fs".to_string(), vec!["write".to_string()])]);

        // Already present → no change.
        assert!(!add_mcp_tool_denies(&mut settings, &filters));
        let deny = settings["permissions"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 2, "must not duplicate or drop existing entries");
        assert!(deny.iter().any(|v| v == "Bash(rm *)"));
    }

    #[test]
    fn testClaudeMcpDeniesEmptyFiltersNoOp() {
        let mut settings = serde_json::json!({ "mcpServers": { "fs": {} } });
        assert!(!add_mcp_tool_denies(&mut settings, &HashMap::new()));
        assert!(settings.get("permissions").is_none());
    }

    #[test]
    fn testRewriteCodexMcpServers() {
        let mut config: toml::Value = toml::from_str("[mcp_servers.filesystem]\ncommand = \"npx\"\nargs = [\"-y\", \"server\"]\n\n[mcp_servers.remote]\nurl = \"https://example.com/mcp\"\n")
        .expect("parse");

        let result =
            rewrite_codex_mcp_servers(&mut config, "http://127.0.0.1:4710", "sk-kyris-test");
        assert!(result.changed);
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string()),]
        );

        let servers = config["mcp_servers"].as_table().expect("mcp_servers");
        assert_eq!(servers["filesystem"]["command"].as_str(), Some("kyris-mcp"));
        assert_eq!(
            servers["remote"]["url"].as_str(),
            Some("http://127.0.0.1:4710/mcp/remote/")
        );
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
            &["mcpServers"],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
        );
        assert!(result.changed);
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string()),]
        );

        let servers = config["mcpServers"].as_object().expect("mcpServers");
        assert_eq!(servers["filesystem"]["command"], "kyris-mcp");
        assert_eq!(
            servers["remote"]["url"],
            "http://127.0.0.1:4710/mcp/remote/"
        );
        assert_eq!(
            servers["remote"]["headers"]["Authorization"],
            "Bearer sk-kyris-test"
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
            &["mcp"],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
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
        assert_eq!(cmd[4], "npx");
        assert_eq!(cmd[5], "-y");
        assert_eq!(cmd[6], "my-mcp-server");
    }

    #[test]
    fn testRewriteJsonMcpServersArrayCommandAlreadyWrapped() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcp": {
                "filesystem": {
                    "command": ["kyris-mcp", "wrap", "--server", "filesystem", "npx"]
                }
            }
        });

        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcp"],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
        );
        assert!(!result.changed);
    }

    #[test]
    fn testRewriteJsonMcpServersSkipsAlreadyWrapped() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "wrapped": {
                    "command": "kyris-mcp",
                    "args": ["wrap", "--server", "wrapped", "npx"]
                }
            }
        });

        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers"],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
        );
        assert!(!result.changed);
        assert!(result.http_rewrites.is_empty());
    }

    #[test]
    fn testRewriteCodexMcpServersIdempotent() {
        let mut config: toml::Value = toml::from_str(
            "[mcp_servers.remote]\nurl = \"http://127.0.0.1:4710/mcp/remote/\"\n\n[mcp_servers.remote.http_headers]\nAuthorization = \"Bearer sk-kyris-test\"\n"
        ).expect("parse");

        let result =
            rewrite_codex_mcp_servers(&mut config, "http://127.0.0.1:4710", "sk-kyris-test");
        assert!(!result.changed);
        assert!(result.http_rewrites.is_empty());
    }
}
