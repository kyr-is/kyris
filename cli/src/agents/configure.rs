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

/// Full setup: prestage + configure, with burn-control rollback on kyrisd failure.
///
/// Execution-surface changes (hooks, adapters, compiled policy) are committed
/// unconditionally — they only need agentpactd. Burn-control changes (env files
/// with base URLs/API keys, MCP URL rewrites) are rolled back if kyrisd is
/// unreachable, since those config rewrites route traffic through kyrisd.
pub fn setup_agent(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    let mut changes = super::prestage::prestage_agent(agent_id)?;

    if agent.is_installed() {
        // PATH shim must exist before we declare success: it is what arms
        // the shell hook inside agent-spawned shells. Skipped for
        // not-yet-installed agents — reconcile will create it when the
        // agent appears, to avoid shadowing a `<binary>: command not
        // found` message with our own.
        changes.extend(super::shim::install_shim(agent_id)?);
        changes.extend(agent.configure_execution(&base_url, inbound_key, agent_specific)?);
        changes.extend(agent.configure_burn_control(&base_url, inbound_key, agent_specific)?);

        if let Err(error) = verify_kyrisd_health(&base_url) {
            return Err(format!(
                "kyrisd unreachable ({error}). \
                 Bring kyrisd up (try `launchctl kickstart gui/$UID/is.kyr.kyrisd` or reinstall), then re-run `kyris agents setup {agent_id}`."
            ));
        }
    } else if let Err(error) = verify_kyrisd_health(&base_url) {
        return Err(format!(
            "kyrisd unreachable ({error}). \
             Bring kyrisd up (try `launchctl kickstart gui/$UID/is.kyr.kyrisd` or reinstall), then re-run `kyris agents setup {agent_id}`."
        ));
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
/// When `skip_burn_control` is true, only execution-surface configuration
/// runs. Used after native promotion removes burn-control artifacts.
pub fn configure_agent(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
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

    let mut changes = super::shim::install_shim(agent_id)?;
    changes.extend(agent.configure_execution(&base_url, inbound_key, agent_specific)?);

    if !skip_burn_control {
        changes.extend(agent.configure_burn_control(&base_url, inbound_key, agent_specific)?);

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
/// Called at the START of each agent's `undo()` / `undo_burn_control()`,
/// before `restore_manifest_entry` restores the file to its pre-kyris state,
/// so we can identify which upstream entries to remove from `kyrisd.yaml`.
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

/// Remove named MCP upstream entries from `kyrisd.yaml`.
///
/// Called during agent `undo()` to reverse the `upsert_mcp_upstreams` call
/// that happened during `configure_burn_control`. Server names not present in
/// `kyrisd.yaml` are silently skipped (idempotent).
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

#[cfg(test)]
mod tests {
    use super::*;

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
