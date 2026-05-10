// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;
use std::path::PathBuf;

use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{
    ensure_json_command_hook, read_json_value, set_json_string_path, write_json_value,
};
use crate::state::{
    discard_manifest_entry, ensure_parent, env_dir, load_manifest, load_or_init_config,
    write_managed_file,
};

use super::registry;

pub(super) fn hook_script_source(agent_id: &str) -> String {
    format!(
        "#!/usr/bin/env bash\n\
         # SPDX-FileCopyrightText: Copyright 2026 Kyris\n\
         # SPDX-License-Identifier: Apache-2.0\n\
         set -euo pipefail\n\n\
         \"$HOME/.kyris/bin/kyris\" hook check --agent {agent_id}\n"
    )
}

pub(super) fn shell_command(path: &std::path::Path) -> String {
    format!("bash \"{}\"", path.display())
}

pub(super) fn install_live_hook_adapter(
    agent_id: &str,
    component: &str,
    hook_phase: &str,
    script_path: &std::path::Path,
    hooks_file_path: &std::path::Path,
    nested: bool,
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
    if ensure_json_command_hook(&mut hooks, hook_phase, &shell_command(script_path), nested) {
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

    let env_tx =
        SetupTransaction::capture_paths(burn_control_env_paths(agent_id, &base_url, inbound_key)?)?;

    let mut changes = super::prestage::prestage_agent(agent_id)?;

    if agent.is_installed() {
        changes.extend(agent.configure_execution(&base_url, inbound_key, agent_specific)?);

        let config_tx = SetupTransaction::capture_paths(agent.burn_control_config_paths())?;

        changes.extend(agent.configure_burn_control(&base_url, inbound_key, agent_specific)?);

        if let Err(error) = verify_kyrisd_health(&base_url) {
            let mut rollback_errors = Vec::new();
            if let Err(e) = config_tx.rollback() {
                rollback_errors.push(e);
            }
            if let Err(e) = env_tx.rollback() {
                rollback_errors.push(e);
            }
            if !rollback_errors.is_empty() {
                return Err(format!(
                    "kyrisd unreachable for {agent_id}: {error}. \
                     Burn-control rollback also failed: {}",
                    rollback_errors.join("; ")
                ));
            }
            clear_disabled_flag(agent_id)?;
            return Err(format!(
                "kyrisd unreachable ({error}). \
                 Execution-surface governance is active (hooks/adapters committed). \
                 Burn-control and MCP routing rolled back — will apply when kyrisd starts."
            ));
        }
    } else if let Err(error) = verify_kyrisd_health(&base_url) {
        if let Err(rollback_error) = env_tx.rollback() {
            return Err(format!(
                "kyrisd unreachable for {agent_id}: {error}. \
                 Burn-control rollback also failed: {rollback_error}"
            ));
        }
        clear_disabled_flag(agent_id)?;
        return Err(format!(
            "kyrisd unreachable ({error}). \
             Burn-control rolled back — will apply when kyrisd starts."
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
/// Prestage must have already run. Burn-control changes are rolled back if
/// kyrisd health check fails, same as `setup_agent`.
///
/// When `skip_burn_control` is true, only execution-surface configuration
/// runs. Used after native promotion removes burn-control artifacts.
pub fn configure_agent(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
    skip_burn_control: bool,
) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    if !agent.is_installed() {
        return Err(format!("{agent_id} is not installed."));
    }

    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    let mut changes = agent.configure_execution(&base_url, inbound_key, agent_specific)?;

    if !skip_burn_control {
        let config_tx = SetupTransaction::capture_paths(agent.burn_control_config_paths())?;

        changes.extend(agent.configure_burn_control(&base_url, inbound_key, agent_specific)?);

        if let Err(error) = verify_kyrisd_health(&base_url) {
            if let Err(rollback_error) = config_tx.rollback() {
                return Err(format!(
                    "kyrisd unreachable for {agent_id}: {error}. \
                     Burn-control rollback also failed: {rollback_error}"
                ));
            }
            return Err(format!(
                "kyrisd unreachable ({error}). \
                 Burn-control and MCP routing rolled back."
            ));
        }
    }

    if changes.is_empty() {
        println!("No changes needed for {agent_id}.");
    } else {
        println!("Configured {agent_id}:");
        for change in &changes {
            println!("  {change}");
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

/// Env files and shell RC files that redirect LLM traffic through kyrisd.
/// Snapshotted before prestage runs, rolled back if kyrisd is unreachable.
fn burn_control_env_paths(
    agent_id: &str,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<PathBuf>, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let home = PathBuf::from(home);
    let mut paths = Vec::new();

    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    let exports = agent.env_exports(base_url, inbound_key);

    if !exports.is_empty() {
        paths.push(env_dir()?.join("load.sh"));
        paths.push(env_dir()?.join(format!("{agent_id}.sh")));
        paths.push(home.join(".zshrc"));
        paths.push(home.join(".bashrc"));
    }

    Ok(paths)
}

#[derive(Debug)]
struct FileSnapshot {
    path: PathBuf,
    original_contents: Option<Vec<u8>>,
    had_manifest_entry: bool,
}

struct SetupTransaction {
    snapshots: Vec<FileSnapshot>,
}

impl SetupTransaction {
    fn capture_paths(paths: Vec<PathBuf>) -> Result<Self, String> {
        let manifest_paths: HashSet<String> = load_manifest()?
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        let mut seen = HashSet::new();
        let mut snapshots = Vec::new();

        for path in paths {
            let key = path.to_string_lossy().to_string();
            if !seen.insert(key.clone()) {
                continue;
            }
            let original_contents = if path.exists() {
                Some(
                    std::fs::read(&path)
                        .map_err(|e| format!("Cannot snapshot {}: {e}", path.display()))?,
                )
            } else {
                None
            };
            snapshots.push(FileSnapshot {
                path,
                original_contents,
                had_manifest_entry: manifest_paths.contains(&key),
            });
        }

        Ok(Self { snapshots })
    }

    fn rollback(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        for snapshot in self.snapshots.iter().rev() {
            if let Err(error) = restore_snapshot(snapshot) {
                errors.push(error);
            }
            if !snapshot.had_manifest_entry
                && let Err(error) = discard_manifest_entry(&snapshot.path)
            {
                errors.push(error);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn restore_snapshot(snapshot: &FileSnapshot) -> Result<(), String> {
    match &snapshot.original_contents {
        Some(contents) => {
            ensure_parent(&snapshot.path)?;
            std::fs::write(&snapshot.path, contents)
                .map_err(|e| format!("Cannot restore {}: {e}", snapshot.path.display()))?;
        }
        None => {
            if snapshot.path.exists() {
                std::fs::remove_file(&snapshot.path)
                    .map_err(|e| format!("Cannot remove {}: {e}", snapshot.path.display()))?;
            }
        }
    }
    Ok(())
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
    fn testRestoreSnapshotRestoresOriginal() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let path = temp_dir.path().join("settings.json");
        std::fs::write(&path, "after").expect("write");

        let snapshot = FileSnapshot {
            path: path.clone(),
            original_contents: Some(b"before".to_vec()),
            had_manifest_entry: false,
        };

        restore_snapshot(&snapshot).expect("restore");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "before");
    }

    #[test]
    fn testRestoreSnapshotRemovesCreatedFile() {
        let temp_dir = tempfile::TempDir::new().expect("tempdir");
        let path = temp_dir.path().join("settings.json");
        std::fs::write(&path, "created").expect("write");

        let snapshot = FileSnapshot {
            path: path.clone(),
            original_contents: None,
            had_manifest_entry: false,
        };

        restore_snapshot(&snapshot).expect("restore");
        assert!(!path.exists());
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
