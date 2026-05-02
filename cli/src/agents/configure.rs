// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;
use std::path::PathBuf;

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
         kyris-hook check-hook --agent {agent_id}\n"
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
) -> Result<Vec<String>, String> {
    let script_source = hook_script_source(agent_id);
    let mut changes = Vec::new();

    if write_managed_file(script_path, &script_source, component, Some(0o755))? {
        changes.push(format!("wrote {}", script_path.display()));
    }

    let mut hooks = read_json_value(hooks_file_path)?;
    if ensure_json_command_hook(&mut hooks, hook_phase, &shell_command(script_path)) {
        write_json_value(hooks_file_path, &hooks, component)?;
        changes.push(format!("updated {}", hooks_file_path.display()));
    }

    Ok(changes)
}

/// Full setup: prestage + configure in a single transaction with health check.
/// Used by the explicit `kyris agents setup <agent>` CLI path.
pub fn setup_agent(agent_id: &str) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    let config = load_or_init_config()?;
    let listen = &config.server.listen;
    let inbound_key = &config.server.inbound_key;

    let transaction = SetupTransaction::capture(agent_id, listen, inbound_key)?;

    let mut changes = super::prestage::prestage_agent(agent_id)?;

    if agent.is_installed() {
        changes.extend(agent.configure(listen, inbound_key)?);

        if let Err(error) = verify_kyrisd_health(listen) {
            if let Err(rollback_error) = transaction.rollback() {
                return Err(format!(
                    "Setup verification failed for {agent_id}: {error}. Rollback also failed: {rollback_error}"
                ));
            }
            return Err(format!(
                "Setup verification failed for {agent_id}: {error}. Rolled back."
            ));
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
/// Prestage must have already run.
pub fn configure_agent(agent_id: &str) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    if !agent.is_installed() {
        return Err(format!("{agent_id} is not installed."));
    }

    let config = load_or_init_config()?;
    let listen = &config.server.listen;
    let inbound_key = &config.server.inbound_key;

    let changes = agent.configure(listen, inbound_key)?;

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
        write_json_value(config_path, &config, component)?;
        changes.push(format!("updated {}", config_path.display()));
    }
    Ok(changes)
}

pub fn rewrite_codex_mcp_servers(
    config: &mut toml::Value,
    listen: &str,
    inbound_key: &str,
) -> bool {
    let Some(root) = config.as_table_mut() else {
        return false;
    };
    let Some(servers) = root
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
    else {
        return false;
    };

    let mut changed = false;
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
            let routed_url = format!("http://{listen}/mcp/{name}/");
            if url != routed_url {
                server.insert("url".to_string(), toml::Value::String(routed_url));
                changed = true;
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

    changed
}

pub fn rewrite_json_mcp_servers(
    config: &mut serde_json::Value,
    servers_path: &[&str],
    listen: &str,
    inbound_key: &str,
) -> bool {
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

        if let Some(url) = server.get("url").and_then(|v| v.as_str()).map(String::from) {
            let routed_url = format!("http://{listen}/mcp/{name}/");
            if url != routed_url {
                server.insert("url".to_string(), serde_json::json!(routed_url));
                changed = true;
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

    changed
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

fn verify_kyrisd_health(listen: &str) -> Result<(), String> {
    let url = format!("http://{listen}/healthz");
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

fn setup_paths_for_agent(
    agent_id: &str,
    listen: &str,
    inbound_key: &str,
) -> Result<Vec<PathBuf>, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let home = PathBuf::from(home);
    let mut paths = Vec::new();

    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    let exports = agent.env_exports(listen, inbound_key);

    if !exports.is_empty() {
        paths.push(env_dir()?.join("load.sh"));
        paths.push(env_dir()?.join(format!("{agent_id}.sh")));
        paths.push(home.join(".zshrc"));
        paths.push(home.join(".bashrc"));
    }

    paths.extend(agent.managed_paths());

    if agent.hook_protocol().is_some() {
        let protocol_path = crate::state::kyris_home()?
            .join("agents")
            .join(agent_id)
            .join("hook-protocol.json");
        paths.push(protocol_path);
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
    fn capture(agent_id: &str, listen: &str, inbound_key: &str) -> Result<Self, String> {
        let manifest_paths: HashSet<String> = load_manifest()?
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        let mut seen = HashSet::new();
        let mut snapshots = Vec::new();

        for path in setup_paths_for_agent(agent_id, listen, inbound_key)? {
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

        assert!(rewrite_codex_mcp_servers(
            &mut config,
            "127.0.0.1:4710",
            "sk-kyris-test"
        ));

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

        assert!(rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers"],
            "127.0.0.1:4710",
            "sk-kyris-test"
        ));

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
    fn testRewriteJsonMcpServersSkipsAlreadyWrapped() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "wrapped": {
                    "command": "kyris-mcp",
                    "args": ["wrap", "--server", "wrapped", "npx"]
                }
            }
        });

        assert!(!rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers"],
            "127.0.0.1:4710",
            "sk-kyris-test"
        ));
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
}
