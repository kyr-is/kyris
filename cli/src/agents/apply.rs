// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;
use std::path::PathBuf;

use crate::integration::{
    cline_settings_path, codex_config_path, opencode_config_path, read_json_value, read_toml_value,
    set_json_string_path, write_json_value, write_toml_value,
};
use crate::state::{
    discard_manifest_entry, ensure_line, ensure_parent, env_dir, load_manifest,
    load_or_init_config, write_managed_file,
};

use super::registry::{self, AgentDescriptor};

const ENV_LOADER_SOURCE: &str = r#"# SPDX-License-Identifier: Apache-2.0
for file in "$HOME/.kyris/env/"*.sh; do
    [ -f "$file" ] || continue
    [ "$file" = "$HOME/.kyris/env/load.sh" ] && continue
    . "$file"
done
"#;

#[derive(Debug)]
struct FileSnapshot {
    path: PathBuf,
    original_contents: Option<Vec<u8>>,
    had_manifest_entry: bool,
}

struct SetupTransaction {
    snapshots: Vec<FileSnapshot>,
}

pub fn apply_agent(agent_id: &str) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    if !agent.is_installed() {
        return Err(format!("{agent_id} is not installed."));
    }

    let config = load_or_init_config()?;
    let listen = &config.server.listen;
    let inbound_key = &config.server.inbound_key;

    let transaction = SetupTransaction::capture(agent_id, listen, inbound_key)?;
    let changes = match agent_id {
        "claude-code" | "gemini-cli" => apply_env_agent(agent.as_ref(), listen, inbound_key)?,
        "codex-cli" => apply_codex(listen, inbound_key)?,
        "opencode" => apply_opencode(listen, inbound_key)?,
        "cline" => apply_cline(listen, inbound_key)?,
        _ => return Err(format!("Unsupported agent: {agent_id}")),
    };

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

    if changes.is_empty() {
        println!("No changes needed for {agent_id}.");
    } else {
        println!("Applied setup for {agent_id}:");
        for change in &changes {
            println!("  {change}");
        }
    }

    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub fn apply_all() -> Result<(), String> {
    println!("Detecting installed agents...");
    for agent in registry::all_agents() {
        if agent.is_installed() {
            println!("\nFound {}, configuring...", agent.id());
            if let Err(error) = apply_agent(agent.id()) {
                eprintln!("{error}");
            }
        }
    }
    Ok(())
}

fn exports_to_shell(exports: &[(String, String)]) -> String {
    let mut contents = String::from("# SPDX-License-Identifier: Apache-2.0\n");
    for (key, value) in exports {
        contents.push_str("export ");
        contents.push_str(key);
        contents.push('=');
        contents.push_str(value);
        contents.push('\n');
    }
    contents
}

fn apply_env_agent(
    agent: &dyn AgentDescriptor,
    listen: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let env_file = env_dir()?.join(format!("{}.sh", agent.id()));
    let loader_path = env_dir()?.join("load.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let exports = agent.env_exports(listen, inbound_key);
    let mut changes = Vec::new();

    if write_managed_file(&loader_path, ENV_LOADER_SOURCE, "agents", Some(0o600))? {
        changes.push(format!("wrote {}", loader_path.display()));
    }
    if write_managed_file(
        &env_file,
        &exports_to_shell(&exports),
        "agents",
        Some(0o600),
    )? {
        changes.push(format!("wrote {}", env_file.display()));
    }

    for (path, label) in [
        (PathBuf::from(&home).join(".zshrc"), "~/.zshrc"),
        (PathBuf::from(&home).join(".bashrc"), "~/.bashrc"),
    ] {
        if ensure_line(&path, "source \"$HOME/.kyris/env/load.sh\"", "agents")? {
            changes.push(format!("updated {label}"));
        }
    }

    Ok(changes)
}

fn apply_codex(listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
    let agent = registry::CodexCli;
    let mut changes = apply_env_agent(&agent, listen, inbound_key)?;
    let config_path = codex_config_path()?;
    let mut config = read_toml_value(&config_path)?;
    if rewrite_codex_mcp_servers(&mut config, listen, inbound_key) {
        write_toml_value(&config_path, &config, "agents")?;
        changes.push(format!("updated {}", config_path.display()));
    }
    Ok(changes)
}

fn apply_opencode(listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
    let agent = registry::OpenCode;
    let mut changes = apply_env_agent(&agent, listen, inbound_key)?;
    let path = opencode_config_path()?;
    let mut config = read_json_value(&path)?;
    let mut config_changed = false;
    if set_json_string_path(
        &mut config,
        &["provider", "anthropic", "options", "baseURL"],
        &format!("http://{listen}"),
    ) {
        config_changed = true;
    }
    if set_json_string_path(
        &mut config,
        &["provider", "anthropic", "options", "apiKey"],
        inbound_key,
    ) {
        config_changed = true;
    }
    if config_changed {
        write_json_value(&path, &config, "agents")?;
        changes.push(format!("updated {}", path.display()));
    }
    Ok(changes)
}

fn apply_cline(listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
    let agent = registry::Cline;
    let mut changes = apply_env_agent(&agent, listen, inbound_key)?;
    let path = cline_settings_path()?;
    let mut settings = read_json_value(&path)?;
    let mut settings_changed = false;
    if set_json_string_path(
        &mut settings,
        &["anthropicBaseUrl"],
        &format!("http://{listen}"),
    ) {
        settings_changed = true;
    }
    if set_json_string_path(&mut settings, &["anthropicApiKey"], inbound_key) {
        settings_changed = true;
    }
    if settings_changed {
        write_json_value(&path, &settings, "agents")?;
        changes.push(format!("updated {}", path.display()));
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
    Ok(paths)
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
        let mut config: toml::Value = r#"
            [mcp_servers.filesystem]
            command = "npx"
            args = ["-y", "server"]

            [mcp_servers.remote]
            url = "https://example.com/mcp"
        "#
        .parse()
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
