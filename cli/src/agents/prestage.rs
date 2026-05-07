// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::state::{ensure_line, env_dir, load_or_init_config, write_managed_file};

use super::registry::{self, AgentDescriptor};

const ENV_LOADER_SOURCE: &str = r#"# SPDX-License-Identifier: Apache-2.0
for file in "$HOME/.kyris/env/"*.sh; do
    [ -f "$file" ] || continue
    [ "$file" = "$HOME/.kyris/env/load.sh" ] && continue
    . "$file"
done
"#;

pub fn prestage_all() -> Result<(), String> {
    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    for agent in registry::all_agents() {
        let changes = prestage_agent_inner(agent.as_ref(), &base_url, inbound_key)?;
        if !changes.is_empty() {
            println!("Prestaged {}:", agent.id());
            for change in &changes {
                println!("  {change}");
            }
        }
    }
    Ok(())
}

pub fn prestage_agent(agent_id: &str) -> Result<Vec<String>, String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    let config = load_or_init_config()?;
    prestage_agent_inner(
        agent.as_ref(),
        &config.base_url(),
        &config.server.inbound_key,
    )
}

fn prestage_agent_inner(
    agent: &dyn AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    prestage_env(agent, base_url, inbound_key)
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

fn prestage_env(
    agent: &dyn AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let exports = agent.env_exports(base_url, inbound_key);
    if exports.is_empty() {
        return Ok(Vec::new());
    }

    let mut changes = ensure_env_loader()?;

    let env_file = env_dir()?.join(format!("{}.sh", agent.id()));
    if write_managed_file(
        &env_file,
        &exports_to_shell(&exports),
        "agents",
        Some(0o600),
    )? {
        changes.push(format!("wrote {}", env_file.display()));
    }

    Ok(changes)
}

/// Ensure `load.sh` exists and shell RC files source it.
/// Called by `prestage_env` for agents with env exports, and by
/// `configure_execution` for agents that write env files directly
/// (e.g. Cline's compiled policy).
pub fn ensure_env_loader() -> Result<Vec<String>, String> {
    let loader_path = env_dir()?.join("load.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let mut changes = Vec::new();

    if write_managed_file(&loader_path, ENV_LOADER_SOURCE, "agents", Some(0o600))? {
        changes.push(format!("wrote {}", loader_path.display()));
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
