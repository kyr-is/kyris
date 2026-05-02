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
    let listen = &config.server.listen;
    let inbound_key = &config.server.inbound_key;

    for agent in registry::all_agents() {
        let changes = prestage_agent_inner(agent.as_ref(), listen, inbound_key)?;
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
        &config.server.listen,
        &config.server.inbound_key,
    )
}

fn prestage_agent_inner(
    agent: &dyn AgentDescriptor,
    listen: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let mut changes = prestage_env(agent, listen, inbound_key)?;

    if agent.id() == "cline" {
        changes.extend(prestage_cline_policy()?);
    }

    if let Some(protocol) = agent.hook_protocol() {
        let agents_dir = crate::state::kyris_home()?.join("agents").join(agent.id());
        std::fs::create_dir_all(&agents_dir)
            .map_err(|e| format!("Cannot create {}: {e}", agents_dir.display()))?;
        let protocol_path = agents_dir.join("hook-protocol.json");
        let json = serde_json::to_string_pretty(&protocol)
            .map_err(|e| format!("Cannot serialize hook protocol: {e}"))?;
        if write_managed_file(&protocol_path, &json, agent.id(), Some(0o600))? {
            changes.push(format!("wrote {}", protocol_path.display()));
        }
    }

    Ok(changes)
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
    listen: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let exports = agent.env_exports(listen, inbound_key);
    if exports.is_empty() {
        return Ok(Vec::new());
    }

    let env_file = env_dir()?.join(format!("{}.sh", agent.id()));
    let loader_path = env_dir()?.join("load.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
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

fn prestage_cline_policy() -> Result<Vec<String>, String> {
    let (permissions, ask_dropped) = crate::compile_policy::compile_cline_permissions(None)?;
    let env_file = env_dir()?.join("cline.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let json = serde_json::to_string(&permissions)
        .map_err(|e| format!("Cannot serialize compiled Cline permissions: {e}"))?;
    let contents = format!(
        "# SPDX-License-Identifier: Apache-2.0\nexport CLINE_COMMAND_PERMISSIONS='{}'\n",
        json.replace('\'', "\\'")
    );
    let mut changes = Vec::new();

    if write_managed_file(&env_file, &contents, "cline", Some(0o600))? {
        changes.push(format!("wrote {}", env_file.display()));
    }

    let loader_path = env_dir()?.join("load.sh");
    if ensure_line(
        &PathBuf::from(&home).join(".zshrc"),
        "source \"$HOME/.kyris/env/load.sh\"",
        "cline",
    )? {
        changes.push("updated ~/.zshrc".to_string());
    }
    if ensure_line(
        &PathBuf::from(&home).join(".bashrc"),
        "source \"$HOME/.kyris/env/load.sh\"",
        "cline",
    )? {
        changes.push("updated ~/.bashrc".to_string());
    }
    if !loader_path.exists()
        && write_managed_file(&loader_path, ENV_LOADER_SOURCE, "cline", Some(0o600))?
    {
        changes.push(format!("wrote {}", loader_path.display()));
    }

    if ask_dropped > 0 {
        changes.push(format!(
            "warning: dropped {ask_dropped} ask rules while compiling Cline permissions"
        ));
    }

    Ok(changes)
}
