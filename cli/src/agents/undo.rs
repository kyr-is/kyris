// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::integration::{cline_settings_path, codex_config_path, opencode_config_path};
use crate::state::{env_dir, load_agent_profile, restore_manifest_entry, save_agent_profile};

use super::registry;

pub fn undo_agent(agent_id: &str) -> Result<(), String> {
    let _agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    match agent_id {
        "claude-code" | "gemini-cli" | "opencode" | "cline" => undo_env_agent(agent_id)?,
        "codex-cli" => undo_codex()?,
        _ => return Err(format!("Unknown agent: {agent_id}")),
    }
    match agent_id {
        "opencode" => undo_opencode_config()?,
        "cline" => undo_cline_config()?,
        _ => {}
    }

    if let Ok(Some(mut profile)) = load_agent_profile(agent_id) {
        profile.execution = super::profile::SurfaceState::none();
        profile.tool = super::profile::SurfaceState::none();
        profile.burn_control = super::profile::SurfaceState::none();
        profile.managed_files.clear();
        let _ = save_agent_profile(&profile);
    }

    Ok(())
}

fn undo_env_agent(agent_id: &str) -> Result<(), String> {
    let env_file = env_dir()?.join(format!("{agent_id}.sh"));
    if restore_manifest_entry(&env_file)? {
        println!("Reverted {}", env_file.display());
    } else if env_file.exists() {
        std::fs::remove_file(&env_file)
            .map_err(|e| format!("Cannot remove {}: {e}", env_file.display()))?;
        println!("Removed {}", env_file.display());
    } else {
        println!("No setup file found for {agent_id}.");
    }

    let agent = registry::agent_by_id(agent_id).expect("validated above");
    let exports = agent.env_exports("", "");
    if !exports.is_empty() {
        println!("# Remove these from your current shell if already exported:");
        for (key, _) in &exports {
            println!("unset {key}");
        }
    }
    Ok(())
}

fn undo_codex() -> Result<(), String> {
    let env_file = env_dir()?.join("codex-cli.sh");
    let _ = restore_manifest_entry(&env_file)?;
    let config_path = codex_config_path()?;
    if restore_manifest_entry(&config_path)? {
        println!("Reverted {}", config_path.display());
    } else {
        println!("No Codex setup backup found.");
    }
    Ok(())
}

fn undo_opencode_config() -> Result<(), String> {
    let path = opencode_config_path()?;
    if restore_manifest_entry(&path)? {
        println!("Reverted {}", path.display());
    }
    Ok(())
}

fn undo_cline_config() -> Result<(), String> {
    let path = cline_settings_path()?;
    if restore_manifest_entry(&path)? {
        println!("Reverted {}", path.display());
    }
    Ok(())
}
