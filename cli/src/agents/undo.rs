// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use crate::state::{env_dir, load_agent_profile, restore_manifest_entry, save_agent_profile};

use super::registry;

pub fn undo_agent(agent_id: &str) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    agent.undo()?;
    // undo_burn_control handles MCP upstream removal and burn-control config
    // restoration for agents where undo() doesn't call it internally.
    // For agents that do call it internally (cline, opencode), the second
    // call is a no-op because the manifest entries are already removed.
    agent.undo_burn_control()?;
    undo_env_agent(agent_id)?;

    let mut profile = load_agent_profile(agent_id)?
        .unwrap_or_else(|| super::profile::AgentProfile::new_empty(agent_id));
    profile.execution = super::profile::SurfaceState::none();
    profile.tool = super::profile::SurfaceState::none();
    profile.burn_control = super::profile::SurfaceState::none();
    profile.managed_files.clear();
    profile.disabled = true;
    save_agent_profile(&profile)?;

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

pub(super) fn remove_file_if_exists(path: &Path) -> Result<bool, String> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("Cannot remove {}: {e}", path.display()))?;
        println!("Removed {}", path.display());
        Ok(true)
    } else {
        Ok(false)
    }
}
