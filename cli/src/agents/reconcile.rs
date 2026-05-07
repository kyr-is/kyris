// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;
use std::path::Path;

use crate::state::{kyris_home, load_agent_profile, save_agent_profile};

use super::profile::{AgentProfile, CapLevel};
use super::registry::{self, AgentDescriptor};

fn was_configured(agent_id: &str) -> bool {
    load_agent_profile(agent_id)
        .ok()
        .flatten()
        .is_some_and(|p| {
            p.execution.level != CapLevel::None
                || p.tool.level != CapLevel::None
                || p.burn_control.level != CapLevel::None
        })
}

const DEBOUNCE_SECONDS: i64 = 300;

fn last_reconcile_path() -> Result<std::path::PathBuf, String> {
    Ok(agents_dir()?.join(".last-reconcile"))
}

fn agents_dir() -> Result<std::path::PathBuf, String> {
    Ok(kyris_home()?.join("agents"))
}

fn native_seen_path(agent_id: &str) -> Result<std::path::PathBuf, String> {
    Ok(agents_dir()?.join(".native-seen").join(agent_id))
}

fn should_skip_debounce(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let elapsed = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    elapsed.as_secs() < DEBOUNCE_SECONDS as u64
}

fn touch_last_reconcile() {
    if let Ok(path) = last_reconcile_path() {
        let _ = crate::state::ensure_parent(&path);
        let _ = std::fs::write(&path, "");
    }
}

fn check_native_breadcrumb(agent_id: &str) -> Option<chrono::DateTime<Utc>> {
    let path = native_seen_path(agent_id).ok()?;
    let contents = std::fs::read_to_string(path).ok()?;
    contents.trim().parse().ok()
}

fn file_contains_marker(path: &Path, markers: &[&str]) -> bool {
    if markers.is_empty() {
        return false;
    }
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    markers.iter().any(|marker| contents.contains(marker))
}

pub type ReconcileResult = Result<Vec<(Box<dyn AgentDescriptor>, AgentProfile)>, String>;

pub fn reconcile_all(auto: bool) -> ReconcileResult {
    if auto
        && let Ok(path) = last_reconcile_path()
        && should_skip_debounce(&path)
    {
        let mut results = Vec::new();
        for agent in registry::all_agents() {
            let profile = load_agent_profile(agent.id())?
                .unwrap_or_else(|| AgentProfile::new_empty(agent.id()));
            results.push((agent, profile));
        }
        return Ok(results);
    }

    let mut results = Vec::new();
    for agent in registry::all_agents() {
        let profile = reconcile_agent(agent.as_ref())?;
        results.push((agent, profile));
    }

    touch_last_reconcile();
    Ok(results)
}

pub fn reconcile_one(agent_id: &str) -> Result<AgentProfile, String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    let profile = reconcile_agent(agent.as_ref())?;
    touch_last_reconcile();
    Ok(profile)
}

#[allow(clippy::too_many_lines)]
fn reconcile_agent(agent: &dyn AgentDescriptor) -> Result<AgentProfile, String> {
    let mut profile =
        load_agent_profile(agent.id())?.unwrap_or_else(|| AgentProfile::new_empty(agent.id()));

    let mut probe = agent.probe();

    if !probe.detected {
        if profile.detected {
            profile.detected = false;
            profile.managed_files.clear();
        }
        profile.last_reconciled = Some(Utc::now());
        save_agent_profile(&profile)?;
        return Ok(profile);
    }

    profile.detected = true;

    let burn_control_native = profile.burn_control.level == CapLevel::Native;

    // Auto-configure: agent is present but has never been configured.
    // Skip if the user explicitly disabled this agent via `kyris agents undo`.
    if !was_configured(agent.id()) && !profile.disabled {
        match super::configure::configure_agent(
            agent.id(),
            &profile.agent_specific,
            burn_control_native,
        ) {
            Ok(()) => {
                println!("Auto-configured {}", agent.id());
            }
            Err(e) => {
                eprintln!("Auto-configure {} failed: {e}", agent.id());
            }
        }
        // Re-probe after configure to get updated surface states.
        let updated = agent.probe();
        probe.execution = updated.execution;
        probe.tool = updated.tool;
        probe.burn_control = updated.burn_control;
        probe.managed_files = updated.managed_files;
    }

    // Reinstall detection: for each managed file, check if Kyris content is gone.
    let markers = agent.kyris_content_markers();
    let mut needs_repair = false;
    for existing_fp in &profile.managed_files {
        let path = Path::new(&existing_fp.path);
        if !path.exists() {
            needs_repair = true;
            break;
        }
        let current_hash = super::probe::sha256_file(path).unwrap_or_default();
        if current_hash != existing_fp.content_hash && !file_contains_marker(path, markers) {
            needs_repair = true;
            break;
        }
    }

    if needs_repair {
        match super::configure::configure_agent(
            agent.id(),
            &profile.agent_specific,
            burn_control_native,
        ) {
            Ok(()) => {
                println!("Repaired {}", agent.id());
            }
            Err(e) => {
                eprintln!("Repair {} failed: {e}", agent.id());
            }
        }
        let updated = agent.probe();
        probe.execution = updated.execution;
        probe.tool = updated.tool;
        probe.burn_control = updated.burn_control;
        probe.managed_files = updated.managed_files;
    }

    // Migrate legacy single-field native evidence to per-surface.
    profile.migrate_native_evidence();

    // Check for native protocol promotion via kyrisd breadcrumb.
    // The breadcrumb (x-kyris-trace-token on LLM path) only proves
    // burn-control nativeness. Execution and tool surfaces need their own
    // evidence sources when agents add native AgentPact support.
    if let Some(ts) = check_native_breadcrumb(agent.id())
        && profile.native_evidence.burn_control.is_none()
    {
        profile.native_evidence.burn_control = Some(ts);
    }

    // Update surface states from probe, preserving native levels that the
    // probe cannot detect (probe only sees filesystem artifacts, not protocol).
    profile.execution = probe.execution;
    profile.tool = probe.tool;
    if profile.burn_control.level != CapLevel::Native {
        profile.burn_control = probe.burn_control;
    }

    // Per-surface native promotion: only promote surfaces with evidence.
    if profile.native_evidence.burn_control.is_some() {
        let (_, _, need_burn) = agent.expected_surfaces();
        if need_burn && profile.burn_control.level == CapLevel::Adapted {
            if let Err(e) = agent.undo_burn_control() {
                eprintln!("Burn-control cleanup for {} failed: {e}", agent.id());
            }
            if let Err(e) =
                super::configure::configure_agent(agent.id(), &profile.agent_specific, true)
            {
                eprintln!("Re-configure {} after promotion failed: {e}", agent.id());
            }
            profile.burn_control = super::profile::SurfaceState::native();
            let updated = agent.probe();
            probe.managed_files = updated.managed_files;
        }
    }
    // Execution and tool promotion placeholders. No evidence source exists
    // today — when native hook/MCP protocols arrive, AgentDescriptor will need
    // dedicated `undo_execution()` / `undo_tool()` methods to remove adapted
    // artifacts without tearing down other surfaces.
    if profile.native_evidence.execution.is_some() && profile.execution.level == CapLevel::Adapted {
        profile.execution = super::profile::SurfaceState::native();
    }
    if profile.native_evidence.tool.is_some() && profile.tool.level == CapLevel::Adapted {
        profile.tool = super::profile::SurfaceState::native();
    }

    profile.managed_files = probe.managed_files;
    profile.last_reconciled = Some(Utc::now());
    save_agent_profile(&profile)?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testDebounceSkipsRecentReconcile() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join(".last-reconcile");
        std::fs::write(&path, "").expect("write");
        assert!(should_skip_debounce(&path));
    }

    #[test]
    fn testDebounceDoesNotSkipMissingFile() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join(".last-reconcile");
        assert!(!should_skip_debounce(&path));
    }

    #[test]
    fn testFileContainsMarker() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("test.json");
        std::fs::write(&path, r#"{"hooks": "agentpact_pretooluse"}"#).expect("write");
        assert!(file_contains_marker(&path, &["agentpact_pretooluse"]));
        assert!(!file_contains_marker(&path, &["nonexistent_marker"]));
    }

    #[test]
    fn testFileContainsMarkerEmptyMarkers() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("test.json");
        std::fs::write(&path, "anything").expect("write");
        assert!(!file_contains_marker(&path, &[]));
    }
}
