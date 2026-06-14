// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;
use std::path::Path;

use crate::lifecycle::log::InstallLog;
use crate::state::{agents_dir, load_agent_profile, save_agent_profile};

use super::profile::{AgentProfile, CapLevel, NativeEvidence, SurfaceEvidence, SurfaceState};
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

fn collect_native_evidence(agent: &dyn AgentDescriptor) -> NativeEvidence {
    let mut evidence = agent.native_evidence();
    if evidence.burn_control.is_none() {
        evidence.burn_control = check_native_breadcrumb(agent.id());
    }
    evidence
}

/// Read the `.live-seen` breadcrumbs (recorded by `kyris hook check`,
/// `kyris-mcp wrap`, and kyrisd when an adapted surface actually works) into a
/// per-surface snapshot. Unlike native evidence this is read wholesale, never
/// merged — the breadcrumbs themselves are the durable store.
fn collect_live_evidence(agent_id: &str) -> SurfaceEvidence {
    use kyris_core::live_evidence as live;
    SurfaceEvidence {
        execution: live::last_seen(agent_id, live::SURFACE_EXECUTION),
        tool: live::last_seen(agent_id, live::SURFACE_TOOL),
        burn_control: live::last_seen(agent_id, live::SURFACE_BURN_CONTROL),
    }
}

fn promote_surface<M>(
    surface: &mut SurfaceState<M>,
    should_promote: bool,
    undo: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    if !should_promote || surface.level == CapLevel::Native {
        return Ok(false);
    }
    if surface.level == CapLevel::Adapted {
        undo()?;
    }
    *surface = SurfaceState::native();
    Ok(true)
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

pub fn reconcile_all(auto: bool, log: Option<&InstallLog>) -> ReconcileResult {
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
        let profile = reconcile_agent(agent.as_ref(), log)?;
        results.push((agent, profile));
    }

    touch_last_reconcile();
    Ok(results)
}

/// Evidence-based configure / repair / native-promotion pass for one agent.
/// `kyris agent setup <id>` runs this after writing settings so an explicit
/// setup repairs drift and promotes adapted→native exactly like the reconcile
/// watcher — there is no separate `reconcile` command. Idempotent and quiet
/// when there's nothing to do (already configured, no drift, no native
/// evidence yet).
pub fn reconcile_one(agent_id: &str) -> Result<AgentProfile, String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    let profile = reconcile_agent(agent.as_ref(), None)?;
    touch_last_reconcile();
    Ok(profile)
}

/// Read-only status snapshot for every agent: load the persisted profile and
/// merge it with a fresh probe of the current on-disk state, WITHOUT
/// configuring, repairing, promoting, or persisting anything.
///
/// `kyris agent status` uses this so an inspection command never mutates the
/// user's agent configs, never installs a shim, never runs `load_or_init_config`
/// (which would create `kyrisd.yaml`), and never resets `last_reconciled` —
/// which would mask a stopped reconcile daemon. Ongoing reconcile is the job of
/// the daemon's reconcile watcher (`daemon/src/reconcile_watcher.rs`) plus the
/// explicit `kyris agent setup` (idempotent — it also repairs) / `kyris install`.
pub fn status_snapshot_all() -> ReconcileResult {
    let mut results = Vec::new();
    for agent in registry::all_agents() {
        let profile = status_snapshot_agent(agent.as_ref())?;
        results.push((agent, profile));
    }
    Ok(results)
}

fn status_snapshot_agent(agent: &dyn AgentDescriptor) -> Result<AgentProfile, String> {
    let mut profile =
        load_agent_profile(agent.id())?.unwrap_or_else(|| AgentProfile::new_empty(agent.id()));
    let probe = agent.probe();

    if !probe.detected {
        // Reflect not-detected in the returned snapshot without persisting it.
        profile.detected = false;
        profile.managed_files.clear();
        return Ok(profile);
    }

    profile.detected = true;
    // Take surface states from the probe, preserving Native levels the probe
    // cannot observe (it only sees filesystem artifacts, not live protocol).
    if profile.execution.level != CapLevel::Native {
        profile.execution = probe.execution;
    }
    if profile.tool.level != CapLevel::Native {
        profile.tool = probe.tool;
    }
    if profile.burn_control.level != CapLevel::Native {
        profile.burn_control = probe.burn_control;
    }
    profile.managed_files = probe.managed_files;
    profile.live_evidence = collect_live_evidence(agent.id());
    Ok(profile)
}

#[allow(clippy::too_many_lines)]
fn reconcile_agent(
    agent: &dyn AgentDescriptor,
    log: Option<&InstallLog>,
) -> Result<AgentProfile, String> {
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

    // The user explicitly disconnected this agent (`kyris agent disconnect`):
    // it's still present, but do NOT configure, repair, or promote it. Disconnect
    // is a STABLE opt-out — only an explicit `kyris agent setup <id>` (which
    // clears `disconnected` before this pass runs) re-governs it. This guard keeps
    // bulk `setup --all` AND the reconcile watcher from silently re-governing an
    // opt-out (auto-configure, drift repair, and native promotion all skipped).
    if profile.disconnected {
        profile.last_reconciled = Some(Utc::now());
        save_agent_profile(&profile)?;
        return Ok(profile);
    }

    // Migrate legacy single-field native evidence to per-surface, then collect
    // current runtime evidence before any auto-configure/repair step so proven
    // native surfaces are not reinstalled as adapted.
    profile.migrate_native_evidence();
    profile
        .native_evidence
        .merge_missing_from(collect_native_evidence(agent));

    let execution_native =
        profile.execution.level == CapLevel::Native || profile.native_evidence.execution.is_some();
    let tool_native =
        profile.tool.level == CapLevel::Native || profile.native_evidence.tool.is_some();
    let burn_control_native = profile.burn_control.level == CapLevel::Native
        || profile.native_evidence.burn_control.is_some();

    // Auto-configure: agent is present but has never been configured.
    // Skip if the user explicitly disconnected this agent via `kyris agent disconnect`.
    if !was_configured(agent.id()) && !profile.disconnected {
        match super::configure::configure_agent_surfaces(
            agent.id(),
            &profile.agent_specific,
            execution_native,
            tool_native,
            burn_control_native,
            log,
        ) {
            Ok(()) => {
                println!("Auto-configured {}", agent.id());
                if let Some(l) = log {
                    l.info(&format!("auto-configured {}", agent.id()));
                }
            }
            Err(e) => {
                eprintln!("Auto-configure {} failed: {e}", agent.id());
                if let Some(l) = log {
                    l.error(&format!("auto-configure {} failed: {e}", agent.id()));
                }
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
    // MCP drift repair: a server ADDED after setup is invisible to the marker
    // check above (the file still carries kyris content vouching for its hash
    // drift), but it runs ungoverned until wrapped. Configure is idempotent,
    // so re-running it to wrap the newcomer is safe.
    if !needs_repair
        && was_configured(agent.id())
        && !super::configure::unwrapped_mcp_server_names(agent).is_empty()
    {
        needs_repair = true;
    }

    if needs_repair {
        match super::configure::configure_agent_surfaces(
            agent.id(),
            &profile.agent_specific,
            execution_native,
            tool_native,
            burn_control_native,
            log,
        ) {
            Ok(()) => {
                println!("Repaired {}", agent.id());
                if let Some(l) = log {
                    l.info(&format!("repaired {}", agent.id()));
                }
            }
            Err(e) => {
                eprintln!("Repair {} failed: {e}", agent.id());
                if let Some(l) = log {
                    l.error(&format!("repair {} failed: {e}", agent.id()));
                }
            }
        }
        let updated = agent.probe();
        probe.execution = updated.execution;
        probe.tool = updated.tool;
        probe.burn_control = updated.burn_control;
        probe.managed_files = updated.managed_files;
    }

    // Update surface states from probe, preserving native levels that the
    // probe cannot detect (probe only sees filesystem artifacts, not protocol).
    if profile.execution.level != CapLevel::Native {
        profile.execution = probe.execution;
    }
    if profile.tool.level != CapLevel::Native {
        profile.tool = probe.tool;
    }
    if profile.burn_control.level != CapLevel::Native {
        profile.burn_control = probe.burn_control;
    }

    // Per-surface native promotion: only promote surfaces with evidence.
    let (need_execution, need_tool, need_burn) = agent.expected_surfaces();
    let promote_execution = need_execution && profile.native_evidence.execution.is_some();
    let promote_tool = need_tool && profile.native_evidence.tool.is_some();
    let promote_burn = need_burn && profile.native_evidence.burn_control.is_some();

    let mut execution_changed = false;
    let mut tool_changed = false;
    let mut burn_changed = false;

    match promote_surface(&mut profile.execution, promote_execution, || {
        agent.undo_execution_surface()
    }) {
        Ok(promoted) => execution_changed = promoted,
        Err(e) => eprintln!("Execution cleanup for {} failed: {e}", agent.id()),
    }
    match promote_surface(&mut profile.tool, promote_tool, || {
        agent.undo_tool_surface()
    }) {
        Ok(promoted) => tool_changed = promoted,
        Err(e) => eprintln!("Tool cleanup for {} failed: {e}", agent.id()),
    }
    match promote_surface(&mut profile.burn_control, promote_burn, || {
        agent.undo_burn_control_surface()
    }) {
        Ok(promoted) => burn_changed = promoted,
        Err(e) => eprintln!("Burn-control cleanup for {} failed: {e}", agent.id()),
    }

    if execution_changed || tool_changed || burn_changed {
        if let Err(e) = super::configure::configure_agent_surfaces(
            agent.id(),
            &profile.agent_specific,
            promote_execution,
            promote_tool,
            promote_burn,
            log,
        ) {
            eprintln!("Re-configure {} after promotion failed: {e}", agent.id());
            if let Some(l) = log {
                l.error(&format!(
                    "re-configure {} after promotion failed: {e}",
                    agent.id()
                ));
            }
        }
        let updated = agent.probe();
        probe.managed_files = updated.managed_files;
    }

    profile.managed_files = probe.managed_files;
    profile.live_evidence = collect_live_evidence(agent.id());
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

    #[test]
    fn testPromoteSurfaceRunsCleanupForAdaptedSurface() {
        let mut surface =
            SurfaceState::adapted(crate::agents::registry::ToolMechanism::McpWrapping);
        let mut cleaned = false;

        let promoted = promote_surface(&mut surface, true, || {
            cleaned = true;
            Ok(())
        })
        .expect("promotion");

        assert!(promoted);
        assert!(cleaned);
        assert_eq!(surface.level, CapLevel::Native);
    }

    #[test]
    fn testPromoteSurfaceDoesNotCleanupNoneSurface() {
        let mut surface = SurfaceState::<crate::agents::registry::ToolMechanism>::none();
        let mut cleaned = false;

        let promoted = promote_surface(&mut surface, true, || {
            cleaned = true;
            Ok(())
        })
        .expect("promotion");

        assert!(promoted);
        assert!(!cleaned);
        assert_eq!(surface.level, CapLevel::Native);
    }
}
