// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use clap::Args;

use crate::lifecycle::log::InstallLog;
use crate::service::{ServiceKind, service_state, stop_service};
use crate::state::restore_all_manifest_entries;

#[derive(Args)]
pub struct UninstallArgs {}

pub fn run(_args: UninstallArgs) {
    let log = InstallLog::open_uninstall();
    log.info("=== kyris uninstall started ===");

    println!("Reversing all install actions...");

    let state = service_state(ServiceKind::Kyrisd);
    if state.managed_by_homebrew || state.launchd_loaded {
        match stop_service(ServiceKind::Kyrisd) {
            Ok(()) => {
                log.info("stopped kyrisd");
                println!("Stopped Kyrisd");
            }
            Err(error) => {
                log.warn(&format!("could not stop kyrisd: {error}"));
                eprintln!("Could not stop Kyrisd: {error}");
            }
        }
        // launchctl bootout is asynchronous. Wait for the process to exit
        // before touching managed files — the reconcile watcher will
        // otherwise re-create deleted config files while the daemon winds down.
        wait_for_kyrisd_exit(15);
    }

    unload_env_launchd(&log);

    // Call each agent's undo() + undo_burn_control() before manifest cleanup.
    // This handles: MCP upstream removal from kyrisd.yaml, agent-specific
    // config cleanup (e.g. resetting codex_hooks flag), and hook/env removal.
    // Manifest cleanup below then handles remaining non-agent-specific entries.
    undo_all_agents(&log);

    match restore_all_manifest_entries() {
        Ok(actions) if actions.is_empty() => {
            log.info("no managed install actions were recorded");
            println!("No managed install actions were recorded.");
        }
        Ok(actions) => {
            for action in &actions {
                log_manifest_action(&log, action);
                println!("{action}");
            }
        }
        Err(error) => {
            log.error(&format!("restore_all_manifest_entries: {error}"));
            eprintln!("{error}");
            std::process::exit(1);
        }
    }

    sweep_well_known_hook_scripts(&log);
    unregister_package(&log);

    super::verify::verify_post_uninstall();

    log.info("=== kyris uninstall complete ===");
    if !log.path().as_os_str().is_empty() {
        println!("\nUninstall log: {}", log.path().display());
    }
}

/// Map the human-readable action strings from `restore_all_manifest_entries`
/// to the appropriate log level/method.
fn log_manifest_action(log: &InstallLog, action: &str) {
    if action.starts_with("removed ") {
        log.removed(action.trim_start_matches("removed "));
    } else if action.starts_with("removed kyris lines from ") {
        log.stripped(action.trim_start_matches("removed kyris lines from "));
    } else if action.starts_with("unapplied JSON patch on ")
        || action.starts_with("unapplied TOML patch on ")
    {
        let path = action
            .trim_start_matches("unapplied JSON patch on ")
            .trim_start_matches("unapplied TOML patch on ");
        log.unpatched(path);
    } else if action.starts_with("skipped ") {
        // e.g. "skipped /path (already absent)"
        log.warn(action);
    } else if action.contains("could not be fully cleaned") {
        log.warn(action);
    } else {
        log.info(action);
    }
}

/// Call undo on every agent that has any configured surface or managed files.
///
/// Runs before manifest cleanup so MCP upstreams are removed from kyrisd.yaml
/// while agent config files still contain the kyris-registered server names.
fn undo_all_agents(log: &InstallLog) {
    use crate::agents::profile::CapLevel;
    use crate::agents::registry;

    for agent in registry::all_agents() {
        let Ok(Some(profile)) = crate::state::load_agent_profile(agent.id()) else {
            continue;
        };
        // Skip agents that were never configured.
        if profile.execution.level == CapLevel::None
            && profile.tool.level == CapLevel::None
            && profile.burn_control.level == CapLevel::None
            && profile.managed_files.is_empty()
        {
            continue;
        }
        log.info(&format!("cleaning up {}", agent.id()));
        println!("Cleaning up {}...", agent.id());
        if let Err(e) = crate::agents::undo::undo_agent(agent.id()) {
            log.warn(&format!("cleanup of {} failed: {e}", agent.id()));
            eprintln!("Warning: cleanup of {} failed: {e}", agent.id());
        }
    }
}

/// Remove the kyris package registry entry so agentpact sees kyris as gone.
///
/// The brew `uninstall_postflight` handles this for brew installs; this covers
/// the script-path and standalone `kyris uninstall` cases.
fn unregister_package(log: &InstallLog) {
    let home = std::env::var("HOME").unwrap_or_default();
    let registry_dir = std::env::var("XDG_DATA_HOME")
        .ok()
        .map_or_else(
            || std::path::PathBuf::from(&home).join(".local").join("share"),
            std::path::PathBuf::from,
        )
        .join("kyr-packages");
    let manifest = registry_dir.join("kyris.json");
    if manifest.exists() {
        match std::fs::remove_file(&manifest) {
            Ok(()) => {
                log.removed(&manifest.display().to_string());
                println!("Removed package manifest at {}", manifest.display());
            }
            Err(e) => {
                log.warn(&format!("could not remove {}: {e}", manifest.display()));
                eprintln!("Warning: could not remove {}: {e}", manifest.display());
            }
        }
    } else {
        log.info(&format!(
            "package manifest not found (already absent): {}",
            manifest.display()
        ));
    }
    // Remove the registry dir if it is now empty (all packages uninstalled).
    let _ = std::fs::remove_dir(&registry_dir); // no-op if non-empty or absent
}

/// Well-known agent-hook script paths that kyris install creates.
///
/// Returned as relative-to-`$HOME` paths so tests can use a synthetic root.
pub(crate) const WELL_KNOWN_HOOK_PATHS: &[&str] = &[
    ".claude/hooks/agentpact_pretooluse.sh",
    ".codex/kyris_pretooluse.sh",
    ".gemini/kyris_pretooluse.sh",
];

/// Substrings that prove a script was generated by kyris. We refuse to
/// touch the path unless one of these is present, so a same-named file
/// produced by another tool is left alone.
pub(crate) const KYRIS_HOOK_MARKERS: &[&str] = &[
    "agentpact_pretooluse",
    "kyris_pretooluse",
    "kyris-mcp",
    "kyris-hook",
    "/.kyris/",
];

/// Best-effort cleanup of agent-hook script paths kyris installs.
///
/// Why this exists in addition to the manifest restore:
/// - `write_managed_file` historically skipped manifest recording when
///   content matched, so identical reinstalls leaked files.
/// - A still-running daemon's reconcile-watcher can repave a hook
///   between manifest restore and the cask's launchctl bootout.
/// - The manifest dir itself may have been wiped by an earlier
///   `zap trash: "~/.kyris"`.
///
/// Always best-effort — failures here don't abort uninstall.
fn sweep_well_known_hook_scripts(log: &InstallLog) {
    let Ok(home) = std::env::var("HOME") else {
        log.warn("HOME not set; skipping hook script sweep");
        return;
    };
    sweep_in_home(Path::new(&home), log);
}

fn sweep_in_home(home: &Path, log: &InstallLog) {
    for rel in WELL_KNOWN_HOOK_PATHS {
        let path = home.join(rel);
        if let Err(error) = sweep_one(&path, log) {
            log.warn(&format!("could not sweep {}: {error}", path.display()));
            eprintln!("Warning: could not sweep {}: {error}", path.display());
        }
    }
}

fn sweep_one(path: &Path, log: &InstallLog) -> Result<(), String> {
    if !path.exists() {
        log.info(&format!("sweep: {} already absent", path.display()));
        return Ok(());
    }
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if !KYRIS_HOOK_MARKERS
        .iter()
        .any(|marker| contents.contains(marker))
    {
        // Looks like a file someone else owns. Leave it.
        log.info(&format!(
            "sweep: {} has no kyris marker — left alone",
            path.display()
        ));
        return Ok(());
    }
    std::fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))?;
    log.removed(&path.display().to_string());
    println!("Removed stale hook script {}", path.display());
    Ok(())
}

fn wait_for_kyrisd_exit(timeout_secs: u64) {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        let still_running = std::process::Command::new("pgrep")
            .args(["-x", "kyrisd"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !still_running {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    eprintln!(
        "[kyris] Warning: kyrisd still running after {timeout_secs}s; proceeding with cleanup"
    );
}

fn unload_env_launchd(log: &InstallLog) {
    let domain = format!("gui/{}", crate::service::uid());

    let target = format!("{domain}/is.kyr.env");
    match std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .status()
    {
        Ok(s) if !s.success() => {
            log.info(&format!(
                "launchctl bootout {target} — not loaded or already removed"
            ));
        }
        Err(e) => {
            log.warn(&format!("launchctl bootout {target} failed: {e}"));
        }
        _ => {
            log.info(&format!("launchctl bootout {target} ok"));
        }
    }

    let _ = std::process::Command::new("launchctl")
        .args(["unsetenv", "BASH_ENV"])
        .status();
    log.info("launchctl unsetenv BASH_ENV");

    let target = format!("{domain}/is.kyr.cline-policy");
    match std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .status()
    {
        Ok(s) if !s.success() => {
            log.info(&format!(
                "launchctl bootout {target} — not loaded or already removed"
            ));
        }
        Err(e) => {
            log.warn(&format!("launchctl bootout {target} failed: {e}"));
        }
        _ => {
            log.info(&format!("launchctl bootout {target} ok"));
        }
    }

    let _ = std::process::Command::new("launchctl")
        .args(["unsetenv", "CLINE_COMMAND_PERMISSIONS"])
        .status();
    log.info("launchctl unsetenv CLINE_COMMAND_PERMISSIONS");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_with_parents(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, contents).expect("write");
    }

    fn null_log() -> InstallLog {
        InstallLog::null()
    }

    #[test]
    fn sweepRemovesMarkedHookScripts() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        for rel in WELL_KNOWN_HOOK_PATHS {
            write_with_parents(
                &temp.path().join(rel),
                "#!/bin/bash\nexec kyris-hook --agent claude-code\n",
            );
        }
        let log = null_log();
        sweep_in_home(temp.path(), &log);
        for rel in WELL_KNOWN_HOOK_PATHS {
            assert!(!temp.path().join(rel).exists(), "should have removed {rel}");
        }
    }

    #[test]
    fn sweepLeavesUnmarkedFilesAlone() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join(".claude/hooks/agentpact_pretooluse.sh");
        let foreign = "#!/bin/bash\necho not ours\n";
        write_with_parents(&path, foreign);
        let log = null_log();
        sweep_in_home(temp.path(), &log);
        assert!(path.exists(), "should not remove foreign file");
        assert_eq!(fs::read_to_string(&path).expect("read"), foreign);
    }

    #[test]
    fn sweepNoopOnMissingFiles() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let log = null_log();
        sweep_in_home(temp.path(), &log);
    }
}
