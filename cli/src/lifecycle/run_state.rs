// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris stop` and `kyris start` — pause and resume governance.
//!
//! `stop` writes the `~/.kyris/disabled` sentinel (which every hook
//! entry point honors as a no-contact early exit), `launchctl disable`s
//! both daemons so they don't come back on reboot, and `launchctl kill
//! TERM`s the running instances. The user is now ungoverned until they
//! run `start`.
//!
//! `start` reverses each step: `launchctl enable`, `launchctl kickstart`,
//! polls both daemons until they respond on their endpoints, and only
//! then removes the sentinel. Polling matters because `kickstart` is
//! fire-and-forget — the daemons need a moment to bind their socket and
//! HTTP port. If either daemon fails to respond within 10s the sentinel
//! stays in place (system pinned to a clean disabled state) and the
//! command prints a reinstall hint.

use clap::Args;
use std::time::Duration;

use crate::service::{
    ServiceKind, disable_service, enable_service, kickstart_service, kill_service,
    wait_for_agentpactd, wait_for_kyrisd,
};

const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Disable governance.
///
/// Stops both daemons (`kyrisd` + `agentpactd`) and bypasses shell and
/// agent hooks via a `~/.kyris/disabled` sentinel. Persists across
/// reboot via `launchctl disable`. No audit log entries are written
/// while disabled. Reverse with `kyris start`.
#[derive(Args)]
pub struct StopArgs {}

/// Re-enable governance.
///
/// `launchctl enable` + `kickstart` both daemons (agentpactd first),
/// waits up to 10s for them to respond on their endpoints, then removes
/// the sentinel. If either daemon fails to come up, the sentinel stays
/// in place and the command exits non-zero with a reinstall hint.
#[derive(Args)]
pub struct StartArgs {}

pub fn run_stop(_args: StopArgs) {
    let sentinel = kyris_core::paths::disabled_marker_path();
    if let Some(parent) = sentinel.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("Failed to ensure {}: {e}", parent.display());
        std::process::exit(1);
    }
    if let Err(e) = std::fs::write(&sentinel, b"") {
        eprintln!("Failed to write sentinel {}: {e}", sentinel.display());
        std::process::exit(1);
    }

    // Order: kyrisd first (it talks to agentpactd via UDS during
    // gateway / MCP routing; shutting agentpactd while kyrisd is still
    // serving means in-flight requests fail mid-flight). Disable
    // before kill so a respawn race can't slip a fresh instance in.
    let mut failures: Vec<String> = Vec::new();
    for kind in [ServiceKind::Kyrisd, ServiceKind::Agentpactd] {
        if let Err(e) = disable_service(kind) {
            failures.push(format!("disable {}: {e}", kind.launchd_label()));
        }
        if let Err(e) = kill_service(kind) {
            failures.push(format!("kill {}: {e}", kind.launchd_label()));
        }
    }

    println!("Kyris stopped. Governance is paused.");
    println!("  - Both daemons (kyrisd, agentpactd) are down and disabled across reboot.");
    println!(
        "  - Shell + agent hooks early-exit via {} — no audit log entries.",
        sentinel.display()
    );
    println!();
    println!("Run `kyris start` to re-enable.");
    if !failures.is_empty() {
        eprintln!();
        eprintln!("Note: some launchctl steps reported errors (system may already have");
        eprintln!("been in the target state — sentinel is what actually disables hooks):");
        for f in &failures {
            eprintln!("  - {f}");
        }
    }
}

pub fn run_start(_args: StartArgs) {
    let mut prelim_failures: Vec<String> = Vec::new();

    // Order: agentpactd first (kyrisd makes UDS calls to it on
    // startup), kyrisd second.
    for kind in [ServiceKind::Agentpactd, ServiceKind::Kyrisd] {
        if let Err(e) = enable_service(kind) {
            prelim_failures.push(format!("enable {}: {e}", kind.launchd_label()));
        }
        if let Err(e) = kickstart_service(kind) {
            prelim_failures.push(format!("kickstart {}: {e}", kind.launchd_label()));
        }
    }

    let agentpactd_up = wait_for_agentpactd(HEALTH_TIMEOUT);
    let kyrisd_up = wait_for_kyrisd(HEALTH_TIMEOUT);

    if agentpactd_up && kyrisd_up {
        let sentinel = kyris_core::paths::disabled_marker_path();
        if sentinel.exists()
            && let Err(e) = std::fs::remove_file(&sentinel)
        {
            // Sentinel removal failure is rare (permissions) but the
            // daemons are up — better to keep the sentinel than lie
            // about the state.
            eprintln!(
                "Daemons up but failed to remove sentinel {}: {e}",
                sentinel.display()
            );
            eprintln!("Hooks will still treat governance as disabled. Remove the file manually:");
            eprintln!("  rm {}", sentinel.display());
            std::process::exit(1);
        }
        println!("Kyris started. Governance is enabled.");
        return;
    }

    // Failure path — keep sentinel in place so hooks stay in the clean
    // "disabled" state instead of trying to reach dead daemons.
    eprintln!(
        "Failed to start kyris within {}s:",
        HEALTH_TIMEOUT.as_secs()
    );
    if !agentpactd_up {
        eprintln!("  - agentpactd: did not become responsive");
    }
    if !kyrisd_up {
        eprintln!("  - kyrisd: /healthz did not respond");
    }
    if !prelim_failures.is_empty() {
        eprintln!();
        eprintln!("launchctl reported earlier errors:");
        for f in &prelim_failures {
            eprintln!("  - {f}");
        }
    }
    eprintln!();
    eprintln!("System is still disabled. Diagnose with `kyris verify`, then reinstall:");
    eprintln!("  ~/.kyris/installer.sh                          (script install)");
    eprintln!("  brew reinstall --cask kyr-is/tap/kyris         (brew install)");
    std::process::exit(1);
}
