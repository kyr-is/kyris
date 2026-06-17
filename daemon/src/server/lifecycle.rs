// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::metering::StatsEvent;
use crate::pending::PendingStore;

pub(super) fn check_crash_recovery() {
    let pid_path = kyris_core::paths::pid_path();
    let Ok(contents) = std::fs::read_to_string(&pid_path) else {
        return;
    };
    let Ok(old_pid) = contents.trim().parse::<i32>() else {
        return;
    };
    #[cfg(unix)]
    {
        use nix::sys::signal;
        use nix::unistd::Pid;

        let alive = signal::kill(Pid::from_raw(old_pid), None).is_ok();
        if !alive {
            let modified = std::fs::metadata(&pid_path).and_then(|m| m.modified()).ok();
            // Distinguish a panic (the previous daemon wrote a crash report, so
            // the cause is recorded) from an uncatchable external kill (SIGKILL /
            // OOM / power loss — the panic hook never ran, so there is NO report).
            // A report modified after the dead daemon wrote its PID file is that
            // daemon's own panic; absence of one means it was killed from outside.
            if let Some(report) = modified.and_then(crate::crash::most_recent_report_since) {
                tracing::warn!(
                    old_pid,
                    crash_report = %report.display(),
                    "previous daemon panicked — see crash report"
                );
            } else {
                tracing::warn!(
                    old_pid,
                    "previous daemon exited without a panic report — killed externally \
                     (SIGKILL / OOM / power loss / forced restart), not a Rust panic"
                );
            }
            let duration = modified.and_then(|m| m.elapsed().ok()).map_or_else(
                || "unknown".to_string(),
                |d| {
                    let secs = d.as_secs();
                    if secs < 60 {
                        format!("{secs}s")
                    } else {
                        format!("{}m", secs / 60)
                    }
                },
            );
            crate::notify::daemon_recovery_toast(&duration);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = old_pid;
    }
}

/// Kill any *other* kyrisd processes owned by this user before we claim
/// the pidfile and port, so exactly one kyrisd survives any start —
/// install or reboot.
///
/// Production kyrisd is launchd-managed and does not orphan, but dev/test
/// runs of the debug binary (`target/debug/kyrisd`) or the cargo test
/// binary (`target/debug/deps/kyrisd-<hex>`) can detach from their parent
/// when the terminal/cargo/IDE that launched them goes away, surviving as
/// strays reparented to launchd. This sweep cleans them up at the next
/// canonical start instead of letting them linger.
///
/// Safety bounds, in order of importance:
/// - never our own PID;
/// - only processes owned by our own UID (never signal another user);
/// - only executables whose file name is exactly `kyrisd` or a cargo
///   test/bench binary (`kyrisd-<hex>`) — the CLI (`kyris`, `kyris-mcp`)
///   and `agentpactd` are deliberately excluded.
///
/// Each stray gets SIGTERM, a short grace period, then SIGKILL if it is
/// still alive.
#[cfg(unix)]
pub(super) async fn reap_stray_daemons() {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::{Pid, Uid};
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let own_pid = std::process::id();
    let owner_uid = Uid::current().as_raw();

    let mut sys = System::new();
    let refresh = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::Always)
        .with_user(UpdateKind::Always);
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);

    let strays: Vec<u32> = sys
        .processes()
        .values()
        .filter_map(|proc| {
            let pid = proc.pid().as_u32();
            if pid == own_pid {
                return None;
            }
            // Same user only — never signal another user's processes.
            // sysinfo's `Uid` derefs to the raw `libc::uid_t`, which is
            // exactly what `nix::Uid::as_raw()` returns.
            if proc.user_id().map(|uid| **uid) != Some(owner_uid) {
                return None;
            }
            let name = proc.exe()?.file_name()?.to_str()?;
            is_kyrisd_executable(name).then_some(pid)
        })
        .collect();

    if strays.is_empty() {
        return;
    }

    tracing::warn!(?strays, "reaping stray kyrisd process(es) on startup");
    for &pid in &strays {
        let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    for &pid in &strays {
        let target = Pid::from_raw(pid as i32);
        // `kill(.., None)` is signal 0: Ok means the process still exists
        // and we may signal it. Anything else (exited, or now unowned) we
        // leave alone.
        if signal::kill(target, None).is_ok() {
            tracing::warn!(pid, "stray kyrisd ignored SIGTERM — sending SIGKILL");
            let _ = signal::kill(target, Signal::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
pub(super) async fn reap_stray_daemons() {}

/// `true` for a kyrisd executable file name: the installed/dev binary
/// (`kyrisd`) or a cargo test/bench binary (`kyrisd-<hex>`). Excludes
/// `kyris`, `kyris-mcp`, `agentpactd`, and unrelated names.
#[cfg(unix)]
pub(super) fn is_kyrisd_executable(file_name: &str) -> bool {
    if file_name == "kyrisd" {
        return true;
    }
    match file_name.strip_prefix("kyrisd-") {
        Some(suffix) => !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

pub(super) fn write_pid_file() {
    let pid_path = kyris_core::paths::pid_path();
    if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&pid_path, std::process::id().to_string()) {
        tracing::warn!(error = %e, "failed to write PID file");
    }
}

pub(super) fn remove_pid_file() {
    let _ = std::fs::remove_file(kyris_core::paths::pid_path());
}

/// Flush the stats pipeline on shutdown.
///
/// In-flight HTTP requests are ALREADY drained by the server's graceful
/// shutdown (`serve_with_graceful_shutdown`) before this runs, so there is
/// nothing here to wait on for request draining — dropping the stats sender
/// lets the writer task finish the channel, bounded by `drain_timeout` so a
/// stuck writer can't hang exit. (A previous version slept the full
/// `drain_timeout` unconditionally here, which made EVERY shutdown take the
/// whole budget — ~30s by default — even when idle. That delayed clean exit
/// past the test harness's force-kill window, leaving a stale PID file that the
/// next start reported as "previous daemon crashed".)
pub(super) async fn drain_and_flush_stats(
    stats_tx: mpsc::Sender<StatsEvent>,
    stats_writer_handle: tokio::task::JoinHandle<()>,
    drain_timeout: Duration,
) -> Result<(), String> {
    tracing::info!("flushing stats pipeline on shutdown");
    drop(stats_tx);
    tokio::time::timeout(drain_timeout, stats_writer_handle)
        .await
        .map_err(|_| "timed out waiting for stats writer flush".to_string())?
        .map_err(|error| format!("stats writer task failed: {error}"))?;
    Ok(())
}

pub(super) async fn run_pending_prune(pending: Arc<PendingStore>) {
    let mut interval = tokio::time::interval(Duration::from_mins(1));
    interval.tick().await; // skip immediate first tick
    loop {
        interval.tick().await;
        pending.prune_resolved();
    }
}
