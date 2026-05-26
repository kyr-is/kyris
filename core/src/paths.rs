// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Centralized filesystem paths the kyris daemon, CLI, and helpers all read
//! from. Three lifecycle categories, all rooted at HOME or XDG_*_HOME:
//!
//!   * [`runtime_dir`] (`~/.kyris/`)              install-managed —
//!     manifest, hook scripts, agent integrations, env shim, backups, pid
//!     file. Safe for `kyris uninstall` / `brew uninstall` to wipe in full;
//!     the installer recreates whatever it owns on next install.
//!
//!   * [`config_dir`] (`~/.config/kyris/`)         user-editable —
//!     kyrisd.yaml. Survives uninstall by design; wiped only by
//!     `--reset-data` / `brew uninstall --zap`.
//!
//!   * [`data_dir`] (`~/.local/share/kyris/`)      precious user data —
//!     credentials.json (sync auth) and kyrisd.duckdb (event-log history).
//!     Regenerating these means losing real history; survives uninstall.
//!
//!   * [`state_dir`] (`~/.local/state/kyris/`)     rotating state —
//!     kyris.log, kyrisd.{stderr,stdout}.log, crash/, diagnostics/,
//!     fail-open.jsonl. Survives uninstall but the user can rotate /
//!     prune freely; wiped on `--reset-data`.
//!
//! The split is what makes "upgrade = uninstall + install" safe: the
//! install-managed dir gets wiped on every cycle, while the three
//! XDG dirs are preserved. Without this split we'd need to layer
//! preserve/restore copy ceremony around every upgrade.
//!
//! XDG env vars (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`) and
//! `KYRIS_HOME` are honored per-category. `KYRIS_HOME` overrides only the
//! runtime dir; the XDG dirs follow `HOME` regardless, so test sandboxes
//! and dev overrides don't accidentally hide precious data behind a
//! runtime-only redirect.

use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::var("HOME").map_or_else(|_| PathBuf::from("/"), PathBuf::from)
}

/// `~/.kyris/` — install-managed runtime ephemera + scaffolding. Holds the
/// install manifest, hook scripts, agent integration backups, env shim, and
/// the pid file. Anything in here is rebuilt by `kyris install` and freely
/// removed by uninstall.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("KYRIS_HOME") {
        return PathBuf::from(explicit);
    }
    home().join(".kyris")
}

/// `$XDG_CONFIG_HOME/kyris/` (default `~/.config/kyris/`) — user-editable
/// configuration that survives uninstall.
#[must_use]
pub fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map_or_else(|_| home().join(".config"), PathBuf::from)
        .join("kyris")
}

/// `$XDG_DATA_HOME/kyris/` (default `~/.local/share/kyris/`) — precious
/// user data (credentials, event-log database). Survives uninstall.
#[must_use]
pub fn data_dir() -> PathBuf {
    std::env::var("XDG_DATA_HOME")
        .map_or_else(|_| home().join(".local").join("share"), PathBuf::from)
        .join("kyris")
}

/// `$XDG_STATE_HOME/kyris/` (default `~/.local/state/kyris/`) — rotating
/// state: logs, crash reports, diagnostics, fail-open spool.
#[must_use]
pub fn state_dir() -> PathBuf {
    std::env::var("XDG_STATE_HOME")
        .map_or_else(|_| home().join(".local").join("state"), PathBuf::from)
        .join("kyris")
}

// --- install-managed (runtime_dir) -----------------------------------------

/// `~/.kyris/manifest.json` — install manifest enumerating every file
/// `kyris install` ever wrote (for surgical uninstall).
#[must_use]
pub fn manifest_path() -> PathBuf {
    runtime_dir().join("manifest.json")
}

/// `~/.kyris/hooks/` — agent hook scripts kyris install drops in place.
#[must_use]
pub fn hooks_dir() -> PathBuf {
    runtime_dir().join("hooks")
}

/// `~/.kyris/agents/` — per-agent integration state managed by reconcile.
#[must_use]
pub fn agents_dir() -> PathBuf {
    runtime_dir().join("agents")
}

/// `~/.kyris/backups/` — pre-edit backups kyris install creates before
/// touching agent JSON configs.
#[must_use]
pub fn backups_dir() -> PathBuf {
    runtime_dir().join("backups")
}

/// `~/.kyris/env` — shell env shim kyris install sources into rc files.
#[must_use]
pub fn env_shim_path() -> PathBuf {
    runtime_dir().join("env")
}

/// `~/.kyris/kyrisd.pid` — runtime pid file for the daemon.
#[must_use]
pub fn pid_path() -> PathBuf {
    runtime_dir().join("kyrisd.pid")
}

// --- user-editable config (config_dir) -------------------------------------

/// `~/.config/kyris/kyrisd.yaml` — the daemon's user-editable config.
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join("kyrisd.yaml")
}

// --- precious user data (data_dir) -----------------------------------------

/// `~/.local/share/kyris/kyrisd.duckdb` — event-log database. The audit
/// trail lives here; losing it means losing real history.
#[must_use]
pub fn storage_path() -> PathBuf {
    data_dir().join("kyrisd.duckdb")
}

/// `~/.local/share/kyris/credentials.json` — sync credentials. Regenerating
/// these requires re-enrolling, so they survive uninstall.
#[must_use]
pub fn credentials_path() -> PathBuf {
    data_dir().join("credentials.json")
}

// --- rotating state (state_dir) --------------------------------------------

/// `~/.local/state/kyris/log/` — log directory for kyris.log plus
/// launchd-captured stdout/stderr.
#[must_use]
pub fn log_dir() -> PathBuf {
    state_dir().join("log")
}

/// `~/.local/state/kyris/log/kyris.log` — the daemon's in-process log file
/// (separate from launchd-captured stdout/stderr).
#[must_use]
pub fn log_path() -> PathBuf {
    log_dir().join("kyris.log")
}

/// `~/.local/state/kyris/log/kyrisd.log` — launchd-captured stdout+stderr.
/// kyrisd writes through tracing (stderr); stdout is merged so stray
/// dependency output is also captured.
#[must_use]
pub fn launchd_log_path() -> PathBuf {
    log_dir().join("kyrisd.log")
}

/// `~/.local/state/kyris/crash/` — panic reports.
#[must_use]
pub fn crash_dir() -> PathBuf {
    state_dir().join("crash")
}

/// `~/.local/state/kyris/diagnostics/` — JSON diagnostic dumps.
#[must_use]
pub fn diagnostics_dir() -> PathBuf {
    state_dir().join("diagnostics")
}

/// `~/.local/state/kyris/fail-open.jsonl` — backup spool the daemon writes
/// to when the primary event log is broken; allows post-recovery replay.
#[must_use]
pub fn fail_open_path() -> PathBuf {
    state_dir().join("fail-open.jsonl")
}

/// `~/.local/state/kyris/approvals.jsonl` — append-only record of every
/// popup-resolved approval (yes / no / always). Source of truth for the
/// `kyris approvals` CLI; not signed (the `AgentPact` `events.jsonl`
/// remains the cryptographic record).
#[must_use]
pub fn approvals_log_path() -> PathBuf {
    state_dir().join("approvals.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // cargo test runs tests in parallel by default. The functions under test
    // read process-wide env vars, so unsynchronized tests race against each
    // other and against any other test in the crate that touches HOME/XDG_*.
    // Serialize via a module-local mutex.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn run_in_isolated_env<F: FnOnce()>(f: F) {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Snapshot relevant env vars, force a clean slate, run, restore.
        let snapshot: Vec<_> = [
            "HOME",
            "KYRIS_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
        ]
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();

        // SAFETY: env mutation is unsafe in Rust 2024 because it can race
        // other threads. ENV_LOCK above guarantees no other test in this
        // module runs concurrently; we don't claim safety against other
        // crates' tests, but cargo runs each crate's tests in a separate
        // process by default so cross-crate interference is impossible.
        unsafe {
            for (k, _) in &snapshot {
                std::env::remove_var(k);
            }
            std::env::set_var("HOME", "/h");
            f();
            for (k, v) in snapshot {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn testDefaultsFromHome() {
        run_in_isolated_env(|| {
            assert_eq!(runtime_dir(), PathBuf::from("/h/.kyris"));
            assert_eq!(config_dir(), PathBuf::from("/h/.config/kyris"));
            assert_eq!(data_dir(), PathBuf::from("/h/.local/share/kyris"));
            assert_eq!(state_dir(), PathBuf::from("/h/.local/state/kyris"));
            assert_eq!(config_path(), PathBuf::from("/h/.config/kyris/kyrisd.yaml"));
            assert_eq!(
                storage_path(),
                PathBuf::from("/h/.local/share/kyris/kyrisd.duckdb")
            );
            assert_eq!(
                credentials_path(),
                PathBuf::from("/h/.local/share/kyris/credentials.json")
            );
            assert_eq!(
                log_path(),
                PathBuf::from("/h/.local/state/kyris/log/kyris.log")
            );
            assert_eq!(crash_dir(), PathBuf::from("/h/.local/state/kyris/crash"));
        });
    }

    #[test]
    fn testKyrisHomeOverridesRuntimeOnly() {
        run_in_isolated_env(|| {
            unsafe {
                std::env::set_var("KYRIS_HOME", "/sandbox/k");
            }
            assert_eq!(runtime_dir(), PathBuf::from("/sandbox/k"));
            // XDG dirs still follow HOME — runtime override does NOT
            // transitively relocate precious data.
            assert_eq!(data_dir(), PathBuf::from("/h/.local/share/kyris"));
            assert_eq!(state_dir(), PathBuf::from("/h/.local/state/kyris"));
            assert_eq!(config_dir(), PathBuf::from("/h/.config/kyris"));
        });
    }

    #[test]
    fn testXdgEnvVarsHonored() {
        run_in_isolated_env(|| {
            unsafe {
                std::env::set_var("XDG_CONFIG_HOME", "/xcfg");
                std::env::set_var("XDG_DATA_HOME", "/xdata");
                std::env::set_var("XDG_STATE_HOME", "/xstate");
            }
            assert_eq!(config_dir(), PathBuf::from("/xcfg/kyris"));
            assert_eq!(data_dir(), PathBuf::from("/xdata/kyris"));
            assert_eq!(state_dir(), PathBuf::from("/xstate/kyris"));
            assert_eq!(runtime_dir(), PathBuf::from("/h/.kyris"));
        });
    }
}
