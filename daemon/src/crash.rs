// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Crash reporting. On panic, writes a sanitized text report into the
//! configured crash directory and logs an error line so launchd
//! captures it in `kyrisd.log`. Does not swallow the panic —
//! the process still aborts and launchd's `KeepAlive.Crashed = true`
//! restarts the daemon.

use std::backtrace::Backtrace;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

use crate::build_info;

/// Path that the active panic hook will write reports into. Wrapped
/// in a Mutex so the early hook (installed before config loads) can
/// be retargeted when the config-aware hook calls
/// `install_panic_hook` with the resolved crash directory.
static CRASH_DIR: OnceLock<Mutex<PathBuf>> = OnceLock::new();
static STARTED_AT: OnceLock<Instant> = OnceLock::new();

/// Install an early panic hook with a best-effort fallback crash
/// directory (see [`kyris_core::paths::crash_dir`], default
/// `$HOME/.local/state/kyris/crash`). Call this BEFORE config loading
/// so panics in `logging::init` or `config::load_config` still
/// produce a report. The config-aware path is installed later via
/// [`install_panic_hook`].
///
/// Crash dumps live under `XDG_STATE_HOME`, not under the
/// install-managed runtime dir — they survive uninstall as audit
/// trail unless wiped with `--reset-data`.
pub fn install_early_panic_hook(started_at: Instant) {
    let fallback = fallback_crash_dir();
    install_panic_hook(fallback, started_at);
}

fn fallback_crash_dir() -> PathBuf {
    kyris_core::paths::crash_dir()
}

/// Install (or retarget) the global panic hook so reports land under
/// `crash_dir`. First call installs the hook; subsequent calls just
/// update the target directory — useful for swapping from the
/// fallback to the config-aware location once config has loaded.
/// `started_at` is captured on first call so uptime in the report is
/// measured from process start, not from when the hook was retargeted.
pub fn install_panic_hook(crash_dir: PathBuf, started_at: Instant) {
    if let Some(lock) = CRASH_DIR.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = crash_dir;
        }
        return;
    }

    let _ = STARTED_AT.set(started_at);
    let _ = CRASH_DIR.set(Mutex::new(crash_dir));

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info.location().map_or_else(
            || "<unknown location>".to_string(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let message = payload_message(info);
        let backtrace = Backtrace::force_capture().to_string();
        let started = STARTED_AT.get().copied().unwrap_or_else(Instant::now);
        let report = format_report(started, &location, &message, &backtrace);
        let dir = CRASH_DIR
            .get()
            .and_then(|m| m.lock().ok().map(|g| g.clone()))
            .unwrap_or_else(fallback_crash_dir);
        let path = write_report(&dir, &report);
        match &path {
            Some(p) => {
                tracing::error!(crash_report = %p.display(), "kyrisd panicked");
            }
            None => {
                tracing::error!("kyrisd panicked (crash report write failed)");
            }
        }
        prev(info);
    }));
}

fn format_report(started_at: Instant, location: &str, message: &str, backtrace: &str) -> String {
    let uptime = started_at.elapsed().as_secs();
    format!(
        "{}\npid: {}\nuptime_secs: {}\nlocation: {}\nmessage: {}\n\nbacktrace:\n{}\n",
        build_info::version_line(),
        std::process::id(),
        uptime,
        location,
        message,
        backtrace,
    )
}

fn write_report(crash_dir: &std::path::Path, report: &str) -> Option<PathBuf> {
    let _ = std::fs::create_dir_all(crash_dir);
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%fZ");
    let path = crash_dir.join(format!("kyrisd-{ts}.txt"));
    std::fs::write(&path, report).ok().map(|()| path)
}

fn payload_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testFormatReportIncludesAllFields() {
        let report = format_report(
            Instant::now(),
            "src/foo.rs:42:10",
            "boom",
            "frame#0\nframe#1",
        );
        assert!(report.contains("kyrisd"));
        assert!(report.contains("location: src/foo.rs:42:10"));
        assert!(report.contains("message: boom"));
        assert!(report.contains("backtrace:\nframe#0"));
        assert!(report.contains(&format!("pid: {}", std::process::id())));
    }

    #[test]
    fn testWriteReportPersistsToCrashDir() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_report(dir.path(), "hello world").expect("write succeeds");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");
        assert!(path.starts_with(dir.path()));
        assert!(
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap()
                .starts_with("kyrisd-"),
        );
    }
}
