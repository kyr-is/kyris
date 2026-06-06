// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris logs` — list the log files kyris and its dependencies write.
//!
//! Replaces the removed `Open Logs` tray menu item. Prints path, size,
//! and last-modified time so the operator can tail or grep them from
//! the shell. Deliberately does not open anything: `Console.app` is
//! unloved; modern operators use their own tools.

use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::time::SystemTime;

/// Print the list of kyris log files with size and last-modified time.
///
/// Covers kyrisd's in-process log, the launchd-captured stdout/stderr
/// log, the agentpactd log, and the shell-hook fail-open log. Missing
/// files are listed too with `-` for size/mtime, since "we expected one
/// here" is just as useful for diagnosis as the existing files.
#[derive(Args)]
pub struct LogsArgs {
    #[command(subcommand)]
    pub command: Option<LogsSubcommand>,
}

#[derive(Subcommand)]
pub enum LogsSubcommand {
    /// Render every event/record across both stores sharing a correlation id
    Trace(crate::query::trace::TraceArgs),
}

pub fn run(args: LogsArgs) {
    match args.command {
        None => {
            let entries = collect_log_entries();
            print_table(&entries);
        }
        Some(LogsSubcommand::Trace(a)) => crate::query::trace::run(a),
    }
}

struct LogEntry {
    label: &'static str,
    path: PathBuf,
}

fn collect_log_entries() -> Vec<LogEntry> {
    let mut entries = vec![
        LogEntry {
            label: "kyris",
            path: kyris_core::paths::log_path(),
        },
        LogEntry {
            label: "kyrisd (launchd)",
            path: kyris_core::paths::launchd_log_path(),
        },
    ];
    entries.push(LogEntry {
        label: "agentpactd",
        path: agentpactd_log_path(),
    });
    let fail_open = kyris_core::paths::state_dir().join("fail-open.jsonl");
    entries.push(LogEntry {
        label: "shell fail-open",
        path: fail_open,
    });
    entries
}

fn agentpactd_log_path() -> PathBuf {
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(state)
            .join("agentpact")
            .join("log")
            .join("agentpactd.log");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("agentpact")
        .join("log")
        .join("agentpactd.log")
}

fn print_table(entries: &[LogEntry]) {
    let label_w = entries
        .iter()
        .map(|e| e.label.len())
        .max()
        .unwrap_or(0)
        .max("LOG".len());
    let path_w = entries
        .iter()
        .map(|e| e.path.to_string_lossy().len())
        .max()
        .unwrap_or(0)
        .max("PATH".len());
    println!(
        "{:<label_w$}  {:<path_w$}  {:>9}  MODIFIED",
        "LOG",
        "PATH",
        "SIZE",
        label_w = label_w,
        path_w = path_w
    );
    for entry in entries {
        let (size, modified) = describe(&entry.path);
        println!(
            "{:<label_w$}  {:<path_w$}  {:>9}  {}",
            entry.label,
            entry.path.display(),
            size,
            modified,
            label_w = label_w,
            path_w = path_w
        );
    }
}

fn describe(path: &std::path::Path) -> (String, String) {
    let Ok(meta) = std::fs::metadata(path) else {
        return ("-".to_string(), "(missing)".to_string());
    };
    let size = humanize_bytes(meta.len());
    let modified = meta
        .modified()
        .ok()
        .map_or_else(|| "-".to_string(), format_modified);
    (size, modified)
}

#[allow(clippy::cast_precision_loss)]
fn humanize_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value < KIB {
        format!("{bytes} B")
    } else if value < KIB * KIB {
        format!("{:.1} KB", value / KIB)
    } else if value < KIB * KIB * KIB {
        format!("{:.1} MB", value / (KIB * KIB))
    } else {
        format!("{:.1} GB", value / (KIB * KIB * KIB))
    }
}

fn format_modified(mtime: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Local> = mtime.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testHumanizeBytesBelowKb() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
    }

    #[test]
    fn testHumanizeBytesKbMbGb() {
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn testDescribeReturnsMissingForMissingPath() {
        let (size, modified) = describe(std::path::Path::new("/definitely/not/a/real/log/path"));
        assert_eq!(size, "-");
        assert_eq!(modified, "(missing)");
    }

    #[test]
    fn testCollectLogEntriesIncludesCoreFour() {
        let entries = collect_log_entries();
        let labels: Vec<&'static str> = entries.iter().map(|e| e.label).collect();
        assert!(labels.contains(&"kyris"));
        assert!(labels.contains(&"kyrisd (launchd)"));
        assert!(labels.contains(&"agentpactd"));
        assert!(labels.contains(&"shell fail-open"));
    }
}
