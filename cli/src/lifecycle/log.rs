// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

const RULE: &str = "----------------------------------------------------------------";

/// Unified log for install, uninstall, and update operations.
///
/// All operations append to the path returned by
/// [`kyris_core::paths::log_path`] (default
/// `~/.local/state/kyris/log/kyris.log`). Each session opens
/// with a horizontal rule and header so install/uninstall/update
/// boundaries are easy to find by eye.
///
/// Format:
///   `TIMESTAMP [component] [ACTION] path`      ← file operations
///   `TIMESTAMP [component] [INFO] message`     ← informational
///   `TIMESTAMP [component] [WARN] message`     ← warnings
///   `TIMESTAMP [component] [ERROR] message`    ← errors
///
/// All writes are best-effort — a logging failure never aborts the
/// operation itself.
pub struct InstallLog {
    inner: Option<File>,
    path: PathBuf,
    component: &'static str,
}

impl InstallLog {
    /// Open for a `kyris install` session. Writes a horizontal rule
    /// and session header before the first entry.
    pub fn open_install() -> Self {
        Self::open("install", "kyris install")
    }

    /// Open for a `kyris uninstall` session.
    pub fn open_uninstall() -> Self {
        Self::open("uninstall", "kyris uninstall")
    }

    /// Open for a `kyris update` session.
    pub fn open_update() -> Self {
        Self::open("update", "kyris update")
    }

    /// No-op instance that silently discards all writes. Used in tests
    /// that exercise logic which takes an `&InstallLog` but don't care
    /// about the log output.
    #[cfg(test)]
    pub fn null() -> Self {
        InstallLog {
            inner: None,
            path: PathBuf::new(),
            component: "null",
        }
    }

    fn open(component: &'static str, header: &str) -> Self {
        let path = kyris_log_path();
        match open_log_at(&path) {
            Ok(mut file) => {
                let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                let banner = format!("{RULE}\n{ts} [{component}] {header}\n{RULE}\n");
                let _ = file.write_all(banner.as_bytes());
                InstallLog {
                    inner: Some(file),
                    path,
                    component,
                }
            }
            Err(e) => {
                eprintln!("[kyris] Could not open kyris.log: {e}");
                InstallLog {
                    inner: None,
                    path: PathBuf::new(),
                    component,
                }
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// File was newly created.
    pub fn created(&self, path: &str) {
        self.write("CREATE", path);
    }

    /// Existing file was overwritten with new content.
    pub fn updated(&self, path: &str) {
        self.write("UPDATE", path);
    }

    /// Binary was replaced during update.
    pub fn replaced(&self, path: &str) {
        self.write("REPLACE", path);
    }

    /// File already matched; no write needed.
    pub fn skipped(&self, path: &str, reason: &str) {
        self.write("SKIP", &format!("{path} — {reason}"));
    }

    /// A line was appended to an existing file.
    pub fn appended(&self, path: &str, line: &str) {
        self.write("APPEND", &format!("{path} — {line}"));
    }

    /// A file or directory was removed during uninstall.
    pub fn removed(&self, path: &str) {
        self.write("REMOVE", path);
    }

    /// Kyris-added lines were surgically stripped from a file.
    pub fn stripped(&self, path: &str) {
        self.write("STRIP", path);
    }

    /// Structural JSON/TOML patch was unapplied.
    pub fn unpatched(&self, path: &str) {
        self.write("UNPATCH", path);
    }

    /// Informational message (section headers, service state, etc.).
    pub fn info(&self, msg: &str) {
        self.write("INFO", msg);
    }

    /// Unexpected or potentially surprising situation that was handled.
    pub fn warn(&self, msg: &str) {
        self.write("WARN", msg);
    }

    /// Operation failed; install/uninstall may have continued anyway.
    pub fn error(&self, msg: &str) {
        self.write("ERROR", msg);
    }

    fn write(&self, tag: &str, msg: &str) {
        let Some(ref file) = self.inner else { return };
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let line = format!("{ts} [{}] [{tag}] {msg}\n", self.component);
        let _ = (file as &File).write_all(line.as_bytes());
    }
}

pub fn kyris_log_path() -> PathBuf {
    kyris_core::paths::log_path()
}

fn open_log_at(path: &std::path::Path) -> Result<File, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create log dir {}: {e}", parent.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Cannot open {}: {e}", path.display()))
}
