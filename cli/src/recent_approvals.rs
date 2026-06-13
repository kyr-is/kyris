// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Short-lived record of human approvals granted through kyris's ask popup,
//! consumed by an agent's native-approval hook (Codex `PermissionRequest`) so
//! the SAME command the developer just approved is not prompted a second time
//! by the agent's own approval ladder.
//!
//! A note is keyed by `(agent, action, cwd, detail)` — the exact request the
//! human saw — and is single-use with a short TTL: the agent's native prompt
//! follows the kyris approval within the same tool dispatch (milliseconds),
//! so anything older is a different invocation and must prompt normally.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(30);

fn notes_dir() -> PathBuf {
    kyris_core::paths::runtime_dir().join("recent-approvals")
}

fn note_path(agent: &str, action: &str, cwd: Option<&str>, detail: &str) -> PathBuf {
    let identity = format!("{agent}\x1f{action}\x1f{}\x1f{detail}", cwd.unwrap_or(""));
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, identity.as_bytes());
    let hex: String = digest.as_ref().iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
        out
    });
    notes_dir().join(hex)
}

fn is_fresh(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .is_ok_and(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .is_ok_and(|age| age <= TTL)
        })
}

/// Record a popup approval. Best-effort (a lost note only means one extra
/// native prompt); stale notes are pruned opportunistically.
pub fn record(agent: &str, action: &str, cwd: Option<&str>, detail: &str) {
    let dir = notes_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.filter_map(Result::ok) {
            if !is_fresh(&entry.path()) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let _ = std::fs::write(note_path(agent, action, cwd, detail), "");
}

/// Consume the note for this exact request if one is fresh: removes it and
/// returns true. Single-use — a second native prompt for the same command
/// must reach the human again.
pub fn consume(agent: &str, action: &str, cwd: Option<&str>, detail: &str) -> bool {
    let path = note_path(agent, action, cwd, detail);
    if !is_fresh(&path) {
        let _ = std::fs::remove_file(&path);
        return false;
    }
    std::fs::remove_file(&path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // note_path/notes_dir depend on HOME via paths::runtime_dir; exercising
    // record/consume against the real layout would race other HOME-mutating
    // tests, so the round-trip is covered via the keying function with the
    // pure parts asserted here and behavior verified in the live roundtrip.
    #[test]
    fn testNoteKeyDistinguishesEveryField() {
        let base = note_path("codex-cli", "execute", Some("/w"), "rm -rf build");
        assert_ne!(
            base,
            note_path("codex-cli", "execute", Some("/w"), "rm -rf src")
        );
        assert_ne!(
            base,
            note_path("codex-cli", "execute", Some("/x"), "rm -rf build")
        );
        assert_ne!(
            base,
            note_path("codex-cli", "apply_patch", Some("/w"), "rm -rf build")
        );
        assert_ne!(
            base,
            note_path("cline", "execute", Some("/w"), "rm -rf build")
        );
        // Field-boundary safety: (a|b, c) must not collide with (a, b|c).
        assert_ne!(
            note_path("a", "b", Some("c"), "d"),
            note_path("a", "bc", None, "d")
        );
    }
}
