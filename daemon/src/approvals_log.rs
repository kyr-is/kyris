// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Append-only JSONL record of every popup-resolved approval.
//!
//! Writes to `~/.local/state/kyris/approvals.jsonl` (see
//! `kyris_core::paths::approvals_log_path`). Fire-and-forget: any I/O error
//! is logged via `tracing::warn` and dropped — never blocks the popup
//! flow. The `AgentPact` `events.jsonl` is still the cryptographic record
//! of every permission request; this file is the user-facing recall log
//! restricted to asks the user actually clicked on.
//!
//! Schema is intentionally narrow (one record per popup answer) so the
//! file can also feed offline command-catalog mining: group by `command`,
//! count, and emit YAML suggestions for the bundled catalog. See item 3
//! discussion in PR notes.

use std::fs::OpenOptions;
use std::io::Write as _;

use serde::Serialize;

/// One popup-resolved decision. Written as a single JSONL line.
#[derive(Debug, Serialize)]
pub struct ApprovalRecord<'a> {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// `agentpactd`'s pending request id — cross-reference for events.jsonl.
    pub pending_id: &'a str,
    /// Server / category label as carried in the hold request
    /// (e.g. shell-hook name, MCP server name).
    pub server: &'a str,
    /// **Verbatim** payload the user actually approved — the shell command
    /// as it would be executed, the file path being read/written, or the
    /// serialized MCP call. Multi-line commands are preserved via JSON's
    /// standard `\n` escaping; parsers reconstruct them transparently.
    /// This is the single source of truth for recall and catalog mining;
    /// the agent's tool label (`"Bash"`, `"Read"`) is intentionally not
    /// recorded because it adds no information beyond the command itself.
    pub command: Option<&'a str>,
    /// Source agent if attributable (`claude-code`, `codex-cli`, …) or
    /// `"unknown"`.
    pub agent: &'a str,
    /// Decision the user clicked. One of `approved` / `denied` / `always`.
    pub decision: &'a str,
}

/// Best-effort append of one approval record. Never panics; never blocks
/// the caller on filesystem latency beyond a single write syscall.
pub fn record(entry: &ApprovalRecord<'_>) {
    let path = kyris_core::paths::approvals_log_path();
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(
            error = %e,
            path = %parent.display(),
            "approvals_log: cannot create state dir; record dropped"
        );
        return;
    }

    let line = match serde_json::to_string(entry) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "approvals_log: serialize failed; record dropped");
            return;
        }
    };

    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "approvals_log: open failed; record dropped"
            );
            return;
        }
    };

    if let Err(e) = writeln!(file, "{line}") {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "approvals_log: write failed; record dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRecordSerializesExpectedShape() {
        // Sanity check on the serialized JSON shape — guards against future
        // field renames that would silently break the `kyris approvals` view.
        let rec = ApprovalRecord {
            ts: "2026-05-17T12:34:56Z".to_string(),
            pending_id: "req_abc",
            server: "claude-code",
            command: Some("git status"),
            agent: "claude-code",
            decision: "approved",
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        assert!(json.contains(r#""ts":"2026-05-17T12:34:56Z""#));
        assert!(json.contains(r#""pending_id":"req_abc""#));
        assert!(json.contains(r#""decision":"approved""#));
        assert!(json.contains(r#""command":"git status""#));
        // tool field intentionally absent — `"Bash"` adds no info over the command
        assert!(!json.contains(r#""tool""#));
    }

    #[test]
    fn testRecordPreservesMultilineCommandViaJsonEscaping() {
        // Multi-line commands embed as a single JSONL record using `\n` —
        // parsers reconstruct the original transparently. Critical for the
        // catalog-mining use case (heredocs, multi-statement bash).
        let rec = ApprovalRecord {
            ts: "2026-05-17T12:34:56Z".to_string(),
            pending_id: "req_multi",
            server: "claude-code",
            command: Some("git status\necho hello\nrm -rf /tmp/test"),
            agent: "claude-code",
            decision: "always",
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        // Serialized record must stay on one line so JSONL streaming works.
        assert!(!json.contains('\n'));
        // Newlines preserved as JSON `\n` escape.
        assert!(json.contains(r#""command":"git status\necho hello\nrm -rf /tmp/test""#));
        // Round-trip reconstructs the original multi-line string.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(
            parsed["command"].as_str(),
            Some("git status\necho hello\nrm -rf /tmp/test")
        );
    }

    #[test]
    fn testRecordHandlesAbsentCommand() {
        let rec = ApprovalRecord {
            ts: "2026-05-17T12:34:56Z".to_string(),
            pending_id: "req_xyz",
            server: "shell",
            command: None,
            agent: "unknown",
            decision: "denied",
        };
        let json = serde_json::to_string(&rec).expect("serialize");
        assert!(json.contains(r#""command":null"#));
    }
}
