// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Append-only operational evidence for approval prompt attempts.
//!
//! `approvals.jsonl` answers "what did the user approve?". This log answers
//! "was a prompt actually attempted, on which surface, and what happened?".

use std::fs::OpenOptions;
use std::io::Write as _;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PromptRecord<'a> {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// `AgentPact` pending request id.
    pub pending_id: &'a str,
    /// Prompt surface: `tray`, `cli`, `api`, `hook`, or a future surface name.
    pub surface: &'a str,
    /// State transition: `held`, `dispatch`, `displayed`, `not_shown`,
    /// `decision_submitted`, `resolved`, `timeout`, etc.
    pub event: &'a str,
    pub server: &'a str,
    pub tool: Option<&'a str>,
    /// Verbatim command/code/path when available.
    pub command: Option<&'a str>,
    /// Source agent if known (`codex-cli`, `claude-code`, ...), else unknown.
    pub agent: &'a str,
    pub allow_always: bool,
    /// Optional result detail such as `approved`, `denied`, `always`,
    /// `could_not_show`, or an error class.
    pub outcome: Option<&'a str>,
}

pub fn record(entry: &PromptRecord<'_>) {
    let path = crate::paths::prompts_log_path();
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "[kyris] prompt_log: cannot create state dir {}: {e}",
            parent.display()
        );
        return;
    }

    let line = match serde_json::to_string(entry) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[kyris] prompt_log: serialize failed: {e}");
            return;
        }
    };

    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "[kyris] prompt_log: open failed for {}: {e}",
                path.display()
            );
            return;
        }
    };

    if let Err(e) = writeln!(file, "{line}") {
        eprintln!(
            "[kyris] prompt_log: write failed for {}: {e}",
            path.display()
        );
    }
}

// Positional mirror of `PromptRecord`'s fields with `ts` stamped here; the
// field count tracks the struct, not a signature that wants decomposing.
#[allow(clippy::too_many_arguments)]
pub fn record_now(
    pending_id: &str,
    surface: &str,
    event: &str,
    server: &str,
    tool: Option<&str>,
    command: Option<&str>,
    agent: &str,
    allow_always: bool,
    outcome: Option<&str>,
) {
    record(&PromptRecord {
        ts: chrono::Utc::now().to_rfc3339(),
        pending_id,
        surface,
        event,
        server,
        tool,
        command,
        agent,
        allow_always,
        outcome,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testPromptRecordSerializesExpectedShape() {
        let record = PromptRecord {
            ts: "2026-06-08T22:30:00Z".to_string(),
            pending_id: "req-1",
            surface: "cli",
            event: "displayed",
            server: "shell",
            tool: Some("printf ok"),
            command: Some("printf ok"),
            agent: "codex-cli",
            allow_always: false,
            outcome: None,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains(r#""surface":"cli""#));
        assert!(json.contains(r#""event":"displayed""#));
        assert!(json.contains(r#""command":"printf ok""#));
    }
}
