// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris approvals` — recall view over the popup-resolved approvals log
//! (`~/.local/state/kyris/approvals.jsonl`).
//!
//! Reads the JSONL file written by `kyrisd::approvals_log::record` and
//! emits a human or machine-readable view. Intentionally narrow: this is
//! the recall surface ("what did I approve last week?"), separate from
//! the `AgentPact` `events.jsonl` cryptographic record served by
//! `kyris timeline` / `kyris history`.

use std::fs::File;
use std::io::{BufRead, BufReader};

use clap::Args;
use serde::Deserialize;

#[derive(Args)]
pub struct ApprovalsArgs {
    /// Filter to a single decision value (`approved`, `denied`, `always`).
    #[arg(long)]
    pub decision: Option<String>,
    /// Output as JSONL (one record per line, unfiltered fields) instead
    /// of the default human-readable table.
    #[arg(long)]
    pub json: bool,
    /// Maximum number of most-recent rows to show (default 50).
    #[arg(long, default_value_t = 50)]
    pub last: usize,
}

#[derive(Deserialize)]
struct LogRow {
    ts: String,
    pending_id: String,
    server: String,
    command: Option<String>,
    agent: String,
    decision: String,
}

pub fn run(args: ApprovalsArgs) {
    let path = kyris_core::paths::approvals_log_path();
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No approvals recorded yet ({}).", path.display());
            return;
        }
        Err(e) => {
            eprintln!("Cannot read {}: {e}", path.display());
            std::process::exit(1);
        }
    };

    // Stream the file; collect into a vector so we can show the last N
    // chronologically. Approval logs grow slowly (one entry per popup);
    // a streamed pre-filter then collect is fine at any realistic size.
    let mut rows: Vec<LogRow> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<LogRow>(&l).ok())
        .filter(|r| {
            args.decision
                .as_deref()
                .is_none_or(|d| r.decision.eq_ignore_ascii_case(d))
        })
        .collect();

    let start = rows.len().saturating_sub(args.last);
    let visible = rows.drain(start..);

    if args.json {
        for row in visible {
            // Serialize back to the on-disk shape so downstream tools get
            // exactly what the log writer produced.
            let line = serde_json::json!({
                "ts": row.ts,
                "pending_id": row.pending_id,
                "server": row.server,
                "command": row.command,
                "agent": row.agent,
                "decision": row.decision,
            });
            println!("{}", serde_json::to_string(&line).unwrap_or_default());
        }
    } else {
        // Table view: collapse multi-line commands to the first line + `…`
        // suffix so the column doesn't wrap. Use --json for the verbatim
        // record (newlines preserved via JSON escaping).
        for row in visible {
            let command = match row.command {
                Some(c) => {
                    let first = c.lines().next().unwrap_or("");
                    if c.lines().count() > 1 {
                        format!("{first} …")
                    } else {
                        first.to_string()
                    }
                }
                None => "-".to_string(),
            };
            println!(
                "{ts}  {decision:<8}  {agent:<12}  {server:<16}  {command}",
                ts = row.ts,
                decision = row.decision,
                agent = row.agent,
                server = row.server,
                command = command,
            );
        }
    }
}
