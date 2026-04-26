// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write as _;

use agentpact::catalog::commands::id_to_shell;
use clap::Args;
use kyris_core::coverage;

#[derive(Args)]
pub struct ReplayArgs {
    pub session: String,
}

pub fn run(args: ReplayArgs) {
    let event_log_dir = event_log_dir();
    let kyrisd_db_path = kyrisd_db_path();

    let db = duckdb::Connection::open_in_memory().expect("open duckdb");

    let glob_jsonl = format!("{event_log_dir}/*.jsonl");
    let glob_gz = format!("{event_log_dir}/*.jsonl.gz");
    db.execute_batch(&format!(
        "CREATE VIEW events AS SELECT * FROM read_json_auto(['{glob_jsonl}', '{glob_gz}'])"
    ))
    .unwrap_or_else(|e| {
        eprintln!("No event log found at {event_log_dir}: {e}");
        std::process::exit(1);
    });

    let has_gw = if std::path::Path::new(&kyrisd_db_path).exists() {
        db.execute_batch(&format!("ATTACH '{kyrisd_db_path}' AS gw (READ_ONLY)"))
            .is_ok()
    } else {
        false
    };

    let cov = coverage::sql_expr();
    let event_query = format!(
        "SELECT timestamp, agent, action, decision, detail, \
                mode, rule_kind, rule_id, rule_display, working_dir, \
                {cov} as coverage \
         FROM events \
         WHERE session_id = ? OR session = ? \
         ORDER BY timestamp ASC"
    );

    let mut stmt = db.prepare(&event_query).unwrap_or_else(|e| {
        eprintln!("Failed to prepare query: {e}");
        std::process::exit(1);
    });
    let mut rows = stmt
        .query([&args.session, &args.session])
        .unwrap_or_else(|e| {
            eprintln!("Failed to execute query: {e}");
            std::process::exit(1);
        });

    let mut count = 0u64;
    while let Some(row) = rows.next().expect("read row") {
        let timestamp: String = row.get(0).unwrap_or_default();
        let agent: String = row.get(1).unwrap_or_default();
        let action: String = row.get(2).unwrap_or_default();
        let decision: String = row.get(3).unwrap_or_default();
        let detail: String = row.get(4).unwrap_or_default();
        let mode: String = row.get(5).unwrap_or_default();
        let rule_kind: Option<String> = row.get(6).ok();
        let rule_id: Option<String> = row.get(7).ok();
        let rule_display: Option<String> = row.get(8).ok();
        let coverage: String = row.get(10).unwrap_or_default();

        let mut line =
            format!("{timestamp}  {agent:<15} {action:<10} {decision:<8} [{coverage:<8}] {detail}");
        if !mode.is_empty() {
            let _ = write!(line, "  mode={mode}");
        }
        if let Some(ref kind) = rule_kind {
            let _ = write!(line, "  rule={kind}");
            if let Some(ref id) = rule_id {
                let _ = write!(line, ":{}", id_to_shell(id));
            }
        }
        if let Some(ref display) = rule_display {
            let _ = write!(line, "  ({display})");
        }

        println!("{line}");
        count += 1;
    }

    if has_gw {
        let gw_query = "SELECT timestamp, provider, model, tokens_in, tokens_out, \
                    cost_usd, latency_ms, status, metering, mcp_server, mcp_tool \
             FROM gw.gateway_records \
             WHERE session_id = ? \
             ORDER BY timestamp ASC";

        let Ok(mut gw_stmt) = db.prepare(gw_query) else {
            return;
        };
        let Ok(mut gw_rows) = gw_stmt.query([&args.session]) else {
            return;
        };
        let mut gw_count = 0u64;
        while let Some(row) = gw_rows.next().expect("read gw row") {
            if gw_count == 0 {
                println!("\nGateway records:");
            }
            let timestamp: String = row.get(0).unwrap_or_default();
            let provider: String = row.get(1).unwrap_or_default();
            let model: String = row.get(2).unwrap_or_default();
            let tokens_in: Option<i64> = row.get(3).ok();
            let tokens_out: Option<i64> = row.get(4).ok();
            let cost_usd: Option<f64> = row.get(5).ok();
            let latency_ms: i64 = row.get(6).unwrap_or(0);
            let status: String = row.get(7).unwrap_or_default();
            let metering: String = row.get(8).unwrap_or_default();
            let mcp_server: Option<String> = row.get(9).ok();
            let mcp_tool: Option<String> = row.get(10).ok();

            let mut line =
                format!("  {timestamp}  {provider:<12} {model:<30} {status:<8} {latency_ms:>5}ms");
            if metering == "unavailable" {
                line.push_str("  [usage unavailable]");
            } else if let (Some(ti), Some(to)) = (tokens_in, tokens_out) {
                let _ = write!(line, "  [{ti}\u{2192}{to}]");
            }
            if let Some(cost) = cost_usd {
                let _ = write!(line, "  ${cost:.4}");
            }
            if let Some(ref server) = mcp_server {
                let _ = write!(line, "  mcp={server}");
                if let Some(ref tool) = mcp_tool {
                    let _ = write!(line, "/{tool}");
                }
            }
            println!("{line}");
            gw_count += 1;
        }
        count += gw_count;
    }

    if count == 0 {
        eprintln!("No events found for session: {}", args.session);
    } else {
        eprintln!("\n{count} events replayed.");
    }
}

fn event_log_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.agentpact/log")
}

fn kyrisd_db_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.kyris/kyrisd.duckdb")
}
