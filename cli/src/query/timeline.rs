// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write as _;

use clap::Args;
use kyris_core::coverage;

use super::sync_state::{build_event_sync_expr, load_sync_metadata};

#[derive(Args)]
pub struct TimelineArgs {
    #[arg(long, default_value = "20")]
    pub last: usize,
}

pub fn run(args: TimelineArgs) {
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

    let sync_meta = if has_gw {
        load_sync_metadata(&db)
    } else {
        None
    };
    let event_sync_expr = build_event_sync_expr(sync_meta.as_ref());

    let cov = coverage::sql_expr();
    let query = if has_gw {
        format!(
            "SELECT * FROM (\
               SELECT \
                 e.timestamp, \
                 e.agent, \
                 e.action, \
                 e.decision, \
                 e.detail, \
                 NULL as model, \
                 NULL as tokens_in, \
                 NULL as tokens_out, \
                 NULL as cost_usd, \
                 {event_sync_expr} as sync_state, \
                 'event' as source, \
                 {cov} as coverage \
               FROM events e \
               UNION ALL \
               SELECT \
                 g.timestamp::VARCHAR, \
                 g.provider, \
                 'think', \
                 g.status, \
                 g.model, \
                 g.model, \
                 g.tokens_in, \
                 g.tokens_out, \
                 g.cost_usd, \
                 CASE \
                   WHEN g.synced THEN 'synced' \
                   WHEN g.working_dir IS NOT NULL THEN 'pending' \
                   ELSE 'local' \
                 END, \
                 'gw' as source, \
                 CASE WHEN g.status = 'circuit_breaker' THEN 'enforced' ELSE 'observed' END as coverage \
               FROM gw.gateway_records g \
               WHERE g.trace_id NOT IN (SELECT e.routing_trace_id FROM events e WHERE e.routing_trace_id IS NOT NULL) \
             ) \
             ORDER BY timestamp DESC \
             LIMIT {}",
            args.last
        )
    } else {
        format!(
            "SELECT e.timestamp, e.agent, e.action, e.decision, e.detail, \
               NULL, NULL, NULL, NULL, NULL, 'event', {cov} as coverage \
             FROM events e \
             ORDER BY e.timestamp DESC \
             LIMIT {}",
            args.last
        )
    };

    let mut stmt = db.prepare(&query).expect("prepare timeline query");
    let mut rows = stmt.query([]).expect("execute timeline query");

    while let Some(row) = rows.next().expect("read row") {
        let timestamp: String = row.get(0).unwrap_or_default();
        let agent: String = row.get(1).unwrap_or_default();
        let action: String = row.get(2).unwrap_or_default();
        let decision: String = row.get(3).unwrap_or_default();
        let detail: String = row.get(4).unwrap_or_default();
        let tokens_in: Option<i64> = row.get(6).ok();
        let tokens_out: Option<i64> = row.get(7).ok();
        let cost_usd: Option<f64> = row.get(8).ok();
        let sync_state: Option<String> = row.get(9).ok();
        let source: String = row.get(10).unwrap_or_default();
        let coverage: String = row.get(11).unwrap_or_default();

        let mut line =
            format!("{timestamp}  {agent:<15} {action:<10} {decision:<8} [{coverage:<8}] {detail}");

        if source == "gw" {
            if let (Some(ti), Some(to)) = (tokens_in, tokens_out) {
                let _ = write!(line, "  [{ti}\u{2192}{to}]");
            }
            if let Some(cost) = cost_usd {
                let _ = write!(line, "  ${cost:.4}");
            }
        }

        if let Some(ref state) = sync_state
            && state != "local"
        {
            let _ = write!(line, "  [{state}]");
        }

        println!("{line}");
    }
}

fn event_log_dir() -> String {
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return format!("{state}/agentpact/log");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.local/state/agentpact/log")
}

fn kyrisd_db_path() -> String {
    kyris_core::paths::storage_path()
        .to_string_lossy()
        .into_owned()
}
