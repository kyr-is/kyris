// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris logs trace <id>` — render every event/record across both stores
//! that shares a given correlation id. The payoff of the error-tracing
//! effort: paste any of the three correlation keys (`id`, `request_id`,
//! `routing_trace_id` on the event side, `trace_id` on the gateway side)
//! and see the full cross-store story for that operation.

use std::fmt::Write as _;

use agentpact::catalog::commands::id_to_shell;
use clap::Args;
use kyris_core::coverage;

use super::sync_state::{build_event_sync_expr, load_sync_metadata};

#[derive(Args)]
pub struct TraceArgs {
    pub id: String,
}

/// The event correlation columns we know how to filter on, in the order we
/// surface them to the operator. `request_id` is a newly-added field; on an
/// event log written before that change the column simply will not exist in
/// the `read_json_auto`-inferred schema, so we must detect presence before
/// referencing it (a missing column in the WHERE clause is a hard error).
const CORRELATION_COLUMNS: [&str; 3] = ["id", "request_id", "routing_trace_id"];

pub fn run(args: TraceArgs) {
    let event_log_dir = event_log_dir();
    let kyrisd_db_path = kyrisd_db_path();

    let db = duckdb::Connection::open_in_memory().expect("open duckdb");

    let glob_jsonl = format!("{event_log_dir}/*.jsonl");
    let glob_gz = format!("{event_log_dir}/*.jsonl.gz");
    let events_ok = db
        .execute_batch(&format!(
            "CREATE VIEW events AS SELECT * FROM read_json_auto(['{glob_jsonl}', '{glob_gz}'])"
        ))
        .is_ok();

    let has_gw = if std::path::Path::new(&kyrisd_db_path).exists() {
        db.execute_batch(&format!("ATTACH '{kyrisd_db_path}' AS gw (READ_ONLY)"))
            .is_ok()
    } else {
        false
    };

    println!("Trace for id: {}", args.id);

    let mut count = 0u64;

    if events_ok {
        let present = present_correlation_columns(&db);
        let filter = build_event_filter(&present);
        if let Some(filter) = filter {
            count += render_events(&db, &args.id, present.len(), &filter, has_gw);
        } else {
            eprintln!("(no correlatable event columns present in event log)");
        }
    }

    if has_gw {
        count += render_gateway_records(&db, &args.id);
    }

    if count == 0 {
        eprintln!("No events or records found for id: {}", args.id);
    } else {
        eprintln!("\n{count} rows traced.");
    }
}

/// Detect which of the correlation columns actually exist on the `events`
/// view. `read_json_auto` only materializes a column if at least one row
/// carries it, so older logs may be missing `request_id` (or others).
fn present_correlation_columns(db: &duckdb::Connection) -> Vec<&'static str> {
    let Ok(mut stmt) = db.prepare("PRAGMA table_info('events')") else {
        return Vec::new();
    };
    let Ok(mut rows) = stmt.query([]) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        // PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
        let name: String = row.get(1).unwrap_or_default();
        if let Some(known) = CORRELATION_COLUMNS.iter().find(|c| **c == name) {
            found.push(*known);
        }
    }
    found
}

/// Build the `(col = ? OR col = ? ...)` filter from only the columns that
/// exist. Returns `None` when none of the correlation columns are present,
/// so the caller can skip the events side entirely.
fn build_event_filter(present: &[&'static str]) -> Option<String> {
    if present.is_empty() {
        return None;
    }
    let clause = present
        .iter()
        .map(|c| format!("{c} = ?"))
        .collect::<Vec<_>>()
        .join(" OR ");
    Some(format!("({clause})"))
}

fn render_events(
    db: &duckdb::Connection,
    id: &str,
    bind_count: usize,
    filter: &str,
    has_gw: bool,
) -> u64 {
    let sync_meta = if has_gw { load_sync_metadata(db) } else { None };
    let event_sync_expr = build_event_sync_expr(sync_meta.as_ref());
    let cov = coverage::sql_expr();

    let event_query = format!(
        "SELECT timestamp, agent, action, decision, detail, \
                mode, rule_kind, rule_id, rule_display, working_dir, \
                request_id, routing_trace_id, \
                {cov} as coverage, \
                {event_sync_expr} as sync_state \
         FROM events \
         WHERE {filter} \
         ORDER BY timestamp ASC"
    );

    let Ok(mut stmt) = db.prepare(&event_query) else {
        return 0;
    };
    // Bind the id once per present column, in declaration order.
    let binds: Vec<&str> = std::iter::repeat_n(id, bind_count).collect();
    let params = duckdb::params_from_iter(binds.iter());
    let Ok(mut rows) = stmt.query(params) else {
        return 0;
    };

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
        let request_id: Option<String> = row.get(10).ok();
        let routing_trace_id: Option<String> = row.get(11).ok();
        let coverage: String = row.get(12).unwrap_or_default();
        let sync_state: Option<String> = row.get(13).ok();

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
        if let Some(ref rid) = request_id
            && !rid.is_empty()
        {
            let _ = write!(line, "  request_id={rid}");
        }
        if let Some(ref tid) = routing_trace_id
            && !tid.is_empty()
        {
            let _ = write!(line, "  routing_trace_id={tid}");
        }
        if let Some(ref state) = sync_state
            && state != "local"
        {
            let _ = write!(line, "  [{state}]");
        }

        println!("{line}");
        count += 1;
    }
    count
}

fn render_gateway_records(db: &duckdb::Connection, id: &str) -> u64 {
    let gw_query = "SELECT timestamp, provider, model, tokens_in, tokens_out, \
                cost_usd, latency_ms, status, metering, mcp_server, mcp_tool, \
                CASE \
                  WHEN synced THEN 'synced' \
                  WHEN working_dir IS NOT NULL THEN 'pending' \
                  ELSE 'local' \
                END as sync_state \
         FROM gw.gateway_records \
         WHERE trace_id = ? \
         ORDER BY timestamp ASC";

    let Ok(mut gw_stmt) = db.prepare(gw_query) else {
        return 0;
    };
    let Ok(mut gw_rows) = gw_stmt.query([id]) else {
        return 0;
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
        let sync_state: String = row.get(11).unwrap_or_default();

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
        if sync_state != "local" {
            let _ = write!(line, "  [{sync_state}]");
        }
        println!("{line}");
        gw_count += 1;
    }
    gw_count
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testBuildEventFilterAllColumns() {
        let filter = build_event_filter(&["id", "request_id", "routing_trace_id"]).unwrap();
        assert_eq!(filter, "(id = ? OR request_id = ? OR routing_trace_id = ?)");
    }

    #[test]
    fn testBuildEventFilterMissingRequestId() {
        // Older logs lack `request_id`; the filter must not reference it.
        let filter = build_event_filter(&["id", "routing_trace_id"]).unwrap();
        assert_eq!(filter, "(id = ? OR routing_trace_id = ?)");
        assert!(!filter.contains("request_id"));
    }

    #[test]
    fn testBuildEventFilterSingleColumn() {
        let filter = build_event_filter(&["routing_trace_id"]).unwrap();
        assert_eq!(filter, "(routing_trace_id = ?)");
    }

    #[test]
    fn testBuildEventFilterNoneWhenEmpty() {
        assert!(build_event_filter(&[]).is_none());
    }

    #[test]
    fn testPresentCorrelationColumnsDetection() {
        let db = duckdb::Connection::open_in_memory().expect("open duckdb");
        db.execute_batch(
            "CREATE VIEW events AS SELECT 'a' AS id, 'b' AS routing_trace_id, 1 AS other",
        )
        .expect("create view");
        let present = present_correlation_columns(&db);
        assert!(present.contains(&"id"));
        assert!(present.contains(&"routing_trace_id"));
        assert!(!present.contains(&"request_id"));
    }

    #[test]
    fn testPresentCorrelationColumnsWithRequestId() {
        let db = duckdb::Connection::open_in_memory().expect("open duckdb");
        db.execute_batch(
            "CREATE VIEW events AS SELECT 'a' AS id, 'b' AS request_id, 'c' AS routing_trace_id",
        )
        .expect("create view");
        let mut present = present_correlation_columns(&db);
        present.sort_unstable();
        assert_eq!(present, vec!["id", "request_id", "routing_trace_id"]);
    }
}
