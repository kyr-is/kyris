// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;

#[derive(Args)]
pub struct HistoryArgs {
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub action: Option<String>,
    #[arg(long)]
    pub decision: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    #[arg(long)]
    pub dir: Option<String>,
    #[arg(long)]
    pub sync_state: Option<String>,
}

pub fn run(args: HistoryArgs) {
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

    if args.sync_state.is_some() {
        if !has_gw {
            eprintln!("--sync-state requires kyrisd database at {kyrisd_db_path}");
            std::process::exit(1);
        }
        run_sync_state_query(&db, &args);
    } else {
        run_event_query(&db, &args);
    }
}

fn run_event_query(db: &duckdb::Connection, args: &HistoryArgs) {
    let (query, params) = build_event_query(args);

    let mut stmt = db.prepare(&query).unwrap_or_else(|e| {
        eprintln!("Failed to prepare query: {e}");
        std::process::exit(1);
    });

    let param_refs: Vec<&dyn duckdb::ToSql> =
        params.iter().map(|s| s as &dyn duckdb::ToSql).collect();

    let mut rows = stmt.query(param_refs.as_slice()).unwrap_or_else(|e| {
        eprintln!("Failed to execute query: {e}");
        std::process::exit(1);
    });

    while let Some(row) = rows.next().expect("read row") {
        let timestamp: String = row.get(0).unwrap_or_default();
        let agent: String = row.get(1).unwrap_or_default();
        let action: String = row.get(2).unwrap_or_default();
        let decision: String = row.get(3).unwrap_or_default();
        let detail: String = row.get(4).unwrap_or_default();
        println!("{timestamp}  {agent:<15} {action:<10} {decision:<8} {detail}");
    }
}

fn run_sync_state_query(db: &duckdb::Connection, args: &HistoryArgs) {
    let (query, params) = build_sync_state_query(args);

    let mut stmt = db.prepare(&query).unwrap_or_else(|e| {
        eprintln!("Failed to prepare query: {e}");
        std::process::exit(1);
    });

    let param_refs: Vec<&dyn duckdb::ToSql> =
        params.iter().map(|s| s as &dyn duckdb::ToSql).collect();

    let mut rows = stmt.query(param_refs.as_slice()).unwrap_or_else(|e| {
        eprintln!("Failed to execute query: {e}");
        std::process::exit(1);
    });

    while let Some(row) = rows.next().expect("read row") {
        let timestamp: String = row.get(0).unwrap_or_default();
        let provider: String = row.get(1).unwrap_or_default();
        let model: String = row.get(2).unwrap_or_default();
        let status: String = row.get(3).unwrap_or_default();
        let sync_state: String = row.get(4).unwrap_or_default();
        let working_dir: String = row.get(5).unwrap_or_default();
        println!(
            "{timestamp}  {provider:<12} {model:<30} {status:<8} [{sync_state}]  {working_dir}"
        );
    }
}

fn build_event_query(args: &HistoryArgs) -> (String, Vec<String>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(ref agent) = args.agent {
        clauses.push(format!("agent = ${}", params.len() + 1));
        params.push(agent.clone());
    }
    if let Some(ref action) = args.action {
        clauses.push(format!("action = ${}", params.len() + 1));
        params.push(action.clone());
    }
    if let Some(ref decision) = args.decision {
        clauses.push(format!("decision = ${}", params.len() + 1));
        params.push(decision.clone());
    }
    if let Some(ref since) = args.since {
        clauses.push(format!("timestamp >= ${}", params.len() + 1));
        params.push(since.clone());
    }
    if let Some(ref until) = args.until {
        clauses.push(format!("timestamp <= ${}", params.len() + 1));
        params.push(until.clone());
    }
    if let Some(ref dir) = args.dir {
        clauses.push(format!("working_dir = ${}", params.len() + 1));
        params.push(dir.clone());
    }

    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let query = format!(
        "SELECT timestamp, agent, action, decision, detail \
         FROM events \
         {where_clause} \
         ORDER BY timestamp DESC \
         LIMIT 100"
    );
    (query, params)
}

fn build_sync_state_query(args: &HistoryArgs) -> (String, Vec<String>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    let sync_state_expr = "CASE WHEN g.synced THEN 'synced' \
              WHEN g.working_dir IS NOT NULL THEN 'pending' \
              ELSE 'local' END";

    if let Some(ref sync_state) = args.sync_state {
        clauses.push(format!("{sync_state_expr} = ${}", params.len() + 1));
        params.push(sync_state.clone());
    }
    if let Some(ref since) = args.since {
        clauses.push(format!("g.timestamp >= ${}", params.len() + 1));
        params.push(since.clone());
    }
    if let Some(ref until) = args.until {
        clauses.push(format!("g.timestamp <= ${}", params.len() + 1));
        params.push(until.clone());
    }
    if let Some(ref dir) = args.dir {
        clauses.push(format!("g.working_dir = ${}", params.len() + 1));
        params.push(dir.clone());
    }

    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };

    let query = format!(
        "SELECT g.timestamp, g.provider, g.model, g.status, \
           {sync_state_expr} as sync_state, \
           COALESCE(g.working_dir, '') as working_dir \
         FROM gw.gateway_records g \
         {where_clause} \
         ORDER BY g.timestamp DESC \
         LIMIT 100"
    );
    (query, params)
}

fn event_log_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.agentpact/log")
}

fn kyrisd_db_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/.kyris/kyrisd.duckdb")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> HistoryArgs {
        HistoryArgs {
            agent: None,
            action: None,
            decision: None,
            since: None,
            until: None,
            dir: None,
            sync_state: None,
        }
    }

    #[test]
    fn testBuildEventQueryNoFilters() {
        let (query, params) = build_event_query(&empty_args());
        assert!(!query.contains("WHERE"));
        assert!(params.is_empty());
        assert!(query.contains("LIMIT 100"));
    }

    #[test]
    fn testBuildEventQuerySingleFilter() {
        let args = HistoryArgs {
            agent: Some("claude".to_string()),
            ..empty_args()
        };
        let (query, params) = build_event_query(&args);
        assert!(query.contains("WHERE agent = $1"));
        assert_eq!(params, vec!["claude"]);
    }

    #[test]
    fn testBuildEventQueryMultipleFilters() {
        let args = HistoryArgs {
            agent: Some("claude".to_string()),
            action: Some("execute".to_string()),
            decision: Some("deny".to_string()),
            ..empty_args()
        };
        let (query, params) = build_event_query(&args);
        assert!(query.contains("agent = $1 AND action = $2 AND decision = $3"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn testBuildEventQueryDateRange() {
        let args = HistoryArgs {
            since: Some("2026-04-01".to_string()),
            until: Some("2026-04-19".to_string()),
            ..empty_args()
        };
        let (query, params) = build_event_query(&args);
        assert!(query.contains("timestamp >= $1 AND timestamp <= $2"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn testBuildEventQueryDirFilter() {
        let args = HistoryArgs {
            dir: Some("/home/user/project".to_string()),
            ..empty_args()
        };
        let (query, params) = build_event_query(&args);
        assert!(query.contains("working_dir = $1"));
        assert_eq!(params[0], "/home/user/project");
    }

    #[test]
    fn testBuildSyncStateQuery() {
        let args = HistoryArgs {
            sync_state: Some("synced".to_string()),
            ..empty_args()
        };
        let (query, params) = build_sync_state_query(&args);
        assert!(query.contains("gw.gateway_records"));
        assert!(query.contains("CASE WHEN g.synced"));
        assert_eq!(params[0], "synced");
    }

    #[test]
    fn testBuildSyncStateQueryWithDir() {
        let args = HistoryArgs {
            sync_state: Some("local".to_string()),
            dir: Some("/work/project".to_string()),
            ..empty_args()
        };
        let (query, params) = build_sync_state_query(&args);
        assert!(query.contains("g.working_dir = $2"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn testBuildEventQueryExcludesSyncState() {
        let args = HistoryArgs {
            agent: Some("a".to_string()),
            sync_state: Some("synced".to_string()),
            ..empty_args()
        };
        let (query, params) = build_event_query(&args);
        assert!(!query.contains("sync_state"));
        assert_eq!(params.len(), 1);
    }
}
