// SPDX-License-Identifier: Apache-2.0
use clap::Args;

#[derive(Args)]
pub struct StatsArgs {
    #[arg(long, default_value = "7d")]
    pub since: String,
}

pub fn run(args: StatsArgs) {
    let event_log_dir = event_log_dir();
    let kyrisd_db_path = kyrisd_db_path();

    let db = duckdb::Connection::open_in_memory().expect("open duckdb");

    let glob_jsonl = format!("{event_log_dir}/*.jsonl");
    let glob_gz = format!("{event_log_dir}/*.jsonl.gz");
    let _ = db.execute_batch(&format!(
        "CREATE VIEW events AS SELECT * FROM read_json_auto(['{glob_jsonl}', '{glob_gz}'])"
    ));

    if std::path::Path::new(&kyrisd_db_path).exists() {
        let _ = db.execute_batch(&format!("ATTACH '{kyrisd_db_path}' AS gw (READ_ONLY)"));
    }

    println!("Usage statistics (since {}):", args.since);

    let mut stmt = db
        .prepare(
            "SELECT action, decision, COUNT(*) as cnt \
             FROM events \
             GROUP BY action, decision \
             ORDER BY cnt DESC",
        )
        .expect("prepare stats query");
    let mut rows = stmt.query([]).expect("execute stats query");

    while let Some(row) = rows.next().expect("read row") {
        let action: String = row.get(0).unwrap_or_default();
        let decision: String = row.get(1).unwrap_or_default();
        let count: i64 = row.get(2).unwrap_or(0);
        println!("  {action:<10} {decision:<8} {count}");
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
