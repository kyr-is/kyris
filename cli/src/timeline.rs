// SPDX-License-Identifier: Apache-2.0
use clap::Args;

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

    if std::path::Path::new(&kyrisd_db_path).exists() {
        let _ = db.execute_batch(&format!("ATTACH '{kyrisd_db_path}' AS gw (READ_ONLY)"));
    }

    let query = format!(
        "SELECT e.timestamp, e.agent, e.action, e.decision, e.detail \
         FROM events e \
         ORDER BY e.timestamp DESC \
         LIMIT {}",
        args.last
    );

    let mut stmt = db.prepare(&query).expect("prepare timeline query");
    let mut rows = stmt.query([]).expect("execute timeline query");

    while let Some(row) = rows.next().expect("read row") {
        let timestamp: String = row.get(0).unwrap_or_default();
        let agent: String = row.get(1).unwrap_or_default();
        let action: String = row.get(2).unwrap_or_default();
        let decision: String = row.get(3).unwrap_or_default();
        let detail: String = row.get(4).unwrap_or_default();
        println!("{timestamp}  {agent:<15} {action:<10} {decision:<8} {detail}");
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
