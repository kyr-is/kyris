// SPDX-License-Identifier: Apache-2.0
use clap::Args;

#[derive(Args)]
pub struct ReplayArgs {
    pub session: String,
}

pub fn run(args: ReplayArgs) {
    let event_log_dir = event_log_dir();

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

    let query = "SELECT timestamp, agent, action, decision, detail \
                 FROM events \
                 WHERE session_id = ? \
                 ORDER BY timestamp ASC";

    let mut stmt = db.prepare(query).unwrap_or_else(|e| {
        eprintln!("Failed to prepare query: {e}");
        std::process::exit(1);
    });
    let mut rows = stmt.query([&args.session]).unwrap_or_else(|e| {
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
        println!("{timestamp}  {agent:<15} {action:<10} {decision:<8} {detail}");
        count += 1;
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
