// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use kyris_core::coverage;

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

    let has_gw = if std::path::Path::new(&kyrisd_db_path).exists() {
        db.execute_batch(&format!("ATTACH '{kyrisd_db_path}' AS gw (READ_ONLY)"))
            .is_ok()
    } else {
        false
    };

    let interval = parse_interval(&args.since);

    print_action_stats(&db, &interval);
    print_coverage_stats(&db, &interval, has_gw);

    if has_gw {
        print_token_stats(&db, &interval);
        print_spend_stats(&db, &interval);
        print_model_stats(&db, &interval);
        print_metering_stats(&db, &interval);
    }
}

fn print_action_stats(db: &duckdb::Connection, interval: &str) {
    println!("Actions by decision:");
    let query = format!(
        "SELECT action, decision, COUNT(*) as cnt \
         FROM events \
         WHERE timestamp >= now() - INTERVAL '{interval}' \
         GROUP BY action, decision \
         ORDER BY cnt DESC"
    );
    let Ok(mut stmt) = db.prepare(&query) else {
        return;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return;
    };
    while let Some(row) = rows.next().expect("read row") {
        let action: String = row.get(0).unwrap_or_default();
        let decision: String = row.get(1).unwrap_or_default();
        let count: i64 = row.get(2).unwrap_or(0);
        println!("  {action:<10} {decision:<8} {count}");
    }
}

fn print_coverage_stats(db: &duckdb::Connection, interval: &str, has_gw: bool) {
    let cov = coverage::sql_expr();
    println!("\nCoverage breakdown:");
    let query = if has_gw {
        format!(
            "SELECT coverage, SUM(cnt) as cnt FROM (\
               SELECT {cov} as coverage, COUNT(*) as cnt \
               FROM events \
               WHERE timestamp >= now() - INTERVAL '{interval}' \
               GROUP BY coverage \
               UNION ALL \
               SELECT \
                 CASE WHEN g.status = 'circuit_breaker' THEN 'enforced' ELSE 'observed' END as coverage, \
                 COUNT(*) as cnt \
               FROM gw.gateway_records g \
               WHERE g.timestamp >= now() - INTERVAL '{interval}' \
                 AND g.trace_id NOT IN (SELECT e.routing_trace_id FROM events e WHERE e.routing_trace_id IS NOT NULL) \
               GROUP BY coverage \
             ) \
             GROUP BY coverage \
             ORDER BY cnt DESC"
        )
    } else {
        format!(
            "SELECT {cov} as coverage, COUNT(*) as cnt \
             FROM events \
             WHERE timestamp >= now() - INTERVAL '{interval}' \
             GROUP BY coverage \
             ORDER BY cnt DESC"
        )
    };
    let Ok(mut stmt) = db.prepare(&query) else {
        return;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return;
    };
    while let Some(row) = rows.next().expect("read row") {
        let coverage: String = row.get(0).unwrap_or_default();
        let count: i64 = row.get(1).unwrap_or(0);
        println!("  {coverage:<16} {count}");
    }
}

fn print_token_stats(db: &duckdb::Connection, interval: &str) {
    println!("\nToken usage:");
    let query = format!(
        "SELECT \
           provider, \
           SUM(CASE WHEN metering = 'available' THEN tokens_in ELSE 0 END) as total_in, \
           SUM(CASE WHEN metering = 'available' THEN tokens_out ELSE 0 END) as total_out, \
           COUNT(*) as requests, \
           SUM(CASE WHEN metering = 'unavailable' THEN 1 ELSE 0 END) as unmetered \
         FROM gw.gateway_records \
         WHERE timestamp >= now() - INTERVAL '{interval}' \
         GROUP BY provider \
         ORDER BY total_in + total_out DESC"
    );
    let Ok(mut stmt) = db.prepare(&query) else {
        return;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return;
    };
    while let Some(row) = rows.next().expect("read row") {
        let provider: String = row.get(0).unwrap_or_default();
        let total_in: i64 = row.get(1).unwrap_or(0);
        let total_out: i64 = row.get(2).unwrap_or(0);
        let requests: i64 = row.get(3).unwrap_or(0);
        let unmetered: i64 = row.get(4).unwrap_or(0);
        print!("  {provider:<12} {requests:>5} requests  {total_in:>10} in  {total_out:>10} out");
        if unmetered > 0 {
            print!("  ({unmetered} unmetered)");
        }
        println!();
    }
}

fn print_spend_stats(db: &duckdb::Connection, interval: &str) {
    println!("\nSpend:");
    let query = format!(
        "SELECT \
           provider, \
           model, \
           SUM(cost_usd) as total_cost, \
           COUNT(*) as requests \
         FROM gw.gateway_records \
         WHERE timestamp >= now() - INTERVAL '{interval}' \
           AND cost_usd IS NOT NULL \
         GROUP BY provider, model \
         ORDER BY total_cost DESC"
    );
    let Ok(mut stmt) = db.prepare(&query) else {
        return;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return;
    };
    while let Some(row) = rows.next().expect("read row") {
        let provider: String = row.get(0).unwrap_or_default();
        let model: String = row.get(1).unwrap_or_default();
        let total_cost: f64 = row.get(2).unwrap_or(0.0);
        let requests: i64 = row.get(3).unwrap_or(0);
        println!("  {provider:<12} {model:<30} ${total_cost:>8.4}  ({requests} requests)");
    }
}

fn print_model_stats(db: &duckdb::Connection, interval: &str) {
    println!("\nModel breakdown:");
    let query = format!(
        "SELECT \
           model, \
           COUNT(*) as requests, \
           SUM(CASE WHEN metering = 'available' THEN tokens_in + tokens_out ELSE 0 END) as total_tokens \
         FROM gw.gateway_records \
         WHERE timestamp >= now() - INTERVAL '{interval}' \
         GROUP BY model \
         ORDER BY requests DESC"
    );
    let Ok(mut stmt) = db.prepare(&query) else {
        return;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return;
    };
    while let Some(row) = rows.next().expect("read row") {
        let model: String = row.get(0).unwrap_or_default();
        let requests: i64 = row.get(1).unwrap_or(0);
        let total_tokens: i64 = row.get(2).unwrap_or(0);
        println!("  {model:<35} {requests:>5} requests  {total_tokens:>10} tokens");
    }
}

fn print_metering_stats(db: &duckdb::Connection, interval: &str) {
    let query = format!(
        "SELECT \
           COUNT(*) as total, \
           SUM(CASE WHEN metering = 'unavailable' THEN 1 ELSE 0 END) as unmetered \
         FROM gw.gateway_records \
         WHERE timestamp >= now() - INTERVAL '{interval}'"
    );
    let Ok(mut stmt) = db.prepare(&query) else {
        return;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return;
    };
    if let Some(row) = rows.next().expect("read row") {
        let total: i64 = row.get(0).unwrap_or(0);
        let unmetered: i64 = row.get(1).unwrap_or(0);
        if unmetered > 0 {
            println!("\nMetering: {unmetered}/{total} requests had unavailable usage data");
        }
    }
}

fn parse_interval(since: &str) -> String {
    let s = since.trim();
    if let Some(days) = s.strip_suffix('d')
        && let Ok(n) = days.parse::<u64>()
    {
        return format!("{n} days");
    }
    if let Some(hours) = s.strip_suffix('h')
        && let Ok(n) = hours.parse::<u64>()
    {
        return format!("{n} hours");
    }
    "7 days".to_string()
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

    #[test]
    fn testParseIntervalDays() {
        assert_eq!(parse_interval("7d"), "7 days");
        assert_eq!(parse_interval("30d"), "30 days");
    }

    #[test]
    fn testParseIntervalHours() {
        assert_eq!(parse_interval("24h"), "24 hours");
    }

    #[test]
    fn testParseIntervalInvalid() {
        assert_eq!(parse_interval("abc"), "7 days");
    }
}
