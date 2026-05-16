// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use duckdb::Connection;
use tokio::sync::mpsc;

use crate::metering::StatsEvent;

static DROP_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn dropped_count() -> u64 {
    DROP_COUNT.load(Ordering::Relaxed)
}

/// Atomically counts a stats-pipeline drop. Called from two paths:
///   1. `flush_batch` when a `DuckDB` insert fails (already counted via
///      `fetch_add(batch.len())` in that path).
///   2. Adapter `try_send` failures (channel full): each event becomes
///      one drop. Per `design/kyris.md` §5.5: "first dropped record
///      increments `AtomicU64` counter, emits `tracing::warn!`, exposed
///      via `GET /readyz` as degraded". We log on the first drop of a
///      daemon session to avoid log spam under sustained overload.
pub fn record_dropped(n: u64) {
    let prev = DROP_COUNT.fetch_add(n, Ordering::Relaxed);
    if prev == 0 {
        tracing::warn!(
            "stats channel full — first event dropped. /readyz will report degraded. \
             Increase stats.channel_capacity or stats.flush_interval_ms in kyrisd.yaml."
        );
    }
}

/// Filters for `query_gateway_records` (operator API).
#[derive(Debug, Default, Clone, Copy)]
pub struct GatewayRecordFilter<'a> {
    pub provider: Option<&'a str>,
    pub model: Option<&'a str>,
    pub status: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    pub mcp_server: Option<&'a str>,
    pub mcp_tool: Option<&'a str>,
    pub since: Option<&'a str>,
    pub limit: Option<u32>,
}

fn gateway_row_to_record(
    row: &duckdb::Row<'_>,
) -> duckdb::Result<kyris_core::record::GatewayRecord> {
    use std::str::FromStr as _;
    let status_str: String = row.get(11)?;
    let metering_str: Option<String> = row.get::<_, Option<String>>(17)?;
    Ok(kyris_core::record::GatewayRecord {
        id: row.get(0)?,
        trace_id: row.get(1)?,
        timestamp: row.get(2)?,
        provider: row.get(3)?,
        model: row.get(4)?,
        tokens_in: row.get(5)?,
        tokens_out: row.get(6)?,
        tokens_cache_create: row.get(7)?,
        tokens_cache_read: row.get(8)?,
        cost_usd: row.get(9)?,
        latency_ms: row.get(10)?,
        status: kyris_core::record::RecordStatus::from_str(&status_str)
            .unwrap_or(kyris_core::record::RecordStatus::Unknown),
        session_id: row.get(12)?,
        synced: row.get(13)?,
        mcp_server: row.get(14)?,
        mcp_tool: row.get(15)?,
        working_dir: row.get(16)?,
        metering: match metering_str.as_deref() {
            Some("unavailable") => kyris_core::record::Metering::Unavailable,
            _ => kyris_core::record::Metering::Available,
        },
    })
}

pub struct DuckDbWriter {
    conn: std::sync::Mutex<Connection>,
}

impl DuckDbWriter {
    pub fn try_open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create database directory {}: {e}", parent.display()))?;
        }
        let conn =
            Connection::open(path).map_err(|e| format!("open duckdb {}: {e}", path.display()))?;
        conn.execute_batch(kyris_core::record::CREATE_GATEWAY_RECORDS)
            .map_err(|e| format!("create gateway_records table: {e}"))?;
        conn.execute_batch(kyris_core::record::CREATE_SESSION_TOKENS)
            .map_err(|e| format!("create session_tokens table: {e}"))?;
        conn.execute_batch(kyris_core::record::CREATE_SYNC_CURSOR)
            .map_err(|e| format!("create sync_cursor table: {e}"))?;
        conn.execute_batch(kyris_core::record::CREATE_SYNC_METADATA)
            .map_err(|e| format!("create sync_metadata table: {e}"))?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    pub fn open(path: &Path) -> Self {
        Self::try_open(path).unwrap_or_else(|e| panic!("{e}"))
    }

    pub fn insert_batch(&self, events: &[StatsEvent]) -> duckdb::Result<()> {
        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn.prepare(
            "INSERT INTO gateway_records (
                id, trace_id, timestamp, provider, model,
                tokens_in, tokens_out, tokens_cache_create, tokens_cache_read,
                cost_usd, latency_ms, status, session_id, synced, mcp_server, mcp_tool,
                working_dir, metering
            ) VALUES (?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?, ?)",
        )?;
        for event in events {
            let id = uuid::Uuid::now_v7().to_string();
            let unavailable = event.metering == kyris_core::record::Metering::Unavailable;
            let tokens_in: Option<i64> = if unavailable {
                None
            } else {
                Some(event.tokens.input)
            };
            let tokens_out: Option<i64> = if unavailable {
                None
            } else {
                Some(event.tokens.output)
            };
            let cache_create: Option<i64> = if unavailable || event.cache_create == 0 {
                None
            } else {
                Some(event.cache_create)
            };
            let cache_read: Option<i64> = if unavailable || event.cache_read == 0 {
                None
            } else {
                Some(event.cache_read)
            };
            let metering_str = match event.metering {
                kyris_core::record::Metering::Available => "available",
                kyris_core::record::Metering::Unavailable => "unavailable",
            };
            stmt.execute(duckdb::params![
                id,
                event.trace_id,
                event.provider,
                event.model,
                tokens_in,
                tokens_out,
                cache_create,
                cache_read,
                event.cost,
                event.latency_ms,
                event.status,
                event.session_id,
                event.mcp_server,
                event.mcp_tool,
                event.working_dir,
                metering_str,
            ])?;
        }
        Ok(())
    }

    pub fn prune(&self, retention_days: u64) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        conn.execute(
            "DELETE FROM gateway_records \
             WHERE timestamp < now()::TIMESTAMP - (INTERVAL '1 day' * ?::INTEGER)",
            duckdb::params![retention_days as i32],
        )
    }

    pub fn upsert_session_tokens(
        &self,
        session_id: &str,
        total_tokens: i64,
    ) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        conn.execute(
            "INSERT INTO session_tokens (session_id, total_tokens, last_activity) \
             VALUES (?, ?, now()) \
             ON CONFLICT (session_id) DO UPDATE SET \
             total_tokens = excluded.total_tokens, last_activity = excluded.last_activity",
            duckdb::params![session_id, total_tokens],
        )
    }

    pub fn load_session_tokens(&self) -> Vec<(String, i64, std::time::Duration)> {
        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn
            .prepare(
                "SELECT session_id, total_tokens, \
                 EXTRACT(EPOCH FROM (now()::TIMESTAMP - last_activity))::BIGINT as elapsed_secs \
                 FROM session_tokens",
            )
            .expect("prepare session_tokens query");
        let rows = stmt
            .query_map([], |row| {
                let elapsed_secs: i64 = row.get(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    std::time::Duration::from_secs(elapsed_secs.max(0) as u64),
                ))
            })
            .expect("query session_tokens");
        rows.filter_map(std::result::Result::ok).collect()
    }

    pub fn prune_session_tokens(&self, idle_timeout_minutes: u64) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        conn.execute(
            "DELETE FROM session_tokens \
             WHERE last_activity < now()::TIMESTAMP - (INTERVAL '1 minute' * ?::INTEGER)",
            duckdb::params![idle_timeout_minutes as i32],
        )
    }

    pub fn save_sync_cursor(&self, filename: &str, byte_offset: u64) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        conn.execute(
            "INSERT INTO sync_cursor (id, filename, byte_offset) VALUES (1, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET filename = excluded.filename, byte_offset = excluded.byte_offset",
            duckdb::params![filename, byte_offset as i64],
        )
    }

    pub fn load_sync_cursor(&self) -> Option<(String, u64)> {
        let conn = self.conn.lock().expect("lock db");
        conn.query_row(
            "SELECT filename, byte_offset FROM sync_cursor WHERE id = 1",
            [],
            |row| {
                let filename: String = row.get(0)?;
                let offset: i64 = row.get(1)?;
                Ok((filename, offset as u64))
            },
        )
        .ok()
    }

    pub fn save_sync_metadata(&self, scope: &[String], synced_at: &str) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        let scope_json = serde_json::to_string(scope).unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO sync_metadata (id, scope_json, last_synced_at) VALUES (1, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET scope_json = excluded.scope_json, last_synced_at = excluded.last_synced_at",
            duckdb::params![scope_json, synced_at],
        )
    }

    pub fn mark_records_synced(&self, record_ids: &[String]) -> duckdb::Result<()> {
        if record_ids.is_empty() {
            return Ok(());
        }

        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn.prepare("UPDATE gateway_records SET synced = true WHERE id = ?")?;
        for record_id in record_ids {
            stmt.execute(duckdb::params![record_id])?;
        }
        Ok(())
    }

    /// Read-only query of `gateway_records` for the operator API.
    ///
    /// All filter parameters AND together. Pass `None` for "no filter".
    /// Results are ordered newest first and capped by `limit`.
    pub fn query_gateway_records(
        &self,
        filters: GatewayRecordFilter<'_>,
    ) -> duckdb::Result<Vec<kyris_core::record::GatewayRecord>> {
        use std::fmt::Write as _;

        let mut sql = String::from(
            "SELECT id, trace_id, \
                    strftime(timestamp, '%Y-%m-%dT%H:%M:%SZ') AS timestamp, \
                    provider, model, \
                    tokens_in, tokens_out, tokens_cache_create, tokens_cache_read, \
                    cost_usd, latency_ms, status, session_id, synced, \
                    mcp_server, mcp_tool, working_dir, metering \
             FROM gateway_records WHERE 1 = 1",
        );
        let mut params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();
        if let Some(provider) = filters.provider {
            sql.push_str(" AND provider = ?");
            params.push(Box::new(provider.to_string()));
        }
        if let Some(model) = filters.model {
            sql.push_str(" AND model = ?");
            params.push(Box::new(model.to_string()));
        }
        if let Some(status) = filters.status {
            sql.push_str(" AND status = ?");
            params.push(Box::new(status.to_string()));
        }
        if let Some(session_id) = filters.session_id {
            sql.push_str(" AND session_id = ?");
            params.push(Box::new(session_id.to_string()));
        }
        if let Some(trace_id) = filters.trace_id {
            sql.push_str(" AND trace_id = ?");
            params.push(Box::new(trace_id.to_string()));
        }
        if let Some(mcp_server) = filters.mcp_server {
            sql.push_str(" AND mcp_server = ?");
            params.push(Box::new(mcp_server.to_string()));
        }
        if let Some(mcp_tool) = filters.mcp_tool {
            sql.push_str(" AND mcp_tool = ?");
            params.push(Box::new(mcp_tool.to_string()));
        }
        if let Some(since) = filters.since {
            sql.push_str(" AND timestamp >= ?::TIMESTAMP");
            params.push(Box::new(since.to_string()));
        }
        sql.push_str(" ORDER BY timestamp DESC");
        let limit = filters.limit.unwrap_or(1_000).min(10_000);
        let _ = write!(sql, " LIMIT {limit}");

        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn duckdb::ToSql> =
            params.iter().map(std::convert::AsRef::as_ref).collect();
        let rows = stmt.query_map(&param_refs[..], gateway_row_to_record)?;
        rows.collect()
    }

    /// Read-only query of `session_tokens` for the operator API.
    pub fn query_session_token(
        &self,
        session_id: &str,
    ) -> duckdb::Result<Option<kyris_core::record::SessionTokenRow>> {
        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn.prepare(
            "SELECT session_id, total_tokens, \
                    strftime(last_activity, '%Y-%m-%dT%H:%M:%SZ') AS last_activity \
             FROM session_tokens WHERE session_id = ?",
        )?;
        let mut rows = stmt.query(duckdb::params![session_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(kyris_core::record::SessionTokenRow {
                session_id: row.get(0)?,
                total_tokens: row.get(1)?,
                last_activity: row.get(2)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn probe_writable(&self) -> bool {
        let conn = self.conn.lock().expect("lock db");
        conn.execute_batch(
            "CREATE TEMPORARY TABLE IF NOT EXISTS _health_probe (v INT); \
             DROP TABLE IF EXISTS _health_probe",
        )
        .is_ok()
    }

    /// Total cost in USD for all completed requests in the last `window_hours`.
    /// Returns `None` if the query fails or no cost data exists.
    pub fn query_spend_usd(&self, window_hours: u64) -> Option<f64> {
        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn
            .prepare(
                "SELECT COALESCE(SUM(cost_usd), 0.0) \
                 FROM gateway_records \
                 WHERE timestamp >= now()::TIMESTAMP - (INTERVAL '1 hour' * ?::INTEGER) \
                   AND cost_usd IS NOT NULL \
                   AND status NOT IN ('error', 'circuit_breaker')",
            )
            .ok()?;
        stmt.query_row(duckdb::params![window_hours as i64], |row| {
            row.get::<_, f64>(0)
        })
        .ok()
    }

    pub fn with_conn<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Connection) -> R,
    {
        let conn = self.conn.lock().expect("lock db");
        f(&conn)
    }
}

pub fn open_db() -> DuckDbWriter {
    let path = if let Ok(p) = std::env::var("KYRIS_DB_PATH") {
        PathBuf::from(p)
    } else {
        kyris_core::paths::storage_path()
    };
    // Make sure the parent dir exists — first run on a fresh XDG layout
    // would otherwise fail to create the duckdb file.
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    DuckDbWriter::try_open(&path).unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to open database");
        std::process::exit(1);
    })
}

pub async fn stats_writer(
    mut rx: mpsc::Receiver<StatsEvent>,
    writer: Arc<DuckDbWriter>,
    circuit_breaker: Arc<crate::circuit_breaker::CircuitBreaker>,
    stats_config: kyris_core::config::StatsConfig,
    spend_config: kyris_core::config::SpendConfig,
    session_idle_minutes: u64,
) {
    let batch_size = stats_config.flush_batch_size;
    let retention_days = stats_config.retention_days;
    let mut batch: Vec<StatsEvent> = Vec::with_capacity(batch_size);
    let mut flush_interval = tokio::time::interval(std::time::Duration::from_millis(
        stats_config.flush_interval_ms,
    ));
    let mut prune_interval = tokio::time::interval(std::time::Duration::from_hours(1));
    // Thresholds (as microdollars) that have already fired a toast this
    // daemon session. Cleared when spend drops back below the threshold so
    // a new crossing fires again.
    let mut notified: std::collections::HashSet<u64> = std::collections::HashSet::new();

    loop {
        tokio::select! {
            recv = rx.recv() => {
                if let Some(event) = recv {
                    batch.push(event);
                    if batch.len() >= batch_size {
                        flush_batch(&writer, &mut batch);
                        persist_session_tokens(&writer, &circuit_breaker);
                        check_spend_thresholds(&writer, &spend_config, &mut notified);
                    }
                } else {
                    if !batch.is_empty() {
                        flush_batch(&writer, &mut batch);
                    }
                    persist_session_tokens(&writer, &circuit_breaker);
                    return;
                }
            }
            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    flush_batch(&writer, &mut batch);
                    persist_session_tokens(&writer, &circuit_breaker);
                    check_spend_thresholds(&writer, &spend_config, &mut notified);
                }
            }
            _ = prune_interval.tick() => {
                if let Err(e) = writer.prune(retention_days) {
                    tracing::warn!(error = %e, "prune failed");
                }
                if let Err(e) = writer.prune_session_tokens(session_idle_minutes) {
                    tracing::warn!(error = %e, "prune session_tokens failed");
                }
                circuit_breaker.prune_idle(std::time::Duration::from_secs(session_idle_minutes * 60));
                // Re-check thresholds after prune so crossing-down resets are caught.
                check_spend_thresholds(&writer, &spend_config, &mut notified);
            }
        }
    }
}

/// Check each spend threshold and fire a toast the first time spend crosses
/// it upward. Removes from `notified` when spend drops back below so a
/// future crossing fires again (e.g. after the rolling window moves forward).
fn check_spend_thresholds(
    writer: &DuckDbWriter,
    config: &kyris_core::config::SpendConfig,
    notified: &mut std::collections::HashSet<u64>,
) {
    if config.warn_thresholds_usd.is_empty() {
        return;
    }
    let Some(total) = writer.query_spend_usd(config.window_hours) else {
        return;
    };
    for &threshold in &config.warn_thresholds_usd {
        if threshold <= 0.0 {
            continue;
        }
        let key = (threshold * 1_000_000.0) as u64;
        if total >= threshold {
            if notified.insert(key) {
                crate::notify::spend_warning_toast(total, threshold, config.window_hours);
            }
        } else {
            notified.remove(&key);
        }
    }
}

fn persist_session_tokens(
    writer: &DuckDbWriter,
    circuit_breaker: &crate::circuit_breaker::CircuitBreaker,
) {
    for (session_id, total) in circuit_breaker.session_totals() {
        if let Err(e) = writer.upsert_session_tokens(&session_id, total) {
            tracing::warn!(error = %e, session_id = %session_id, "upsert session_tokens failed");
        }
    }
}

fn flush_batch(writer: &DuckDbWriter, batch: &mut Vec<StatsEvent>) {
    tracing::debug!(count = batch.len(), "flushing stats batch");
    if let Err(e) = writer.insert_batch(batch) {
        tracing::warn!(error = %e, count = batch.len(), "insert_batch failed, dropping events");
        DROP_COUNT.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
    batch.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metering::TokenCounts;

    fn sample_event(trace_id: &str) -> StatsEvent {
        StatsEvent {
            trace_id: trace_id.to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens: TokenCounts {
                input: 100,
                output: 50,
            },
            cache_create: 0,
            cache_read: 0,
            cost: Some(0.015),
            latency_ms: 250,
            status: "success".to_string(),
            session_id: None,
            mcp_server: None,
            mcp_tool: None,
            metering: kyris_core::record::Metering::Available,
            working_dir: None,
        }
    }

    #[test]
    fn testInsertAndQueryBatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        let events: Vec<StatsEvent> = (0..5)
            .map(|i| sample_event(&format!("trace-{i}")))
            .collect();
        writer.insert_batch(&events).expect("insert_batch");

        let count: i64 = writer.with_conn(|conn| {
            conn.query_row("SELECT count(*) FROM gateway_records", [], |row| row.get(0))
                .expect("query count")
        });
        assert_eq!(count, 5);

        let model: String = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT model FROM gateway_records WHERE trace_id = ?",
                ["trace-0"],
                |row| row.get(0),
            )
            .expect("query model")
        });
        assert_eq!(model, "claude-4-opus");
    }

    #[test]
    fn testUpsertAndLoadSessionTokens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        writer
            .upsert_session_tokens("sess-1", 150_000)
            .expect("upsert");
        writer
            .upsert_session_tokens("sess-2", 50_000)
            .expect("upsert");

        let sessions = writer.load_session_tokens();
        assert_eq!(sessions.len(), 2);

        writer
            .upsert_session_tokens("sess-1", 200_000)
            .expect("upsert update");
        let sessions = writer.load_session_tokens();
        let sess1 = sessions.iter().find(|(id, _, _)| id == "sess-1").unwrap();
        assert_eq!(sess1.1, 200_000);
    }

    #[test]
    fn testPruneSessionTokens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        writer.upsert_session_tokens("sess-1", 100).expect("upsert");
        let deleted = writer.prune_session_tokens(0).expect("prune");
        assert_eq!(deleted, 1);
        assert!(writer.load_session_tokens().is_empty());
    }

    #[test]
    fn testPruneRemovesOldRows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        // Insert a row with an old timestamp directly
        writer.with_conn(|conn| {
            conn.execute(
                "INSERT INTO gateway_records (
                    id, trace_id, timestamp, provider, model,
                    tokens_in, tokens_out, cost_usd, latency_ms, status, synced
                ) VALUES ('old-1', 'old-1', '2020-01-01 00:00:00', 'test', 'test',
                    0, 0, NULL, 100, 'success', false)",
                [],
            )
            .expect("insert old row")
        });

        // Insert a current row via insert_batch
        writer
            .insert_batch(&[sample_event("recent-1")])
            .expect("insert recent");

        let before: i64 = writer.with_conn(|conn| {
            conn.query_row("SELECT count(*) FROM gateway_records", [], |row| row.get(0))
                .expect("count before")
        });
        assert_eq!(before, 2);

        let deleted = writer.prune(7).expect("prune");
        assert_eq!(deleted, 1);

        let after: i64 = writer.with_conn(|conn| {
            conn.query_row("SELECT count(*) FROM gateway_records", [], |row| row.get(0))
                .expect("count after")
        });
        assert_eq!(after, 1);

        let remaining: String = writer.with_conn(|conn| {
            conn.query_row("SELECT trace_id FROM gateway_records", [], |row| row.get(0))
                .expect("remaining trace_id")
        });
        assert_eq!(remaining, "recent-1");
    }

    #[test]
    fn testSyncCursorSaveAndLoad() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        assert!(writer.load_sync_cursor().is_none());

        writer
            .save_sync_cursor("events.jsonl", 4096)
            .expect("save cursor");
        let (filename, offset) = writer.load_sync_cursor().expect("load cursor");
        assert_eq!(filename, "events.jsonl");
        assert_eq!(offset, 4096);

        writer
            .save_sync_cursor("events-2026-04-12.jsonl", 8192)
            .expect("update cursor");
        let (filename, offset) = writer.load_sync_cursor().expect("load updated cursor");
        assert_eq!(filename, "events-2026-04-12.jsonl");
        assert_eq!(offset, 8192);
    }

    #[test]
    fn testMarkRecordsSynced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        writer
            .insert_batch(&[sample_event("trace-sync-a"), sample_event("trace-sync-b")])
            .expect("insert batch");

        let record_ids: Vec<String> = writer.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT id FROM gateway_records ORDER BY trace_id")
                .expect("prepare record query");
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query record ids");
            rows.filter_map(std::result::Result::ok).collect()
        });

        writer
            .mark_records_synced(&record_ids[..1])
            .expect("mark synced");

        let synced_rows: Vec<(String, bool)> = writer.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT trace_id, synced FROM gateway_records ORDER BY trace_id")
                .expect("prepare synced query");
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
                })
                .expect("query synced rows");
            rows.filter_map(std::result::Result::ok).collect()
        });

        assert_eq!(
            synced_rows,
            vec![
                ("trace-sync-a".to_string(), true),
                ("trace-sync-b".to_string(), false),
            ]
        );
    }

    #[test]
    fn testInsertBatchWithSessionAndMcpFields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        let event = StatsEvent {
            trace_id: "trace-mcp".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens: TokenCounts {
                input: 50,
                output: 25,
            },
            cache_create: 0,
            cache_read: 0,
            cost: Some(0.01),
            latency_ms: 100,
            status: "success".to_string(),
            session_id: Some("sess-42".to_string()),
            mcp_server: Some("github".to_string()),
            mcp_tool: Some("read_file".to_string()),
            metering: kyris_core::record::Metering::Available,
            working_dir: Some("/tmp/project".to_string()),
        };

        writer
            .insert_batch(&[event])
            .expect("insert with session/mcp fields");

        let (session_id, mcp_server, mcp_tool): (String, String, String) = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT session_id, mcp_server, mcp_tool FROM gateway_records WHERE trace_id = 'trace-mcp'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("query session/mcp fields")
        });

        assert_eq!(session_id, "sess-42");
        assert_eq!(mcp_server, "github");
        assert_eq!(mcp_tool, "read_file");
    }

    #[test]
    fn testInsertBatchWithNullOptionalFields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        writer
            .insert_batch(&[sample_event("trace-null")])
            .expect("insert");

        let has_nulls: bool = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT session_id IS NULL AND mcp_server IS NULL AND mcp_tool IS NULL \
                 FROM gateway_records WHERE trace_id = 'trace-null'",
                [],
                |row| row.get(0),
            )
            .expect("check nulls")
        });

        assert!(has_nulls);
    }

    #[test]
    fn testInsertBatchPersistsWorkingDirAndMetering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        let mut event = sample_event("trace-wd");
        event.working_dir = Some("/home/user/project".to_string());
        writer.insert_batch(&[event]).expect("insert");

        let (working_dir, metering): (String, String) = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT working_dir, metering FROM gateway_records WHERE trace_id = 'trace-wd'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("query working_dir and metering")
        });
        assert_eq!(working_dir, "/home/user/project");
        assert_eq!(metering, "available");
    }

    #[test]
    fn testInsertBatchUnavailableMeteringNullsTokens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        let event = StatsEvent {
            trace_id: "trace-unavail".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens: TokenCounts::default(),
            cache_create: 0,
            cache_read: 0,
            cost: None,
            latency_ms: 100,
            status: "error".to_string(),
            session_id: None,
            mcp_server: None,
            mcp_tool: None,
            metering: kyris_core::record::Metering::Unavailable,
            working_dir: None,
        };
        writer.insert_batch(&[event]).expect("insert");

        let (tokens_null, metering): (bool, String) = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT tokens_in IS NULL AND tokens_out IS NULL, metering \
                 FROM gateway_records WHERE trace_id = 'trace-unavail'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("query unavailable record")
        });
        assert!(tokens_null);
        assert_eq!(metering, "unavailable");
    }

    #[test]
    fn testSyncMetadataSaveAndLoad() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        writer
            .save_sync_metadata(
                &["/work/*".to_string(), "/corp/*".to_string()],
                "2026-04-29T12:00:00Z",
            )
            .expect("save metadata");

        let (scope_json, last_synced_at): (String, String) = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT scope_json, last_synced_at FROM sync_metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("query sync_metadata")
        });
        let scope: Vec<String> = serde_json::from_str(&scope_json).expect("parse scope_json");
        assert_eq!(scope, vec!["/work/*", "/corp/*"]);
        assert_eq!(last_synced_at, "2026-04-29T12:00:00Z");
    }

    #[test]
    fn testSyncMetadataUpsert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test.duckdb");
        let writer = DuckDbWriter::open(&db_path);

        writer
            .save_sync_metadata(&["/work/*".to_string()], "2026-04-29T12:00:00Z")
            .expect("first save");
        writer
            .save_sync_metadata(
                &["/work/*".to_string(), "/new/*".to_string()],
                "2026-04-29T13:00:00Z",
            )
            .expect("second save");

        let (scope_json, last_synced_at): (String, String) = writer.with_conn(|conn| {
            conn.query_row(
                "SELECT scope_json, last_synced_at FROM sync_metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("query sync_metadata")
        });
        let scope: Vec<String> = serde_json::from_str(&scope_json).expect("parse scope_json");
        assert_eq!(scope, vec!["/work/*", "/new/*"]);
        assert_eq!(last_synced_at, "2026-04-29T13:00:00Z");
    }

    fn event_with_cost(trace_id: &str, cost: Option<f64>, status: &str) -> StatsEvent {
        StatsEvent {
            trace_id: trace_id.to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens: TokenCounts {
                input: 100,
                output: 50,
            },
            cache_create: 0,
            cache_read: 0,
            cost,
            latency_ms: 100,
            status: status.to_string(),
            session_id: None,
            mcp_server: None,
            mcp_tool: None,
            metering: kyris_core::record::Metering::Available,
            working_dir: None,
        }
    }

    #[test]
    fn testQuerySpendUsdSumsRecentCosts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = DuckDbWriter::open(&dir.path().join("test.duckdb"));

        let events = vec![
            event_with_cost("t1", Some(5.00), "success"),
            event_with_cost("t2", Some(3.50), "success"),
            event_with_cost("t3", Some(1.00), "error"), // excluded
            event_with_cost("t4", Some(0.50), "circuit_breaker"), // excluded
            event_with_cost("t5", None, "success"),     // NULL cost, excluded
        ];
        writer.insert_batch(&events).expect("insert");

        let total = writer.query_spend_usd(24).expect("query_spend_usd");
        // Only t1 ($5.00) and t2 ($3.50) are included.
        assert!(
            (total - 8.50).abs() < 0.01,
            "expected $8.50, got ${total:.4}"
        );
    }

    #[test]
    fn testQuerySpendUsdReturnsZeroWhenNoRecords() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = DuckDbWriter::open(&dir.path().join("test.duckdb"));

        let total = writer.query_spend_usd(24).expect("query returns Some");
        // Empty-table case — exact 0.0 is the contract (no records → no spend).
        #[allow(clippy::float_cmp)]
        let is_zero = total == 0.0;
        assert!(is_zero, "expected exactly 0.0 with no records, got {total}");
    }

    #[test]
    fn testCheckSpendThresholdsFiresOnCrossing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = DuckDbWriter::open(&dir.path().join("test.duckdb"));

        // Insert $12 of spend.
        let events = vec![
            event_with_cost("t1", Some(7.00), "success"),
            event_with_cost("t2", Some(5.00), "success"),
        ];
        writer.insert_batch(&events).expect("insert");

        let config = kyris_core::config::SpendConfig {
            warn_thresholds_usd: vec![10.0, 50.0],
            window_hours: 24,
        };
        let mut notified = std::collections::HashSet::new();

        // First check: $12 > $10 threshold → inserts into notified.
        check_spend_thresholds(&writer, &config, &mut notified);
        let key_10 = (10.0_f64 * 1_000_000.0) as u64;
        let key_50 = (50.0_f64 * 1_000_000.0) as u64;
        assert!(
            notified.contains(&key_10),
            "$10 threshold should be in notified"
        );
        assert!(
            !notified.contains(&key_50),
            "$50 threshold should not fire yet"
        );

        // Second check with same data: already notified, no double-fire.
        check_spend_thresholds(&writer, &config, &mut notified);
        assert!(
            notified.contains(&key_10),
            "still notified after second check"
        );
    }

    #[test]
    fn testCheckSpendThresholdsResetsWhenDropsBelowThreshold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = DuckDbWriter::open(&dir.path().join("test.duckdb"));

        let config = kyris_core::config::SpendConfig {
            warn_thresholds_usd: vec![10.0],
            window_hours: 24,
        };
        let mut notified = std::collections::HashSet::new();
        let key_10 = (10.0_f64 * 1_000_000.0) as u64;

        // Pre-seed notified as if it had fired before.
        notified.insert(key_10);

        // Zero spend in DB → below threshold → should be removed from notified.
        check_spend_thresholds(&writer, &config, &mut notified);
        assert!(
            !notified.contains(&key_10),
            "should be removed from notified when below threshold"
        );
    }

    #[test]
    fn testCheckSpendThresholdsNoOpWhenEmpty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = DuckDbWriter::open(&dir.path().join("test.duckdb"));

        let config = kyris_core::config::SpendConfig {
            warn_thresholds_usd: vec![],
            window_hours: 24,
        };
        let mut notified = std::collections::HashSet::new();
        // Should not panic or query the DB.
        check_spend_thresholds(&writer, &config, &mut notified);
        assert!(notified.is_empty());
    }

    #[test]
    fn testRecordDroppedIncrementsCounter() {
        // DROP_COUNT is a process-global static, so this test asserts a
        // monotonic delta rather than a specific value (other tests in the
        // same process may also exercise the counter).
        let before = dropped_count();
        record_dropped(3);
        let after = dropped_count();
        assert!(
            after >= before + 3,
            "record_dropped(3) should increment counter by >= 3 (before={before}, after={after})"
        );
        // Subsequent increments still accumulate, just without the
        // first-drop warning. Confirm the count keeps moving.
        record_dropped(2);
        let after2 = dropped_count();
        assert!(
            after2 >= after + 2,
            "record_dropped(2) should increment counter by >= 2 (after={after}, after2={after2})"
        );
    }
}
