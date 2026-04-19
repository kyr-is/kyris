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

pub struct DuckDbWriter {
    conn: std::sync::Mutex<Connection>,
}

impl DuckDbWriter {
    pub fn open(path: &Path) -> Self {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create database directory");
        }
        let conn = Connection::open(path).expect("open duckdb");
        conn.execute_batch(kyris_core::record::CREATE_GATEWAY_RECORDS)
            .expect("create gateway_records table");
        conn.execute_batch(kyris_core::record::CREATE_SESSION_TOKENS)
            .expect("create session_tokens table");
        conn.execute_batch(kyris_core::record::CREATE_SYNC_CURSOR)
            .expect("create sync_cursor table");
        Self {
            conn: std::sync::Mutex::new(conn),
        }
    }

    pub fn insert_batch(&self, events: &[StatsEvent]) -> duckdb::Result<()> {
        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn.prepare(
            "INSERT INTO gateway_records (
                id, trace_id, timestamp, provider, model,
                tokens_in, tokens_out, tokens_cache_create, tokens_cache_read,
                cost_usd, latency_ms, status, session_id, cached, mcp_server, mcp_tool
            ) VALUES (?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?)",
        )?;
        for event in events {
            let id = uuid::Uuid::now_v7().to_string();
            let cache_create: Option<i64> = if event.cache_create > 0 {
                Some(event.cache_create)
            } else {
                None
            };
            let cache_read: Option<i64> = if event.cache_read > 0 {
                Some(event.cache_read)
            } else {
                None
            };
            stmt.execute(duckdb::params![
                id,
                event.trace_id,
                event.provider,
                event.model,
                event.tokens.input,
                event.tokens.output,
                cache_create,
                cache_read,
                event.cost,
                event.latency_ms,
                event.status,
                event.session_id,
                event.mcp_server,
                event.mcp_tool,
            ])?;
        }
        Ok(())
    }

    pub fn prune(&self, retention_days: u64) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        conn.execute(
            &format!(
                "DELETE FROM gateway_records \
                 WHERE timestamp < now()::TIMESTAMP - INTERVAL '{retention_days} days'"
            ),
            [],
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

    pub fn load_session_tokens(&self) -> Vec<(String, i64)> {
        let conn = self.conn.lock().expect("lock db");
        let mut stmt = conn
            .prepare("SELECT session_id, total_tokens FROM session_tokens")
            .expect("prepare session_tokens query");
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .expect("query session_tokens");
        rows.filter_map(std::result::Result::ok).collect()
    }

    pub fn prune_session_tokens(&self, idle_timeout_minutes: u64) -> duckdb::Result<usize> {
        let conn = self.conn.lock().expect("lock db");
        conn.execute(
            &format!(
                "DELETE FROM session_tokens \
                 WHERE last_activity < now()::TIMESTAMP - INTERVAL '{idle_timeout_minutes} minutes'"
            ),
            [],
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

    pub fn with_conn<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Connection) -> R,
    {
        let conn = self.conn.lock().expect("lock db");
        f(&conn)
    }
}

pub fn open_db() -> DuckDbWriter {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = PathBuf::from(format!("{home}/.kyris/kyrisd.duckdb"));
    DuckDbWriter::open(&path)
}

pub async fn stats_writer(
    mut rx: mpsc::Receiver<StatsEvent>,
    writer: DuckDbWriter,
    circuit_breaker: Arc<crate::circuit_breaker::CircuitBreaker>,
    stats_config: kyris_core::config::StatsConfig,
    session_idle_minutes: u64,
) {
    let batch_size = stats_config.flush_batch_size;
    let retention_days = stats_config.retention_days;
    let mut batch: Vec<StatsEvent> = Vec::with_capacity(batch_size);
    let mut flush_interval = tokio::time::interval(
        std::time::Duration::from_millis(stats_config.flush_interval_ms),
    );
    let mut prune_interval = tokio::time::interval(std::time::Duration::from_hours(1));

    loop {
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Some(event) => {
                        batch.push(event);
                        if batch.len() >= batch_size {
                            flush_batch(&writer, &mut batch);
                            persist_session_tokens(&writer, &circuit_breaker);
                        }
                    }
                    None => {
                        if !batch.is_empty() {
                            flush_batch(&writer, &mut batch);
                        }
                        persist_session_tokens(&writer, &circuit_breaker);
                        return;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    flush_batch(&writer, &mut batch);
                    persist_session_tokens(&writer, &circuit_breaker);
                }
            }
            _ = prune_interval.tick() => {
                if let Err(e) = writer.prune(retention_days) {
                    tracing::warn!(error = %e, "prune failed");
                }
                if let Err(e) = writer.prune_session_tokens(session_idle_minutes) {
                    tracing::warn!(error = %e, "prune session_tokens failed");
                }
            }
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
        let sess1 = sessions.iter().find(|(id, _)| id == "sess-1").unwrap();
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
                    tokens_in, tokens_out, cost_usd, latency_ms, status, cached
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
}
