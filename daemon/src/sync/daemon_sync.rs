// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kyris_core::sync::SyncCursor;

use super::event_sync::{EventSyncer, send_batch};
use crate::server::AppState;

struct Credentials {
    machine_id: String,
    machine_token: String,
}

fn load_credentials() -> Option<Credentials> {
    let home = std::env::var("HOME").ok()?;
    let path = format!("{home}/.kyris/credentials.json");
    let contents = std::fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&contents).ok()?;
    let machine_id = parsed.get("machine_id")?.as_str()?.to_string();
    let machine_token = parsed.get("machine_token")?.as_str()?.to_string();
    Some(Credentials {
        machine_id,
        machine_token,
    })
}

fn agentpact_log_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.agentpact/log"))
}

pub async fn run_sync_loop(state: Arc<AppState>) {
    let config = state.config.load();
    if !config.sync.enabled {
        tracing::debug!("sync disabled, skipping event sync loop");
        return;
    }

    let relay_url = config.sync.relay_url.clone();
    if relay_url.is_empty() {
        tracing::warn!("sync enabled but relay_url not configured");
        return;
    }

    let Some(credentials) = load_credentials() else {
        tracing::warn!("sync enabled but credentials not found, run `kyris enroll`");
        return;
    };

    let cursor = state.db.load_sync_cursor().map_or_else(
        || SyncCursor {
            filename: "events.jsonl".to_string(),
            byte_offset: 0,
        },
        |(filename, byte_offset)| SyncCursor {
            filename,
            byte_offset,
        },
    );

    let scope = config.sync.scope.clone();
    let log_dir = agentpact_log_dir();

    let mut syncer = EventSyncer::new(cursor, scope, log_dir);
    let client = reqwest::Client::new();

    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        syncer.check_rotation();
        let events = syncer.read_new_events();

        if events.is_empty() {
            continue;
        }

        let kyrisd_records = fetch_unsynced_records(&state);
        let batch = syncer.build_batch(events, &credentials.machine_id, kyrisd_records);

        match send_batch(
            &client,
            &relay_url,
            &credentials.machine_id,
            &credentials.machine_token,
            &batch,
        )
        .await
        {
            Ok(()) => {
                let cursor = syncer.cursor();
                if let Err(e) = state
                    .db
                    .save_sync_cursor(&cursor.filename, cursor.byte_offset)
                {
                    tracing::warn!(error = %e, "failed to persist sync cursor");
                }
                tracing::debug!(
                    batch_id = %batch.batch_id,
                    events = batch.events.len(),
                    "sync batch sent"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "relay sync failed");
                crate::notify::relay_sync_error_toast(&e);
                crate::tray::set_state(crate::tray::TrayState::RelayDisconnected);
            }
        }
    }
}

fn fetch_unsynced_records(state: &AppState) -> Vec<kyris_core::record::GatewayRecord> {
    state.db.with_conn(|conn| {
        let mut stmt = conn
            .prepare(
                "SELECT id, trace_id, timestamp, provider, model, \
                 tokens_in, tokens_out, tokens_cache_create, tokens_cache_read, \
                 cost_usd, latency_ms, status, session_id, cached, mcp_server, mcp_tool \
                 FROM gateway_records WHERE cached = false ORDER BY timestamp LIMIT 500",
            )
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "prepare unsynced records query failed");
                conn.prepare("SELECT 1 WHERE false").unwrap()
            });

        let rows = stmt
            .query_map([], |row| {
                let status_str: String = row.get(11)?;
                let status = status_str
                    .parse::<kyris_core::record::RecordStatus>()
                    .unwrap_or(kyris_core::record::RecordStatus::Success);
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
                    status,
                    session_id: row.get(12)?,
                    cached: row.get(13)?,
                    mcp_server: row.get(14)?,
                    mcp_tool: row.get(15)?,
                    metering: kyris_core::record::Metering::default(),
                    working_dir: None,
                })
            })
            .ok();

        match rows {
            Some(r) => r.filter_map(std::result::Result::ok).collect(),
            None => vec![],
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testAgentpactLogDir() {
        let dir = agentpact_log_dir();
        assert!(dir.to_string_lossy().ends_with(".agentpact/log"));
    }
}
