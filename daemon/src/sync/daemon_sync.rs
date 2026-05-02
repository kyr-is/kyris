// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify_debouncer_mini::new_debouncer;

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

    let mut syncer = EventSyncer::new(cursor, scope.clone(), log_dir.clone());
    let client = reqwest::Client::new();

    let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<()>(1);
    let debounce_duration = Duration::from_secs(1);

    if log_dir.exists() {
        let fs_tx_clone = fs_tx.clone();
        match new_debouncer(debounce_duration, move |_res| {
            let _ = fs_tx_clone.try_send(());
        }) {
            Ok(mut debouncer) => {
                if let Err(e) = debouncer
                    .watcher()
                    .watch(&log_dir, notify::RecursiveMode::NonRecursive)
                {
                    tracing::warn!(error = %e, "failed to watch log dir, falling back to poll");
                } else {
                    // Leak the debouncer so it lives for the process lifetime.
                    // The sync loop runs for the entire daemon lifetime, so this is intentional.
                    std::mem::forget(debouncer);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to create file watcher, falling back to poll");
            }
        }
    }

    let flush_interval = Duration::from_mins(1);

    loop {
        tokio::select! {
            _ = fs_rx.recv() => {}
            () = tokio::time::sleep(flush_interval) => {}
        }

        syncer.check_rotation();
        let (mut events, new_offset) = syncer.read_new_events();
        let (raw_fail_open, fail_open_line_count) = crate::fail_open_log::read();
        let fail_open_events = filter_fail_open_in_scope(&syncer, raw_fail_open);
        let has_fail_open = !fail_open_events.is_empty();
        events.extend(fail_open_events);
        let typed_records = filter_records_in_scope(&syncer, fetch_unsynced_records(&state));
        let synced_record_ids = typed_records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let kyrisd_records = EventSyncer::serialize_records(typed_records);

        if events.is_empty() && kyrisd_records.is_empty() {
            syncer.commit_read(new_offset);
            continue;
        }

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
                syncer.commit_read(new_offset);
                if has_fail_open {
                    crate::fail_open_log::drain(fail_open_line_count);
                }
                let cursor = syncer.cursor();
                if let Err(e) = state
                    .db
                    .save_sync_cursor(&cursor.filename, cursor.byte_offset)
                {
                    tracing::warn!(error = %e, "failed to persist sync cursor");
                }
                if let Err(e) = state.db.mark_records_synced(&synced_record_ids) {
                    tracing::warn!(error = %e, "failed to mark synced kyrisd records");
                }
                let now = chrono::Utc::now().to_rfc3339();
                if let Err(e) = state.db.save_sync_metadata(&scope, &now) {
                    tracing::warn!(error = %e, "failed to persist sync metadata");
                }
                tracing::debug!(
                    batch_id = %batch.batch_id,
                    events = batch.events.len(),
                    kyrisd_records = synced_record_ids.len(),
                    "sync batch sent"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "relay sync failed — will retry from same offset");
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
                 cost_usd, latency_ms, status, session_id, synced, mcp_server, mcp_tool, \
                 working_dir, metering \
                 FROM gateway_records WHERE synced = false AND working_dir IS NOT NULL ORDER BY timestamp LIMIT 500",
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
                let metering_str: String = row.get(17)?;
                let metering = match metering_str.as_str() {
                    "unavailable" => kyris_core::record::Metering::Unavailable,
                    _ => kyris_core::record::Metering::Available,
                };
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
                    synced: row.get(13)?,
                    mcp_server: row.get(14)?,
                    mcp_tool: row.get(15)?,
                    metering,
                    working_dir: row.get(16)?,
                })
            })
            .ok();

        match rows {
            Some(r) => r.filter_map(std::result::Result::ok).collect(),
            None => vec![],
        }
    })
}

fn filter_fail_open_in_scope(
    syncer: &EventSyncer,
    events: Vec<Box<serde_json::value::RawValue>>,
) -> Vec<Box<serde_json::value::RawValue>> {
    events
        .into_iter()
        .filter(|raw| {
            serde_json::from_str::<kyris_core::event::Event>(raw.get())
                .ok()
                .is_some_and(|e| syncer.is_in_scope(e.working_dir.as_deref()))
        })
        .collect()
}

fn filter_records_in_scope(
    syncer: &EventSyncer,
    records: Vec<kyris_core::record::GatewayRecord>,
) -> Vec<kyris_core::record::GatewayRecord> {
    records
        .into_iter()
        .filter(|record| syncer.is_in_scope(record.working_dir.as_deref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyris_core::record::{GatewayRecord, Metering, RecordStatus};
    use std::io::Write;

    fn sample_gateway_record(id: &str, working_dir: Option<&str>) -> GatewayRecord {
        GatewayRecord {
            id: id.to_string(),
            trace_id: format!("trace-{id}"),
            timestamp: "2026-04-20T00:00:00Z".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens_in: Some(100),
            tokens_out: Some(50),
            tokens_cache_create: None,
            tokens_cache_read: None,
            cost_usd: Some(0.01),
            latency_ms: 250,
            status: RecordStatus::Success,
            session_id: None,
            synced: false,
            mcp_server: None,
            mcp_tool: None,
            metering: Metering::Available,
            working_dir: working_dir.map(str::to_string),
        }
    }

    #[test]
    fn testAgentpactLogDir() {
        let dir = agentpact_log_dir();
        assert!(dir.to_string_lossy().ends_with(".agentpact/log"));
    }

    #[test]
    fn testLoadCredentialsValidFile() {
        let dir = tempfile::tempdir().unwrap();
        let kyris_dir = dir.path().join(".kyris");
        std::fs::create_dir_all(&kyris_dir).unwrap();
        let cred_path = kyris_dir.join("credentials.json");
        let mut f = std::fs::File::create(&cred_path).unwrap();
        writeln!(f, r#"{{"machine_id":"m-123","machine_token":"tok-abc"}}"#).unwrap();

        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };
        let creds = load_credentials().unwrap();
        assert_eq!(creds.machine_id, "m-123");
        assert_eq!(creds.machine_token, "tok-abc");
    }

    #[test]
    fn testLoadCredentialsMissingMachineId() {
        let dir = tempfile::tempdir().unwrap();
        let kyris_dir = dir.path().join(".kyris");
        std::fs::create_dir_all(&kyris_dir).unwrap();
        let cred_path = kyris_dir.join("credentials.json");
        std::fs::write(&cred_path, r#"{"machine_token":"tok-abc"}"#).unwrap();

        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };
        assert!(load_credentials().is_none());
    }

    #[test]
    fn testLoadCredentialsMissingFile() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };
        assert!(load_credentials().is_none());
    }

    #[test]
    fn testLoadCredentialsInvalidJson() {
        let dir = tempfile::tempdir().unwrap();
        let kyris_dir = dir.path().join(".kyris");
        std::fs::create_dir_all(&kyris_dir).unwrap();
        let cred_path = kyris_dir.join("credentials.json");
        std::fs::write(&cred_path, "not valid json {{{").unwrap();

        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };
        assert!(load_credentials().is_none());
    }

    #[test]
    fn testLoadCredentialsNonStringValues() {
        let dir = tempfile::tempdir().unwrap();
        let kyris_dir = dir.path().join(".kyris");
        std::fs::create_dir_all(&kyris_dir).unwrap();
        let cred_path = kyris_dir.join("credentials.json");
        std::fs::write(&cred_path, r#"{"machine_id":123,"machine_token":"tok"}"#).unwrap();

        unsafe { std::env::set_var("HOME", dir.path().to_str().unwrap()) };
        assert!(load_credentials().is_none());
    }

    #[test]
    fn testFilterRecordsInScope() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = EventSyncer::new(
            SyncCursor {
                filename: "events.jsonl".to_string(),
                byte_offset: 0,
            },
            vec!["/work/*".to_string()],
            dir.path().to_path_buf(),
        );

        let filtered = filter_records_in_scope(
            &syncer,
            vec![
                sample_gateway_record("a", Some("/work/project")),
                sample_gateway_record("b", Some("/personal/project")),
                sample_gateway_record("c", None),
            ],
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "a");
    }
}
