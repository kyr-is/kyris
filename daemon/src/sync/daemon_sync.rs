// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use notify_debouncer_mini::new_debouncer;

use kyris_core::event::{Action, Event};
use kyris_core::record::GatewayRecord;
use kyris_core::sync::SyncCursor;
use kyris_core::timeline::TimelineEntry;

use super::event_sync::{EventSyncer, SendError, send_batch};
use crate::server::AppState;
use crate::timeline::{
    TimelineEventRow, agentpact_log_dir, entry_from_event, entry_from_orphan_record,
};

/// A model-call (`think`) event whose gateway record has not committed yet is
/// held back this long before shipping it un-enriched. kyrisd controls both
/// streams, so the record almost always lands within a flush interval; this
/// only bounds the rare dropped-record case so the cursor never stalls forever.
/// (Not the relay-side per-stream settle timer the design rejected — kyrisd is
/// the source and defers its own un-joined rows.)
const RECORD_SETTLE_GRACE: chrono::Duration = chrono::Duration::seconds(10);

/// An unsynced record whose `trace_id` never appeared as an event for this long
/// is a true model-only orphan (its `trace.attach` failed) and ships as a
/// synthetic row. Comfortably larger than `RECORD_SETTLE_GRACE` so a record is
/// only orphaned once its event would certainly have been read if it existed.
const ORPHAN_GRACE: chrono::Duration = chrono::Duration::seconds(60);

/// Consecutive *unexpected* sync failures (not a 401, not a relay 5xx, not a
/// transport error) tolerated before we treat sync as broken and flip to the
/// enrollment-error state. A 401 flips immediately; 5xx / network are transient
/// and never escalate (the relay being down isn't a credential problem).
const MAX_UNKNOWN_SYNC_FAILURES: u32 = 3;

/// The orphan grace, overridable via `KYRIS_ORPHAN_GRACE_SECS`. Dedicated-kyrisd
/// e2e tests run without an `agentpactd`, so a model-only record never gets a
/// `think` event to join to and would otherwise wait the full minute before
/// shipping; they set this small so a record syncs within seconds. Mirrors the
/// `KYRIS_SYNC_FLUSH_SECS` gate.
fn orphan_grace() -> chrono::Duration {
    std::env::var("KYRIS_ORPHAN_GRACE_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .map_or(ORPHAN_GRACE, chrono::Duration::seconds)
}

/// The sync loop's decision after a send attempt — the testable core of the
/// state machine. `consecutive_failures` is reset on success and incremented on
/// an *unexpected* failure; the caller applies the side effects (cursor, tray,
/// toast) for each verdict.
#[derive(Debug, PartialEq, Eq)]
enum SyncVerdict {
    /// Batch accepted — commit cursor, mark records synced, clear status.
    Sent,
    /// Credential rejected (401) or persistently failing — pause until re-enroll.
    EnrollmentError,
    /// Relay 5xx or unreachable — transient; keep accumulating + retry, silently.
    RelayUnavailable,
    /// Unexpected failure under the cap — transient; keep accumulating + retry.
    Retrying,
}

fn classify_send_outcome(
    result: &Result<(), SendError>,
    consecutive_failures: &mut u32,
) -> SyncVerdict {
    match result {
        Ok(()) => {
            *consecutive_failures = 0;
            SyncVerdict::Sent
        }
        // Auth rejection: the relay can't validate this machine's credential
        // (unknown/revoked, or a token it can't decrypt → 401). Enrollment
        // problem — escalate immediately.
        Err(SendError::Status(401)) => SyncVerdict::EnrollmentError,
        // Relay up-but-erroring (5xx) or unreachable (transport): transient. The
        // relay being down is not a credential problem, so this NEVER escalates
        // to enrollment error and does NOT count toward the unknown-failure cap.
        Err(SendError::Status(code)) if (500..600).contains(code) => SyncVerdict::RelayUnavailable,
        Err(SendError::Transport(_)) => SyncVerdict::RelayUnavailable,
        // Any other non-success status (unexpected 4xx, etc.): retry, but count
        // it — after `MAX_UNKNOWN_SYNC_FAILURES` in a row, treat sync as broken
        // and flip to enrollment error (re-enroll usually fixes a persistent
        // client/credential mismatch).
        Err(SendError::Status(_)) => {
            *consecutive_failures += 1;
            if *consecutive_failures >= MAX_UNKNOWN_SYNC_FAILURES {
                SyncVerdict::EnrollmentError
            } else {
                SyncVerdict::Retrying
            }
        }
    }
}

pub async fn run_sync_loop(state: Arc<AppState>) {
    let config = state.config.load();

    // Sync needs a relay to send to (config `relay.url`). Enrollment is checked
    // per-tick inside the loop (not once here) so that enrolling / un-enrolling
    // while kyrisd runs takes effect without a restart — and so an un-enrolled
    // or enrollment-errored machine never syncs.
    let relay_base = config.relay.url.trim_end_matches('/');
    if relay_base.is_empty() {
        tracing::warn!("`relay.url` is unset in kyrisd.yaml: event sync disabled");
        return;
    }

    // The ingest endpoint is `/api/v1/ingest/events`. `send_batch` POSTs to this
    // URL verbatim, so the full path must be built here (a bare base URL 404s).
    let relay_url = format!("{relay_base}/api/v1/ingest/events");

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

    // Canonicalize the user-configured scope once, here at the config-load edge:
    // a scope entry typed through a symlinked root (`/tmp/...`, or `~/work`
    // → `/mnt/...`) is resolved to the same canonical spelling the upstream
    // `working_dir` already has (agentpactd canonicalizes at ingest; peer-cwd
    // comes from getcwd). Downstream `SyncScope` then compares literally.
    let scope: Vec<String> = config
        .sync
        .scope
        .iter()
        .map(|s| super::scope::canonicalize_scope_path(s))
        .collect();
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

    // Production: flush once a minute (records also flush promptly on each
    // agentpactd event via `fs_rx`). Tests with no agentpactd set
    // `KYRIS_SYNC_FLUSH_SECS` to a small value so a record syncs within seconds
    // instead of waiting the full minute.
    let flush_interval = std::env::var("KYRIS_SYNC_FLUSH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or_else(|| Duration::from_mins(1), Duration::from_secs);
    let orphan_grace = orphan_grace();

    // Sync state machine (see module-level behavior). On any non-success the cursor is NOT advanced
    // and records are NOT marked synced, so local data always keeps accumulating
    // and flushes once sync recovers.
    let mut consecutive_failures: u32 = 0;
    // Set when the relay rejects this machine's credential (401) or sync fails
    // unexpectedly `MAX_UNKNOWN_SYNC_FAILURES` times in a row. While set, sync is
    // paused; it clears when a *different* credential appears (a successful
    // re-enroll).
    let mut enrollment_error_machine: Option<String> = None;
    let mut standalone_logged = false;

    loop {
        tokio::select! {
            _ = fs_rx.recv() => {}
            () = tokio::time::sleep(flush_interval) => {}
        }

        // Per-tick enrollment gate: do not sync while not enrolled.
        let Some(credentials) = kyris_core::credentials::load() else {
            if !standalone_logged {
                tracing::info!("standalone (not enrolled): event sync paused — run `kyris enroll`");
                standalone_logged = true;
            }
            // Reset error/backoff state and clear status; re-enroll re-initializes.
            consecutive_failures = 0;
            enrollment_error_machine = None;
            crate::tray::clear_issue("sync_relay");
            continue;
        };
        standalone_logged = false;

        // Enrollment-error gate: a credential the relay rejected stays paused
        // (no sync) until a *new* credential appears (successful re-enroll).
        if let Some(errored) = enrollment_error_machine.as_deref() {
            if errored == credentials.machine_id {
                continue; // still the rejected credential — do not sync
            }
            // A different credential => re-enrolled. Recover.
            tracing::info!("re-enrolled (new machine credential) — resuming event sync");
            enrollment_error_machine = None;
            consecutive_failures = 0;
            crate::tray::clear_issue("sync_relay");
        }

        syncer.check_rotation();
        let (raw_events, new_offset) = syncer.read_new_events();
        let (raw_fail_open, fail_open_line_count) = crate::fail_open_log::read();
        let fail_open_events = filter_fail_open_in_scope(&syncer, raw_fail_open);
        let has_fail_open = !fail_open_events.is_empty();

        // Parse the new log lines (+ fail-open spool) into typed events for the
        // join. They were validated as JSON during the scoped read; a parse
        // failure here just drops that line.
        let events: Vec<Event> = raw_events
            .iter()
            .chain(fail_open_events.iter())
            .filter_map(|raw| serde_json::from_str::<Event>(raw.get()).ok())
            .collect();

        let records = filter_records_in_scope(&syncer, fetch_unsynced_records(&state));

        if events.is_empty() && records.is_empty() {
            syncer.commit_read(new_offset);
            continue;
        }

        let now = chrono::Utc::now();

        // Join-completeness gate: a `think` event whose record has not committed
        // yet would ship un-enriched (the relay no longer joins to fix it). Hold
        // the whole tick — without advancing the cursor — until the record lands
        // (or the grace elapses, breaking a stall on a dropped record).
        if has_pending_join(&events, &records, now) {
            tracing::debug!("sync: deferring tick — a think event's record has not committed yet");
            continue;
        }

        let (entries, synced_record_ids) = build_entries(events, records, now, orphan_grace);

        if entries.is_empty() {
            syncer.commit_read(new_offset);
            continue;
        }

        let batch = syncer.build_batch(entries, &credentials.machine_id);

        let send_result = send_batch(
            &client,
            &relay_url,
            &credentials.machine_id,
            &credentials.machine_token,
            &batch,
        )
        .await;
        let verdict = classify_send_outcome(&send_result, &mut consecutive_failures);
        let err_msg = send_result
            .as_ref()
            .err()
            .map_or_else(String::new, ToString::to_string);

        match verdict {
            SyncVerdict::Sent => {
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
                    entries = batch.entries.len(),
                    records_synced = synced_record_ids.len(),
                    "sync batch sent"
                );
                // Recovered (classify reset the backoff): drop the tray issue.
                crate::tray::clear_issue("sync_relay");
            }
            // Credential rejected (401) or persistently failing → enrollment
            // problem. Pause sync until a *new* credential (re-enroll) appears,
            // and toast ONCE. The cursor stays put + records stay unsynced, so
            // data keeps accumulating.
            SyncVerdict::EnrollmentError => {
                tracing::warn!(
                    machine_id = %credentials.machine_id,
                    error = %err_msg,
                    "sync enrollment error — paused until re-enroll"
                );
                enrollment_error_machine = Some(credentials.machine_id.clone());
                crate::tray::report_issue(
                    "sync_relay",
                    "enrollment error — run `kyris enroll` to resume sync",
                );
                crate::notify::enrollment_error_toast();
            }
            // Relay 5xx / unreachable: transient. Stay quiet (status only, NO
            // toast) so a relay blip doesn't spam the user; data stays queued
            // locally and retries next tick.
            SyncVerdict::RelayUnavailable => {
                tracing::warn!(error = %err_msg, "relay unavailable — events queued locally, will retry");
                crate::tray::report_issue(
                    "sync_relay",
                    "relay unavailable — events queued locally",
                );
            }
            // Unexpected failure under the cap: transient, status only, retry.
            SyncVerdict::Retrying => {
                tracing::warn!(
                    error = %err_msg,
                    failures = consecutive_failures,
                    "unexpected relay sync failure — events queued locally, will retry"
                );
                crate::tray::report_issue("sync_relay", "relay sync failing — retrying");
            }
        }
    }
}

#[cfg(test)]
mod sync_state_tests {
    use super::*;

    fn classify(result: Result<(), SendError>, failures: &mut u32) -> SyncVerdict {
        classify_send_outcome(&result, failures)
    }

    #[test]
    fn testSuccessResetsFailuresAndSends() {
        let mut failures = 2;
        assert_eq!(classify(Ok(()), &mut failures), SyncVerdict::Sent);
        assert_eq!(failures, 0, "success must reset the backoff counter");
    }

    #[test]
    fn test401IsEnrollmentErrorImmediately() {
        let mut failures = 0;
        assert_eq!(
            classify(Err(SendError::Status(401)), &mut failures),
            SyncVerdict::EnrollmentError
        );
        assert_eq!(
            failures, 0,
            "401 escalates immediately, not via the counter"
        );
    }

    #[test]
    fn test5xxIsRelayUnavailableAndNeverEscalates() {
        let mut failures = 0;
        for _ in 0..(MAX_UNKNOWN_SYNC_FAILURES + 5) {
            assert_eq!(
                classify(Err(SendError::Status(503)), &mut failures),
                SyncVerdict::RelayUnavailable,
            );
        }
        assert_eq!(
            failures, 0,
            "5xx must not count toward the unknown-failure cap"
        );
    }

    #[test]
    fn testTransportIsRelayUnavailable() {
        let mut failures = 0;
        assert_eq!(
            classify(
                Err(SendError::Transport("connection refused".into())),
                &mut failures
            ),
            SyncVerdict::RelayUnavailable
        );
        assert_eq!(failures, 0);
    }

    #[test]
    fn testUnexpectedStatusRetriesThenEscalatesAtCap() {
        let mut failures = 0;
        // Below the cap → Retrying.
        for n in 1..MAX_UNKNOWN_SYNC_FAILURES {
            assert_eq!(
                classify(Err(SendError::Status(400)), &mut failures),
                SyncVerdict::Retrying,
                "failure #{n} should still be retrying"
            );
        }
        // The Nth consecutive unexpected failure → EnrollmentError.
        assert_eq!(
            classify(Err(SendError::Status(400)), &mut failures),
            SyncVerdict::EnrollmentError
        );
        assert_eq!(failures, MAX_UNKNOWN_SYNC_FAILURES);
    }

    #[test]
    fn testSuccessBetweenUnexpectedFailuresPreventsEscalation() {
        let mut failures = 0;
        classify(Err(SendError::Status(400)), &mut failures);
        classify(Err(SendError::Status(400)), &mut failures);
        // A success resets the streak…
        assert_eq!(classify(Ok(()), &mut failures), SyncVerdict::Sent);
        // …so the next unexpected failure is only #1 again, not an escalation.
        assert_eq!(
            classify(Err(SendError::Status(400)), &mut failures),
            SyncVerdict::Retrying
        );
    }
}

fn is_think(event: &Event) -> bool {
    event.action == Action::Think
}

/// Seconds since `timestamp` (RFC3339), or `None` if it doesn't parse.
fn event_age(now: chrono::DateTime<chrono::Utc>, timestamp: &str) -> Option<chrono::Duration> {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|ts| now.signed_duration_since(ts.with_timezone(&chrono::Utc)))
}

/// True if any recent `think` event still lacks its committed record. Such a
/// row must not ship yet — it would land un-enriched and never be fixed (the
/// relay does not join). Events older than [`RECORD_SETTLE_GRACE`] are allowed
/// through un-enriched so a single dropped record can't stall the cursor.
fn has_pending_join(
    events: &[Event],
    records: &[GatewayRecord],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let committed: HashSet<&str> = records.iter().map(|r| r.trace_id.as_str()).collect();
    events.iter().any(|e| {
        is_think(e)
            && e.trace_id
                .as_deref()
                .is_some_and(|t| !committed.contains(t))
            && event_age(now, &e.timestamp).is_none_or(|age| age < RECORD_SETTLE_GRACE)
    })
}

/// Join this tick's events to records and produce the entries to ship plus the
/// ids of the records consumed (so they can be marked synced). Uses the shared
/// timeline mappers — the same join definition the operator API uses.
///
/// A record is shipped as a model-only orphan only once it has gone unmatched
/// for [`ORPHAN_GRACE`]; younger unmatched records are left for the event that
/// is about to arrive, so a `think` event and its record never ship twice.
fn build_entries(
    events: Vec<Event>,
    records: Vec<GatewayRecord>,
    now: chrono::DateTime<chrono::Utc>,
    orphan_grace: chrono::Duration,
) -> (Vec<TimelineEntry>, Vec<String>) {
    let by_trace: std::collections::HashMap<&str, &GatewayRecord> =
        records.iter().map(|r| (r.trace_id.as_str(), r)).collect();
    let event_traces: HashSet<&str> = events
        .iter()
        .filter_map(|e| e.trace_id.as_deref())
        .collect();

    // Entries shipped to the relay carry no kyrisd-local sync state; the relay
    // knows they are synced to it. (Pass an empty scope → sync_state is None.)
    let scope = crate::timeline::SyncScope::default();

    let mut entries = Vec::with_capacity(events.len());
    let mut synced_ids = Vec::new();

    for event in &events {
        let row = TimelineEventRow::from(event);
        let rec = row
            .trace_id
            .as_deref()
            .and_then(|t| by_trace.get(t).copied());
        if let Some(r) = rec {
            synced_ids.push(r.id.clone());
        }
        entries.push(entry_from_event(&row, rec, &scope));
    }

    for rec in &records {
        let unmatched = !event_traces.contains(rec.trace_id.as_str());
        let aged_out = event_age(now, &rec.timestamp).is_none_or(|age| age >= orphan_grace);
        if unmatched && aged_out {
            entries.push(entry_from_orphan_record(rec));
            synced_ids.push(rec.id.clone());
        }
    }

    (entries, synced_ids)
}

fn fetch_unsynced_records(state: &AppState) -> Vec<kyris_core::record::GatewayRecord> {
    // Delegates to the storage layer, which shares the row mapping with
    // `query_gateway_records` (the operator API) — notably `strftime`-ing the
    // duckdb TIMESTAMP into the `String` the record expects. A previous inline
    // copy here read the raw TIMESTAMP as a String, which errored per-row and
    // silently dropped every record, so nothing ever synced.
    state.db.query_unsynced_records().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to query unsynced records for sync");
        Vec::new()
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
    use std::path::PathBuf;

    use super::*;
    use kyris_core::record::{GatewayRecord, Metering, PlanStatus, RecordStatus};

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
            plan_status: PlanStatus::Overage,
            working_dir: working_dir.map(str::to_string),
            agent: None,
        }
    }

    fn think_event(trace: Option<&str>, timestamp: &str) -> Event {
        serde_json::from_value(serde_json::json!({
            "id": format!("evt-{}", trace.unwrap_or("none")),
            "timestamp": timestamp,
            "agent": "claude",
            "action": "think",
            "detail": "model call",
            "decision": "auto",
            "working_dir": "/work/repo",
            "trace_id": trace,
            "binary": "claude",
            "attribution_method": "lineage",
        }))
        .unwrap()
    }

    #[test]
    fn testHasPendingJoinHoldsRecentThinkWithoutRecord() {
        let now = chrono::Utc::now();
        let recent = now.to_rfc3339();
        let events = vec![think_event(Some("trace-1"), &recent)];
        // No record committed yet → must hold.
        assert!(has_pending_join(&events, &[], now));
    }

    #[test]
    fn testHasPendingJoinReleasesWhenRecordPresent() {
        let now = chrono::Utc::now();
        let recent = now.to_rfc3339();
        let events = vec![think_event(Some("trace-1"), &recent)];
        let mut rec = sample_gateway_record("1", Some("/work/repo"));
        rec.trace_id = "trace-1".to_string();
        assert!(!has_pending_join(&events, &[rec], now));
    }

    #[test]
    fn testHasPendingJoinReleasesAgedThinkAsStallBreaker() {
        let now = chrono::Utc::now();
        // Older than the settle grace → ship un-enriched rather than stall.
        let old = (now - chrono::Duration::seconds(30)).to_rfc3339();
        let events = vec![think_event(Some("trace-x"), &old)];
        assert!(!has_pending_join(&events, &[], now));
    }

    #[test]
    fn testBuildEntriesEnrichesAndMarksRecordSynced() {
        let now = chrono::Utc::now();
        let events = vec![think_event(Some("trace-1"), &now.to_rfc3339())];
        let mut rec = sample_gateway_record("rec1", Some("/work/repo"));
        rec.trace_id = "trace-1".to_string();
        let (entries, synced) = build_entries(events, vec![rec], now, ORPHAN_GRACE);
        assert_eq!(
            entries.len(),
            1,
            "no separate orphan row for a matched record"
        );
        assert_eq!(entries[0].cost_usd, Some(0.01));
        assert_eq!(entries[0].model.as_deref(), Some("claude-4-opus"));
        assert_eq!(synced, vec!["rec1".to_string()]);
    }

    #[test]
    fn testBuildEntriesYoungUnmatchedRecordNotOrphanedYet() {
        let now = chrono::Utc::now();
        // A record with no event, younger than ORPHAN_GRACE: its event may still
        // be coming, so it is neither shipped nor marked synced this tick.
        let mut rec = sample_gateway_record("rec2", Some("/work/repo"));
        rec.timestamp = now.to_rfc3339();
        let (entries, synced) = build_entries(vec![], vec![rec], now, ORPHAN_GRACE);
        assert!(entries.is_empty());
        assert!(synced.is_empty());
    }

    #[test]
    fn testBuildEntriesAgedUnmatchedRecordBecomesOrphan() {
        let now = chrono::Utc::now();
        let mut rec = sample_gateway_record("rec3", Some("/work/repo"));
        rec.timestamp = (now - chrono::Duration::seconds(120)).to_rfc3339();
        rec.trace_id = "trace-orphan".to_string();
        let (entries, synced) = build_entries(vec![], vec![rec], now, ORPHAN_GRACE);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, "synthetic");
        assert_eq!(entries[0].trace_id.as_deref(), Some("trace-orphan"));
        assert_eq!(synced, vec!["rec3".to_string()]);
    }

    #[test]
    fn testAgentpactLogDir() {
        // agentpact's log dir moved under XDG_STATE_HOME with its own XDG
        // migration; agentpact_log_dir() should resolve there.
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
            std::env::set_var("HOME", "/tmp/test-home");
        }
        let dir = agentpact_log_dir();
        assert_eq!(
            dir,
            PathBuf::from("/tmp/test-home/.local/state/agentpact/log")
        );
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
