// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::server::AppState;
use crate::storage;

// ---------------------------------------------------------------------------
// /api/hook/log — best-effort audit endpoint, called once per hook
// invocation at exit. The CLI sends one payload carrying inputs, the
// daemon's decision, and timing; this endpoint emits a single
// `hook resolved` tracing line. Optional fields (segments, approval_id)
// are omitted from the line when absent rather than serialized as null.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct HookLogBody {
    /// Correlation id for one hook invocation. Lets operators group
    /// related entries and spot duplicate asks (same
    /// agent+action+detail, different `hook_id`).
    pub(super) hook_id: String,
    /// Agent that triggered the hook (e.g. `claude-code`, `codex-cli`).
    agent: String,
    /// `AgentPact` action (`execute`, `read`, `write`, `call`).
    action: String,
    /// Verbatim payload from the agent — shell command, file path, MCP
    /// tool args. Free-form; not parsed.
    detail: String,
    /// Compound segments the daemon split `detail` into, when more than
    /// one. Only populated for `action=execute` compound commands.
    pub(super) segments: Option<Vec<String>>,
    /// Final decision routed back to the agent (`allow`, `deny`).
    decision: String,
    /// Who/what decided. See `cli/src/hook_cmd.rs` for the canonical
    /// set (`agentpact_auto`, `agentpact_deny`, `user_approved`,
    /// `user_denied`, `user_timeout`, `kyrisd_unreachable`,
    /// `agentpact_unreachable`, `passthrough`, `unmapped`,
    /// `protocol_mismatch`).
    source: String,
    /// `AgentPact` approval id when the decision went through an ask
    /// path; lets operators correlate hook records with approval-
    /// dialog lifecycle in `kyris::approval`. Absent for auto-decide
    /// paths.
    pub(super) approval_id: Option<String>,
    /// Whether the agent will get another say after kyris's response.
    /// `"none"` — kyris denied (exit 2) or returned a definitive
    /// allow-shape that suppresses the agent's prompt. `"agent_decides"`
    /// — kyris allowed silently (empty stdout) and the agent applies
    /// its own permission rules, which may or may not prompt.
    pub(super) agent_prompt: String,
    /// Wall-clock time from hook entry to outcome, in milliseconds.
    elapsed_ms: u64,
}

pub(super) async fn hook_log(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<HookLogBody>,
) -> StatusCode {
    // Single line per hook. `segments` and `approval_id` are tracing
    // fields only when present; when absent the line simply omits them.
    let segments_json = body
        .segments
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_default());
    tracing::info!(
        target: "kyrisd::hook",
        hook_id = %body.hook_id,
        agent = %body.agent,
        action = %body.action,
        detail = %body.detail,
        segments = segments_json.as_deref(),
        decision = %body.decision,
        source = %body.source,
        approval_id = body.approval_id.as_deref(),
        agent_prompt = %body.agent_prompt,
        elapsed_ms = body.elapsed_ms,
        "hook resolved"
    );
    StatusCode::NO_CONTENT
}

// ---------------------------------------------------------------------------
// /operator/* — read-only data inspection. Auth: operator_key (Bearer).
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub(super) struct GatewayRecordsQuery {
    provider: Option<String>,
    model: Option<String>,
    status: Option<String>,
    session_id: Option<String>,
    trace_id: Option<String>,
    mcp_server: Option<String>,
    mcp_tool: Option<String>,
    /// RFC3339 timestamp; only records strictly newer are returned.
    since: Option<String>,
    /// Hard cap is `10_000`; default `1_000`.
    limit: Option<u32>,
}

#[derive(Serialize)]
pub(super) struct GatewayRecordsResponse {
    records: Vec<kyris_core::record::GatewayRecord>,
}

#[derive(Deserialize, Default)]
pub(super) struct TimelineQuery {
    agent: Option<String>,
    action: Option<String>,
    decision: Option<String>,
    session: Option<String>,
    trace_id: Option<String>,
    /// `working_dir` prefix (a directory and everything beneath it).
    dir: Option<String>,
    /// RFC3339 inclusive lower / upper bounds.
    since: Option<String>,
    until: Option<String>,
    /// Newest-first row cap. Default 50, hard cap `10_000` (in `query_timeline`).
    limit: Option<u32>,
}

#[derive(Deserialize, Default)]
pub(super) struct StatsQuery {
    /// RFC3339 inclusive lower bound for the aggregation window.
    since: Option<String>,
    dir: Option<String>,
}

/// Reject a non-RFC3339 `since`/`until` with `400`. Both timeline readers
/// compare these bounds against stored timestamps, but they do so differently —
/// the event-log reader over `read_json` and the typed gateway-record reader —
/// so a malformed value would filter inconsistently (one path silently keeps
/// everything, the other drops everything). Failing fast here keeps the window
/// honest: a bad bound is a client error, not a misleading partial result.
fn validate_rfc3339(
    name: &str,
    val: Option<&str>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Some(v) = val
        && chrono::DateTime::parse_from_rfc3339(v).is_err()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("invalid `{name}`: expected an RFC3339 timestamp, got {v:?}")
            })),
        ));
    }
    Ok(())
}

/// GET /operator/timeline — the unified event↔record timeline, joined in kyrisd
/// (no `DuckDB` lock: kyrisd owns the records and reads the event log itself).
/// Returns finished `TimelineEntry` rows; the CLI renders them.
pub(super) async fn operator_timeline(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<TimelineQuery>,
) -> Result<Json<kyris_core::timeline::TimelinePage>, (StatusCode, Json<serde_json::Value>)> {
    validate_rfc3339("since", q.since.as_deref())?;
    validate_rfc3339("until", q.until.as_deref())?;
    let filter = crate::timeline::TimelineFilter {
        agent: q.agent,
        action: q.action,
        decision: q.decision,
        session: q.session,
        trace_id: q.trace_id,
        dir: q.dir,
        since: q.since,
        until: q.until,
        limit: q.limit.unwrap_or(50),
    };
    let log_dir = crate::timeline::agentpact_log_dir();
    let entries = crate::timeline::query_timeline(&state.db, &log_dir, &filter);
    Ok(Json(kyris_core::timeline::TimelinePage {
        entries,
        cursor: None,
    }))
}

/// GET /operator/stats — aggregate usage over a window, computed in kyrisd from
/// the same unified timeline. The CLI renders the numbers.
pub(super) async fn operator_stats(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<StatsQuery>,
) -> Result<Json<kyris_core::timeline::TimelineStats>, (StatusCode, Json<serde_json::Value>)> {
    validate_rfc3339("since", q.since.as_deref())?;
    let filter = crate::timeline::TimelineFilter {
        since: q.since,
        dir: q.dir,
        // Aggregate over the whole window, not a newest-N slice.
        limit: 10_000,
        ..Default::default()
    };
    let log_dir = crate::timeline::agentpact_log_dir();
    let entries = crate::timeline::query_timeline(&state.db, &log_dir, &filter);
    Ok(Json(crate::timeline::compute_stats(&entries)))
}

pub(super) async fn operator_gateway_records(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<GatewayRecordsQuery>,
) -> Result<Json<GatewayRecordsResponse>, (StatusCode, Json<serde_json::Value>)> {
    validate_rfc3339("since", q.since.as_deref())?;
    let filter = storage::GatewayRecordFilter {
        provider: q.provider.as_deref(),
        model: q.model.as_deref(),
        status: q.status.as_deref(),
        session_id: q.session_id.as_deref(),
        trace_id: q.trace_id.as_deref(),
        mcp_server: q.mcp_server.as_deref(),
        mcp_tool: q.mcp_tool.as_deref(),
        since: q.since.as_deref(),
        limit: q.limit,
    };
    match state.db.query_gateway_records(filter) {
        Ok(records) => Ok(Json(GatewayRecordsResponse { records })),
        Err(err) => {
            tracing::warn!(error = %err, "operator gateway-records query failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            ))
        }
    }
}

/// Live stream of gateway records as they are persisted (L4 of the monitoring
/// strategy). Server-Sent Events; one JSON `GatewayRecord` per event. Subscribers
/// that fall behind the broadcast buffer skip ahead (records are dropped for that
/// reader, not buffered indefinitely) — the `DuckDB` store remains the full record.
pub(super) async fn operator_stream(
    State(state): State<Arc<AppState>>,
) -> axum::response::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};

    let rx = state.db.subscribe_records();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(record) => {
                    let event = Event::default()
                        .json_data(&record)
                        .unwrap_or_else(|_| Event::default().comment("record serialize error"));
                    return Some((Ok::<_, std::convert::Infallible>(event), rx));
                }
                // Slow consumer: skip the gap and keep streaming (loop re-polls).
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                // Sender dropped (daemon shutting down): end the stream.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub(super) async fn operator_session_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Result<Json<kyris_core::record::SessionTokenRow>, (StatusCode, Json<serde_json::Value>)> {
    match state.db.query_session_token(&session_id) {
        Ok(Some(row)) => Ok(Json(row)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "session not found", "session_id": session_id })),
        )),
        Err(err) => {
            tracing::warn!(error = %err, %session_id, "operator session-token query failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            ))
        }
    }
}

#[derive(Serialize)]
pub(super) struct HealthzResponse {
    ready: bool,
    providers: usize,
    dropped_events: u64,
    db_writable: bool,
}

pub(super) async fn healthz(
    State(state): State<Arc<AppState>>,
) -> (axum::http::StatusCode, Json<HealthzResponse>) {
    let config = state.config.load();
    let dropped = storage::dropped_count();
    let providers = config.providers.len();
    let db_writable = state.db.probe_writable();
    let ready = dropped == 0 && db_writable;
    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(HealthzResponse {
            ready,
            providers,
            dropped_events: dropped,
            db_writable,
        }),
    )
}
