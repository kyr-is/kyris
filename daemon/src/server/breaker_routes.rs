// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use serde::Deserialize;

use crate::server::AppState;

#[derive(Deserialize)]
pub(super) struct CircuitBreakerResetRequest {
    session_id: String,
}

#[derive(Deserialize)]
pub(super) struct CircuitBreakerStopRequest {
    /// Omit to stop every session currently held at an open prompt.
    #[serde(default)]
    session_id: Option<String>,
}

pub(super) async fn circuit_breaker_reset(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CircuitBreakerResetRequest>,
) -> axum::http::StatusCode {
    // This endpoint is also how a human answers an open runaway prompt (the
    // desktop dialog, tray, and app all land here): release any request waiting
    // on this session with Continue. The breaker reset itself happens inside the
    // gate on Continue, but do it here too so a plain reset (no prompt open)
    // still clears the session.
    state
        .gate
        .resolve(&body.session_id, crate::gate::GateDecision::Continue);
    if state.circuit_breaker.reset(&body.session_id) {
        tracing::info!(session_id = %body.session_id, "circuit breaker reset");
        axum::http::StatusCode::OK
    } else {
        tracing::warn!(session_id = %body.session_id, "circuit breaker reset: unknown session");
        axum::http::StatusCode::NOT_FOUND
    }
}

/// Reset every session that's currently sitting at or above its token
/// cap. Returns the list of session IDs that were cleared so the caller
/// (tray / app) can show exactly which sessions resumed. Empty list
/// is a valid success — no sessions were tripped.
pub(super) async fn circuit_breaker_reset_all(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    // Release every open runaway prompt with Continue (the reset-all path used
    // by the tray / app), then clear every tripped session's counter.
    state.gate.resolve_all(crate::gate::GateDecision::Continue);
    let cleared = state.circuit_breaker.reset_all_tripped();
    if cleared.is_empty() {
        tracing::info!("circuit breaker reset-all: no sessions were tripped");
    } else {
        tracing::info!(count = cleared.len(), "circuit breaker reset-all");
    }
    Json(serde_json::json!({ "cleared": cleared }))
}

/// Stop a runaway session held at an open prompt — the GUI/tray "Stop" control.
/// Releases the waiting request with a 429 (or in-stream stop event). With no
/// session arg, stops every open prompt.
pub(super) async fn circuit_breaker_stop(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CircuitBreakerStopRequest>,
) -> Json<serde_json::Value> {
    if let Some(session_id) = body.session_id {
        state
            .gate
            .resolve(&session_id, crate::gate::GateDecision::Stop);
        tracing::info!(session_id = %session_id, "circuit breaker stop");
        Json(serde_json::json!({ "stopped": [session_id] }))
    } else {
        let stopped = state.gate.resolve_all(crate::gate::GateDecision::Stop);
        tracing::info!(count = stopped.len(), "circuit breaker stop-all");
        Json(serde_json::json!({ "stopped": stopped }))
    }
}
