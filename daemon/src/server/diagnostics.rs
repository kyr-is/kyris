// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use crate::server::AppState;

/// Maximum auto-revert window the diag endpoint accepts (1 hour).
/// Past this, edit `kyrisd.yaml`'s `log.filter` and restart — long-
/// term verbose logging shouldn't ride on a Tokio timer that the
/// next crash wipes.
const DIAG_LOG_FILTER_MAX_DURATION_SECS: u64 = 3600;

#[derive(Deserialize)]
pub(super) struct DiagLogFilterRequest {
    /// `EnvFilter` directive string (e.g. `kyrisd::adapter=trace,kyrisd=debug`).
    filter: String,
    /// Auto-revert window in seconds. Absent / 0 = manual revert.
    /// Capped at [`DIAG_LOG_FILTER_MAX_DURATION_SECS`].
    #[serde(default)]
    duration_secs: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct DiagLogFilterResponse {
    previous_filter: String,
    new_filter: String,
    /// Absent when no auto-revert was requested or `duration_secs=0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reverts_at: Option<String>,
}

/// GET /operator/diag/log-filter — read the currently-active filter.
/// Returns whatever `try_set_filter` last accepted (or the startup
/// value when nothing has been mutated since boot).
pub(super) async fn diag_log_filter_get() -> Json<serde_json::Value> {
    let current =
        crate::logging::current_filter().unwrap_or_else(|| "(not initialized)".to_string());
    Json(serde_json::json!({ "filter": current }))
}

/// POST /operator/diag/log-filter — swap the active filter,
/// optionally scheduling an auto-revert. Validates the directive
/// before applying so a typo never breaks logging mid-stream.
pub(super) async fn diag_log_filter_set(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DiagLogFilterRequest>,
) -> Result<Json<DiagLogFilterResponse>, (StatusCode, Json<serde_json::Value>)> {
    let previous =
        crate::logging::current_filter().unwrap_or_else(|| state.config.load().log.filter.clone());

    if let Err(error) = crate::logging::try_set_filter(&req.filter) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        ));
    }

    let duration = req
        .duration_secs
        .filter(|d| *d > 0)
        .map(|d| d.min(DIAG_LOG_FILTER_MAX_DURATION_SECS));

    let reverts_at = duration.map(|secs| {
        let when = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
        when.to_rfc3339()
    });

    if let Some(secs) = duration {
        let revert_to = previous.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            match crate::logging::try_set_filter(&revert_to) {
                Ok(()) => tracing::info!(
                    reverted_to = %revert_to,
                    source = "diag_endpoint_auto_revert",
                    "log_filter_reverted"
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    "log_filter auto-revert failed; current filter unchanged"
                ),
            }
        });
    }

    tracing::info!(
        previous = %previous,
        new = %req.filter,
        duration_secs = ?duration,
        source = "diag_endpoint",
        "log_filter_changed"
    );

    Ok(Json(DiagLogFilterResponse {
        previous_filter: previous,
        new_filter: req.filter,
        reverts_at,
    }))
}

/// Write a JSON diagnostics dump to
/// `~/.local/state/kyris/diagnostics/` (see
/// [`kyris_core::paths::diagnostics_dir`]). Called from the SIGUSR1
/// handler. Doesn't dump deep daemon state yet — that would require
/// hold-and-snapshot of various mutexes. For now we emit basic
/// build/process metadata; richer dumps can be added as the daemon's
/// internal state surfaces are stabilized.
#[cfg(unix)]
fn write_diagnostics_dump() -> std::io::Result<std::path::PathBuf> {
    let dir = kyris_core::paths::diagnostics_dir();
    std::fs::create_dir_all(&dir)?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let path = dir.join(format!("dump-{ts}.json"));

    let dump = serde_json::json!({
        "schema_version": 1,
        "version": crate::build_info::VERSION,
        "build_date": crate::build_info::BUILD_DATE,
        "commit": crate::build_info::COMMIT,
        "features": crate::build_info::FEATURES,
        "pid": std::process::id(),
        "tray_issues": crate::tray::list_issues()
            .into_iter()
            .map(|(k, v)| serde_json::json!({"key": k, "reason": v}))
            .collect::<Vec<_>>(),
    });
    let body = serde_json::to_vec_pretty(&dump).expect("serialize diagnostics dump");
    std::fs::write(&path, body)?;
    Ok(path)
}

#[cfg(unix)]
pub(super) async fn sigusr1_diagnostics(mut sigusr1: tokio::signal::unix::Signal) {
    loop {
        sigusr1.recv().await;
        match write_diagnostics_dump() {
            Ok(path) => tracing::info!(dump = %path.display(), "SIGUSR1 diagnostics dump"),
            Err(e) => tracing::warn!("SIGUSR1 diagnostics dump failed: {e}"),
        }
    }
}

#[cfg(not(unix))]
pub(super) async fn sigusr1_diagnostics(_sigusr1: ()) {
    std::future::pending::<()>().await;
}

/// SIGUSR2 — toggle the active log filter between the configured
/// baseline (`log.filter`) and the verbose preset (`log.verbose_filter`).
/// Lets an operator with shell access flip on adapter-level debug
/// during a misbehaving request without restarting the daemon, and
/// flip back when done. The transition itself is always logged at
/// INFO so it appears in the log regardless of which filter is now
/// active.
///
/// No auto-revert on this path — it sticks until another SIGUSR2 or
/// a daemon restart. For bounded-window debugging, prefer the
/// admin endpoint (`POST /operator/diag/log-filter`) which accepts
/// `duration_secs` and auto-reverts via a Tokio timer.
#[cfg(unix)]
pub(super) async fn sigusr2_toggle_log_filter(
    state: Arc<AppState>,
    mut sigusr2: tokio::signal::unix::Signal,
) {
    loop {
        sigusr2.recv().await;
        let config = state.config.load();
        let baseline = config.log.filter.clone();
        let verbose = config.log.verbose_filter.clone();
        match crate::logging::try_toggle_verbose(&baseline, &verbose) {
            Ok(now_active) => {
                tracing::info!(
                    active_filter = %now_active,
                    baseline = %baseline,
                    verbose = %verbose,
                    source = "sigusr2",
                    "log_filter_toggled"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGUSR2 log-filter toggle failed");
            }
        }
    }
}

#[cfg(not(unix))]
pub(super) async fn sigusr2_toggle_log_filter(_state: Arc<AppState>, _sigusr2: ()) {
    std::future::pending::<()>().await;
}
