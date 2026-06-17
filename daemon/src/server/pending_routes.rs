// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use kyris_agentpact_client as agentpact;
use serde::Deserialize;

use crate::pending::ResolveError;
use crate::server::{AppState, agentpact_socket_for};

pub(super) async fn list_pending(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let held = state.pending.list_held();
    Json(serde_json::json!({ "requests": held }))
}

#[derive(Deserialize)]
pub(super) struct ResolveRequest {
    decision: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResolveDecision {
    Approved,
    Denied,
    Always,
}

impl ResolveDecision {
    fn as_approval_response(self) -> agentpact::ApprovalResponse {
        match self {
            Self::Approved => agentpact::ApprovalResponse::Approved,
            Self::Denied => agentpact::ApprovalResponse::Denied,
            Self::Always => agentpact::ApprovalResponse::Always,
        }
    }

    fn allows_execution(self) -> bool {
        matches!(self, Self::Approved | Self::Always)
    }
}

/// Map an approval-dialog outcome to a resolution.
///
/// `CouldNotShow` maps to `None`: the dialog never reached the user (occluded,
/// off-space, or — on platforms without an approval UI — never attempted), so
/// the request is left **pending** for the tray / app to resolve
/// rather than resolved. Returning `Approved` here would defeat the permission
/// gate; see `notify::ask_approval`'s non-macOS fallback, which returns
/// `CouldNotShow` precisely so this leaves the request pending.
pub(super) fn decision_for_approval_outcome(
    outcome: crate::notify::ApprovalOutcome,
) -> Option<ResolveDecision> {
    match outcome {
        crate::notify::ApprovalOutcome::Yes => Some(ResolveDecision::Approved),
        crate::notify::ApprovalOutcome::Always => Some(ResolveDecision::Always),
        crate::notify::ApprovalOutcome::No => Some(ResolveDecision::Denied),
        crate::notify::ApprovalOutcome::CouldNotShow => None,
    }
}

pub(super) fn parse_resolve_decision(value: &str) -> Option<ResolveDecision> {
    match value {
        "approved" => Some(ResolveDecision::Approved),
        "denied" => Some(ResolveDecision::Denied),
        "always" => Some(ResolveDecision::Always),
        _ => None,
    }
}

async fn send_permission_response(
    socket: String,
    approval_token: &str,
    decision: ResolveDecision,
) -> Result<(), String> {
    let token = approval_token.to_string();
    tokio::task::spawn_blocking(move || {
        // Discard the optional advisory warning (e.g. an unpersisted "always"
        // grant); agentpactd logs it, and the pending-resolution HTTP path has
        // no channel to relay it back to the developer.
        agentpact::send_permission_response(
            &socket,
            "kyrisd-resolve",
            &token,
            decision.as_approval_response(),
            None,
        )
        .map(|_warning| ())
        .map_err(|reason| reason.replace("approval response", "resolution"))
    })
    .await
    .map_err(|e| format!("permission.respond task failed: {e}"))?
}

pub(super) async fn resolve_pending(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<ResolveRequest>,
) -> StatusCode {
    let Some(decision) = parse_resolve_decision(&body.decision) else {
        return StatusCode::BAD_REQUEST;
    };

    let pending_info = state.pending.list().into_iter().find(|p| p.id == id);
    let claim = match state.pending.claim(&id) {
        Ok(claim) => claim,
        Err(ResolveError::NotFound | ResolveError::NoLongerResolvable(_)) => {
            return StatusCode::GONE;
        }
        Err(ResolveError::AlreadyResolved(_)) => return StatusCode::CONFLICT,
    };

    let socket = agentpact_socket_for(&state);
    if let Err(error) = send_permission_response(socket, &claim.approval_token, decision).await {
        tracing::warn!(pending_id = %id, %error, "failed to resolve pending request with agentpactd");
        state.pending.abandon_claim(claim);
        return StatusCode::BAD_GATEWAY;
    }

    state
        .pending
        .complete_claim(claim, decision.allows_execution());
    if let Some(info) = pending_info {
        let command = info.code.as_deref().or(info.tool.as_deref());
        let decision_label = match decision {
            ResolveDecision::Approved => "approved",
            ResolveDecision::Always => "always",
            ResolveDecision::Denied => "denied",
        };
        kyris_core::prompt_log::record_now(
            &id,
            "api",
            "resolved",
            &info.server,
            info.tool.as_deref(),
            command,
            &info.agent,
            info.allow_always,
            Some(decision_label),
        );
        crate::approvals_log::record(&crate::approvals_log::ApprovalRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            pending_id: &id,
            server: &info.server,
            command,
            agent: &info.agent,
            decision: decision_label,
        });
    }
    StatusCode::OK
}

#[derive(Deserialize)]
pub(super) struct HoldRequest {
    id: String,
    approval_token: String,
    server: String,
    tool: Option<String>,
    /// Optional verbatim code/command/path to render in the popup's
    /// accessoryView. Distinct from `tool` because `tool` is a short
    /// label ("Bash", "Read"); `code` is what the user actually needs
    /// to read to decide ("git push --force origin main").
    #[serde(default)]
    code: Option<String>,
    /// Source agent or integration surface (`codex-cli`, `claude-code`,
    /// `kyris-mcp`, ...).
    agent: String,
    /// Whether the popup may offer "For session".
    allow_always: bool,
    /// Pre-formatted "why this needs approval" body the holder rendered from
    /// agentpactd's structured ask-context. Shown as the popup's informative
    /// text. Absent for paths without ask-context (breaker holds, older callers).
    #[serde(default)]
    detail: Option<String>,
    /// Caller-sized lifetime for this pending entry, in seconds — the
    /// holder's own poll window plus margin, so the dialog outlives the
    /// wait instead of timing out mid-poll on long windows (codex's hook
    /// holds for days). Absent → the `mcp.pending_timeout_seconds` config
    /// default (older callers).
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

pub(super) async fn hold_pending(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HoldRequest>,
) -> StatusCode {
    let pending_timeout = body
        .ttl_seconds
        .unwrap_or_else(|| state.config.load().mcp.pending_timeout_seconds);
    let pending = state.pending.clone();
    let timeout_id = body.id.clone();

    // Clone for the dialog task before fields are moved into hold()
    let dialog_id = body.id.clone();
    let dialog_server = body.server.clone();
    let dialog_tool = body.tool.clone();
    let dialog_code = body.code.clone();
    let dialog_agent = body.agent.clone();
    let dialog_allow_always = body.allow_always;
    let dialog_detail = body.detail.clone();

    let _rx = state.pending.hold(
        body.id.clone(),
        body.approval_token,
        body.server,
        body.tool,
        dialog_code.clone(),
        body.agent,
        dialog_allow_always,
        body.detail,
    );
    kyris_core::prompt_log::record_now(
        &body.id,
        "api",
        "held",
        &dialog_server,
        dialog_tool.as_deref(),
        dialog_code.as_deref().or(dialog_tool.as_deref()),
        &dialog_agent,
        dialog_allow_always,
        None,
    );
    let handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(pending_timeout)).await;
        pending.timeout(&timeout_id);
    });
    state.pending.set_timeout_handle(&body.id, handle);

    // Show the approval dialog immediately rather than waiting for the tray / app.
    #[cfg(feature = "tray")]
    {
        let state = state.clone();
        tracing::info!(
            target: "kyrisd::approval",
            pending_id = %body.id,
            server = %dialog_server,
            tool = ?dialog_tool,
            "dispatching approval dialog"
        );
        kyris_core::prompt_log::record_now(
            &body.id,
            "tray",
            "dispatch",
            &dialog_server,
            dialog_tool.as_deref(),
            dialog_code.as_deref().or(dialog_tool.as_deref()),
            &dialog_agent,
            dialog_allow_always,
            None,
        );
        tokio::spawn(async move {
            let tool_label = dialog_tool.as_deref().unwrap_or("unknown tool");
            // Title/body kept lean: the window titlebar already says
            // "Kyris", and when a code block is present it speaks for
            // itself — no need for a "Review and approve:" prompt. The
            // no-code path keeps prose because there's nothing else to
            // show the user.
            // Prefer the daemon's structured "why" (effects, classification,
            // what "For session" does) when present — that is the whole point of the
            // ask-context. Fall back to the lean code-speaks-for-itself empty
            // body, then to prose when there's nothing else to show.
            let body_line = match dialog_detail.as_deref() {
                Some(detail) if !detail.is_empty() => detail.to_string(),
                _ if dialog_code.is_some() => String::new(),
                _ => format!("Agent wants to run {tool_label}. Allow?"),
            };
            let outcome = crate::notify::ask_approval(
                &format!("Allow {dialog_server}"),
                &body_line,
                dialog_code.as_deref(),
                dialog_allow_always,
            )
            .await;
            let prompt_outcome = match outcome {
                crate::notify::ApprovalOutcome::Yes => "approved",
                crate::notify::ApprovalOutcome::No => "denied",
                crate::notify::ApprovalOutcome::Always => "always",
                crate::notify::ApprovalOutcome::CouldNotShow => "could_not_show",
            };
            // CouldNotShow means the panel never became visible to the user
            // — treat as "no answer yet" and leave the request pending so
            // the menu-bar attention path (or the tray / app) can pick it
            // up. Treating CouldNotShow as Denied would silently reject
            // every request whenever the user is in a fullscreen app or on
            // a different Space — the exact failure mode this design fixes.
            let Some(decision) = decision_for_approval_outcome(outcome) else {
                kyris_core::prompt_log::record_now(
                    &dialog_id,
                    "tray",
                    "not_shown",
                    &dialog_server,
                    dialog_tool.as_deref(),
                    dialog_code.as_deref().or(dialog_tool.as_deref()),
                    &dialog_agent,
                    dialog_allow_always,
                    Some(prompt_outcome),
                );
                tracing::warn!(
                    pending_id = %dialog_id,
                    "approval panel could not be shown — leaving request pending"
                );
                return;
            };
            kyris_core::prompt_log::record_now(
                &dialog_id,
                "tray",
                "resolved",
                &dialog_server,
                dialog_tool.as_deref(),
                dialog_code.as_deref().or(dialog_tool.as_deref()),
                &dialog_agent,
                dialog_allow_always,
                Some(prompt_outcome),
            );
            // Best-effort log of the user's answer for `kyris approvals`
            // recall and offline catalog mining. Records the verbatim command
            // (multi-line preserved via JSON `\n` escaping); the agent's tool
            // label is intentionally not recorded. Falls back to dialog_tool
            // when no verbatim payload was carried in the hold request (older
            // callers that only sent the short label).
            let command = dialog_code.as_deref().or(dialog_tool.as_deref());
            crate::approvals_log::record(&crate::approvals_log::ApprovalRecord {
                ts: chrono::Utc::now().to_rfc3339(),
                pending_id: &dialog_id,
                server: &dialog_server,
                command,
                agent: &dialog_agent,
                decision: match decision {
                    ResolveDecision::Approved => "approved",
                    ResolveDecision::Always => "always",
                    ResolveDecision::Denied => "denied",
                },
            });
            let Ok(claim) = state.pending.claim(&dialog_id) else {
                return; // already timed out or resolved by another path
            };
            let socket = agentpact_socket_for(&state);
            if let Err(e) = send_permission_response(socket, &claim.approval_token, decision).await
            {
                tracing::warn!(pending_id = %dialog_id, %e, "failed to send approval dialog response");
                state.pending.abandon_claim(claim);
                return;
            }
            state
                .pending
                .complete_claim(claim, decision.allows_execution());
        });
    }

    StatusCode::OK
}

pub(super) async fn cancel_pending(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    if let Some(token) = state.pending.cancel(&id) {
        let socket = agentpact_socket_for(&state);
        let _ = send_permission_response(socket, &token, ResolveDecision::Denied).await;
    }
    StatusCode::OK
}

pub(super) async fn pending_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.pending.get_state(&id) {
        Some(s) => (StatusCode::OK, Json(serde_json::json!({ "state": s }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found" })),
        ),
    }
}
