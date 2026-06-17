// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{Body, Bytes, Response, StatusCode};

fn circuit_breaker_message(token_count: i64) -> String {
    format!(
        "Circuit breaker: {token_count} tokens generated without a tool call. The run was stopped — resume from the Kyris dialog, tray, or app."
    )
}

/// The SSE "stop" event for an Anthropic stream gated then stopped by the
/// human. A true 429 is impossible once a 200 SSE response has begun, so the
/// agent is halted with an in-stream `error` event.
pub(super) fn anthropic_stop_chunk(token_count: i64) -> Bytes {
    let payload = serde_json::json!({
        "type": "error",
        "error": {
            "type": "circuit_breaker",
            "message": circuit_breaker_message(token_count),
        }
    });
    Bytes::from(format!("event: error\ndata: {payload}\n\n"))
}

/// Whether a Messages response object contains a `tool_use` content block (or a
/// `stop_reason` of `tool_use`) — the agent took an action, so the runaway
/// counter resets (see [`crate::circuit_breaker`]).
pub(super) fn anthropic_body_has_tool_call(body: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    if v.get("stop_reason").and_then(|s| s.as_str()) == Some("tool_use") {
        return true;
    }
    v.get("content")
        .and_then(|c| c.as_array())
        .is_some_and(|blocks| {
            blocks
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
        })
}

/// Tool-call detection for a single Messages SSE event: a `content_block_start`
/// whose block is a `tool_use`, or a `message_delta` reporting
/// `stop_reason: tool_use`.
pub(super) fn anthropic_sse_has_tool_call(json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    if v.get("content_block")
        .and_then(|b| b.get("type"))
        .and_then(|t| t.as_str())
        == Some("tool_use")
    {
        return true;
    }
    v.get("delta")
        .and_then(|d| d.get("stop_reason"))
        .and_then(|s| s.as_str())
        == Some("tool_use")
}

/// Pre-request circuit breaker response (429). Used for both streaming and
/// non-streaming requests: the SSE connection has not been established yet,
/// so a plain HTTP 429 is the correct response regardless of stream mode.
/// Mid-stream circuit breaker injection (once SSE is active) remains 200.
pub(super) fn circuit_breaker_response(trace_id: &str, token_count: i64) -> Response {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(
            serde_json::json!({
                "type": "error",
                "error": {
                    "type": "circuit_breaker",
                    "message": circuit_breaker_message(token_count),
                },
            })
            .to_string(),
        ))
        .expect("build circuit breaker response")
}

/// Fail-fast response (401) when the caller supplied no provider credential.
/// kyrisd is a pure passthrough — it forwards the caller's credential and
/// stores none — so there is nothing to send upstream.
pub(super) fn no_credential_response(trace_id: &str) -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(
            serde_json::json!({
                "error": "no provider credential supplied; kyrisd forwards your agent's credential and stores none"
            })
            .to_string(),
        ))
        .expect("build no-credential response")
}
