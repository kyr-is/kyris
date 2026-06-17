// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{Body, Bytes, Response, StatusCode};

fn circuit_breaker_message(token_count: i64) -> String {
    format!(
        "Circuit breaker: {token_count} tokens generated without a tool call. The run was stopped — resume from the Kyris dialog, tray, or app."
    )
}

/// The SSE "stop" event for a Google stream gated then stopped by the human. A
/// true 429 is impossible once a 200 SSE response has begun, so the agent is
/// halted with an in-stream error event (`alt=sse`, so `data:`-framed).
pub(super) fn google_stop_chunk(token_count: i64) -> Bytes {
    let payload = serde_json::json!({
        "error": {
            "code": 429,
            "message": circuit_breaker_message(token_count),
            "status": "RESOURCE_EXHAUSTED"
        }
    });
    Bytes::from(format!("data: {payload}\n\n"))
}

/// Whether a Gemini `GenerateContentResponse` value contains a `functionCall`
/// part — the model invoked a tool, so the runaway counter resets (see
/// [`crate::circuit_breaker`]).
fn google_value_has_tool_call(v: &serde_json::Value) -> bool {
    v.get("candidates")
        .and_then(|c| c.as_array())
        .is_some_and(|cands| {
            cands.iter().any(|c| {
                c.get("content")
                    .and_then(|content| content.get("parts"))
                    .and_then(|parts| parts.as_array())
                    .is_some_and(|parts| {
                        parts
                            .iter()
                            .any(|p| p.get("functionCall").is_some_and(|f| !f.is_null()))
                    })
            })
        })
}

pub(super) fn google_body_has_tool_call(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| google_value_has_tool_call(&v))
}

pub(super) fn google_json_has_tool_call(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).is_ok_and(|v| google_value_has_tool_call(&v))
}

pub(super) fn circuit_breaker_error(trace_id: &str, token_count: i64) -> Response {
    let payload = serde_json::json!({
        "error": {
            "code": 429,
            "message": circuit_breaker_message(token_count),
            "status": "RESOURCE_EXHAUSTED"
        }
    });

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(payload.to_string()))
        .expect("build circuit breaker error response")
}

/// Fail-fast response (401) when the caller supplied no Google API key (neither
/// `x-goog-api-key` header nor `?key=` query). kyrisd is a pure passthrough —
/// it forwards the caller's credential and stores none.
pub(super) fn no_credential_error(trace_id: &str) -> Response {
    let payload = serde_json::json!({
        "error": "no provider credential supplied; kyrisd forwards your agent's credential and stores none"
    });

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(payload.to_string()))
        .expect("build no-credential error response")
}
