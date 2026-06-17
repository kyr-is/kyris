// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{Body, Bytes, Response, StatusCode};

pub(super) fn circuit_breaker_message(token_count: i64) -> String {
    format!(
        "Circuit breaker: {token_count} tokens generated without a tool call. The run was stopped — resume from the Kyris dialog, tray, or app."
    )
}

pub(super) fn circuit_breaker_error(trace_id: &str, token_count: i64) -> Response {
    let payload = serde_json::json!({
        "error": {
            "message": circuit_breaker_message(token_count),
            "type": "circuit_breaker",
            "code": "circuit_breaker"
        }
    });

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(payload.to_string()))
        .expect("build circuit breaker error response")
}

/// The SSE "stop" event for an `OpenAI` stream gated then stopped by the human.
/// A true 429 is impossible once a 200 SSE response has begun, so the agent is
/// halted with an in-stream error event carrying the same shape as the
/// pre-flight 429 body.
pub(super) fn openai_stop_chunk(token_count: i64) -> Bytes {
    let payload = serde_json::json!({
        "error": {
            "message": circuit_breaker_message(token_count),
            "type": "circuit_breaker",
            "code": "circuit_breaker"
        }
    });
    Bytes::from(format!("data: {payload}\n\n"))
}

/// Whether a chat-completions response (object or one SSE chunk) took any
/// tool/function action — a `tool_calls`/`function_call` in the message/delta,
/// or a `finish_reason` of `tool_calls`/`function_call`. Such a response resets
/// the runaway counter (see [`crate::circuit_breaker`]).
pub(super) fn chat_value_has_tool_call(v: &serde_json::Value) -> bool {
    let Some(choices) = v.get("choices").and_then(|c| c.as_array()) else {
        return false;
    };
    choices.iter().any(|choice| {
        let finish = choice.get("finish_reason").and_then(|f| f.as_str());
        if matches!(finish, Some("tool_calls" | "function_call")) {
            return true;
        }
        let msg = choice.get("message").or_else(|| choice.get("delta"));
        msg.is_some_and(|m| {
            m.get("tool_calls")
                .and_then(|t| t.as_array())
                .is_some_and(|a| !a.is_empty())
                || m.get("function_call").is_some_and(|f| !f.is_null())
        })
    })
}

pub(super) fn chat_body_has_tool_call(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| chat_value_has_tool_call(&v))
}

pub(super) fn chat_sse_has_tool_call(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).is_ok_and(|v| chat_value_has_tool_call(&v))
}

/// Whether a Responses-API output-item `type` denotes a tool/function/shell
/// call (e.g. `function_call`, `local_shell_call`, `custom_tool_call`,
/// `web_search_call`, `computer_call`) rather than `message` / `reasoning`.
pub(super) fn is_responses_call_type(t: &str) -> bool {
    t == "function_call" || t.ends_with("_call")
}

pub(super) fn responses_output_has_tool_call(output: &serde_json::Value) -> bool {
    output.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item.get("type")
                .and_then(|t| t.as_str())
                .is_some_and(is_responses_call_type)
        })
    })
}

pub(super) fn responses_body_has_tool_call(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("output").map(responses_output_has_tool_call))
        .unwrap_or(false)
}

/// Tool-call detection for a single Responses-API SSE event: the terminal
/// `response.completed` event carries the full response object with its
/// `output` array; streaming `response.output_item.*` events carry a single
/// `item`; and function-call argument-delta events carry a `function_call`
/// type marker.
pub(super) fn responses_sse_has_tool_call(json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    if let Some(output) = v.get("response").and_then(|r| r.get("output"))
        && responses_output_has_tool_call(output)
    {
        return true;
    }
    if let Some(t) = v
        .get("item")
        .and_then(|i| i.get("type"))
        .and_then(|t| t.as_str())
        && is_responses_call_type(t)
    {
        return true;
    }
    v.get("type")
        .and_then(|t| t.as_str())
        .is_some_and(|t| t.contains("function_call"))
}

/// Fail-fast response (401) when the caller supplied no `authorization`
/// credential. kyrisd is a pure passthrough — it forwards the caller's
/// credential and stores none — so there is nothing to send upstream.
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
