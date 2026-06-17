// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::TokenCounts;

pub(super) fn extract_tokens_from_body(body: &[u8]) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["prompt_tokens"].as_i64().unwrap_or(0),
        output: usage["completion_tokens"].as_i64().unwrap_or(0),
    })
}

/// Extract tokens from an `OpenAI` SSE chunk's `usage` field.
/// Only the final chunk (with `stream_options.include_usage`) has usage data.
pub(super) fn extract_tokens_from_sse_json(json: &str) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["prompt_tokens"].as_i64().unwrap_or(0),
        output: usage["completion_tokens"].as_i64().unwrap_or(0),
    })
}

pub(super) fn extract_responses_tokens_from_body(body: &[u8]) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["input_tokens"].as_i64().unwrap_or(0),
        output: usage["output_tokens"].as_i64().unwrap_or(0),
    })
}

/// Extract tokens from a Responses API SSE event's `response.usage` or top-level `usage`.
/// Usage arrives in the `response.completed` event which contains the full response object.
pub(super) fn extract_responses_tokens_from_sse_json(json: &str) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let usage = v
        .get("response")
        .and_then(|r| r.get("usage"))
        .or_else(|| v.get("usage"))?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["input_tokens"].as_i64().unwrap_or(0),
        output: usage["output_tokens"].as_i64().unwrap_or(0),
    })
}
