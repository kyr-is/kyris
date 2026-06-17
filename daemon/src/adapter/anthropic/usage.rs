// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{StreamTokenCounts, TokenCounts};

pub(super) struct BodyUsage {
    pub(super) tokens: TokenCounts,
    pub(super) cache_create: i64,
    pub(super) cache_read: i64,
}

pub(super) fn extract_usage_from_body(body: &[u8]) -> Option<BodyUsage> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(BodyUsage {
        tokens: TokenCounts {
            input: usage["input_tokens"].as_i64().unwrap_or(0),
            output: usage["output_tokens"].as_i64().unwrap_or(0),
        },
        cache_create: usage["cache_creation_input_tokens"].as_i64().unwrap_or(0),
        cache_read: usage["cache_read_input_tokens"].as_i64().unwrap_or(0),
    })
}

/// Extract token information from a single SSE data JSON payload (Anthropic format).
pub fn extract_tokens_from_sse_json(json: &str) -> Option<StreamTokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let event_type = v.get("type")?.as_str()?;

    match event_type {
        "message_start" => {
            let usage = &v["message"]["usage"];
            let input = usage["input_tokens"].as_i64().unwrap_or(0);
            let cache_creation = usage["cache_creation_input_tokens"].as_i64().unwrap_or(0);
            let cache_read = usage["cache_read_input_tokens"].as_i64().unwrap_or(0);
            Some(StreamTokenCounts {
                tokens: TokenCounts { input, output: 0 },
                cache_creation_input: cache_creation,
                cache_read_input: cache_read,
            })
        }
        "message_delta" => {
            let usage = &v["usage"];
            let output = usage["output_tokens"].as_i64().unwrap_or(0);
            Some(StreamTokenCounts {
                tokens: TokenCounts { input: 0, output },
                cache_creation_input: 0,
                cache_read_input: 0,
            })
        }
        _ => None,
    }
}
