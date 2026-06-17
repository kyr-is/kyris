// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::TokenCounts;

pub(super) fn extract_tokens_from_body(body: &[u8]) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usageMetadata")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["promptTokenCount"].as_i64().unwrap_or(0),
        output: usage["candidatesTokenCount"].as_i64().unwrap_or(0),
    })
}

/// Extract usage metadata from a single NDJSON line (Google format).
pub(super) fn extract_tokens_from_ndjson_line(json: &str) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let usage = v.get("usageMetadata")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["promptTokenCount"].as_i64().unwrap_or(0),
        output: usage["candidatesTokenCount"].as_i64().unwrap_or(0),
    })
}
