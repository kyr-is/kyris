// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::metering::TokenCounts;

pub struct TokenDelta {
    pub input: i64,
    pub output: i64,
    pub cache_creation_input: i64,
    pub cache_read_input: i64,
}

impl TokenDelta {
    pub fn new(input: i64, output: i64) -> Self {
        Self {
            input,
            output,
            cache_creation_input: 0,
            cache_read_input: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StreamTokenCounts {
    pub tokens: TokenCounts,
    pub cache_creation_input: i64,
    pub cache_read_input: i64,
}

impl StreamTokenCounts {
    pub fn accumulate(&mut self, other: &StreamTokenCounts) {
        self.tokens.input += other.tokens.input;
        self.tokens.output += other.tokens.output;
        self.cache_creation_input += other.cache_creation_input;
        self.cache_read_input += other.cache_read_input;
    }
}

/// Parse a single SSE line, returning the JSON payload if present.
/// Returns `None` for comment lines, empty lines, `data: [DONE]`, and non-data fields.
pub fn parse_sse_line(line: &str) -> Option<&str> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let data = trimmed.strip_prefix("data: ")?;
    if data == "[DONE]" {
        return None;
    }
    if data.is_empty() {
        return None;
    }
    Some(data)
}

/// Split a raw SSE text buffer into complete lines and a trailing partial line.
pub fn split_sse_lines(buf: &str) -> (Vec<&str>, &str) {
    if let Some(last_newline) = buf.rfind('\n') {
        let complete = &buf[..=last_newline];
        let remainder = &buf[last_newline + 1..];
        let lines: Vec<&str> = complete.lines().collect();
        (lines, remainder)
    } else {
        (vec![], buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testParseSSELineDataPayload() {
        let json = parse_sse_line("data: {\"type\":\"content_block_delta\"}");
        assert_eq!(json, Some("{\"type\":\"content_block_delta\"}"));
    }

    #[test]
    fn testParseSSELineDone() {
        assert_eq!(parse_sse_line("data: [DONE]"), None);
    }

    #[test]
    fn testParseSSELineEmpty() {
        assert_eq!(parse_sse_line(""), None);
    }

    #[test]
    fn testParseSSELineComment() {
        assert_eq!(parse_sse_line(": keepalive"), None);
    }

    #[test]
    fn testParseSSELineEventField() {
        assert_eq!(parse_sse_line("event: message_start"), None);
    }

    #[test]
    fn testParseSSELineWithTrailingNewline() {
        let json = parse_sse_line("data: {\"type\":\"ping\"}\r\n");
        assert_eq!(json, Some("{\"type\":\"ping\"}"));
    }

    #[test]
    fn testParseSSELineEmptyData() {
        assert_eq!(parse_sse_line("data: "), None);
    }

    #[test]
    fn testSplitSSELinesComplete() {
        let buf = "data: {\"a\":1}\n\ndata: {\"b\":2}\n";
        let (lines, remainder) = split_sse_lines(buf);
        assert_eq!(lines, vec!["data: {\"a\":1}", "", "data: {\"b\":2}"]);
        assert_eq!(remainder, "");
    }

    #[test]
    fn testSplitSSELinesPartial() {
        let buf = "data: {\"a\":1}\ndata: {\"par";
        let (lines, remainder) = split_sse_lines(buf);
        assert_eq!(lines, vec!["data: {\"a\":1}"]);
        assert_eq!(remainder, "data: {\"par");
    }

    #[test]
    fn testSplitSSELinesNoNewline() {
        let buf = "data: partial";
        let (lines, remainder) = split_sse_lines(buf);
        assert!(lines.is_empty());
        assert_eq!(remainder, "data: partial");
    }

    #[test]
    fn testTokenDeltaNew() {
        let delta = TokenDelta::new(10, 20);
        assert_eq!(delta.input, 10);
        assert_eq!(delta.output, 20);
        assert_eq!(delta.cache_creation_input, 0);
        assert_eq!(delta.cache_read_input, 0);
    }

    #[test]
    fn testStreamTokenCountsAccumulate() {
        let mut total = StreamTokenCounts::default();
        let delta = StreamTokenCounts {
            tokens: TokenCounts {
                input: 10,
                output: 5,
            },
            cache_creation_input: 3,
            cache_read_input: 2,
        };
        total.accumulate(&delta);
        assert_eq!(total.tokens.input, 10);
        assert_eq!(total.tokens.output, 5);
        assert_eq!(total.cache_creation_input, 3);
        assert_eq!(total.cache_read_input, 2);

        total.accumulate(&delta);
        assert_eq!(total.tokens.input, 20);
        assert_eq!(total.tokens.output, 10);
    }
}
