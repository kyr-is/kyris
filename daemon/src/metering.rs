// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Default)]
pub struct TokenCounts {
    pub input: i64,
    pub output: i64,
}

#[derive(Debug)]
pub struct StatsEvent {
    pub trace_id: String,
    pub provider: String,
    pub model: String,
    pub tokens: TokenCounts,
    pub cache_create: i64,
    pub cache_read: i64,
    pub cost: Option<f64>,
    pub latency_ms: i64,
    pub status: String,
    pub session_id: Option<String>,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testTokenCountsDefault() {
        let tc = TokenCounts::default();
        assert_eq!(tc.input, 0);
        assert_eq!(tc.output, 0);
    }
}
