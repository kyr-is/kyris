// SPDX-License-Identifier: Apache-2.0

pub use kyris_types::config::*;

pub fn apply_env_overrides(config: &mut KyrisdConfig) {
    apply_overrides_from(config, |key| std::env::var(key).ok());
}

pub fn apply_overrides_from<F>(config: &mut KyrisdConfig, get: F)
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(v) = get("KYRIS_SERVER_LISTEN") {
        config.server.listen = v;
    }
    if let Some(v) = get("KYRIS_SERVER_INBOUND_KEY") {
        config.server.inbound_key = v;
    }
    if let Some(v) = get("KYRIS_SERVER_OPERATOR_KEY") {
        config.server.operator_key = v;
    }
    if let Some(n) = get("KYRIS_SERVER_MAX_REQUEST_BODY_BYTES").and_then(|v| v.parse().ok()) {
        config.server.max_request_body_bytes = n;
    }
    if let Some(n) = get("KYRIS_SERVER_DRAIN_TIMEOUT_SECONDS").and_then(|v| v.parse().ok()) {
        config.server.drain_timeout_seconds = n;
    }
    if let Some(v) = get("KYRIS_CIRCUIT_BREAKER_ENABLED") {
        config.circuit_breaker.enabled = v == "true" || v == "1";
    }
    if let Some(n) = get("KYRIS_CIRCUIT_BREAKER_MAX_TOKENS").and_then(|v| v.parse().ok()) {
        config.circuit_breaker.max_tokens = n;
    }
    if let Some(n) = get("KYRIS_CIRCUIT_BREAKER_SESSION_IDLE_MINUTES").and_then(|v| v.parse().ok())
    {
        config.circuit_breaker.session_idle_minutes = n;
    }
    if let Some(v) = get("KYRIS_SYNC_ENABLED") {
        config.sync.enabled = v == "true" || v == "1";
    }
    if let Some(n) = get("KYRIS_PRICING_FETCH_INTERVAL_HOURS").and_then(|v| v.parse().ok()) {
        config.pricing.fetch_interval_hours = n;
    }
    if let Some(n) = get("KYRIS_STATS_RETENTION_DAYS").and_then(|v| v.parse().ok()) {
        config.stats.retention_days = n;
    }
    if let Some(n) = get("KYRIS_STATS_CHANNEL_CAPACITY").and_then(|v| v.parse().ok()) {
        config.stats.channel_capacity = n;
    }
    if let Some(v) = get("KYRIS_MCP_ENABLED") {
        config.mcp.enabled = v == "true" || v == "1";
    }
    if let Some(n) = get("KYRIS_MCP_PENDING_TIMEOUT_SECONDS").and_then(|v| v.parse().ok()) {
        config.mcp.pending_timeout_seconds = n;
    }
    if let Some(n) = get("KYRIS_MCP_SOCKET_TIMEOUT_MS").and_then(|v| v.parse().ok()) {
        config.mcp.socket_timeout_ms = n;
    }
}

pub fn load_mcp_config() -> McpConfig {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = std::path::PathBuf::from(format!("{home}/.kyris/kyrisd.yaml"));
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|contents| serde_saphyr::from_str::<KyrisdConfig>(&contents).ok())
        .map_or_else(McpConfig::default, |c| c.mcp)
}

pub struct KyrisdConnection {
    pub base_url: String,
    pub operator_key: String,
}

#[must_use]
pub fn load_kyrisd_connection() -> Option<KyrisdConnection> {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = std::path::PathBuf::from(format!("{home}/.kyris/kyrisd.yaml"));
    let config: KyrisdConfig = std::fs::read_to_string(&path)
        .ok()
        .and_then(|contents| serde_saphyr::from_str(&contents).ok())?;
    if config.server.operator_key.is_empty() {
        return None;
    }
    Some(KyrisdConnection {
        base_url: format!(
            "http://{}",
            rewrite_wildcard_to_loopback(&config.server.listen)
        ),
        operator_key: config.server.operator_key,
    })
}

fn rewrite_wildcard_to_loopback(listen: &str) -> String {
    if let Some(port) = listen.strip_prefix("0.0.0.0") {
        return format!("127.0.0.1{port}");
    }
    if let Some(port) = listen.strip_prefix("[::]:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = listen.strip_prefix("[::]") {
        return format!("127.0.0.1{port}");
    }
    listen.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn testApplyOverridesListen() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        apply_overrides_from(
            &mut config,
            env_from(&[("KYRIS_SERVER_LISTEN", "0.0.0.0:9999")]),
        );
        assert_eq!(config.server.listen, "0.0.0.0:9999");
    }

    #[test]
    fn testApplyOverridesCircuitBreaker() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        apply_overrides_from(
            &mut config,
            env_from(&[
                ("KYRIS_CIRCUIT_BREAKER_MAX_TOKENS", "500000"),
                ("KYRIS_CIRCUIT_BREAKER_ENABLED", "false"),
            ]),
        );
        assert_eq!(config.circuit_breaker.max_tokens, 500_000);
        assert!(!config.circuit_breaker.enabled);
    }

    #[test]
    fn testApplyOverridesInvalidNumberIgnored() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let original = config.circuit_breaker.max_tokens;
        apply_overrides_from(
            &mut config,
            env_from(&[("KYRIS_CIRCUIT_BREAKER_MAX_TOKENS", "not_a_number")]),
        );
        assert_eq!(config.circuit_breaker.max_tokens, original);
    }

    #[test]
    fn testApplyOverridesAllFields() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        apply_overrides_from(
            &mut config,
            env_from(&[
                ("KYRIS_SERVER_INBOUND_KEY", "sk-test"),
                ("KYRIS_SERVER_OPERATOR_KEY", "sk-ops-test"),
                ("KYRIS_SERVER_MAX_REQUEST_BODY_BYTES", "1024"),
                ("KYRIS_SERVER_DRAIN_TIMEOUT_SECONDS", "10"),
                ("KYRIS_SYNC_ENABLED", "1"),
                ("KYRIS_PRICING_FETCH_INTERVAL_HOURS", "12"),
                ("KYRIS_STATS_RETENTION_DAYS", "14"),
                ("KYRIS_STATS_CHANNEL_CAPACITY", "5000"),
                ("KYRIS_MCP_ENABLED", "true"),
                ("KYRIS_MCP_PENDING_TIMEOUT_SECONDS", "120"),
            ]),
        );
        assert_eq!(config.server.inbound_key, "sk-test");
        assert_eq!(config.server.operator_key, "sk-ops-test");
        assert_eq!(config.server.max_request_body_bytes, 1024);
        assert_eq!(config.server.drain_timeout_seconds, 10);
        assert!(config.sync.enabled);
        assert_eq!(config.pricing.fetch_interval_hours, 12);
        assert_eq!(config.stats.retention_days, 14);
        assert_eq!(config.stats.channel_capacity, 5000);
        assert!(config.mcp.enabled);
        assert_eq!(config.mcp.pending_timeout_seconds, 120);
    }

    #[test]
    fn testRewriteWildcardIpv4() {
        assert_eq!(
            rewrite_wildcard_to_loopback("0.0.0.0:4710"),
            "127.0.0.1:4710"
        );
    }

    #[test]
    fn testRewriteWildcardIpv6() {
        assert_eq!(rewrite_wildcard_to_loopback("[::]:4710"), "127.0.0.1:4710");
    }

    #[test]
    fn testRewritePassthroughLoopback() {
        assert_eq!(
            rewrite_wildcard_to_loopback("127.0.0.1:4710"),
            "127.0.0.1:4710"
        );
    }

    #[test]
    fn testRewritePassthroughExplicitIp() {
        assert_eq!(
            rewrite_wildcard_to_loopback("192.168.1.5:4710"),
            "192.168.1.5:4710"
        );
    }
}
