// SPDX-FileCopyrightText: Copyright 2026 Kyris
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
    // The inbound/operator secret keys are deliberately NOT env-overridable:
    // the on-disk secret store is their single source of truth (see
    // `kyris_core::secret`). An env override would let a stale value shadow the
    // stored key and silently re-introduce hook<->daemon drift.
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
    let path = crate::paths::config_path();
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
    let path = crate::paths::config_path();
    let config: KyrisdConfig = std::fs::read_to_string(&path)
        .ok()
        .and_then(|contents| serde_saphyr::from_str(&contents).ok())?;
    // The operator key is not in the yaml — it lives in the secret store (see
    // `crate::secret`). Fetch it there; `get_or_create` mints one if absent and
    // otherwise returns the existing value, so this connection always carries
    // the same key the daemon validates against. `None` on any store error
    // preserves the caller's graceful-degradation path.
    let operator_key =
        crate::secret::get_or_create(crate::secret::ACCOUNT_OPERATOR, "sk-kyris-ops").ok()?;
    Some(KyrisdConnection {
        base_url: format!(
            "http://{}",
            rewrite_wildcard_to_loopback(&config.server.listen)
        ),
        operator_key,
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
                ("KYRIS_SERVER_MAX_REQUEST_BODY_BYTES", "1024"),
                ("KYRIS_SERVER_DRAIN_TIMEOUT_SECONDS", "10"),
                ("KYRIS_PRICING_FETCH_INTERVAL_HOURS", "12"),
                ("KYRIS_STATS_RETENTION_DAYS", "14"),
                ("KYRIS_STATS_CHANNEL_CAPACITY", "5000"),
                ("KYRIS_MCP_ENABLED", "true"),
                ("KYRIS_MCP_PENDING_TIMEOUT_SECONDS", "120"),
            ]),
        );
        assert_eq!(config.server.max_request_body_bytes, 1024);
        assert_eq!(config.server.drain_timeout_seconds, 10);
        assert_eq!(config.pricing.fetch_interval_hours, 12);
        assert_eq!(config.stats.retention_days, 14);
        assert_eq!(config.stats.channel_capacity, 5000);
        assert!(config.mcp.enabled);
        assert_eq!(config.mcp.pending_timeout_seconds, 120);
    }

    #[test]
    fn testSecretKeysAreNotEnvOverridable() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.server.inbound_key = "from-store".to_string();
        config.server.operator_key = "ops-from-store".to_string();
        apply_overrides_from(
            &mut config,
            env_from(&[
                ("KYRIS_SERVER_INBOUND_KEY", "sk-evil"),
                ("KYRIS_SERVER_OPERATOR_KEY", "sk-ops-evil"),
            ]),
        );
        // The secret store is the single source of truth; env must not shadow it.
        assert_eq!(config.server.inbound_key, "from-store");
        assert_eq!(config.server.operator_key, "ops-from-store");
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
