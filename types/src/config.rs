// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyrisdConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub pricing: PricingConfig,
    #[serde(default)]
    pub stats: StatsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub inbound_key: String,
    #[serde(default)]
    pub operator_key: String,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_drain_timeout_seconds")]
    pub drain_timeout_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            inbound_key: String::new(),
            operator_key: String::new(),
            max_request_body_bytes: default_max_request_body_bytes(),
            drain_timeout_seconds: default_drain_timeout_seconds(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub api_key: String,
    pub upstream: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_streaming_timeout_seconds")]
    pub streaming_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pending_timeout_seconds")]
    pub pending_timeout_seconds: u64,
    #[serde(default = "default_socket_timeout_ms")]
    pub socket_timeout_ms: u64,
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pending_timeout_seconds: default_pending_timeout_seconds(),
            socket_timeout_ms: default_socket_timeout_ms(),
            servers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub upstream: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u64,
    #[serde(default = "default_session_idle_minutes")]
    pub session_idle_minutes: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_tokens: default_max_tokens(),
            session_idle_minutes: default_session_idle_minutes(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub relay_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    #[serde(default = "default_pricing_file")]
    pub file: String,
    #[serde(default = "default_fetch_interval_hours")]
    pub fetch_interval_hours: u64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            file: default_pricing_file(),
            fetch_interval_hours: default_fetch_interval_hours(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsConfig {
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_flush_batch_size")]
    pub flush_batch_size: usize,
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
            flush_interval_ms: default_flush_interval_ms(),
            flush_batch_size: default_flush_batch_size(),
            channel_capacity: default_channel_capacity(),
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:4710".to_string()
}
fn default_max_request_body_bytes() -> usize {
    10_485_760
}
fn default_drain_timeout_seconds() -> u64 {
    30
}
fn default_timeout_seconds() -> u64 {
    30
}
fn default_streaming_timeout_seconds() -> u64 {
    300
}
fn default_pending_timeout_seconds() -> u64 {
    60
}
fn default_socket_timeout_ms() -> u64 {
    50
}
fn default_true() -> bool {
    true
}
fn default_max_tokens() -> u64 {
    200_000
}
fn default_session_idle_minutes() -> u64 {
    30
}
fn default_pricing_file() -> String {
    "config/pricing.yaml".to_string()
}
fn default_fetch_interval_hours() -> u64 {
    6
}
fn default_retention_days() -> u64 {
    7
}
fn default_flush_interval_ms() -> u64 {
    1000
}
fn default_flush_batch_size() -> usize {
    100
}
fn default_channel_capacity() -> usize {
    10_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testServerConfigDefaults() {
        let config = ServerConfig::default();
        assert_eq!(config.listen, "127.0.0.1:4710");
        assert_eq!(config.max_request_body_bytes, 10_485_760);
        assert_eq!(config.drain_timeout_seconds, 30);
    }

    #[test]
    fn testCircuitBreakerDefaults() {
        let config = CircuitBreakerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_tokens, 200_000);
        assert_eq!(config.session_idle_minutes, 30);
    }

    #[test]
    fn testStatsDefaults() {
        let config = StatsConfig::default();
        assert_eq!(config.retention_days, 7);
        assert_eq!(config.flush_interval_ms, 1000);
        assert_eq!(config.flush_batch_size, 100);
        assert_eq!(config.channel_capacity, 10_000);
    }

    #[test]
    fn testKyrisdConfigFromYaml() {
        let yaml_str = r#"
server:
  listen: "127.0.0.1:4710"
  inbound_key: "sk-kyris-test"
  operator_key: "sk-kyris-ops-test"
providers:
  - name: anthropic
    api_key: "sk-ant-test"
    upstream: "https://api.anthropic.com"
    models:
      - claude-4-opus
circuit_breaker:
  max_tokens: 100000
"#;
        let config: KyrisdConfig = serde_saphyr::from_str(yaml_str).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:4710");
        assert_eq!(config.server.inbound_key, "sk-kyris-test");
        assert_eq!(config.server.operator_key, "sk-kyris-ops-test");
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "anthropic");
        assert_eq!(config.circuit_breaker.max_tokens, 100_000);
        assert!(config.circuit_breaker.enabled);
    }

    #[test]
    fn testKyrisdConfigEmptyYaml() {
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:4710");
        assert!(config.providers.is_empty());
        assert!(!config.mcp.enabled);
        assert!(!config.sync.enabled);
    }

    #[test]
    fn testMcpConfigFromYaml() {
        let yaml_str = r#"
mcp:
  enabled: true
  pending_timeout_seconds: 120
  servers:
    - name: github
      upstream: "http://localhost:8080"
"#;
        let config: KyrisdConfig = serde_saphyr::from_str(yaml_str).unwrap();
        assert!(config.mcp.enabled);
        assert_eq!(config.mcp.pending_timeout_seconds, 120);
        assert_eq!(config.mcp.servers.len(), 1);
        assert_eq!(config.mcp.servers[0].name, "github");
    }

    #[test]
    fn testSyncConfigDefaults() {
        let config = SyncConfig::default();
        assert!(!config.enabled);
        assert!(config.scope.is_empty());
    }
}
