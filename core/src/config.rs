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

pub fn apply_env_overrides(config: &mut KyrisdConfig) {
    apply_overrides_from(config, |key| std::env::var(key).ok());
}

pub fn apply_overrides_from<F>(config: &mut KyrisdConfig, get: F)
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(v) = get("KYRISO_LISTEN") {
        config.server.listen = v;
    }
    if let Some(v) = get("KYRISO_INBOUND_KEY") {
        config.server.inbound_key = v;
    }
    if let Some(v) = get("KYRISO_OPERATOR_KEY") {
        config.server.operator_key = v;
    }
    if let Some(n) = get("KYRISO_MAX_REQUEST_BODY_BYTES").and_then(|v| v.parse().ok()) {
        config.server.max_request_body_bytes = n;
    }
    if let Some(n) = get("KYRISO_DRAIN_TIMEOUT_SECONDS").and_then(|v| v.parse().ok()) {
        config.server.drain_timeout_seconds = n;
    }
    if let Some(v) = get("KYRISO_CIRCUIT_BREAKER_ENABLED") {
        config.circuit_breaker.enabled = v == "true" || v == "1";
    }
    if let Some(n) = get("KYRISO_CIRCUIT_BREAKER_MAX_TOKENS").and_then(|v| v.parse().ok()) {
        config.circuit_breaker.max_tokens = n;
    }
    if let Some(n) = get("KYRISO_CIRCUIT_BREAKER_SESSION_IDLE_MINUTES").and_then(|v| v.parse().ok())
    {
        config.circuit_breaker.session_idle_minutes = n;
    }
    if let Some(v) = get("KYRISO_SYNC_ENABLED") {
        config.sync.enabled = v == "true" || v == "1";
    }
    if let Some(n) = get("KYRISO_PRICING_FETCH_INTERVAL_HOURS").and_then(|v| v.parse().ok()) {
        config.pricing.fetch_interval_hours = n;
    }
    if let Some(n) = get("KYRISO_STATS_RETENTION_DAYS").and_then(|v| v.parse().ok()) {
        config.stats.retention_days = n;
    }
    if let Some(n) = get("KYRISO_STATS_CHANNEL_CAPACITY").and_then(|v| v.parse().ok()) {
        config.stats.channel_capacity = n;
    }
    if let Some(v) = get("KYRISO_MCP_ENABLED") {
        config.mcp.enabled = v == "true" || v == "1";
    }
    if let Some(n) = get("KYRISO_MCP_PENDING_TIMEOUT_SECONDS").and_then(|v| v.parse().ok()) {
        config.mcp.pending_timeout_seconds = n;
    }
    if let Some(n) = get("KYRISO_MCP_SOCKET_TIMEOUT_MS").and_then(|v| v.parse().ok()) {
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

#[must_use]
pub fn discover_project_config(working_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dir = working_dir;
    loop {
        let candidate = dir.join(".kyris.yaml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default)]
    pub mcp: Option<ProjectMcpConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectMcpConfig {
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
}

impl ProjectConfig {
    pub fn merge_into(&self, config: &mut KyrisdConfig) {
        if let Some(ref cb) = self.circuit_breaker {
            config.circuit_breaker = cb.clone();
        }
        if let Some(ref mcp) = self.mcp {
            config.mcp.servers.extend(mcp.servers.iter().cloned());
        }
    }
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
        apply_overrides_from(&mut config, env_from(&[("KYRISO_LISTEN", "0.0.0.0:9999")]));
        assert_eq!(config.server.listen, "0.0.0.0:9999");
    }

    #[test]
    fn testApplyOverridesCircuitBreaker() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        apply_overrides_from(
            &mut config,
            env_from(&[
                ("KYRISO_CIRCUIT_BREAKER_MAX_TOKENS", "500000"),
                ("KYRISO_CIRCUIT_BREAKER_ENABLED", "false"),
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
            env_from(&[("KYRISO_CIRCUIT_BREAKER_MAX_TOKENS", "not_a_number")]),
        );
        assert_eq!(config.circuit_breaker.max_tokens, original);
    }

    #[test]
    fn testApplyOverridesAllFields() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        apply_overrides_from(
            &mut config,
            env_from(&[
                ("KYRISO_INBOUND_KEY", "sk-test"),
                ("KYRISO_OPERATOR_KEY", "sk-ops-test"),
                ("KYRISO_MAX_REQUEST_BODY_BYTES", "1024"),
                ("KYRISO_DRAIN_TIMEOUT_SECONDS", "10"),
                ("KYRISO_SYNC_ENABLED", "1"),
                ("KYRISO_PRICING_FETCH_INTERVAL_HOURS", "12"),
                ("KYRISO_STATS_RETENTION_DAYS", "14"),
                ("KYRISO_STATS_CHANNEL_CAPACITY", "5000"),
                ("KYRISO_MCP_ENABLED", "true"),
                ("KYRISO_MCP_PENDING_TIMEOUT_SECONDS", "120"),
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
    fn testDiscoverProjectConfigFindsFile() {
        let dir = tempfile::tempdir().unwrap();
        let project_dir = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&project_dir).unwrap();
        let config_path = dir.path().join("a").join(".kyris.yaml");
        std::fs::write(&config_path, "circuit_breaker:\n  max_tokens: 50000\n").unwrap();
        let found = discover_project_config(&project_dir);
        assert_eq!(found.unwrap(), config_path);
    }

    #[test]
    fn testDiscoverProjectConfigNoneWhenMissing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(discover_project_config(dir.path()).is_none());
    }

    #[test]
    fn testProjectConfigMergeInto() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let project: ProjectConfig = serde_saphyr::from_str(
            r"
circuit_breaker:
  max_tokens: 50000
  session_idle_minutes: 15
",
        )
        .unwrap();
        project.merge_into(&mut config);
        assert_eq!(config.circuit_breaker.max_tokens, 50_000);
        assert_eq!(config.circuit_breaker.session_idle_minutes, 15);
    }

    #[test]
    fn testProjectConfigMergeIntoMcpServers() {
        let mut config: KyrisdConfig = serde_saphyr::from_str(
            r#"
mcp:
  enabled: true
  servers:
    - name: global
      upstream: "http://localhost:8080"
"#,
        )
        .unwrap();
        let project: ProjectConfig = serde_saphyr::from_str(
            r#"
mcp:
  servers:
    - name: project-local
      upstream: "http://localhost:9090"
"#,
        )
        .unwrap();
        project.merge_into(&mut config);
        assert_eq!(config.mcp.servers.len(), 2);
        assert_eq!(config.mcp.servers[1].name, "project-local");
    }
}
