// SPDX-FileCopyrightText: Copyright 2026 Kyris
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
    pub relay: RelayConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub pricing: PricingConfig,
    #[serde(default)]
    pub stats: StatsConfig,
    #[serde(default)]
    pub agents: AgentsConfig,
    #[serde(default)]
    pub spend: SpendConfig,
    #[serde(default)]
    pub log: LogConfig,
}

/// Operational logging configuration. `filter` is the baseline
/// `EnvFilter` directive applied at startup (overridden by
/// `KYRIS_LOG` / `RUST_LOG` env vars when present). `verbose_filter`
/// is what `SIGUSR2` toggles to and back from — typically something
/// like `kyrisd::adapter=trace,kyrisd=debug` for one-off forensics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_filter")]
    pub filter: String,
    #[serde(default = "default_log_verbose_filter")]
    pub verbose_filter: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            filter: default_log_filter(),
            verbose_filter: default_log_verbose_filter(),
        }
    }
}

fn default_log_filter() -> String {
    "kyrisd=info".to_string()
}

fn default_log_verbose_filter() -> String {
    "kyrisd::adapter=trace,kyrisd::auth=debug,kyrisd=debug".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    // Secret bearer keys are NOT persisted to kyrisd.yaml. They live in the
    // login Keychain (see `kyris_core::keychain`) and are populated into these
    // in-memory fields at config-load time, so they survive `--reset-data` and
    // can't drift between the daemon and the hook. `#[serde(skip)]` keeps them
    // out of both the parsed file and any rewrite of it.
    #[serde(skip)]
    pub inbound_key: String,
    #[serde(skip)]
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

impl TlsConfig {
    /// Checks that cert and key paths exist when TLS is enabled.
    ///
    /// # Errors
    /// Returns an error if paths are empty or do not exist on disk.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.cert_path.is_empty() {
            return Err("tls.enabled is true but tls.cert_path is empty".to_string());
        }
        if self.key_path.is_empty() {
            return Err("tls.enabled is true but tls.key_path is empty".to_string());
        }
        let cert = std::path::Path::new(&self.cert_path);
        if !cert.exists() {
            return Err(format!("tls.cert_path does not exist: {}", self.cert_path));
        }
        let key = std::path::Path::new(&self.key_path);
        if !key.exists() {
            return Err(format!("tls.key_path does not exist: {}", self.key_path));
        }
        Ok(())
    }
}

impl KyrisdConfig {
    #[must_use]
    pub fn base_url(&self) -> String {
        let scheme = if self.tls.enabled { "https" } else { "http" };
        format!("{scheme}://{}", self.server.listen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderFormat {
    Anthropic,
    #[serde(rename = "openai")]
    OpenAI,
    Google,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub format: ProviderFormat,
    pub api_key: String,
    pub upstream: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_streaming_timeout_seconds")]
    pub streaming_timeout_seconds: u64,
}

impl ProviderConfig {
    /// Canonical defaults for each well-known format: a fresh-install kyrisd
    /// with no `providers[]` configured is still a usable transparent proxy —
    /// the agent brings its own credential and kyrisd forwards it to the
    /// standard upstream. Explicit `providers[]` entries only matter when you
    /// want to override the upstream or supply a fallback API key.
    #[must_use]
    pub fn default_for(format: ProviderFormat) -> Self {
        let (name, upstream) = match format {
            ProviderFormat::Anthropic => ("anthropic", "https://api.anthropic.com"),
            ProviderFormat::OpenAI => ("openai", "https://api.openai.com"),
            ProviderFormat::Google => ("google", "https://generativelanguage.googleapis.com"),
        };
        Self {
            name: name.to_string(),
            format,
            api_key: String::new(),
            upstream: upstream.to_string(),
            models: Vec::new(),
            timeout_seconds: default_timeout_seconds(),
            streaming_timeout_seconds: default_streaming_timeout_seconds(),
        }
    }
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
    #[serde(default)]
    pub working_dir: Option<String>,
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

/// The relay this install talks to. The single home for the relay URL — it is
/// NOT stored in `credentials.json` (that artifact holds only the machine
/// identity). Read at runtime by the daemon (`pricing_fetch` GETs
/// `<url>/api/v1/pricing`; `daemon_sync` POSTs events there, additionally
/// needing the enrolled `machine_token`), and at enroll time by `kyris enroll`
/// as the relay to enroll against when no `--relay-url` / `KYRIS_RELAY_URL` is
/// given. Pricing needs no enrollment. Ships `https://relay.kyr.is` in
/// `default.yaml`; the dev patch overrides it to a local relay, and
/// `--relay-url` overrides per `kyris enroll` invocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayConfig {
    #[serde(default)]
    pub url: String,
}

/// Sync directory scope. Whether sync runs at all is determined by
/// enrollment (`credentials.json`), not config; this only narrows which
/// directories' events are synced (empty = all).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    #[serde(default = "default_fetch_interval_hours")]
    pub fetch_interval_hours: u64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsConfig {
    #[serde(default = "default_reconcile_interval_minutes")]
    pub reconcile_interval_minutes: u64,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            reconcile_interval_minutes: default_reconcile_interval_minutes(),
        }
    }
}

/// Spend warning configuration. Toasts fire when the rolling spend total
/// crosses any threshold. Default: no thresholds (warnings disabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendConfig {
    /// Dollar amounts at which to fire a toast notification. Each threshold
    /// fires once when the rolling window total crosses it upward; resets
    /// when spend drops back below (e.g. after the window rolls over).
    /// Example: `[10.0, 50.0, 100.0]`
    #[serde(default)]
    pub warn_thresholds_usd: Vec<f64>,
    /// Rolling window for spend aggregation in hours. Default: 24.
    #[serde(default = "default_spend_window_hours")]
    pub window_hours: u64,
}

impl Default for SpendConfig {
    fn default() -> Self {
        Self {
            warn_thresholds_usd: Vec::new(),
            window_hours: default_spend_window_hours(),
        }
    }
}

fn default_spend_window_hours() -> u64 {
    24
}

fn default_reconcile_interval_minutes() -> u64 {
    15
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
    // kyrisd expires a held approval after this long. Kept above kyris's 590s
    // no-TTY poll window so the pending dialog outlives the wait rather than
    // vanishing mid-poll. See kyris-core `NATIVE_HOOK_POLL_TIMEOUT`.
    900
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
    format: anthropic
    api_key: "sk-ant-test"
    upstream: "https://api.anthropic.com"
    models:
      - claude-4-opus
circuit_breaker:
  max_tokens: 100000
"#;
        let config: KyrisdConfig = serde_saphyr::from_str(yaml_str).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:4710");
        // Secret keys are NOT sourced from the yaml — they live in the on-disk
        // secret store (see `kyris_core::secret`). A yaml that still carries the
        // old key lines parses fine (they're ignored), and the in-memory fields
        // stay empty until a store-populating load path fills them.
        assert!(config.server.inbound_key.is_empty());
        assert!(config.server.operator_key.is_empty());
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "anthropic");
        assert_eq!(config.providers[0].format, ProviderFormat::Anthropic);
        assert_eq!(config.circuit_breaker.max_tokens, 100_000);
        assert!(config.circuit_breaker.enabled);
    }

    #[test]
    fn testProviderFormatFromYaml() {
        let yaml_str = r#"
providers:
  - name: bedrock-claude
    format: anthropic
    api_key: ""
    upstream: "https://bedrock-runtime.us-east-1.amazonaws.com"
"#;
        let config: KyrisdConfig = serde_saphyr::from_str(yaml_str).unwrap();
        assert_eq!(config.providers[0].name, "bedrock-claude");
        assert_eq!(config.providers[0].format, ProviderFormat::Anthropic);
    }

    #[test]
    fn testKyrisdConfigEmptyYaml() {
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:4710");
        assert!(config.providers.is_empty());
        assert!(!config.mcp.enabled);
        assert!(config.sync.scope.is_empty());
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
      working_dir: "/workspace/project"
"#;
        let config: KyrisdConfig = serde_saphyr::from_str(yaml_str).unwrap();
        assert!(config.mcp.enabled);
        assert_eq!(config.mcp.pending_timeout_seconds, 120);
        assert_eq!(config.mcp.servers.len(), 1);
        assert_eq!(config.mcp.servers[0].name, "github");
        assert_eq!(
            config.mcp.servers[0].working_dir.as_deref(),
            Some("/workspace/project")
        );
    }

    #[test]
    fn testSyncConfigDefaults() {
        let config = SyncConfig::default();
        assert!(config.scope.is_empty());
    }

    #[test]
    fn testTlsValidateDisabledOk() {
        let tls = TlsConfig::default();
        assert!(tls.validate().is_ok());
    }

    #[test]
    fn testTlsValidateEnabledMissingPaths() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: String::new(),
            key_path: String::new(),
        };
        assert!(tls.validate().unwrap_err().contains("cert_path is empty"));
    }

    #[test]
    fn testTlsValidateEnabledMissingKeyPath() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        std::fs::write(&cert, "cert").unwrap();
        let tls = TlsConfig {
            enabled: true,
            cert_path: cert.to_string_lossy().to_string(),
            key_path: String::new(),
        };
        assert!(tls.validate().unwrap_err().contains("key_path is empty"));
    }

    #[test]
    fn testTlsValidateEnabledNonexistentCert() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: "/nonexistent/cert.pem".to_string(),
            key_path: "/nonexistent/key.pem".to_string(),
        };
        assert!(tls.validate().unwrap_err().contains("does not exist"));
    }

    #[test]
    fn testTlsValidateEnabledValidPaths() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, "cert").unwrap();
        std::fs::write(&key, "key").unwrap();
        let tls = TlsConfig {
            enabled: true,
            cert_path: cert.to_string_lossy().to_string(),
            key_path: key.to_string_lossy().to_string(),
        };
        assert!(tls.validate().is_ok());
    }

    #[test]
    fn testBaseUrlHttp() {
        let config = KyrisdConfig {
            server: ServerConfig {
                listen: "127.0.0.1:4710".to_string(),
                ..Default::default()
            },
            ..serde_saphyr::from_str("{}").unwrap()
        };
        assert_eq!(config.base_url(), "http://127.0.0.1:4710");
    }

    #[test]
    fn testBaseUrlHttps() {
        let config = KyrisdConfig {
            server: ServerConfig {
                listen: "0.0.0.0:4710".to_string(),
                ..Default::default()
            },
            tls: TlsConfig {
                enabled: true,
                cert_path: "cert.pem".to_string(),
                key_path: "key.pem".to_string(),
            },
            ..serde_saphyr::from_str("{}").unwrap()
        };
        assert_eq!(config.base_url(), "https://0.0.0.0:4710");
    }
}
