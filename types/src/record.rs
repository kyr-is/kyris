// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct GatewayRecord {
    pub id: String,
    pub trace_id: String,
    pub timestamp: String,
    pub provider: String,
    pub model: String,
    pub tokens_in: Option<i64>,
    pub tokens_out: Option<i64>,
    pub tokens_cache_create: Option<i64>,
    pub tokens_cache_read: Option<i64>,
    pub cost_usd: Option<f64>,
    pub latency_ms: i64,
    pub status: RecordStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub synced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    #[serde(default)]
    pub metering: Metering,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Success,
    Error,
    CircuitBreaker,
    CacheHit,
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for RecordStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Error => f.write_str("error"),
            Self::CircuitBreaker => f.write_str("circuit_breaker"),
            Self::CacheHit => f.write_str("cache_hit"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

impl std::str::FromStr for RecordStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "error" => Ok(Self::Error),
            "circuit_breaker" => Ok(Self::CircuitBreaker),
            "cache_hit" => Ok(Self::CacheHit),
            _ => Ok(Self::Unknown),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Metering {
    Unavailable,
    #[default]
    #[serde(other)]
    Available,
}

pub const CREATE_GATEWAY_RECORDS: &str = "\
CREATE TABLE IF NOT EXISTS gateway_records (
    id          VARCHAR PRIMARY KEY,
    trace_id    VARCHAR NOT NULL,
    timestamp   TIMESTAMP NOT NULL,
    provider    VARCHAR NOT NULL,
    model       VARCHAR NOT NULL,
    tokens_in   INTEGER,
    tokens_out  INTEGER,
    tokens_cache_create INTEGER,
    tokens_cache_read   INTEGER,
    cost_usd    DOUBLE,
    latency_ms  INTEGER NOT NULL,
    status      VARCHAR NOT NULL,
    session_id  VARCHAR,
    synced      BOOLEAN NOT NULL DEFAULT FALSE,
    mcp_server  VARCHAR,
    mcp_tool    VARCHAR,
    working_dir VARCHAR,
    metering    VARCHAR NOT NULL DEFAULT 'available'
)";

pub const CREATE_SESSION_TOKENS: &str = "\
CREATE TABLE IF NOT EXISTS session_tokens (
    session_id    VARCHAR PRIMARY KEY,
    total_tokens  BIGINT NOT NULL DEFAULT 0,
    last_activity TIMESTAMP NOT NULL
)";

pub const CREATE_SYNC_CURSOR: &str = "\
CREATE TABLE IF NOT EXISTS sync_cursor (
    id          INTEGER PRIMARY KEY DEFAULT 1,
    filename    VARCHAR NOT NULL,
    byte_offset BIGINT NOT NULL
)";

pub const CREATE_SYNC_METADATA: &str = "\
CREATE TABLE IF NOT EXISTS sync_metadata (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    scope_json      VARCHAR NOT NULL DEFAULT '[]',
    last_synced_at  VARCHAR
)";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionTokenRow {
    pub session_id: String,
    pub total_tokens: i64,
    pub last_activity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRecordStatusSerializes() {
        assert_eq!(
            serde_json::to_string(&RecordStatus::Success).unwrap(),
            r#""success""#
        );
        assert_eq!(
            serde_json::to_string(&RecordStatus::CircuitBreaker).unwrap(),
            r#""circuit_breaker""#
        );
    }

    #[test]
    fn testMeteringDefault() {
        assert_eq!(Metering::default(), Metering::Available);
    }

    #[test]
    fn testGatewayRecordRoundTrip() {
        let record = GatewayRecord {
            id: "rec-1".to_string(),
            trace_id: "trace-1".to_string(),
            timestamp: "2026-04-12T00:00:00Z".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens_in: Some(100),
            tokens_out: Some(50),
            tokens_cache_create: None,
            tokens_cache_read: None,
            cost_usd: Some(0.015),
            latency_ms: 250,
            status: RecordStatus::Success,
            session_id: Some("sess-1".to_string()),
            synced: false,
            mcp_server: None,
            mcp_tool: None,
            metering: Metering::Available,
            working_dir: Some("/tmp/project".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: GatewayRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "rec-1");
        assert_eq!(parsed.tokens_in, Some(100));
        assert_eq!(parsed.status, RecordStatus::Success);
    }

    #[test]
    fn testGatewayRecordSkipsNoneFields() {
        let record = GatewayRecord {
            id: "rec-2".to_string(),
            trace_id: "trace-2".to_string(),
            timestamp: "2026-04-12T00:00:00Z".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            tokens_in: None,
            tokens_out: None,
            tokens_cache_create: None,
            tokens_cache_read: None,
            cost_usd: None,
            latency_ms: 100,
            status: RecordStatus::Error,
            session_id: None,
            synced: false,
            mcp_server: None,
            mcp_tool: None,
            metering: Metering::Unavailable,
            working_dir: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("mcp_server"));
        assert!(!json.contains("mcp_tool"));
    }

    #[test]
    fn testSchemaConstantsNotEmpty() {
        assert!(CREATE_GATEWAY_RECORDS.contains("gateway_records"));
        assert!(CREATE_SESSION_TOKENS.contains("session_tokens"));
        assert!(CREATE_SYNC_CURSOR.contains("sync_cursor"));
        assert!(CREATE_SYNC_METADATA.contains("sync_metadata"));
    }

    #[test]
    fn testRecordStatusFromStr() {
        assert_eq!(
            "success".parse::<RecordStatus>().unwrap(),
            RecordStatus::Success
        );
        assert_eq!(
            "error".parse::<RecordStatus>().unwrap(),
            RecordStatus::Error
        );
        assert_eq!(
            "circuit_breaker".parse::<RecordStatus>().unwrap(),
            RecordStatus::CircuitBreaker
        );
        assert_eq!(
            "cache_hit".parse::<RecordStatus>().unwrap(),
            RecordStatus::CacheHit
        );
        assert_eq!(
            "rate_limited".parse::<RecordStatus>().unwrap(),
            RecordStatus::Unknown
        );
    }

    #[test]
    fn testRecordStatusDeserializeUnknownFallsBack() {
        let status: RecordStatus = serde_json::from_str(r#""rate_limited""#).unwrap();
        assert_eq!(status, RecordStatus::Unknown);
        assert_eq!(status.to_string(), "unknown");
    }
}
