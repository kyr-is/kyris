// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde_json::{Map, Value, json};

#[must_use]
pub fn generate() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://kyr-is.github.io/kyris/config.json",
        "title": "kyrisd configuration",
        "description": "Schema for kyrisd.yaml configuration",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "server": { "$ref": "#/$defs/ServerConfig" },
            "tls": { "$ref": "#/$defs/TlsConfig" },
            "providers": {
                "type": "array",
                "items": { "$ref": "#/$defs/ProviderConfig" }
            },
            "mcp": { "$ref": "#/$defs/McpConfig" },
            "circuit_breaker": { "$ref": "#/$defs/CircuitBreakerConfig" },
            "relay": { "$ref": "#/$defs/RelayConfig" },
            "sync": { "$ref": "#/$defs/SyncConfig" },
            "pricing": { "$ref": "#/$defs/PricingConfig" },
            "stats": { "$ref": "#/$defs/StatsConfig" },
            "agents": { "$ref": "#/$defs/AgentsConfig" },
            "spend": { "$ref": "#/$defs/SpendConfig" },
            "log": { "$ref": "#/$defs/LogConfig" }
        },
        "$defs": defs()
    })
}

fn defs() -> Value {
    let mut defs = Map::new();
    defs.insert("ServerConfig".into(), server_config());
    defs.insert("TlsConfig".into(), tls_config());
    defs.insert("ProviderConfig".into(), provider_config());
    defs.insert("McpConfig".into(), mcp_config());
    defs.insert("McpServerConfig".into(), mcp_server_config());
    defs.insert("CircuitBreakerConfig".into(), circuit_breaker_config());
    defs.insert("RelayConfig".into(), relay_config());
    defs.insert("SyncConfig".into(), sync_config());
    defs.insert("PricingConfig".into(), pricing_config());
    defs.insert("StatsConfig".into(), stats_config());
    defs.insert("AgentsConfig".into(), agents_config());
    defs.insert("SpendConfig".into(), spend_config());
    defs.insert("LogConfig".into(), log_config());
    Value::Object(defs)
}

fn server_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "listen": {
                "type": "string",
                "default": "127.0.0.1:4710",
                "description": "Address and port for the HTTP listener"
            },
            "max_request_body_bytes": {
                "type": "integer",
                "minimum": 0,
                "default": 10_485_760,
                "description": "Maximum request body size in bytes"
            },
            "drain_timeout_seconds": {
                "type": "integer",
                "minimum": 0,
                "default": 30,
                "description": "Seconds to wait for in-flight requests during graceful shutdown"
            }
        }
    })
}

fn tls_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "enabled": {
                "type": "boolean",
                "default": false
            },
            "cert_path": {
                "type": "string",
                "description": "Path to TLS certificate file"
            },
            "key_path": {
                "type": "string",
                "description": "Path to TLS private key file"
            }
        }
    })
}

fn provider_config() -> Value {
    json!({
        "type": "object",
        "required": ["name", "format", "upstream"],
        "additionalProperties": false,
        "properties": {
            "name": {
                "type": "string",
                "description": "Provider identifier (e.g. openai, anthropic, google, bedrock-claude)"
            },
            "format": {
                "type": "string",
                "enum": ["anthropic", "openai", "google"],
                "description": "Wire format for this provider (anthropic, openai, or google)"
            },
            "upstream": {
                "type": "string",
                "format": "uri",
                "description": "Base URL of the upstream provider API"
            },
            "models": {
                "type": "array",
                "items": { "type": "string" },
                "description": "List of model identifiers this provider serves"
            },
            "timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "default": 30,
                "description": "Request timeout for non-streaming calls"
            },
            "streaming_timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "default": 300,
                "description": "Request timeout for streaming calls"
            }
        }
    })
}

fn mcp_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "enabled": {
                "type": "boolean",
                "default": false
            },
            "pending_timeout_seconds": {
                "type": "integer",
                "minimum": 1,
                "default": 900,
                "description": "Seconds before a pending approval (MCP or no-TTY hook) times out; kept above kyris's 590s no-TTY poll window"
            },
            "socket_timeout_ms": {
                "type": "integer",
                "minimum": 1,
                "default": 50,
                "description": "Milliseconds for agentpactd UDS socket read/write timeout"
            },
            "servers": {
                "type": "array",
                "items": { "$ref": "#/$defs/McpServerConfig" }
            }
        }
    })
}

fn mcp_server_config() -> Value {
    json!({
        "type": "object",
        "required": ["name", "upstream"],
        "additionalProperties": false,
        "properties": {
            "name": {
                "type": "string",
                "description": "Logical name for this MCP server"
            },
            "upstream": {
                "type": "string",
                "format": "uri",
                "description": "URL of the upstream MCP server"
            }
        }
    })
}

fn circuit_breaker_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "enabled": {
                "type": "boolean",
                "default": true
            },
            "max_tokens": {
                "type": "integer",
                "minimum": 0,
                "default": 200_000,
                "description": "Max output tokens generated without a tool/shell/MCP call before the runaway prompt fires (a tool call resets the counter)"
            },
            "session_idle_minutes": {
                "type": "integer",
                "minimum": 0,
                "default": 30,
                "description": "Minutes of idle time before a session's token counter resets"
            },
            "decision_timeout_seconds": {
                "type": "integer",
                "minimum": 0,
                "default": 604_800,
                "description": "How long the runaway 'continue or stop?' prompt holds the request waiting for a human before defaulting to stop (7 days)"
            }
        }
    })
}

fn relay_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "url": {
                "type": "string",
                "description": "Base URL of the kyris-relay this install talks to (pricing fetch and `kyris enroll`). Read at enroll time and at runtime by the daemon; not part of credentials.json."
            }
        }
    })
}

fn sync_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "scope": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Directory globs to sync (empty = all). Whether sync runs at all is determined by enrollment (credentials.json), not config."
            }
        }
    })
}

fn pricing_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "fetch_interval_hours": {
                "type": "integer",
                "minimum": 1,
                "default": 6,
                "description": "Hours between pricing table refreshes from relay"
            }
        }
    })
}

fn stats_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "retention_days": {
                "type": "integer",
                "minimum": 1,
                "default": 7,
                "description": "Days to retain usage records in the local database"
            },
            "flush_interval_ms": {
                "type": "integer",
                "minimum": 1,
                "default": 1000,
                "description": "Milliseconds between stats buffer flushes"
            },
            "flush_batch_size": {
                "type": "integer",
                "minimum": 1,
                "default": 100,
                "description": "Maximum records per flush batch"
            },
            "channel_capacity": {
                "type": "integer",
                "minimum": 1,
                "default": 10000,
                "description": "Bounded channel capacity for the stats pipeline"
            }
        }
    })
}

fn agents_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "reconcile_interval_minutes": {
                "type": "integer",
                "minimum": 1,
                "default": 15,
                "description": "Minutes between agent-config reconciliation passes"
            }
        }
    })
}

fn spend_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "warn_thresholds_usd": {
                "type": "array",
                "items": { "type": "number", "minimum": 0 },
                "description": "Dollar amounts at which to fire a spend toast (each fires once per upward crossing of the rolling-window total)"
            },
            "window_hours": {
                "type": "integer",
                "minimum": 1,
                "default": 24,
                "description": "Rolling window for spend aggregation, in hours"
            }
        }
    })
}

fn log_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "filter": {
                "type": "string",
                "default": "kyrisd=info",
                "description": "Default tracing EnvFilter directive for the daemon log"
            },
            "verbose_filter": {
                "type": "string",
                "default": "kyrisd::adapter=trace,kyrisd::auth=debug,kyrisd=debug",
                "description": "Tracing EnvFilter directive used when verbose logging is enabled"
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testSchemaIsValidJson() {
        let schema = generate();
        assert!(schema.is_object());
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }

    #[test]
    fn testSchemaHasAllTopLevelSections() {
        let schema = generate();
        let props = schema["properties"].as_object().unwrap();
        for section in [
            "server",
            "tls",
            "providers",
            "mcp",
            "circuit_breaker",
            "relay",
            "sync",
            "pricing",
            "stats",
            "agents",
            "spend",
            "log",
        ] {
            assert!(props.contains_key(section), "missing section: {section}");
        }
    }

    #[test]
    fn testSchemaDefsMatchProperties() {
        let schema = generate();
        let defs = schema["$defs"].as_object().unwrap();
        for def in [
            "ServerConfig",
            "TlsConfig",
            "ProviderConfig",
            "McpConfig",
            "McpServerConfig",
            "CircuitBreakerConfig",
            "RelayConfig",
            "SyncConfig",
            "PricingConfig",
            "StatsConfig",
            "AgentsConfig",
            "SpendConfig",
            "LogConfig",
        ] {
            assert!(defs.contains_key(def), "missing $def: {def}");
        }
    }

    #[test]
    fn testProviderConfigRequiredFields() {
        let schema = generate();
        let required = schema["$defs"]["ProviderConfig"]["required"]
            .as_array()
            .unwrap();
        for field in ["name", "format", "upstream"] {
            assert!(
                required.contains(&json!(field)),
                "missing required: {field}"
            );
        }
    }

    #[test]
    fn testServerConfigDefaults() {
        let schema = generate();
        let server = &schema["$defs"]["ServerConfig"]["properties"];
        assert_eq!(server["listen"]["default"], "127.0.0.1:4710");
        assert_eq!(server["max_request_body_bytes"]["default"], 10_485_760);
        assert_eq!(server["drain_timeout_seconds"]["default"], 30);
    }

    #[test]
    fn testCircuitBreakerDefaults() {
        let schema = generate();
        let cb = &schema["$defs"]["CircuitBreakerConfig"]["properties"];
        assert_eq!(cb["enabled"]["default"], true);
        assert_eq!(cb["max_tokens"]["default"], 200_000);
        assert_eq!(cb["session_idle_minutes"]["default"], 30);
    }

    #[test]
    fn testAllDefsRejectAdditionalProperties() {
        let schema = generate();
        let defs = schema["$defs"].as_object().unwrap();
        for (name, def) in defs {
            assert_eq!(
                def["additionalProperties"],
                json!(false),
                "{name} should reject additional properties"
            );
        }
    }
}
