// SPDX-License-Identifier: Apache-2.0
use serde_json::{Map, Value, json};

#[must_use]
pub fn generate() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://kyr-is.github.io/kyris/config.json",
        "title": "kyrisd configuration",
        "description": "Schema for kyrisd.yaml and .kyris.yaml configuration files",
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
            "sync": { "$ref": "#/$defs/SyncConfig" },
            "pricing": { "$ref": "#/$defs/PricingConfig" },
            "stats": { "$ref": "#/$defs/StatsConfig" }
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
    defs.insert("SyncConfig".into(), sync_config());
    defs.insert("PricingConfig".into(), pricing_config());
    defs.insert("StatsConfig".into(), stats_config());
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
            "inbound_key": {
                "type": "string",
                "description": "Bearer token required on inbound API requests"
            },
            "operator_key": {
                "type": "string",
                "description": "Bearer token for operator endpoints (stats, health)"
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
        "required": ["name", "api_key", "upstream"],
        "additionalProperties": false,
        "properties": {
            "name": {
                "type": "string",
                "description": "Provider identifier (e.g. openai, anthropic, google)"
            },
            "api_key": {
                "type": "string",
                "description": "API key for the upstream provider"
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
                "default": 60,
                "description": "Seconds before a pending MCP permission request times out"
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
                "description": "Maximum tokens per session before the circuit breaker trips"
            },
            "session_idle_minutes": {
                "type": "integer",
                "minimum": 0,
                "default": 30,
                "description": "Minutes of idle time before a session's token counter resets"
            }
        }
    })
}

fn sync_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "enabled": {
                "type": "boolean",
                "default": false
            },
            "scope": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Directory globs to sync"
            },
            "relay_url": {
                "type": "string",
                "format": "uri",
                "description": "URL of the kyris-relay server"
            }
        }
    })
}

fn pricing_config() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "file": {
                "type": "string",
                "default": "config/pricing.yaml",
                "description": "Path to the bundled pricing table"
            },
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
            "sync",
            "pricing",
            "stats",
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
            "SyncConfig",
            "PricingConfig",
            "StatsConfig",
        ] {
            assert!(defs.contains_key(def), "missing $def: {def}");
        }
    }

    #[test]
    fn testProviderConfigRequiresNameApiKeyUpstream() {
        let schema = generate();
        let required = schema["$defs"]["ProviderConfig"]["required"]
            .as_array()
            .unwrap();
        assert!(required.contains(&json!("name")));
        assert!(required.contains(&json!("api_key")));
        assert!(required.contains(&json!("upstream")));
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
