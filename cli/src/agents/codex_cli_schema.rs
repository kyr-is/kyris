// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Vendored shape for `~/.codex/config.toml` covering only the keys kyris
//! writes. Unknown keys (anything codex adds in newer releases that kyris
//! doesn't touch) flow through `_rest` opaquely — the assumption is that
//! codex evolves additively and never changes the meaning of fields kyris
//! owns. If a field codex marks as deprecated needs a kyris-side rewrite,
//! that's a separate `codex_cli.rs` change, not a schema change.
//!
//! Used as the type parameter to `TomlShapeValidator<CodexConfigShape>` in
//! `agents/codex_cli.rs` so every write to config.toml is shape-checked
//! before disk mutation.

// Fields below are populated by serde during validation and aren't read by
// Rust code — that's the entire point of a shape-validation type. Suppress
// dead-code warnings for the whole module rather than per-field.
#![allow(dead_code)]

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CodexConfigShape {
    /// Deprecated Kyris routing key. Still accepted so cleanup/migration can
    /// validate configs left behind by older installs.
    pub openai_base_url: Option<String>,
    /// Kyris adds a `kyris` entry under this map; codex may have other entries.
    pub model_providers: Option<HashMap<String, ModelProvider>>,
    /// Kyris rewrites entries here to proxy through `kyris-mcp`.
    pub mcp_servers: Option<HashMap<String, McpServer>>,
    /// Kyris flips `hooks` to enable hook integration. `codex_hooks` is accepted
    /// as a deprecated alias for older configs.
    pub features: Option<Features>,
    /// Everything else codex defines — preserved without validation.
    #[serde(flatten)]
    pub _rest: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ModelProvider {
    pub name: String,
    pub base_url: String,
    pub wire_api: String,
    /// Renamed in some codex versions; treat as optional so kyris doesn't fail
    /// to validate if codex moved this elsewhere.
    pub experimental_bearer_token: Option<String>,
    pub http_headers: Option<HashMap<String, String>>,
    pub requires_openai_auth: Option<bool>,
    pub supports_websockets: Option<bool>,
    #[serde(flatten)]
    pub _rest: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct McpServer {
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub url: Option<String>,
    #[serde(flatten)]
    pub _rest: HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Features {
    pub hooks: Option<bool>,
    pub codex_hooks: Option<bool>,
    #[serde(flatten)]
    pub _rest: HashMap<String, toml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_writer::{ConfigValidator, TomlShapeValidator};

    fn validator() -> TomlShapeValidator<CodexConfigShape> {
        TomlShapeValidator::new()
    }

    #[test]
    fn testAcceptsTypicalKyrisModifiedConfig() {
        let toml = r#"
            model_provider = "kyris"

            [model_providers.kyris]
            name = "Kyris"
            base_url = "http://127.0.0.1:4710/v1"
            wire_api = "responses"
            requires_openai_auth = true
            supports_websockets = false

            [model_providers.kyris.http_headers]
            x-kyris-inbound = "sk-kyris-abc"

            [mcp_servers.foo]
            command = "kyris-mcp"
            args = ["--upstream", "foo"]

            [features]
            hooks = true
        "#;
        validator()
            .validate(toml)
            .expect("kyris-shaped config should validate");
    }

    #[test]
    fn testToleratesUnknownTopLevelKeys() {
        let toml = r#"
            openai_base_url = "http://localhost/v1"
            future_codex_field = "whatever"

            [some_new_section]
            new_key = 42
        "#;
        validator()
            .validate(toml)
            .expect("unknown keys must be tolerated");
    }

    #[test]
    fn testToleratesUnknownKeysInsideKnownSections() {
        let toml = r#"
            [model_providers.kyris]
            name = "Kyris"
            base_url = "http://x/v1"
            wire_api = "responses"
            future_provider_field = true

            [features]
            hooks = true
            future_feature = "ok"
        "#;
        validator()
            .validate(toml)
            .expect("unknown subkeys must be tolerated");
    }

    #[test]
    fn testRejectsWrongTypeForOwnedField() {
        // hooks must be bool — string fails
        let toml = r#"
            [features]
            hooks = "yes"
        "#;
        validator()
            .validate(toml)
            .expect_err("type mismatch should fail validation");
    }

    #[test]
    fn testRejectsMissingRequiredProviderField() {
        // model_providers.kyris.name is required
        let toml = r#"
            [model_providers.kyris]
            base_url = "http://x/v1"
            wire_api = "responses"
        "#;
        validator()
            .validate(toml)
            .expect_err("missing required field 'name' should fail validation");
    }

    #[test]
    fn testEmptyConfigIsValid() {
        validator().validate("").expect("empty config is valid");
    }
}
