// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Burn-control TOML for codex: the `[model_providers.kyris]` route through
//! kyrisd and the shell-environment governed-subprocess marker.
use crate::integration::{ensure_toml_bool_path, ensure_toml_string_path};

pub(super) fn ensure_codex_kyris_model_provider(
    config: &mut toml::Value,
    base_url_v1: &str,
    inbound_key: &str,
) -> bool {
    let mut changed = false;
    if ensure_toml_string_path(config, &["model_providers", "kyris", "name"], "Kyris") {
        changed = true;
    }
    if ensure_toml_string_path(
        config,
        &["model_providers", "kyris", "base_url"],
        base_url_v1,
    ) {
        changed = true;
    }
    if ensure_toml_string_path(
        config,
        &["model_providers", "kyris", "wire_api"],
        "responses",
    ) {
        changed = true;
    }
    // The inbound key authenticates codex TO kyrisd via a custom header — NOT the
    // bearer. Putting it in `experimental_bearer_token` made codex send it as the
    // `Authorization: Bearer`, which kyrisd forwards UPSTREAM (→ OpenAI rejects
    // `sk-kyris-…` as an invalid API key, 401). The bearer must stay codex's OWN
    // credential (login/api-key), which kyrisd forwards and classifies
    // included-vs-overage — exactly like claude's `x-kyris-inbound` custom header.
    if ensure_toml_string_path(
        config,
        &[
            "model_providers",
            "kyris",
            "http_headers",
            "x-kyris-inbound",
        ],
        inbound_key,
    ) {
        changed = true;
    }
    // codex must use ITS OWN auth (auth.json — ChatGPT login OR api key) as the
    // upstream bearer, which kyrisd forwards and classifies included-vs-overage.
    // `requires_openai_auth = true` makes this custom provider draw from auth.json
    // like the built-in openai provider (model-provider/src/auth.rs hands a
    // command-less provider the global auth_manager). The built-in openai provider
    // can't be used instead — its ID is reserved and can't carry the
    // x-kyris-inbound header.
    if ensure_toml_bool_path(
        config,
        &["model_providers", "kyris", "requires_openai_auth"],
        true,
    ) {
        changed = true;
    }
    // kyrisd serves `/v1/responses` over HTTP only — a WS upgrade there returns
    // 405, so codex would waste ~6s retrying the WS transport before falling back.
    // Disable it so codex goes straight to HTTP (wire_api = "responses" still
    // streams fine over HTTP/SSE).
    if ensure_toml_bool_path(
        config,
        &["model_providers", "kyris", "supports_websockets"],
        false,
    ) {
        changed = true;
    }
    // Migration: older kyris installs wrote the inbound key into
    // `experimental_bearer_token`, which codex sends as the `Authorization: Bearer`
    // — kyrisd forwards it upstream and OpenAI rejects `sk-kyris-…` (401). Our
    // helpers only add/update keys, so explicitly delete the stale one; codex then
    // falls back to its auth.json credential (the bearer now comes from there).
    if let Some(provider) = config
        .get_mut("model_providers")
        .and_then(toml::Value::as_table_mut)
        .and_then(|m| m.get_mut("kyris"))
        .and_then(toml::Value::as_table_mut)
        && provider.remove("experimental_bearer_token").is_some()
    {
        changed = true;
    }
    changed
}

pub(super) fn ensure_codex_shell_env_marker(config: &mut toml::Value) -> bool {
    ensure_toml_string_path(
        config,
        &[
            "shell_environment_policy",
            "set",
            "KYRIS_GOVERNED_SUBPROCESS",
        ],
        "codex-cli",
    )
}
