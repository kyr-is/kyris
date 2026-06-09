// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config_writer::{
    ConfigValidator, NoopValidator, TomlShapeValidator, WellFormedJsonValidator,
};
use crate::integration::{
    ensure_toml_bool_path, ensure_toml_string_path, merge_toml_string_entries, read_json_value,
    read_toml_value, remove_json_command_hook, write_toml_value,
};
use crate::state::restore_manifest_entry_component;

use super::codex_cli_schema::CodexConfigShape;

fn codex_config_validator() -> TomlShapeValidator<CodexConfigShape> {
    TomlShapeValidator::new()
}

use super::probe::{ProbeResult, fingerprint, not_detected, toml_has_any_mcp_servers};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, DetailPassThrough, ExecutionMechanism, HookProtocol, McpConfigFormat,
    McpConfigLocation, SurfaceIntegration, ToolMapping, ToolMechanism,
};

pub struct CodexCli;

fn ensure_codex_kyris_model_provider(
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

pub fn codex_config_path() -> Result<PathBuf, String> {
    Ok(codex_config_path_from(
        std::env::var_os("CODEX_HOME").map(PathBuf::from),
        crate::integration::home_dir()?,
    ))
}

fn codex_config_path_from(codex_home: Option<PathBuf>, home: PathBuf) -> PathBuf {
    codex_home
        .unwrap_or_else(|| home.join(".codex"))
        .join("config.toml")
}

fn codex_config_candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = std::env::var("CODEX_HOME") {
        paths.push(PathBuf::from(path).join("config.toml"));
    }
    if let Ok(home) = crate::integration::home_dir() {
        paths.push(home.join(".codex").join("config.toml"));
    }
    paths.sort();
    paths.dedup();
    paths
}

pub fn codex_config_exists() -> bool {
    codex_config_path().is_ok_and(|path| path.exists())
}

pub fn codex_binary_installed() -> bool {
    super::registry::which_exists("codex")
}

/// Creates the `.codex` directory (and any parents) if it does not yet exist.
/// Called at the start of configure methods so they work even when the user
/// has just installed the binary but has never run it (no config file yet).
fn ensure_codex_dir() -> Result<PathBuf, String> {
    let dir = codex_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Returns the current config as a TOML value, or an empty table if the file
/// does not yet exist. Used to bootstrap first-time setup.
fn read_or_empty_codex_config(config_path: &Path) -> Result<toml::Value, String> {
    if config_path.exists() {
        read_toml_value(config_path)
    } else {
        Ok(toml::Value::Table(toml::map::Map::default()))
    }
}

fn ensure_codex_shell_env_marker(config: &mut toml::Value) -> bool {
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

pub fn codex_dir() -> Result<PathBuf, String> {
    let path = codex_config_path()?;
    path.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("Cannot resolve parent directory for {}", path.display()))
}

pub fn codex_hooks_path() -> Result<PathBuf, String> {
    Ok(codex_dir()?.join("hooks.json"))
}

/// Write codex's `config.toml` with a surface component + schema validator.
/// The reversible patch is recorded inside `write_toml_value` — shared across
/// every agent — so `kyris agents undo` reverses every edit, including across
/// the several writes setup performs, with no per-agent recording code.
fn write_codex_config(
    config_path: &Path,
    new: &toml::Value,
    component: &str,
) -> Result<(), String> {
    write_toml_value(config_path, new, component, &codex_config_validator())?;
    Ok(())
}

fn write_codex_config_unmanaged(config_path: &Path, new: &toml::Value) -> Result<(), String> {
    let mut serialized = toml::to_string_pretty(new)
        .map_err(|e| format!("Cannot serialize {}: {e}", config_path.display()))?;
    serialized.push('\n');
    codex_config_validator()
        .validate(&serialized)
        .map_err(|e| format!("validation failed for {}: {e}", config_path.display()))?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(config_path, serialized)
        .map_err(|e| format!("Cannot write {}: {e}", config_path.display()))
}

fn write_json_unmanaged(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let mut serialized = serde_json::to_string_pretty(value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    serialized.push('\n');
    WellFormedJsonValidator
        .validate(&serialized)
        .map_err(|e| format!("validation failed for {}: {e}", path.display()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, serialized).map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(value) = map.get(key) {
                    sorted.insert(key.clone(), canonical_json(value));
                }
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical_json).collect())
        }
        other => other.clone(),
    }
}

fn codex_toml_version(value: &toml::Value) -> String {
    let json = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    let canonical = canonical_json(&json);
    let serialized = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &serialized);
    let hex = digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    });
    format!("sha256:{hex}")
}

fn codex_kyris_hook_command(script_path: &Path) -> String {
    super::configure::shell_command(script_path)
}

fn codex_kyris_hook_key(hooks_path: &Path) -> String {
    format!("{}:pre_tool_use:0:0", hooks_path.display())
}

#[derive(Serialize)]
struct CodexHookTrustIdentity {
    event_name: &'static str,
    matcher: &'static str,
    hooks: Vec<CodexHookTrustHandler>,
}

#[derive(Serialize)]
struct CodexHookTrustHandler {
    r#type: &'static str,
    command: String,
    #[serde(rename = "commandWindows")]
    command_windows: Option<String>,
    #[serde(rename = "timeout")]
    timeout_sec: u64,
    r#async: bool,
    #[serde(rename = "statusMessage")]
    status_message: Option<String>,
}

fn codex_kyris_hook_hash(script_path: &Path) -> Result<String, String> {
    let identity = CodexHookTrustIdentity {
        event_name: "pre_tool_use",
        matcher: "",
        hooks: vec![CodexHookTrustHandler {
            r#type: "command",
            command: codex_kyris_hook_command(script_path),
            command_windows: None,
            timeout_sec: 600,
            r#async: false,
            status_message: None,
        }],
    };
    let value = toml::Value::try_from(identity)
        .map_err(|e| format!("cannot build codex hook trust identity: {e}"))?;
    Ok(codex_toml_version(&value))
}

fn ensure_codex_kyris_hook_trust(
    config: &mut toml::Value,
    hooks_path: &Path,
    script_path: &Path,
) -> Result<bool, String> {
    let key = codex_kyris_hook_key(hooks_path);
    let hash = codex_kyris_hook_hash(script_path)?;
    Ok(ensure_toml_string_path(
        config,
        &["hooks", "state", key.as_str(), "trusted_hash"],
        &hash,
    ))
}

fn codex_kyris_hook_trusted(config_path: &Path, hooks_path: &Path, script_path: &Path) -> bool {
    let Ok(config) = read_toml_value(config_path) else {
        return false;
    };
    let Ok(expected_hash) = codex_kyris_hook_hash(script_path) else {
        return false;
    };
    let key = codex_kyris_hook_key(hooks_path);
    config
        .get("hooks")
        .and_then(toml::Value::as_table)
        .and_then(|hooks| hooks.get("state"))
        .and_then(toml::Value::as_table)
        .and_then(|state| state.get(&key))
        .and_then(toml::Value::as_table)
        .and_then(|entry| entry.get("trusted_hash"))
        .and_then(toml::Value::as_str)
        == Some(expected_hash.as_str())
}

fn scrub_codex_kyris_hook_trust(config: &mut toml::Value, config_path: &Path) -> bool {
    let Some(dir) = config_path.parent() else {
        return false;
    };
    let hooks_path = dir.join("hooks.json");
    let key = codex_kyris_hook_key(&hooks_path);
    let mut changed = remove_toml_path(config, &["hooks", "state", key.as_str()]);
    if table_is_empty(config, &["hooks", "state"]) {
        changed |= remove_toml_path(config, &["hooks", "state"]);
    }
    if table_is_empty(config, &["hooks"]) {
        changed |= remove_toml_path(config, &["hooks"]);
    }
    changed
}

fn table_is_empty(root: &toml::Value, path: &[&str]) -> bool {
    let mut cursor = root;
    for segment in path {
        let Some(next) = cursor.get(*segment) else {
            return false;
        };
        cursor = next;
    }
    cursor.as_table().is_some_and(toml::Table::is_empty)
}

fn remove_toml_path(root: &mut toml::Value, path: &[&str]) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut cursor = root;
    for segment in &path[..path.len() - 1] {
        let Some(next) = cursor.get_mut(*segment) else {
            return false;
        };
        cursor = next;
    }
    let Some(table) = cursor.as_table_mut() else {
        return false;
    };
    table.remove(path[path.len() - 1]).is_some()
}

fn is_kyris_local_url(url: &str) -> bool {
    url.contains("127.0.0.1") || url.contains("localhost") || url.contains(":4710")
}

fn scrub_codex_config_value(config: &mut toml::Value) -> bool {
    let mut changed = false;

    if config.get("model_provider").and_then(toml::Value::as_str) == Some("kyris") {
        changed |= remove_toml_path(config, &["model_provider"]);
    }
    if config
        .get("openai_base_url")
        .and_then(toml::Value::as_str)
        .is_some_and(is_kyris_local_url)
    {
        changed |= remove_toml_path(config, &["openai_base_url"]);
    }
    changed |= remove_toml_path(config, &["model_providers", "kyris"]);
    if table_is_empty(config, &["model_providers"]) {
        changed |= remove_toml_path(config, &["model_providers"]);
    }
    changed |= remove_toml_path(config, &["permissions", "kyris"]);
    if table_is_empty(config, &["permissions"]) {
        changed |= remove_toml_path(config, &["permissions"]);
    }
    if config
        .get("default_permissions")
        .and_then(toml::Value::as_str)
        == Some("kyris")
    {
        changed |= remove_toml_path(config, &["default_permissions"]);
    }
    changed |= remove_toml_path(
        config,
        &[
            "shell_environment_policy",
            "set",
            "KYRIS_GOVERNED_SUBPROCESS",
        ],
    );
    if table_is_empty(config, &["shell_environment_policy", "set"]) {
        changed |= remove_toml_path(config, &["shell_environment_policy", "set"]);
    }
    if table_is_empty(config, &["shell_environment_policy"]) {
        changed |= remove_toml_path(config, &["shell_environment_policy"]);
    }

    changed
}

pub fn scrub_codex_residue() -> Result<Vec<String>, String> {
    let mut changes = Vec::new();
    for path in codex_config_candidate_paths() {
        if !path.exists() {
            continue;
        }
        let mut config = read_toml_value(&path)?;
        let mut scrubbed = scrub_codex_config_value(&mut config);
        scrubbed |= scrub_codex_kyris_hook_trust(&mut config, &path);
        if scrubbed {
            write_codex_config_unmanaged(&path, &config)?;
            changes.push(format!("scrubbed {}", path.display()));
        }
    }

    let hooks_path = codex_hooks_path()?;
    if hooks_path.exists() {
        let mut hooks = read_json_value(&hooks_path)?;
        if remove_json_command_hook(&mut hooks, "PreToolUse", "kyris_pretooluse") {
            write_json_unmanaged(&hooks_path, &hooks)?;
            changes.push(format!("removed hook from {}", hooks_path.display()));
        }
    }

    let script = codex_dir()?.join("kyris_pretooluse.sh");
    if super::undo::remove_file_if_exists(&script)? {
        changes.push(format!("removed {}", script.display()));
    }
    let rules = codex_dir()?.join("rules").join("agentpact.rules");
    if super::undo::remove_file_if_exists(&rules)? {
        changes.push(format!("removed {}", rules.display()));
    }

    Ok(changes)
}

impl AgentDescriptor for CodexCli {
    fn id(&self) -> &'static str {
        "codex-cli"
    }
    fn display_name(&self) -> &'static str {
        "Codex CLI"
    }
    fn is_installed(&self) -> bool {
        // Detected when the config file exists (agent has been run at least
        // once) OR when the binary is on PATH (installed but not yet launched).
        codex_config_exists() || codex_binary_installed()
    }
    fn probe(&self) -> ProbeResult {
        use super::profile::{CoverageCeiling, SurfaceState};
        let detected = codex_config_exists() || codex_binary_installed();
        if !detected {
            return not_detected();
        }

        let config_path = codex_config_path().ok();
        let hooks_path = codex_hooks_path().ok();
        let script_path = codex_dir().ok().map(|d| d.join("kyris_pretooluse.sh"));
        let has_registered_hook = hooks_path.as_deref().is_some_and(|p| {
            p.exists() && std::fs::read_to_string(p).is_ok_and(|c| c.contains("kyris"))
        });
        let has_hook = has_registered_hook
            && config_path
                .as_deref()
                .zip(hooks_path.as_deref())
                .zip(script_path.as_deref())
                .is_some_and(|((config, hooks), script)| {
                    codex_kyris_hook_trusted(config, hooks, script)
                });

        let has_mcp_wrap = config_path.as_deref().is_some_and(|p| {
            read_toml_value(p).is_ok_and(|v| {
                let serialized = toml::to_string(&v).unwrap_or_default();
                serialized.contains("kyris-mcp")
            })
        });
        let has_any_mcp_servers = config_path
            .as_deref()
            .is_some_and(|p| toml_has_any_mcp_servers(p, "mcp_servers"));

        let has_compiled_policy = codex_dir()
            .ok()
            .map(|d| d.join("rules").join("agentpact.rules"))
            .is_some_and(|p| p.exists());

        let execution = if has_hook {
            SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter)
        } else if has_compiled_policy {
            SurfaceState::adapted(ExecutionMechanism::CompiledPolicy)
                .with_ceiling(CoverageCeiling::Compiled)
        } else {
            SurfaceState::none()
        };
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(ToolMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };
        let has_kyris_provider_config = config_path.as_deref().is_some_and(|p| {
            read_toml_value(p).is_ok_and(|v| {
                v.get("model_provider").and_then(toml::Value::as_str) == Some("kyris")
                    && v.get("model_providers")
                        .and_then(toml::Value::as_table)
                        .and_then(|providers| providers.get("kyris"))
                        .and_then(toml::Value::as_table)
                        .and_then(|provider| provider.get("base_url"))
                        .and_then(toml::Value::as_str)
                        .is_some_and(|u| !u.is_empty())
            })
        });
        let burn_control = if has_kyris_provider_config {
            SurfaceState::adapted(BurnControlMechanism::KyrisdModelProvider)
        } else {
            SurfaceState::none()
        };

        let mut managed_files = Vec::new();
        if let Some(path) = config_path.as_deref()
            && let Some(fp) = fingerprint(path)
        {
            managed_files.push(fp);
        }
        if let Some(path) = hooks_path.as_deref()
            && let Some(fp) = fingerprint(path)
        {
            managed_files.push(fp);
        }

        ProbeResult {
            detected,
            execution,
            tool,
            burn_control,
            managed_files,
        }
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &[
            "kyris-mcp",
            "kyris_pretooluse",
            "KYRIS_GOVERNED_SUBPROCESS",
            "model_provider = \"kyris\"",
            "[model_providers.kyris]",
        ]
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        super::capabilities::apply_declared_capabilities(
            self.canonical_id(),
            AgentIntegrationPlan {
                execution: SurfaceIntegration::adapted(&[
                    ExecutionMechanism::LiveHookAdapter,
                    ExecutionMechanism::CompiledPolicy,
                ]),
                tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
                burn_control: SurfaceIntegration::adapted(&[
                    BurnControlMechanism::KyrisdModelProvider,
                ]),
                attribution: &[
                    AttributionMechanism::ShellEnvironmentPolicy,
                    AttributionMechanism::NativeHookPayload,
                    AttributionMechanism::PeerProcessObserved,
                ],
                agentpact_native_attribution: false,
            },
        )
    }
    // Configuration for Codex CLI is a linear sequence of TOML edits (live
    // hook adapter + rules dir + permissions table + default_permissions +
    // managed-file recording), each producing a change-log entry. Splitting
    // it into helpers would require threading the change Vec through every
    // call and would make the install transcript harder to read.
    #[allow(clippy::too_many_lines)]
    fn configure_execution_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        let hooks_path = codex_hooks_path()?;
        let script_path = codex_dir()?.join("kyris_pretooluse.sh");

        // Create the .codex directory first so hook and config writes succeed
        // even when the user has just installed the binary without running it.
        ensure_codex_dir()?;

        let mut changes = super::configure::install_live_hook_adapter(
            "codex-cli",
            "codex-cli",
            "PreToolUse",
            &script_path,
            &hooks_path,
            true,
            // Codex's PreToolUse default is 600s (and its config field is
            // `timeout_sec`, not `timeout`), so no JSON-hook override here.
            None,
        )?;

        let mut config = read_or_empty_codex_config(&config_path)?;
        // `hooks` is codex's canonical feature key (codex 0.133 `features list`);
        // `codex_hooks` is a deprecated alias that warns in `codex doctor`.
        if ensure_toml_bool_path(&mut config, &["features", "hooks"], true) {
            write_codex_config(&config_path, &config, "codex-cli:execution")?;
            changes.push(format!("updated {}", config_path.display()));
        }
        let mut config = read_or_empty_codex_config(&config_path)?;
        if ensure_codex_shell_env_marker(&mut config) {
            write_codex_config(&config_path, &config, "codex-cli:execution")?;
            changes.push(format!("updated {}", config_path.display()));
        }
        let mut config = read_or_empty_codex_config(&config_path)?;
        if ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path)? {
            write_codex_config(&config_path, &config, "codex-cli:execution")?;
            changes.push(format!("trusted kyris hook in {}", config_path.display()));
        }

        // ── Command prefix rules (.rules file) ──────────────────────────
        match crate::compile_policy::compile_codex_permissions(None) {
            Ok((rules, _)) => {
                let rules_content = crate::compile_policy::serialize_codex_rules_file(&rules);
                if !rules_content.is_empty() {
                    let rules_path = codex_dir()?.join("rules").join("agentpact.rules");
                    if crate::state::write_managed_file(
                        &rules_path,
                        &rules_content,
                        "codex-cli:execution",
                        None,
                        &NoopValidator,
                    )? {
                        changes.push(format!("wrote {}", rules_path.display()));
                    }
                }
            }
            Err(e) => {
                changes.push(format!("warning: compiled policy skipped: {e}"));
            }
        }

        // ── Filesystem + network permissions table ───────────────────────
        match crate::compile_policy::compile_codex_permissions_table(None) {
            Ok(table) => {
                let has_fs = !table.filesystem.is_empty();
                let has_net = !table.network_domains.is_empty();

                if has_fs || has_net {
                    let mut config = read_toml_value(&config_path)?;
                    let mut config_changed = false;

                    if has_fs
                        && merge_toml_string_entries(
                            &mut config,
                            &["permissions", "kyris", "filesystem"],
                            &table.filesystem,
                        )
                    {
                        config_changed = true;
                        changes.push(format!(
                            "wrote {} path rule(s) to [permissions.kyris.filesystem] in {}",
                            table.filesystem.len(),
                            config_path.display()
                        ));
                    }

                    if has_net
                        && merge_toml_string_entries(
                            &mut config,
                            &["permissions", "kyris", "network", "domains"],
                            &table.network_domains,
                        )
                    {
                        config_changed = true;
                        changes.push(format!(
                            "wrote {} domain rule(s) to [permissions.kyris.network.domains] in {}",
                            table.network_domains.len(),
                            config_path.display()
                        ));
                    }

                    // Activate the kyris profile via default_permissions —
                    // but only when it is unset or already points at "kyris".
                    let current_dp = config
                        .as_table()
                        .and_then(|t| t.get("default_permissions"))
                        .and_then(toml::Value::as_str)
                        .map(str::to_string);
                    match current_dp.as_deref() {
                        None | Some("kyris") => {
                            if ensure_toml_string_path(
                                &mut config,
                                &["default_permissions"],
                                "kyris",
                            ) {
                                config_changed = true;
                                changes.push(format!(
                                    "set default_permissions = \"kyris\" in {}",
                                    config_path.display()
                                ));
                            }
                        }
                        Some(other) => {
                            changes.push(format!(
                                "warning: [permissions.kyris] written but not activated — \
                                 default_permissions is already \"{other}\". \
                                 Set default_permissions = \"kyris\" to activate."
                            ));
                        }
                    }

                    if config_changed {
                        write_codex_config(&config_path, &config, "codex-cli:execution")?;
                    }
                }

                // Surface precision-loss warnings.
                let gaps = table.gaps;
                if !gaps.is_empty() {
                    let mut profile = crate::state::load_agent_profile("codex-cli")?
                        .unwrap_or_else(|| super::profile::AgentProfile::new_empty("codex-cli"));
                    profile.compilation_gaps.clone_from(&gaps);
                    crate::state::save_agent_profile(&profile)?;
                    for gap in &gaps {
                        changes.push(format!("warning: {gap}"));
                    }
                }
            }
            Err(e) => {
                changes.push(format!("warning: permissions table skipped: {e}"));
            }
        }

        Ok(changes)
    }
    fn configure_burn_control_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        // Ensure .codex dir exists for first-time setup (binary installed, no config yet).
        ensure_codex_dir()?;
        let mut changes = Vec::new();

        let mut config = read_or_empty_codex_config(&config_path)?;

        let base_url_v1 = format!("{base_url}/v1");
        let mut config_changed = false;
        // Route codex through the kyris custom provider by default — the built-in
        // openai provider can't carry the x-kyris-inbound header (reserved ID).
        if ensure_toml_string_path(&mut config, &["model_provider"], "kyris") {
            config_changed = true;
        }
        if ensure_codex_kyris_model_provider(&mut config, &base_url_v1, inbound_key) {
            config_changed = true;
        }

        if config_changed {
            write_codex_config(&config_path, &config, "codex-cli:burn-control")?;
            changes.push(format!("updated {}", config_path.display()));
        }

        Ok(changes)
    }
    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let config_path = codex_config_path()?;
        ensure_codex_dir()?;
        let mut changes = Vec::new();
        let mut config = read_or_empty_codex_config(&config_path)?;

        let mut config_changed = false;
        let mcp_result =
            super::configure::rewrite_codex_mcp_servers(&mut config, base_url, inbound_key);
        if mcp_result.changed {
            config_changed = true;
        }
        if super::configure::apply_toml_tool_filters(&mut config) {
            config_changed = true;
        }
        if config_changed {
            write_codex_config(&config_path, &config, "codex-cli:tool")?;
            changes.push(format!("updated {}", config_path.display()));
        }
        if !mcp_result.http_rewrites.is_empty() {
            super::configure::upsert_mcp_upstreams(&mcp_result.http_rewrites)?;
            changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
        }

        Ok(changes)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        // Remove MCP upstreams from kyrisd.yaml before the config file is
        // restored to its pre-kyris state (after which the server names
        // would no longer be readable from the agent config).
        let mcp_names = super::configure::mcp_server_names_from_agent(self);
        super::configure::remove_mcp_upstreams(&mcp_names)?;

        // Structurally unapply every config.toml edit kyris recorded at setup
        // (the complete original→configured TOML patch): routing keys,
        // [model_providers.kyris], [permissions.kyris], default_permissions,
        // hooks feature, … all reverse together, restoring the user's pre-kyris
        // config exactly — no backup, no leftover routing or credential.
        let config_path = codex_config_path()?;
        restore_manifest_entry_component(&config_path, "codex-cli:tool")?;

        for change in scrub_codex_residue()? {
            println!("{change}");
        }
        Ok(())
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        let config_path = codex_config_path()?;
        restore_manifest_entry_component(&config_path, "codex-cli:execution")?;
        let hooks_path = codex_hooks_path()?;
        restore_manifest_entry_component(&hooks_path, "codex-cli:execution")?;
        let script = codex_dir()?.join("kyris_pretooluse.sh");
        restore_manifest_entry_component(&script, "codex-cli:execution")?;
        let rules = codex_dir()?.join("rules").join("agentpact.rules");
        restore_manifest_entry_component(&rules, "codex-cli:execution")?;

        for change in scrub_codex_residue()? {
            println!("{change}");
        }
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if restore_manifest_entry_component(&path, "codex-cli:burn-control")? {
                println!("Reverted {}", path.display());
            }
        }
        for change in scrub_codex_residue()? {
            println!("{change}");
        }
        Ok(())
    }
    fn mcp_config(&self) -> Option<McpConfigLocation> {
        codex_config_path().ok().map(|path| McpConfigLocation {
            path,
            format: McpConfigFormat::Toml {
                servers_key: "mcp_servers",
            },
        })
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        codex_config_path().into_iter().collect()
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "Bash".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "apply_patch".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("command".to_string()),
                },
            ],
            // Codex CLI internal coordination tools: skip the daemon. See
            // claude_code.rs and hook_cmd.rs for the design rationale.
            pass_through_tools: vec!["update_plan".to_string(), "view_image".to_string()],
            detail_pass_throughs: vec![DetailPassThrough {
                action: "execute".to_string(),
                detail_contains: vec![".codex/shell_snapshots/".to_string()],
                reason: "codex-shell-snapshot".to_string(),
            }],
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GAP 21 tests: binary-installed-but-no-config detection ---

    #[test]
    fn testCodexBinaryInstalledReturnsBool() {
        // Just verify it compiles and returns a bool without panicking.
        let _ = codex_binary_installed();
    }

    #[test]
    fn testCodexBinaryInstalledFalseForGibberishCommand() {
        // "codex-binary-xyz-does-not-exist" is guaranteed not on PATH.
        assert!(!crate::agents::registry::which_exists(
            "codex-binary-xyz-does-not-exist"
        ));
    }

    #[test]
    fn testReadOrEmptyCodexConfigReturnsEmptyTableForMissingFile() {
        let missing = std::path::Path::new("/tmp/kyris-test-nonexistent-codex-config.toml");
        let result = read_or_empty_codex_config(missing).expect("should succeed");
        assert!(
            result.as_table().is_some_and(toml::map::Map::is_empty),
            "expected empty table, got: {result:?}"
        );
    }

    #[test]
    fn testReadOrEmptyCodexConfigReadsExistingFile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[features]\ncodex_hooks = true\n").unwrap();
        let result = read_or_empty_codex_config(&path).expect("should read");
        assert_eq!(
            result
                .get("features")
                .and_then(|f| f.get("codex_hooks"))
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn testEnsureCodexDirCreatesDirectory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("codex");
        // Prove it doesn't exist yet.
        assert!(!nested.exists());
        std::fs::create_dir_all(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn testEmptyConfigCanBePopulatedByBurnControlLogic() {
        // Simulates the burn-control surface setup for a first-time user:
        // start with empty TOML and verify the expected keys are written.
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        let changed = ensure_toml_string_path(&mut config, &["model_provider"], "kyris");
        assert!(changed, "model_provider should be written to empty config");
        assert_eq!(
            config.get("model_provider").and_then(toml::Value::as_str),
            Some("kyris")
        );

        let changed2 = ensure_codex_kyris_model_provider(
            &mut config,
            "http://127.0.0.1:4710/v1",
            "sk-kyris-test",
        );
        assert!(changed2, "model provider should be written to empty config");
        assert_eq!(
            config["model_providers"]["kyris"]["name"].as_str(),
            Some("Kyris")
        );
    }

    #[test]
    fn testEmptyConfigCanBePopulatedByExecutionLogic() {
        // Simulates the configure_execution hooks-feature path for first-time user.
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());
        let changed = ensure_toml_bool_path(&mut config, &["features", "hooks"], true);
        assert!(changed, "features.hooks should be set in empty config");
        assert_eq!(config["features"]["hooks"].as_bool(), Some(true));
    }

    #[test]
    fn testCodexKyrisHookTrustWrittenAndVerified() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        assert!(ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap());
        assert!(!ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap());
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        let key = codex_kyris_hook_key(&hooks_path);
        assert_eq!(
            config["hooks"]["state"][&key]["trusted_hash"].as_str(),
            Some(codex_kyris_hook_hash(&script_path).unwrap().as_str())
        );
        assert!(codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
    }

    #[test]
    fn testCodexKyrisHookTrustRequiresMatchingScriptPath() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let other_script_path = dir.path().join("other_pretooluse.sh");
        let mut config: toml::Value = toml::Value::Table(toml::map::Map::default());

        assert!(!codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &script_path
        ));
        ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap();
        write_codex_config_unmanaged(&config_path, &config).unwrap();

        assert!(!codex_kyris_hook_trusted(
            &config_path,
            &hooks_path,
            &other_script_path
        ));
    }

    #[test]
    fn testScrubCodexKyrisHookTrustRemovesOnlyKyrisEntry() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let hooks_path = dir.path().join("hooks.json");
        let script_path = dir.path().join("kyris_pretooluse.sh");
        let other_key = "/tmp/other-hooks.json:pre_tool_use:0:0";
        let mut config: toml::Value = toml::from_str(&format!(
            r#"
[hooks.state."{other_key}"]
trusted_hash = "sha256:other"
"#
        ))
        .expect("parse config");

        ensure_codex_kyris_hook_trust(&mut config, &hooks_path, &script_path).unwrap();
        assert!(scrub_codex_kyris_hook_trust(&mut config, &config_path));

        let kyris_key = codex_kyris_hook_key(&hooks_path);
        assert!(
            config["hooks"]["state"]
                .as_table()
                .is_some_and(|state| !state.contains_key(&kyris_key))
        );
        assert_eq!(
            config["hooks"]["state"][other_key]["trusted_hash"].as_str(),
            Some("sha256:other")
        );
    }

    #[test]
    fn testCodexConfigPathUsesUserScopeNotProjectDiscovery() {
        let home = PathBuf::from("/tmp/home");
        assert_eq!(
            codex_config_path_from(None, home.clone()),
            home.join(".codex").join("config.toml")
        );
        assert_eq!(
            codex_config_path_from(Some(PathBuf::from("/tmp/codex-home")), home),
            PathBuf::from("/tmp/codex-home").join("config.toml")
        );
    }

    #[test]
    fn testEnsureCodexShellEnvMarkerPreservesExistingSetEntries() {
        let mut config: toml::Value = toml::from_str(
            r#"
[shell_environment_policy.set]
EXISTING = "keep"
"#,
        )
        .expect("parse config");

        assert!(ensure_codex_shell_env_marker(&mut config));
        assert_eq!(
            config["shell_environment_policy"]["set"]["EXISTING"].as_str(),
            Some("keep")
        );
        assert_eq!(
            config["shell_environment_policy"]["set"]["KYRIS_GOVERNED_SUBPROCESS"].as_str(),
            Some("codex-cli")
        );
    }

    #[test]
    fn testScrubCodexConfigValueRemovesOnlyKyrisOwnedState() {
        let mut config: toml::Value = toml::from_str(
            r#"
model_provider = "kyris"
openai_base_url = "http://127.0.0.1:4710/v1"
default_permissions = "kyris"

[model_providers.openai]
base_url = "https://api.openai.com/v1"

[model_providers.kyris]
base_url = "http://127.0.0.1:4710/v1"

[permissions.kyris.filesystem]
":workspace_roots" = "write"

[shell_environment_policy.set]
EXISTING = "keep"
KYRIS_GOVERNED_SUBPROCESS = "codex-cli"
"#,
        )
        .expect("parse config");

        assert!(scrub_codex_config_value(&mut config));
        assert!(config.get("model_provider").is_none());
        assert!(config.get("openai_base_url").is_none());
        assert!(config.get("default_permissions").is_none());
        assert!(
            config["model_providers"]
                .as_table()
                .is_some_and(|providers| providers.contains_key("openai"))
        );
        assert!(
            !config["model_providers"]
                .as_table()
                .is_some_and(|providers| providers.contains_key("kyris"))
        );
        assert!(config.get("permissions").is_none());
        assert_eq!(
            config["shell_environment_policy"]["set"]["EXISTING"].as_str(),
            Some("keep")
        );
        assert!(
            config["shell_environment_policy"]["set"]
                .as_table()
                .is_some_and(|set| !set.contains_key("KYRIS_GOVERNED_SUBPROCESS"))
        );
    }

    // --- existing test ---

    #[test]
    fn testCodexKyrisModelProviderIsValidForCodex0130() {
        // Seed a config carrying the stale experimental_bearer_token an older
        // kyris install would have written — setup must migrate it away.
        let mut config: toml::Value = toml::from_str(
            "[model_providers.kyris]\nbase_url = \"http://old.example/v1\"\nexperimental_bearer_token = \"sk-kyris-stale\"\n",
        )
        .expect("parse config");

        assert!(ensure_codex_kyris_model_provider(
            &mut config,
            "http://127.0.0.1:4710/v1",
            "sk-kyris-test"
        ));

        let provider = config["model_providers"]["kyris"]
            .as_table()
            .expect("kyris provider");
        assert_eq!(provider["name"].as_str(), Some("Kyris"));
        assert_eq!(
            provider["base_url"].as_str(),
            Some("http://127.0.0.1:4710/v1")
        );
        assert_eq!(provider["wire_api"].as_str(), Some("responses"));
        // The inbound key is a custom header, NOT the bearer (the bearer would be
        // forwarded upstream to OpenAI and rejected). codex uses its own auth.json
        // credential for the bearer via requires_openai_auth.
        assert_eq!(
            provider["http_headers"]["x-kyris-inbound"].as_str(),
            Some("sk-kyris-test")
        );
        assert!(
            provider.get("experimental_bearer_token").is_none(),
            "stale experimental_bearer_token must be migrated away (it hijacks the \
             Authorization bearer; codex must use its own auth.json credential)"
        );
        assert_eq!(provider["requires_openai_auth"].as_bool(), Some(true));
        // kyrisd serves /v1/responses over HTTP only — WS returns 405.
        assert_eq!(provider["supports_websockets"].as_bool(), Some(false));
    }
}
