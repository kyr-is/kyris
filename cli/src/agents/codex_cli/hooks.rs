// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Codex hook trust-identity machinery (hashing hooks.json entries the way
//! codex itself does, minting/probing/scrubbing the `hooks.state` trust keys)
//! plus the residue scrub that `kyris agent disconnect` runs to strip every
//! kyris-owned config key, hook registration, and generated file.
use std::path::Path;

use serde::Serialize;

use crate::integration::{
    ensure_toml_string_path, read_json_value, read_toml_value, remove_json_command_hook,
};

use super::paths::{
    codex_config_candidate_paths, codex_dir, codex_hooks_path, write_codex_config_unmanaged,
    write_json_unmanaged,
};

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

pub(super) fn codex_kyris_hook_command(script_path: &Path) -> String {
    crate::agents::configure::shell_command(script_path)
}

/// The hook events kyris registers for codex, as `(hooks.json key, the
/// snake_case label codex uses in trust-state keys and identity hashes)`.
/// `PreToolUse` is the governance gate; `PermissionRequest` answers codex's
/// native approval prompts (allow / abstain — see `run_permission_request`).
const CODEX_HOOK_EVENTS: &[(&str, &str)] = &[
    ("PreToolUse", "pre_tool_use"),
    ("PermissionRequest", "permission_request"),
];

/// Per-hook `timeout` (seconds) kyris writes on its hooks.json handlers — one
/// week, i.e. effectively forever. This is the approval-hold ceiling: a kyris
/// popup ask can wait this long for the developer (walk away, answer from the
/// tray days later) before codex kills the hook. Codex honors any explicit
/// value uncapped (`timeout_sec.unwrap_or(600).max(1)`, discovery.rs) and
/// enforces it with a tokio timer, so large finite values are safe where a
/// literal "no timeout" does not exist. `HookRuntime.agent_hook_timeout_secs`
/// and the trust-identity hash both derive from this constant — single source.
pub(super) const CODEX_HOOK_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60;

/// Codex's own default per-hook timeout — the value baked into trust hashes
/// written by kyris installs that predate the explicit
/// [`CODEX_HOOK_TIMEOUT_SECS`] pin. Kept only so scrub can recognize (and
/// remove) those legacy trust entries.
const CODEX_LEGACY_HOOK_TIMEOUT_SECS: u64 = 600;

pub(super) fn codex_kyris_hook_key(hooks_path: &Path, event_label: &str) -> String {
    format!("{}:{event_label}:0:0", hooks_path.display())
}

#[derive(Serialize)]
struct CodexHookTrustIdentity {
    event_name: &'static str,
    matcher: String,
    hooks: Vec<CodexHookTrustHandler>,
}

#[derive(Serialize)]
struct CodexHookTrustHandler {
    r#type: String,
    command: String,
    #[serde(rename = "commandWindows")]
    command_windows: Option<String>,
    #[serde(rename = "timeout")]
    timeout_sec: u64,
    r#async: bool,
    #[serde(rename = "statusMessage")]
    status_message: Option<String>,
}

fn codex_hook_identity_hash(
    event_label: &'static str,
    matcher: &str,
    handler: CodexHookTrustHandler,
) -> Result<String, String> {
    let identity = CodexHookTrustIdentity {
        event_name: event_label,
        matcher: matcher.to_string(),
        hooks: vec![handler],
    };
    let value = toml::Value::try_from(identity)
        .map_err(|e| format!("cannot build codex hook trust identity: {e}"))?;
    Ok(codex_toml_version(&value))
}

/// The hash for the hook entry kyris ITSELF writes for `event_label` (matcher
/// "", explicit `timeout` = [`CODEX_HOOK_TIMEOUT_SECS`]). Used by configure
/// when minting the trust entry and by scrub to identify kyris's entries; the
/// probe instead recomputes from the file (see [`codex_kyris_hook_file_trust`])
/// so user edits surface as drift.
pub(super) fn codex_kyris_hook_hash(
    script_path: &Path,
    event_label: &'static str,
) -> Result<String, String> {
    codex_kyris_hook_hash_with_timeout(script_path, event_label, CODEX_HOOK_TIMEOUT_SECS)
}

fn codex_kyris_hook_hash_with_timeout(
    script_path: &Path,
    event_label: &'static str,
    timeout_sec: u64,
) -> Result<String, String> {
    codex_hook_identity_hash(
        event_label,
        "",
        CodexHookTrustHandler {
            r#type: "command".to_string(),
            command: codex_kyris_hook_command(script_path),
            command_windows: None,
            timeout_sec,
            r#async: false,
            status_message: None,
        },
    )
}

/// Locate kyris's handler for one hook EVENT in hooks.json and compute the
/// trust (key, hash) the way CODEX does: keyed by the entry's ACTUAL
/// `group:handler` indices and hashed from the FILE's field values (timeout
/// default 600). This is the semantic probe core — the old probe read back
/// kyris's own constants at a hardcoded `0:0`, so a user-edited entry (→
/// codex sees Modified, hook silently stops running) or a kyris group
/// appended after pre-existing user groups (→ trust entry at the wrong key,
/// hook Untrusted) still showed green.
fn codex_kyris_hook_file_trust(
    hooks_path: &Path,
    script_path: &Path,
    event_json_key: &str,
    event_label: &'static str,
) -> Option<(String, String)> {
    let value = crate::integration::read_json_value(hooks_path).ok()?;
    let groups = value.get("hooks")?.get(event_json_key)?.as_array()?;
    let expected_command = codex_kyris_hook_command(script_path);
    for (group_idx, group) in groups.iter().enumerate() {
        let matcher = group.get("matcher").and_then(|v| v.as_str()).unwrap_or("");
        let Some(handlers) = group.get("hooks").and_then(|v| v.as_array()) else {
            continue;
        };
        for (handler_idx, handler) in handlers.iter().enumerate() {
            if handler.get("command").and_then(|v| v.as_str()) != Some(expected_command.as_str()) {
                continue;
            }
            let trust_handler = CodexHookTrustHandler {
                r#type: handler
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("command")
                    .to_string(),
                command: expected_command.clone(),
                command_windows: handler
                    .get("commandWindows")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                timeout_sec: handler
                    .get("timeout")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(600),
                r#async: handler
                    .get("async")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                status_message: handler
                    .get("statusMessage")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            };
            let hash = codex_hook_identity_hash(event_label, matcher, trust_handler).ok()?;
            let key = format!(
                "{}:{event_label}:{group_idx}:{handler_idx}",
                hooks_path.display()
            );
            return Some((key, hash));
        }
    }
    None
}

pub(super) fn ensure_codex_kyris_hook_trust(
    config: &mut toml::Value,
    hooks_path: &Path,
    script_path: &Path,
) -> Result<bool, String> {
    // One trust entry per registered EVENT, keyed by the entry's ACTUAL
    // group:handler index in hooks.json (codex's keying) — kyris's group is
    // APPENDED, so with pre-existing user groups it does not sit at 0:0;
    // minting at a hardcoded 0:0 left the kyris hook Untrusted (never run)
    // and clobbered the user's own trust entry. hooks.json is written before
    // this runs; the 0:0 fallback only covers a read failure of the file just
    // written.
    //
    // Mint ONLY when the file entry hashes to kyris's canonical identity:
    // blessing a user-edited entry would both endorse an edit kyris didn't
    // make and break the G3 timing contract (e.g. a user `timeout: 30` kills
    // the hook far inside the approval window). A drifted entry is indicated,
    // not silently re-trusted — the probe shows the hook as not live.
    let mut changed = false;
    for (event_json_key, event_label) in CODEX_HOOK_EVENTS {
        let canonical_hash = codex_kyris_hook_hash(script_path, event_label)?;
        let (key, hash) =
            match codex_kyris_hook_file_trust(hooks_path, script_path, event_json_key, event_label)
            {
                Some((key, file_hash)) if file_hash == canonical_hash => (key, file_hash),
                Some((key, _)) => {
                    eprintln!(
                        "[kyris] codex hooks.json entry at {key} differs from what kyris \
                         installs (edited?); not re-trusting it — re-run \
                         `kyris agent setup codex-cli` after reverting the edit, or remove \
                         the entry"
                    );
                    continue;
                }
                None => (
                    codex_kyris_hook_key(hooks_path, event_label),
                    canonical_hash,
                ),
            };
        changed |= ensure_toml_string_path(
            config,
            &["hooks", "state", key.as_str(), "trusted_hash"],
            &hash,
        );
    }
    Ok(changed)
}

/// The EXECUTION-surface probe checks the `PreToolUse` entry only: that is the
/// governance gate. The `PermissionRequest` entry is a UX completion (allow
/// path) whose absence degrades to double-prompting, not to un-governance.
pub(super) fn codex_kyris_hook_trusted(
    config_path: &Path,
    hooks_path: &Path,
    script_path: &Path,
) -> bool {
    let Ok(config) = read_toml_value(config_path) else {
        return false;
    };
    let Some((key, expected_hash)) =
        codex_kyris_hook_file_trust(hooks_path, script_path, "PreToolUse", "pre_tool_use")
    else {
        return false;
    };
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

pub(super) fn scrub_codex_kyris_hook_trust(config: &mut toml::Value, config_path: &Path) -> bool {
    let Some(dir) = config_path.parent() else {
        return false;
    };
    let hooks_path = dir.join("hooks.json");
    // The trust entries may sit at any group index (keyed by where the kyris
    // groups landed in hooks.json, which undo may already have restored), so
    // identify kyris's entries by their HASHES — the entries kyris writes
    // always hash to the constant per-event identity (matcher "", the pinned
    // timeout) — scoped to this hooks.json's keys so a user's identical hook
    // in another file is untouched. Both the current pinned-timeout hash and
    // the legacy 600s-default hash are matched, so undo also heals installs
    // that predate the explicit timeout.
    let script_path = dir.join("kyris_pretooluse.sh");
    let kyris_hashes: Vec<String> = CODEX_HOOK_EVENTS
        .iter()
        .flat_map(|(_, label)| {
            [
                codex_kyris_hook_hash_with_timeout(&script_path, label, CODEX_HOOK_TIMEOUT_SECS),
                codex_kyris_hook_hash_with_timeout(
                    &script_path,
                    label,
                    CODEX_LEGACY_HOOK_TIMEOUT_SECS,
                ),
            ]
        })
        .filter_map(Result::ok)
        .collect();
    let key_prefix = format!("{}:", hooks_path.display());
    let kyris_keys: Vec<String> = config
        .get("hooks")
        .and_then(toml::Value::as_table)
        .and_then(|hooks| hooks.get("state"))
        .and_then(toml::Value::as_table)
        .map(|state| {
            state
                .iter()
                .filter(|(key, entry)| {
                    key.starts_with(&key_prefix)
                        && entry
                            .get("trusted_hash")
                            .and_then(toml::Value::as_str)
                            .is_some_and(|h| kyris_hashes.iter().any(|kh| kh == h))
                })
                .map(|(key, _)| key.clone())
                .collect()
        })
        .unwrap_or_default();
    let mut changed = false;
    for key in &kyris_keys {
        changed |= remove_toml_path(config, &["hooks", "state", key.as_str()]);
    }
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

pub(super) fn scrub_codex_config_value(config: &mut toml::Value) -> bool {
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
    // Residue cleanup of the native-mode approval routing (the manifest undo
    // restores the user's prior value semantically; this best-effort scrub only
    // strips kyris's "untrusted" when no manifest is available).
    if config.get("approval_policy").and_then(toml::Value::as_str) == Some("untrusted") {
        changed |= remove_toml_path(config, &["approval_policy"]);
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
        let mut removed = false;
        for (event_json_key, _) in CODEX_HOOK_EVENTS {
            removed |= remove_json_command_hook(&mut hooks, event_json_key, "kyris_pretooluse");
        }
        if removed {
            write_json_unmanaged(&hooks_path, &hooks)?;
            changes.push(format!("removed hook(s) from {}", hooks_path.display()));
        }
    }

    let script = codex_dir()?.join("kyris_pretooluse.sh");
    if crate::agents::undo::remove_file_if_exists(&script)? {
        changes.push(format!("removed {}", script.display()));
    }
    let rules = codex_dir()?.join("rules").join("agentpact.rules");
    if crate::agents::undo::remove_file_if_exists(&rules)? {
        changes.push(format!("removed {}", rules.display()));
    }

    Ok(changes)
}
