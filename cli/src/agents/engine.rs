// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The generic engine that executes an [`AdaptationProfile`]'s bounded op
//! vocabulary against an agent's real config — the single, agent-agnostic
//! replacement for the per-agent descriptor code. This module owns the pure,
//! side-effect-free primitives (detection, config-path resolution, value
//! templating); the surface configure/probe/undo executors that perform I/O are
//! layered on top and reuse the existing shared write/probe/restore helpers.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::adaptation::{AdaptationProfile, Discovery, FileFormat};
use super::capabilities::NativeCapabilityDeclaration;
use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{
    is_kyris_key, read_json_value, remove_json_string_if, set_json_string_path,
    set_json_value_path, write_json_value,
};
use crate::state::{restore_manifest_entry_component, write_managed_file};

/// Expand a leading `~` / `~/` to the home directory; other paths pass through.
pub fn expand_tilde(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        crate::integration::home_dir()
    } else if let Some(rest) = path.strip_prefix("~/") {
        Ok(crate::integration::home_dir()?.join(rest))
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Resolve a single config file's path from its discovery rule. `working_dir`
/// anchors walk-up discovery (the agent's launch/permitted dir).
pub fn resolve_config_path(
    discovery: &Discovery,
    working_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    match discovery {
        Discovery::Static { path } => expand_tilde(path),
        Discovery::EnvRooted {
            env,
            subpath,
            fallback,
        } => env_rooted_path(std::env::var(env).ok().as_deref(), subpath, fallback),
        Discovery::WalkUp {
            filenames,
            global_dir,
        } => {
            let mut dir = working_dir;
            while let Some(d) = dir {
                for name in filenames {
                    let cand = d.join(name);
                    if cand.exists() {
                        return Ok(cand);
                    }
                }
                dir = d.parent();
            }
            // Then the global dir, same filename preference, defaulting to the
            // last (lowest-precedence) filename when none exist.
            let global = expand_tilde(global_dir)?;
            for name in filenames {
                let cand = global.join(name);
                if cand.exists() {
                    return Ok(cand);
                }
            }
            let last = filenames
                .last()
                .ok_or_else(|| "walk_up requires at least one filename".to_string())?;
            Ok(global.join(last))
        }
        Discovery::WalkUpOptional { filenames } => {
            let mut dir = working_dir;
            while let Some(d) = dir {
                for name in filenames {
                    let cand = d.join(name);
                    if cand.exists() {
                        return Ok(cand);
                    }
                }
                dir = d.parent();
            }
            // No global fallback: not-found is a (recoverable) error so an
            // `optional` MCP source is simply skipped.
            Err("walk_up_optional: no matching file found".to_string())
        }
        Discovery::SiblingOf { .. } => Err(
            "sibling_of is resolved by the caller (it needs the referenced file's path)"
                .to_string(),
        ),
    }
}

/// `<env_value or fallback>/subpath` (e.g. `CODEX_HOME`). Pure for testability;
/// `resolve_config_path` supplies the live env value.
fn env_rooted_path(
    env_value: Option<&str>,
    subpath: &str,
    fallback: &str,
) -> Result<PathBuf, String> {
    match env_value {
        Some(v) if !v.is_empty() => Ok(PathBuf::from(v).join(subpath)),
        _ => expand_tilde(fallback),
    }
}

/// Whether the agent is present per its `detect` block: any declared binary on
/// `PATH`, or any declared config file existing.
#[must_use]
pub fn is_detected(profile: &AdaptationProfile) -> bool {
    if profile
        .detect
        .binaries
        .iter()
        .any(|b| crate::state::find_in_path(b).is_some())
    {
        return true;
    }
    let working_dir = std::env::current_dir().ok();
    profile.detect.config_paths.iter().any(|name| {
        profile.config_files.get(name).is_some_and(|cf| {
            // Anchor walk-up discovery at the cwd so a project-level config (e.g.
            // opencode.json in/above the working dir) counts as detection.
            resolve_config_path(&cf.discovery, working_dir.as_deref()).is_ok_and(|p| p.exists())
        })
    })
}

/// The values a configure op's templated strings can reference.
pub struct SubstCtx<'a> {
    pub base_url: &'a str,
    pub inbound_key: &'a str,
    pub agent_id: &'a str,
}

impl SubstCtx<'_> {
    fn apply(&self, s: &str) -> String {
        // `_v1` first is harmless (distinct literals) but keeps intent clear.
        s.replace("{base_url_v1}", &format!("{}/v1", self.base_url))
            .replace("{base_url}", self.base_url)
            .replace("{inbound_key}", self.inbound_key)
            .replace("{agent_id}", self.agent_id)
    }
}

/// Substitute template tokens inside a configure value. Only string scalars are
/// templated; numbers/bools/objects pass through unchanged (a `set_key` value of
/// `1` stays `1`).
#[must_use]
pub fn substitute_value(value: &Value, ctx: &SubstCtx) -> Value {
    match value {
        Value::String(s) => Value::String(ctx.apply(s)),
        other => other.clone(),
    }
}

/// Parse a Unix mode string (`"0644"`, `"0o755"`, `"755"`) as octal.
fn parse_mode(mode: &str) -> Result<u32, String> {
    let digits = mode.trim_start_matches("0o");
    u32::from_str_radix(digits, 8).map_err(|e| format!("invalid mode {mode:?}: {e}"))
}

/// `install_file` op: write a named bridge template to `dest`, substituting the
/// agent's hook spawn timeout, under the given manifest `component` scope.
pub fn install_template(
    template: &str,
    dest: &Path,
    mode: Option<&str>,
    spawn_timeout_ms: u64,
    component: &str,
) -> Result<Vec<String>, String> {
    let content = super::templates::bridge_template(template)
        .ok_or_else(|| format!("unknown bridge template: {template}"))?
        .replace("__SPAWN_TIMEOUT_MS__", &spawn_timeout_ms.to_string());
    let mode = match mode {
        Some(m) => Some(parse_mode(m)?),
        None => None,
    };
    let mut changes = Vec::new();
    // Bridge scripts are opaque (JS / shell) — no schema to validate.
    if write_managed_file(dest, &content, component, mode, &NoopValidator)? {
        changes.push(format!("wrote {}", dest.display()));
    }
    Ok(changes)
}

/// A batch of `set_key` ops (templated value at a key path) targeting one JSON
/// file: read once, set all, write once under `component` — matching the
/// single-write behavior the hand-written descriptors used.
pub fn apply_json_set_keys(
    path: &Path,
    ops: &[(Vec<String>, Value)],
    ctx: &SubstCtx,
    component: &str,
) -> Result<Vec<String>, String> {
    let mut config = if path.exists() {
        read_json_value(path)?
    } else {
        Value::Object(serde_json::Map::new())
    };
    let mut modified = false;
    for (key_path, value) in ops {
        let refs: Vec<&str> = key_path.iter().map(String::as_str).collect();
        if set_json_value_path(&mut config, &refs, substitute_value(value, ctx)) {
            modified = true;
        }
    }
    let mut changes = Vec::new();
    if modified {
        write_json_value(path, &config, component, &WellFormedJsonValidator)?;
        changes.push(format!("wrote {}", path.display()));
    }
    Ok(changes)
}

/// `manifest_restore` undo op: semantically revert a managed file by scope; if
/// nothing was managed and `delete_if_unmanaged`, remove the file.
pub fn restore(path: &Path, scope: &str, delete_if_unmanaged: bool) -> Result<(), String> {
    if !restore_manifest_entry_component(path, scope)? && delete_if_unmanaged {
        super::undo::remove_file_if_exists(path)?;
    }
    Ok(())
}

// ── Config format support ───────────────────────────────────────────────────

/// Read a config respecting its declared format: strict JSON for `Json`, a
/// comment/trailing-comma-tolerant parse for `Jsonc`. An absent file is an empty
/// object. (TOML lands with the codex port.)
pub fn read_config(path: &Path, format: FileFormat) -> Result<Value, String> {
    match format {
        FileFormat::Jsonc => read_jsonc_tolerant(path),
        FileFormat::Json => {
            if path.exists() {
                read_json_value(path)
            } else {
                Ok(Value::Object(serde_json::Map::new()))
            }
        }
        FileFormat::Toml => {
            Err("TOML config read is not yet supported by the generic engine".to_string())
        }
    }
}

fn read_jsonc_tolerant(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let tolerant = strip_trailing_commas(&strip_jsonc_comments(&raw));
    serde_json::from_str(&tolerant).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// `require_writable` op: refuse a JSONC-syntax config kyris cannot round-trip
/// without losing the comments/commas. Strict-JSON or absent files pass.
pub fn require_writable(path: &Path) -> Result<(), String> {
    if !path.exists() || read_json_value(path).is_ok() {
        return Ok(());
    }
    if read_jsonc_tolerant(path).is_ok() {
        return Err(format!(
            "{} uses JSONC syntax (comments and/or trailing commas), which kyris cannot manage \
             without losing it. Convert it to standard JSON (remove the JSONC syntax), then \
             re-run setup.",
            path.display()
        ));
    }
    Ok(())
}

/// `set_governed_permissions` op: opencode's scoped permission normalization.
pub fn set_governed_permissions(
    path: &Path,
    format: FileFormat,
    component: &str,
) -> Result<Vec<String>, String> {
    let mut config = read_config(path, format)?;
    if apply_governed_permissions(&mut config) {
        write_json_value(path, &config, component, &WellFormedJsonValidator)?;
        return Ok(vec![format!(
            "allowed kyris-governed tools in {} (preserving other native gates)",
            path.display()
        )]);
    }
    Ok(Vec::new())
}

/// `strip_kyris_apikey` op: remove an upstream `apiKey` slot whose value is a
/// kyris-issued key. This covers the current inbound key AND any stale one a
/// prior enrollment left behind: such a value is never a usable provider
/// credential, so the agent must fall back to its own key (env / native auth).
///
/// `inbound` is the current inbound key — matched explicitly so a non-prefixed
/// legacy value is still caught — but the primary signal is the `sk-kyris-`
/// prefix ([`is_kyris_key`]), which survives key rotation.
pub fn strip_kyris_apikey(
    path: &Path,
    format: FileFormat,
    key_path: &[String],
    inbound: &str,
    component: &str,
) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut config = read_config(path, format)?;
    let refs: Vec<&str> = key_path.iter().map(String::as_str).collect();
    if remove_json_string_if(&mut config, &refs, |v| v == inbound || is_kyris_key(v)) {
        write_json_value(path, &config, component, &WellFormedJsonValidator)?;
        return Ok(vec![format!(
            "removed stale kyris credential in {}",
            path.display()
        )]);
    }
    Ok(Vec::new())
}

/// Set `permission.{bash,edit,write} = "allow"` so the agent does not re-prompt
/// for tools kyris governs, WITHOUT a blunt allow-all that would defeat the
/// agent's own doom-loop / webfetch / plan-mode gates. Preserves the user's
/// other permission rules; drops only a lone allow-all (kyris's prior value).
fn apply_governed_permissions(config: &mut Value) -> bool {
    const GOVERNED: [&str; 3] = ["bash", "edit", "write"];
    let mut perm: serde_json::Map<String, Value> = match config.get("permission") {
        Some(Value::Object(m)) => {
            let mut m = m.clone();
            if m.len() == 1 && m.get("*").and_then(|v| v.as_str()) == Some("allow") {
                m.clear();
            }
            m
        }
        Some(Value::String(s)) if s != "allow" => {
            let mut m = serde_json::Map::new();
            m.insert("*".to_string(), Value::String(s.clone()));
            m
        }
        _ => serde_json::Map::new(),
    };
    for tool in GOVERNED {
        perm.insert(tool.to_string(), Value::String("allow".to_string()));
    }
    set_json_value_path(config, &["permission"], Value::Object(perm))
}

fn strip_trailing_commas(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let (mut in_str, mut escaped, mut pending_comma) = (false, false, false);
    let mut pending_ws = String::new();
    for c in src.chars() {
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if pending_comma {
            if c.is_whitespace() {
                pending_ws.push(c);
                continue;
            }
            if c == '}' || c == ']' {
                out.push_str(&pending_ws);
            } else {
                out.push(',');
                out.push_str(&pending_ws);
                if c == '"' {
                    in_str = true;
                }
            }
            out.push(c);
            pending_comma = false;
            pending_ws.clear();
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push('"');
            }
            ',' => pending_comma = true,
            _ => out.push(c),
        }
    }
    if pending_comma {
        out.push(',');
        out.push_str(&pending_ws);
    }
    out
}

fn strip_jsonc_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let (mut in_str, mut in_line, mut in_block, mut escaped) = (false, false, false, false);
    while let Some(c) = chars.next() {
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push('\n');
            }
            continue;
        }
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push('"');
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                in_line = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

/// Run an agent's `agentpact` capability-declaration command (§13.3) and return
/// its validated native flags, or `None` on any failure — missing binary,
/// non-zero exit, output that is not one parseable `AgentCapabilities` object, an
/// unsupported version, or an `agent` mismatch — so the caller falls back to the
/// in-code declaration (fail-closed to fully adapted). stdin is closed so a
/// binary awaiting input cannot hang. Only invoked for agents whose document
/// opts in via `live_query` (so a non-supporting binary is never run with an
/// unknown subcommand).
#[must_use]
pub fn query_live_capabilities(
    binaries: &[String],
    canonical: &str,
) -> Option<NativeCapabilityDeclaration> {
    for binary in binaries {
        let Some(bin) = crate::state::find_in_path(binary) else {
            continue;
        };
        let Some(stdout) = run_agentpact_command(&bin) else {
            continue;
        };
        if let Ok(manifest) = super::manifest::parse_and_validate(&stdout, canonical) {
            return Some(manifest.native_capabilities());
        }
    }
    None
}

/// Run `<bin> agentpact` and return its stdout, with a hard 5s timeout (a
/// misbehaving binary that hangs is killed rather than freezing setup) and
/// stdin closed (a binary awaiting input cannot block). `None` on spawn failure,
/// non-zero exit, or timeout.
fn run_agentpact_command(bin: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let mut child = std::process::Command::new(bin)
        .arg("agentpact")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut out = String::new();
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return Some(out);
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

// ── gemini-specific op handlers (engine-owned, agent-agnostic by data) ──────

const ROUTABLE_AUTH_TYPES: &[&str] = &["gemini-api-key", "vertex-ai", "gateway"];

fn json_get<'a>(v: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    Some(cur)
}

fn selected_auth_type(settings: &Value) -> Option<&str> {
    settings
        .get("security")?
        .get("auth")?
        .get("selectedType")?
        .as_str()
}

/// Whether a settings document's `security.auth.selectedType` routes through
/// kyrisd (an OAuth/Code-Assist selection ignores the base URL).
#[must_use]
pub fn auth_routable(settings: &Value) -> bool {
    selected_auth_type(settings).is_some_and(|t| ROUTABLE_AUTH_TYPES.contains(&t))
}

/// Whether an auth-type string routes through kyrisd.
#[must_use]
pub fn is_routable_auth_type(t: &str) -> bool {
    ROUTABLE_AUTH_TYPES.contains(&t)
}

/// Whether the user has a usable Gemini API key the `gemini-api-key` path would
/// resolve (env, credentials file, or keychain metadata — no secret read).
fn gemini_api_key_available() -> bool {
    if std::env::var("GEMINI_API_KEY").is_ok_and(|v| !v.trim().is_empty()) {
        return true;
    }
    if crate::integration::home_dir()
        .is_ok_and(|h| h.join(".gemini").join("gemini-credentials.json").exists())
    {
        return true;
    }
    std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "gemini-cli-api-key",
            "-a",
            "default-api-key",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// `ensure_routable_auth` op: switch a non-routable auth selection to the
/// API-key path when a key is available; otherwise indicate the gap (no flip).
pub fn ensure_routable_auth(
    path: &Path,
    format: FileFormat,
    component: &str,
) -> Result<Vec<String>, String> {
    let mut settings = read_config(path, format)?;
    if auth_routable(&settings) {
        return Ok(Vec::new());
    }
    if !gemini_api_key_available() {
        return Ok(vec![
            "warning: gemini is using OAuth/Code Assist and no GEMINI_API_KEY is available — \
             kyris cannot meter that traffic (the base-URL redirect is ignored on the OAuth \
             path). Provide a GEMINI_API_KEY and re-run setup to enable burn-control."
                .to_string(),
        ]);
    }
    if set_json_string_path(
        &mut settings,
        &["security", "auth", "selectedType"],
        "gemini-api-key",
    ) {
        write_json_value(path, &settings, component, &WellFormedJsonValidator)?;
        return Ok(vec![format!(
            "set security.auth.selectedType = \"gemini-api-key\" in {} \
             (prior selection could not route through kyrisd)",
            path.display()
        )]);
    }
    Ok(Vec::new())
}

/// `write_compiled_policy` op: compile kyris policy to gemini's TOML format and
/// write it (skipped when there are no rules).
pub fn write_compiled_policy(dest: &Path, component: &str) -> Result<Vec<String>, String> {
    match crate::compile_policy::compile_gemini_permissions(None) {
        Ok((rules, _)) => {
            if rules.as_array().is_some_and(|a| !a.is_empty()) {
                let toml = crate::compile_policy::serialize_gemini_policy_toml(&rules);
                if write_managed_file(dest, &toml, component, None, &NoopValidator)? {
                    return Ok(vec![format!("wrote {}", dest.display())]);
                }
            }
            Ok(Vec::new())
        }
        Err(e) => Ok(vec![format!("warning: compiled policy skipped: {e}")]),
    }
}

/// `set_setting_from_input` op: set `key_path` to a non-negative integer parsed
/// from a `--set` value, refusing to clobber a non-object parent.
pub fn set_setting_from_input(
    path: &Path,
    format: FileFormat,
    key_path: &[String],
    value: &str,
    component: &str,
) -> Result<Vec<String>, String> {
    let n: u64 = value.parse().map_err(|_| {
        format!(
            "{} must be a non-negative integer, got '{value}'",
            key_path.join(".")
        )
    })?;
    let mut settings = read_config(path, format)?;
    if key_path.len() >= 2 {
        let parent = &key_path[..key_path.len() - 1];
        if json_get(&settings, parent).is_some_and(|v| !v.is_object() && !v.is_null()) {
            return Err(format!(
                "cannot set {}: {} has a non-object `{}` value; fix it to an object first",
                key_path.join("."),
                path.display(),
                parent.join(".")
            ));
        }
    }
    let refs: Vec<&str> = key_path.iter().map(String::as_str).collect();
    set_json_value_path(&mut settings, &refs, Value::from(n));
    write_json_value(path, &settings, component, &WellFormedJsonValidator)?;
    Ok(vec![format!(
        "set {} in {}",
        key_path.join("."),
        path.display()
    )])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testExpandTilde() {
        let home = crate::integration::home_dir().unwrap();
        assert_eq!(expand_tilde("~/x/y").unwrap(), home.join("x/y"));
        assert_eq!(expand_tilde("~").unwrap(), home);
        assert_eq!(
            expand_tilde("/abs/path").unwrap(),
            PathBuf::from("/abs/path")
        );
    }

    #[test]
    fn testResolveStaticAndEnvRooted() {
        let s = Discovery::Static {
            path: "/tmp/x.json".to_string(),
        };
        assert_eq!(
            resolve_config_path(&s, None).unwrap(),
            PathBuf::from("/tmp/x.json")
        );

        // env resolution is tested via the pure helper (env mutation is unsafe
        // and forbidden crate-wide): unset → fallback, set → rooted at env.
        assert_eq!(
            env_rooted_path(None, "config.toml", "/tmp/fallback/config.toml").unwrap(),
            PathBuf::from("/tmp/fallback/config.toml")
        );
        assert_eq!(
            env_rooted_path(Some(""), "config.toml", "/tmp/fallback/config.toml").unwrap(),
            PathBuf::from("/tmp/fallback/config.toml")
        );
        assert_eq!(
            env_rooted_path(Some("/custom/codex"), "config.toml", "/fb").unwrap(),
            PathBuf::from("/custom/codex/config.toml")
        );
    }

    #[test]
    fn testStripKyrisApikeyHandlesRotatedStaleKey() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("opencode.json");
        // The config holds a STALE inbound key (from a prior enrollment) while
        // the CURRENT inbound key has since rotated to a different value — the
        // exact shape that left opencode forwarding `sk-kyris-…` upstream.
        std::fs::write(
            &cfg,
            r#"{"provider":{"anthropic":{"options":{"apiKey":"sk-kyris-STALE-OLD","baseURL":"x"}}}}"#,
        )
        .unwrap();
        let path = vec![
            "provider".to_string(),
            "anthropic".to_string(),
            "options".to_string(),
            "apiKey".to_string(),
        ];
        let changes = strip_kyris_apikey(
            &cfg,
            FileFormat::Json,
            &path,
            "sk-kyris-CURRENT-NEW", // current inbound ≠ the stale value
            "test",
        )
        .unwrap();
        assert_eq!(changes.len(), 1, "stale kyris key should be stripped");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
        let opts = &v["provider"]["anthropic"]["options"];
        assert!(opts.get("apiKey").is_none(), "apiKey must be removed");
        assert_eq!(opts["baseURL"], "x", "siblings untouched");
    }

    #[test]
    fn testStripKyrisApikeyLeavesRealProviderKey() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("opencode.json");
        // A genuine upstream key must NOT be stripped.
        std::fs::write(
            &cfg,
            r#"{"provider":{"anthropic":{"options":{"apiKey":"sk-ant-REAL"}}}}"#,
        )
        .unwrap();
        let path = vec![
            "provider".to_string(),
            "anthropic".to_string(),
            "options".to_string(),
            "apiKey".to_string(),
        ];
        let changes =
            strip_kyris_apikey(&cfg, FileFormat::Json, &path, "sk-kyris-CURRENT", "test").unwrap();
        assert!(changes.is_empty(), "real provider key must be preserved");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
        assert_eq!(
            v["provider"]["anthropic"]["options"]["apiKey"],
            "sk-ant-REAL"
        );
    }

    #[test]
    fn testResolveWalkUpFindsNearestThenFallback() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let marker = tmp.path().join("a/opencode.json");
        std::fs::write(&marker, "{}").unwrap();
        let wu = Discovery::WalkUp {
            filenames: vec!["opencode.jsonc".to_string(), "opencode.json".to_string()],
            global_dir: "/tmp/global".to_string(),
        };
        // walking up from a/b/c finds a/opencode.json
        assert_eq!(resolve_config_path(&wu, Some(&nested)).unwrap(), marker);
        // nothing up an unrelated tree → global fallback
        let other = tmp.path().join("z");
        std::fs::create_dir_all(&other).unwrap();
        assert_eq!(
            resolve_config_path(&wu, Some(&other)).unwrap(),
            PathBuf::from("/tmp/global/opencode.json")
        );
    }

    #[test]
    fn testSubstituteValue() {
        let ctx = SubstCtx {
            base_url: "http://127.0.0.1:4710",
            inbound_key: "sk-kyris",
            agent_id: "cline/cline",
        };
        assert_eq!(
            substitute_value(&serde_json::json!("{base_url_v1}"), &ctx),
            serde_json::json!("http://127.0.0.1:4710/v1")
        );
        assert_eq!(
            substitute_value(&serde_json::json!("{agent_id}"), &ctx),
            serde_json::json!("cline/cline")
        );
        // non-strings pass through
        assert_eq!(
            substitute_value(&serde_json::json!(1), &ctx),
            serde_json::json!(1)
        );
    }

    #[test]
    fn testStripJsoncComments() {
        let src = r#"{
  // line comment
  "a": 1, /* block */ "b": "http://x//y", /* keep // inside string */
  "c": "/* not a comment */"
}"#;
        let v: Value = serde_json::from_str(&strip_jsonc_comments(src)).expect("valid JSON");
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], "http://x//y", "slashes inside strings preserved");
        assert_eq!(v["c"], "/* not a comment */");
    }

    #[test]
    fn testStripJsoncPreservesNonAscii() {
        let src = r#"{"name": "café", "emoji": "🚀", "path": "/tmp/naïve"}"#;
        let v: Value = serde_json::from_str(&strip_jsonc_comments(src)).unwrap();
        assert_eq!(v["name"], "café");
        assert_eq!(v["emoji"], "🚀");
        assert_eq!(v["path"], "/tmp/naïve");
    }

    #[test]
    fn testStripTrailingCommas() {
        let src = r#"{ "a": [1, 2, 3,], "b": { "x": 1, }, "c": "1,]", }"#;
        let v: Value = serde_json::from_str(&strip_trailing_commas(src)).unwrap();
        assert_eq!(v["a"], serde_json::json!([1, 2, 3]));
        assert_eq!(v["b"]["x"], 1);
        assert_eq!(v["c"], "1,]", "comma+bracket inside a string is untouched");
    }

    #[test]
    fn testApplyGovernedPermissionsScopedNotBlanket() {
        let mut config = serde_json::json!({});
        assert!(apply_governed_permissions(&mut config));
        let perm = config["permission"].as_object().expect("permission object");
        assert_eq!(perm["bash"], "allow");
        assert_eq!(perm["edit"], "allow");
        assert_eq!(perm["write"], "allow");
        assert!(!perm.contains_key("*"), "no blanket allow-all");
        assert!(!apply_governed_permissions(&mut config), "idempotent");
    }

    #[test]
    fn testApplyGovernedPermissionsMigratesBlanketAndPreservesRules() {
        // Old `{"*":"allow"}` is dropped; a user's bare default + explicit rules survive.
        let mut blanket = serde_json::json!({ "permission": {"*": "allow"} });
        apply_governed_permissions(&mut blanket);
        assert!(!blanket["permission"].as_object().unwrap().contains_key("*"));

        let mut user = serde_json::json!({ "permission": {"*": "ask", "webfetch": "deny"} });
        apply_governed_permissions(&mut user);
        let perm = user["permission"].as_object().unwrap();
        assert_eq!(perm["*"], "ask", "user default preserved");
        assert_eq!(perm["webfetch"], "deny", "user rule preserved");
        assert_eq!(perm["edit"], "allow");
    }

    #[test]
    fn testParseMode() {
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("0o755").unwrap(), 0o755);
        assert_eq!(parse_mode("755").unwrap(), 0o755);
        assert!(parse_mode("nope").is_err());
    }

    #[test]
    fn testIsDetectedByConfigFile() {
        let tmp = tempfile::tempdir().unwrap();
        let present = tmp.path().join("providers.json");
        std::fs::write(&present, "{}").unwrap();
        let doc = format!(
            r#"{{"apiVersion":"agentpact/v1","kind":"AgentCapabilities","agent":"x/y","native":{{}},
                "adaptation":{{
                  "detect":{{"binaries":["definitely-not-a-real-binary-xyz"],"config_paths":["providers"]}},
                  "config_files":{{"providers":{{"discovery":{{"static":{{"path":"{}"}}}},"format":"json"}}}}
                }}}}"#,
            present.display()
        );
        let m = super::super::manifest::parse_and_validate(&doc, "x/y").unwrap();
        let ad = m.adaptation.unwrap();
        assert!(is_detected(&ad), "config file present → detected");

        // remove the file → not detected (binary is bogus)
        std::fs::remove_file(&present).unwrap();
        assert!(!is_detected(&ad), "no binary, no config → not detected");
    }
}
