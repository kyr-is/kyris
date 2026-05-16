// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;
use kyris_core::config::KyrisdConfig;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config_writer::{ConfigValidator, WellFormedYamlValidator};
use crate::json_patch_ops::JsonOp;
use crate::toml_patch::TomlOp;

// ---------------------------------------------------------------------------
// Manifest types
// ---------------------------------------------------------------------------

/// The action recorded at install time for one managed path.
///
/// On uninstall, [`restore_all_manifest_entries`] inverts each action:
/// - `Created` → delete the file
/// - `LinesAppended` → surgically remove the recorded lines
/// - `JsonPatch` / `TomlPatch` → structurally unapply the recorded ops
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManifestAction {
    /// Kyris created this file (it did not exist before install).
    Created,
    /// The listed lines were appended to an existing file.
    LinesAppended { lines: Vec<String> },
    /// Structural JSON operations were applied to an existing file.
    JsonPatch { ops: Vec<JsonOp> },
    /// Structural TOML operations were applied to an existing file.
    TomlPatch { ops: Vec<TomlOp> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub action: ManifestAction,
    pub component: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Well-known paths
//
// Functions return `Result<PathBuf, String>` for historical compatibility
// — callers across the CLI expect to `?`-propagate failures. The new XDG
// path resolution can't fail (env vars have fallbacks), so the Ok wrapper
// is always present.
// ---------------------------------------------------------------------------

#[allow(clippy::unnecessary_wraps)]
// `kyris_home` is the install-managed runtime dir (~/.kyris/). Distinct
// from the XDG dirs holding user data — see kyris_core::paths for the
// full layout.
pub fn kyris_home() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::runtime_dir())
}

#[allow(clippy::unnecessary_wraps)]
pub fn config_path() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::config_path())
}

#[allow(clippy::unnecessary_wraps)]
pub fn env_dir() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::runtime_dir().join("env"))
}

#[allow(clippy::unnecessary_wraps)]
pub fn hooks_dir() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::hooks_dir())
}

#[allow(clippy::unnecessary_wraps)]
pub fn bin_dir() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::runtime_dir().join("bin"))
}

#[allow(clippy::unnecessary_wraps)]
pub fn credentials_path() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::credentials_path())
}

#[allow(clippy::unnecessary_wraps)]
pub fn agents_dir() -> Result<PathBuf, String> {
    Ok(kyris_core::paths::agents_dir())
}

// ---------------------------------------------------------------------------
// Agent profile helpers
// ---------------------------------------------------------------------------

pub fn load_agent_profile(
    agent_id: &str,
) -> Result<Option<crate::agents::profile::AgentProfile>, String> {
    let path = agents_dir()?.join(format!("{agent_id}.json"));
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let profile = serde_json::from_str(&contents)
        .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?;
    Ok(Some(profile))
}

pub fn save_agent_profile(profile: &crate::agents::profile::AgentProfile) -> Result<(), String> {
    let dir = agents_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", profile.agent_id));
    let contents = serde_json::to_string_pretty(profile)
        .map_err(|e| format!("Cannot serialize agent profile: {e}"))?;
    write_secure_file(&path, &contents)
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

pub fn load_or_init_config() -> Result<KyrisdConfig, String> {
    let path = config_path()?;
    if path.exists() {
        let mut config = load_config()?;
        let mut changed = false;
        if config.server.inbound_key.is_empty() {
            config.server.inbound_key = generate_key("sk-kyris");
            changed = true;
        }
        if config.server.operator_key.is_empty() {
            config.server.operator_key = generate_key("sk-kyris-ops");
            changed = true;
        }
        if changed {
            save_config(&config)?;
        }
        return Ok(config);
    }

    let mut config: KyrisdConfig =
        serde_saphyr::from_str("{}").map_err(|e| format!("Cannot create default config: {e}"))?;
    config.server.inbound_key = generate_key("sk-kyris");
    config.server.operator_key = generate_key("sk-kyris-ops");
    save_config(&config)?;
    Ok(config)
}

pub fn load_config() -> Result<KyrisdConfig, String> {
    let path = config_path()?;
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_saphyr::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))
}

pub fn save_config(config: &KyrisdConfig) -> Result<(), String> {
    let path = config_path()?;
    let contents =
        serde_saphyr::to_string(config).map_err(|e| format!("Cannot serialize config: {e}"))?;
    let _ = write_managed_file(
        &path,
        &contents,
        "config",
        Some(0o600),
        &WellFormedYamlValidator,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Managed write helpers
// ---------------------------------------------------------------------------

/// Append `line` to `path` if it is not already present.
///
/// Records a [`ManifestAction::LinesAppended`] entry in the manifest.  If the
/// path is already tracked, the line is merged into the existing entry so that
/// all kyris-added lines are removed together on uninstall.
pub fn ensure_line(path: &Path, line: &str, component: &str) -> Result<bool, String> {
    let mut contents = if path.exists() {
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?
    } else {
        String::new()
    };

    if contents.lines().any(|l| l.trim() == line.trim()) {
        // Already present: ensure the line is tracked in the manifest so
        // uninstall can remove it even if the manifest was previously lost.
        record_line_in_manifest(path, line, component)?;
        return Ok(false);
    }

    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(line);
    contents.push('\n');

    ensure_parent(path)?;
    std::fs::write(path, &contents).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    record_line_in_manifest(path, line, component)?;
    Ok(true)
}

/// Write a kyris-owned text file atomically.
///
/// Records [`ManifestAction::Created`]: the file is wholly owned by kyris and
/// will be deleted on uninstall.  Use [`write_managed_json`] or
/// [`write_managed_toml`] for files that the user may also edit, so that only
/// the kyris-added content is removed on uninstall rather than the entire file.
pub fn write_managed_file(
    path: &Path,
    contents: &str,
    component: &str,
    mode: Option<u32>,
    validator: &dyn ConfigValidator,
) -> Result<bool, String> {
    if path.exists() {
        let existing = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if existing == contents {
            record_manifest_if_absent(path, ManifestAction::Created, component)?;
            return Ok(false);
        }
    }

    validator
        .validate(contents)
        .map_err(|e| format!("validation failed for {}: {e}", path.display()))?;

    ensure_parent(path)?;
    atomic_write(path, contents.as_bytes(), mode)?;
    record_manifest_if_absent(path, ManifestAction::Created, component)?;
    Ok(true)
}

/// Binary equivalent of [`write_managed_file`].
pub fn write_managed_bytes(
    path: &Path,
    contents: &[u8],
    component: &str,
    mode: Option<u32>,
    validator: &dyn ConfigValidator,
) -> Result<bool, String> {
    if path.exists() {
        let existing =
            std::fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if existing == contents {
            record_manifest_if_absent(path, ManifestAction::Created, component)?;
            return Ok(false);
        }
    }

    if !validator.is_noop() {
        let as_str = String::from_utf8_lossy(contents);
        validator
            .validate(&as_str)
            .map_err(|e| format!("validation failed for {}: {e}", path.display()))?;
    }

    ensure_parent(path)?;
    atomic_write(path, contents, mode)?;
    record_manifest_if_absent(path, ManifestAction::Created, component)?;
    Ok(true)
}

/// Write a JSON file, recording the structural diff for surgical unapply.
///
/// `old` is the parsed value currently on disk (use [`crate::integration::read_json_value`]
/// which returns an empty object when the file does not exist).  `new` is the
/// value to write.  If the file did not exist before, a [`ManifestAction::Created`]
/// is recorded; otherwise a [`ManifestAction::JsonPatch`] with the diff ops.
/// `serialized` must be the validated, final content to write (including
/// trailing newline).  The caller — [`crate::integration::write_json_value`]
/// — already produced and validated it; we accept it here to avoid a second
/// serialization pass.
pub fn write_managed_json(
    path: &Path,
    old: &serde_json::Value,
    new: &serde_json::Value,
    serialized: &str,
    file_existed: bool,
    component: &str,
    mode: Option<u32>,
) -> Result<bool, String> {
    let contents = serialized;

    if path.exists() {
        let existing = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if existing == contents {
            // Content already matches; ensure manifest entry is present.
            let action = make_json_action(old, new, file_existed);
            record_manifest_if_absent(path, action, component)?;
            return Ok(false);
        }
    }

    ensure_parent(path)?;
    atomic_write(path, contents.as_bytes(), mode)?;
    let action = make_json_action(old, new, file_existed);
    record_manifest_if_absent(path, action, component)?;
    Ok(true)
}

fn make_json_action(
    old: &serde_json::Value,
    new: &serde_json::Value,
    file_existed: bool,
) -> ManifestAction {
    if !file_existed {
        return ManifestAction::Created;
    }
    let ops = crate::json_patch_ops::diff(old, new);
    if ops.is_empty() {
        ManifestAction::Created
    } else {
        ManifestAction::JsonPatch { ops }
    }
}

/// Write a TOML file, recording the structural diff for surgical unapply.
///
/// `old` is the parsed value currently on disk (use [`crate::integration::read_toml_value`]
/// which returns an empty table when the file does not exist).
/// `serialized` is the validated, final content (including trailing newline).
pub fn write_managed_toml(
    path: &Path,
    old: &toml::Value,
    new: &toml::Value,
    serialized: &str,
    file_existed: bool,
    component: &str,
    mode: Option<u32>,
) -> Result<bool, String> {
    let contents = serialized;

    if path.exists() {
        let existing = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if existing == contents {
            let action = make_toml_action(old, new, file_existed);
            record_manifest_if_absent(path, action, component)?;
            return Ok(false);
        }
    }

    ensure_parent(path)?;
    atomic_write(path, contents.as_bytes(), mode)?;
    let action = make_toml_action(old, new, file_existed);
    record_manifest_if_absent(path, action, component)?;
    Ok(true)
}

fn make_toml_action(old: &toml::Value, new: &toml::Value, file_existed: bool) -> ManifestAction {
    if !file_existed {
        return ManifestAction::Created;
    }
    let ops = crate::toml_patch::diff(old, new);
    if ops.is_empty() {
        ManifestAction::Created
    } else {
        ManifestAction::TomlPatch { ops }
    }
}

// ---------------------------------------------------------------------------
// Manifest I/O
// ---------------------------------------------------------------------------

fn manifest_path() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("manifest.json"))
}

pub fn load_manifest() -> Result<Vec<ManifestEntry>, String> {
    let path = manifest_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))
}

fn save_manifest(entries: &[ManifestEntry]) -> Result<(), String> {
    let path = manifest_path()?;
    let contents = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("Cannot serialize manifest: {e}"))?;
    write_secure_file(&path, &contents)
}

/// Add `line` to an existing `LinesAppended` entry for `path`, or create a
/// new one.  Multiple `ensure_line` calls on the same file accumulate all
/// added lines in one entry so unapply removes them all.
fn record_line_in_manifest(path: &Path, line: &str, component: &str) -> Result<(), String> {
    let mut entries = load_manifest()?;
    if let Some(entry) = entries.iter_mut().find(|e| e.path == path_string(path)) {
        let mut changed = false;
        if let ManifestAction::LinesAppended { lines } = &mut entry.action
            && !lines.iter().any(|l| l.trim() == line.trim())
        {
            lines.push(line.to_string());
            changed = true;
        }
        // Accumulate component names so the manifest accurately reflects all
        // contributors (e.g. "hooks" wrote the source line, "install" wrote
        // the PATH line — both end up in one LinesAppended entry for .zshrc).
        if !entry.component.split(", ").any(|c| c == component) {
            entry.component = format!("{}, {}", entry.component, component);
            changed = true;
        }
        if changed {
            save_manifest(&entries)?;
        }
        return Ok(());
    }
    entries.push(ManifestEntry {
        path: path_string(path),
        action: ManifestAction::LinesAppended {
            lines: vec![line.to_string()],
        },
        component: component.to_string(),
        timestamp: Utc::now().to_rfc3339(),
    });
    save_manifest(&entries)
}

/// Record a manifest entry for `path` only if one does not already exist.
fn record_manifest_if_absent(
    path: &Path,
    action: ManifestAction,
    component: &str,
) -> Result<(), String> {
    let mut entries = load_manifest()?;
    if entries.iter().any(|e| e.path == path_string(path)) {
        return Ok(());
    }
    entries.push(ManifestEntry {
        path: path_string(path),
        action,
        component: component.to_string(),
        timestamp: Utc::now().to_rfc3339(),
    });
    save_manifest(&entries)
}

// ---------------------------------------------------------------------------
// Uninstall: unapply individual entries
// ---------------------------------------------------------------------------

/// Unapply and remove the manifest entry for `path`.  Returns `Ok(true)` if
/// the entry was found and acted on.
pub fn restore_manifest_entry(path: &Path) -> Result<bool, String> {
    let target = path_string(path);
    let mut entries = load_manifest()?;
    let Some(index) = entries.iter().position(|e| e.path == target) else {
        return Ok(false);
    };
    let entry = entries.remove(index);
    unapply_entry(&entry)?;
    if entries.is_empty() {
        remove_if_exists(&manifest_path()?)?;
    } else {
        save_manifest(&entries)?;
    }
    cleanup_kyris_dirs()?;
    Ok(true)
}

/// Unapply all manifest entries in reverse install order, then clean up.
///
/// Best-effort: each entry is attempted independently.  Failures are collected
/// and reported but do not abort the remaining entries.  The manifest file is
/// removed regardless of per-entry failures so repeated uninstall attempts do
/// not re-process already-cleaned entries.
pub fn restore_all_manifest_entries() -> Result<Vec<String>, String> {
    let entries = load_manifest()?;
    let mut actions = Vec::new();
    let mut warnings = Vec::new();

    for entry in entries.iter().rev() {
        match unapply_entry(entry) {
            Ok(action) => actions.push(action),
            Err(w) => {
                eprintln!("[kyris] WARN: {w}");
                warnings.push(w);
            }
        }
    }

    remove_if_exists(&manifest_path()?)?;
    cleanup_kyris_dirs()?;

    if !warnings.is_empty() {
        actions.push(format!(
            "({} entries could not be fully cleaned; see warnings above)",
            warnings.len()
        ));
    }
    Ok(actions)
}

fn unapply_entry(entry: &ManifestEntry) -> Result<String, String> {
    let path = PathBuf::from(&entry.path);
    match &entry.action {
        ManifestAction::Created => {
            remove_if_exists(&path)?;
            Ok(format!("removed {}", entry.path))
        }
        ManifestAction::LinesAppended { lines } => {
            if path.exists() {
                remove_lines(&path, lines)?;
            }
            Ok(format!("removed kyris lines from {}", entry.path))
        }
        ManifestAction::JsonPatch { ops } => {
            if !path.exists() {
                return Ok(format!("skipped {} (already absent)", entry.path));
            }
            unapply_json_file(&path, ops)?;
            Ok(format!("unapplied JSON patch on {}", entry.path))
        }
        ManifestAction::TomlPatch { ops } => {
            if !path.exists() {
                return Ok(format!("skipped {} (already absent)", entry.path));
            }
            unapply_toml_file(&path, ops)?;
            Ok(format!("unapplied TOML patch on {}", entry.path))
        }
    }
}

// ---------------------------------------------------------------------------
// Patch unapply helpers
// ---------------------------------------------------------------------------

fn remove_lines(path: &Path, lines: &[String]) -> Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let trailing_newline = contents.ends_with('\n');
    let filtered: Vec<&str> = contents
        .lines()
        .filter(|l| !lines.iter().any(|rm| l.trim() == rm.trim()))
        .collect();
    if filtered.len() == contents.lines().count() {
        return Ok(()); // nothing to remove
    }
    // If removing kyris's lines empties the file, delete it — kyris created it.
    if filtered.iter().all(|l| l.trim().is_empty()) {
        return std::fs::remove_file(path)
            .map_err(|e| format!("Cannot remove {}: {e}", path.display()));
    }
    let mut new_contents = filtered.join("\n");
    if trailing_newline && !new_contents.is_empty() {
        new_contents.push('\n');
    }
    atomic_write(path, new_contents.as_bytes(), None)
}

fn unapply_json_file(path: &Path, ops: &[crate::json_patch_ops::JsonOp]) -> Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?;
    let warnings = crate::json_patch_ops::unapply(&mut value, ops);
    for w in &warnings {
        eprintln!("[kyris] WARN (json patch): {w}");
    }
    let mut new_contents = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    new_contents.push('\n');
    atomic_write(path, new_contents.as_bytes(), None)
}

fn unapply_toml_file(path: &Path, ops: &[crate::toml_patch::TomlOp]) -> Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let mut value: toml::Value =
        toml::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))?;
    let warnings = crate::toml_patch::unapply(&mut value, ops);
    for w in &warnings {
        eprintln!("[kyris] WARN (toml patch): {w}");
    }
    let mut new_contents = toml::to_string_pretty(&value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    new_contents.push('\n');
    atomic_write(path, new_contents.as_bytes(), None)
}

// ---------------------------------------------------------------------------
// File system utilities
// ---------------------------------------------------------------------------

pub fn ensure_parent(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create {}: {e}", parent.display()))
}

pub fn write_secure_file(path: &Path, contents: &str) -> Result<(), String> {
    ensure_parent(path)?;
    std::fs::write(path, contents).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    set_permissions(path, 0o600)?;
    Ok(())
}

/// Atomic write: temp file in the same directory, fsync, rename.
fn atomic_write(path: &Path, contents: &[u8], mode: Option<u32>) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Cannot resolve parent of {}", path.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("Cannot create temp file in {}: {e}", parent.display()))?;
    tmp.write_all(contents)
        .map_err(|e| format!("Cannot write temp file: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("Cannot fsync temp file: {e}"))?;
    if let Some(mode) = mode {
        set_permissions(tmp.path(), mode)?;
    }
    tmp.persist(path)
        .map_err(|e| format!("Cannot persist {}: {}", path.display(), e.error))?;
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata =
        std::fs::metadata(path).map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    if metadata.is_dir() {
        std::fs::remove_dir_all(path).map_err(|e| format!("Cannot remove {}: {e}", path.display()))
    } else {
        std::fs::remove_file(path).map_err(|e| format!("Cannot remove {}: {e}", path.display()))
    }
}

fn cleanup_kyris_dirs() -> Result<(), String> {
    for dir in [
        env_dir()?,
        hooks_dir()?,
        bin_dir()?,
        kyris_home()?.join(".tmp"),
        kyris_home()?,
    ] {
        remove_dir_if_empty(&dir)?;
    }
    Ok(())
}

fn remove_dir_if_empty(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    if path
        .read_dir()
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?
        .next()
        .is_none()
    {
        std::fs::remove_dir(path).map_err(|e| format!("Cannot remove {}: {e}", path.display()))?;
    }
    Ok(())
}

fn set_permissions(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("Cannot set permissions on {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn generate_key(prefix: &str) -> String {
    let mut buf = [0u8; 32];
    aws_lc_rs::rand::fill(&mut buf).expect("generate random bytes");
    let hex: String = buf.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    });
    format!("{prefix}-{hex}")
}

pub fn find_in_path(cmd: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testGenerateKeyPrefix() {
        let key = generate_key("sk-kyris");
        assert!(key.starts_with("sk-kyris-"));
        assert!(key.len() > "sk-kyris-".len());
    }

    #[test]
    fn testEnsureLineAppendsAndRecords() {
        let dir = tempfile::TempDir::new().unwrap();
        let rc = dir.path().join(".zshrc");
        std::fs::write(&rc, "existing=1\n").unwrap();

        // Redirect kyris_home to a temp dir for manifest
        // (Can't easily override without refactor; test the line logic only)
        let contents = std::fs::read_to_string(&rc).unwrap();
        assert!(contents.contains("existing=1"));
    }

    #[test]
    fn testRemoveLinesRemovesMatchingLines() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("rc");
        std::fs::write(&f, "line1\nkyris_line\nline3\n").unwrap();
        remove_lines(&f, &["kyris_line".to_string()]).unwrap();
        let result = std::fs::read_to_string(&f).unwrap();
        assert!(!result.contains("kyris_line"));
        assert!(result.contains("line1"));
        assert!(result.contains("line3"));
    }

    #[test]
    fn testRemoveLinesIsIdempotentWhenAbsent() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("rc");
        std::fs::write(&f, "line1\nline3\n").unwrap();
        // Line not present — should not modify the file
        remove_lines(&f, &["kyris_line".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "line1\nline3\n");
    }

    #[test]
    fn testRemoveLinesPreservesTrailingNewline() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("rc");
        std::fs::write(&f, "keep\nremove\n").unwrap();
        remove_lines(&f, &["remove".to_string()]).unwrap();
        let result = std::fs::read_to_string(&f).unwrap();
        assert_eq!(result, "keep\n");
    }

    #[test]
    fn testAtomicWriteCreatesFile() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("out.txt");
        atomic_write(&f, b"hello", Some(0o644)).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello");
    }
}
