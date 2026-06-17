// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Codex config/dir path resolution and the low-level config-file IO helpers
//! (managed + unmanaged TOML/JSON writes, the schema validator) shared by the
//! `CodexCli` surface methods and the hook/scrub machinery.
use std::path::{Path, PathBuf};

use crate::config_writer::{ConfigValidator, TomlShapeValidator, WellFormedJsonValidator};
use crate::integration::{read_toml_value, write_toml_value};

use super::CodexConfigShape;

pub(super) fn codex_config_validator() -> TomlShapeValidator<CodexConfigShape> {
    TomlShapeValidator::new()
}

pub fn codex_config_path() -> Result<PathBuf, String> {
    Ok(codex_config_path_from(
        std::env::var_os("CODEX_HOME").map(PathBuf::from),
        crate::integration::home_dir()?,
    ))
}

pub(super) fn codex_config_path_from(codex_home: Option<PathBuf>, home: PathBuf) -> PathBuf {
    codex_home
        .unwrap_or_else(|| home.join(".codex"))
        .join("config.toml")
}

pub(super) fn codex_config_candidate_paths() -> Vec<PathBuf> {
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
    crate::agents::registry::which_exists("codex")
}

/// Creates the `.codex` directory (and any parents) if it does not yet exist.
/// Called at the start of configure methods so they work even when the user
/// has just installed the binary but has never run it (no config file yet).
pub(super) fn ensure_codex_dir() -> Result<PathBuf, String> {
    let dir = codex_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Returns the current config as a TOML value, or an empty table if the file
/// does not yet exist. Used to bootstrap first-time setup.
pub(super) fn read_or_empty_codex_config(config_path: &Path) -> Result<toml::Value, String> {
    if config_path.exists() {
        read_toml_value(config_path)
    } else {
        Ok(toml::Value::Table(toml::map::Map::default()))
    }
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
/// every agent — so `kyris agent disconnect` reverses every edit, including across
/// the several writes setup performs, with no per-agent recording code.
pub(super) fn write_codex_config(
    config_path: &Path,
    new: &toml::Value,
    component: &str,
) -> Result<(), String> {
    write_toml_value(config_path, new, component, &codex_config_validator())?;
    Ok(())
}

pub(super) fn write_codex_config_unmanaged(
    config_path: &Path,
    new: &toml::Value,
) -> Result<(), String> {
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

pub(super) fn write_json_unmanaged(path: &Path, value: &serde_json::Value) -> Result<(), String> {
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
