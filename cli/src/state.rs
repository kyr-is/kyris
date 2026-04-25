// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;
use kyris_core::config::KyrisdConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub backup_path: Option<String>,
    pub component: String,
    pub timestamp: String,
}

pub fn kyris_home() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".kyris"))
}

pub fn config_path() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("kyrisd.yaml"))
}

pub fn env_dir() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("env"))
}

pub fn hooks_dir() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("hooks"))
}

pub fn bin_dir() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("bin"))
}

pub fn credentials_path() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("credentials.json"))
}

fn backups_dir() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("backups"))
}

fn manifest_path() -> Result<PathBuf, String> {
    Ok(kyris_home()?.join("manifest.json"))
}

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
    let _ = write_managed_file(&path, &contents, "config", Some(0o600))?;
    Ok(())
}

pub fn ensure_line(path: &Path, line: &str, component: &str) -> Result<bool, String> {
    let mut contents = if path.exists() {
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?
    } else {
        String::new()
    };

    if contents
        .lines()
        .any(|existing| existing.trim() == line.trim())
    {
        return Ok(false);
    }

    backup_existing(path, component)?;

    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(line);
    contents.push('\n');

    ensure_parent(path)?;
    std::fs::write(path, contents).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    record_manifest(path, None, component)?;
    Ok(true)
}

pub fn write_managed_file(
    path: &Path,
    contents: &str,
    component: &str,
    mode: Option<u32>,
) -> Result<bool, String> {
    if path.exists() {
        let existing = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if existing == contents {
            return Ok(false);
        }
    }

    backup_existing(path, component)?;
    ensure_parent(path)?;
    std::fs::write(path, contents).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    if let Some(mode) = mode {
        set_permissions(path, mode)?;
    }
    record_manifest(path, None, component)?;
    Ok(true)
}

pub fn write_managed_bytes(
    path: &Path,
    contents: &[u8],
    component: &str,
    mode: Option<u32>,
) -> Result<bool, String> {
    if path.exists() {
        let existing =
            std::fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if existing == contents {
            return Ok(false);
        }
    }

    backup_existing(path, component)?;
    ensure_parent(path)?;
    std::fs::write(path, contents).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    if let Some(mode) = mode {
        set_permissions(path, mode)?;
    }
    record_manifest(path, None, component)?;
    Ok(true)
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

pub fn restore_manifest_entry(path: &Path) -> Result<bool, String> {
    let target = path_string(path);
    let mut entries = load_manifest()?;
    let Some(index) = entries.iter().position(|entry| entry.path == target) else {
        return Ok(false);
    };

    let entry = entries.remove(index);
    restore_entry(&entry)?;

    if entries.is_empty() {
        remove_if_exists(&manifest_path()?)?;
    } else {
        save_manifest(&entries)?;
    }
    cleanup_backup(&entry)?;
    cleanup_kyris_dirs()?;
    Ok(true)
}

pub fn discard_manifest_entry(path: &Path) -> Result<bool, String> {
    let target = path_string(path);
    let mut entries = load_manifest()?;
    let Some(index) = entries.iter().position(|entry| entry.path == target) else {
        return Ok(false);
    };

    let entry = entries.remove(index);
    if entries.is_empty() {
        remove_if_exists(&manifest_path()?)?;
    } else {
        save_manifest(&entries)?;
    }
    cleanup_backup(&entry)?;
    cleanup_kyris_dirs()?;
    Ok(true)
}

pub fn restore_all_manifest_entries() -> Result<Vec<String>, String> {
    let entries = load_manifest()?;
    let mut actions = Vec::new();

    for entry in entries.iter().rev() {
        restore_entry(entry)?;
        actions.push(format!("restored {}", entry.path));
        cleanup_backup(entry)?;
    }

    remove_if_exists(&manifest_path()?)?;
    remove_if_exists(&backups_dir()?)?;
    cleanup_kyris_dirs()?;
    Ok(actions)
}

fn backup_existing(path: &Path, component: &str) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let mut entries = load_manifest()?;
    if let Some(existing) = entries.iter().find(|entry| entry.path == path_string(path)) {
        return Ok(existing.backup_path.clone().map(PathBuf::from));
    }

    let backup_dir = backups_dir()?;
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| format!("Cannot create {}: {e}", backup_dir.display()))?;

    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup_name = format!(
        "{timestamp}-{}-{}",
        sanitize_component(component),
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("backup")
    );
    let backup_path = backup_dir.join(backup_name);
    std::fs::copy(path, &backup_path).map_err(|e| {
        format!(
            "Cannot back up {} to {}: {e}",
            path.display(),
            backup_path.display()
        )
    })?;

    entries.push(ManifestEntry {
        path: path_string(path),
        backup_path: Some(path_string(&backup_path)),
        component: component.to_string(),
        timestamp: Utc::now().to_rfc3339(),
    });
    save_manifest(&entries)?;
    Ok(Some(backup_path))
}

fn record_manifest(path: &Path, backup_path: Option<&Path>, component: &str) -> Result<(), String> {
    let mut entries = load_manifest()?;
    if entries.iter().any(|entry| entry.path == path_string(path)) {
        return Ok(());
    }

    entries.push(ManifestEntry {
        path: path_string(path),
        backup_path: backup_path.map(path_string),
        component: component.to_string(),
        timestamp: Utc::now().to_rfc3339(),
    });
    save_manifest(&entries)
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

fn sanitize_component(component: &str) -> String {
    component
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn set_permissions(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, permissions)
            .map_err(|e| format!("Cannot set permissions on {}: {e}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }

    Ok(())
}

fn restore_entry(entry: &ManifestEntry) -> Result<(), String> {
    let path = PathBuf::from(&entry.path);
    if let Some(backup_path) = &entry.backup_path {
        let backup = PathBuf::from(backup_path);
        ensure_parent(&path)?;
        std::fs::copy(&backup, &path).map_err(|e| {
            format!(
                "Cannot restore {} from {}: {e}",
                path.display(),
                backup.display()
            )
        })?;
    } else {
        remove_if_exists(&path)?;
    }
    Ok(())
}

fn cleanup_backup(entry: &ManifestEntry) -> Result<(), String> {
    if let Some(backup_path) = &entry.backup_path {
        remove_if_exists(&PathBuf::from(backup_path))?;
    }
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
        backups_dir()?,
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
    fn testSanitizeComponent() {
        assert_eq!(sanitize_component("setup/hooks"), "setup-hooks");
    }
}
