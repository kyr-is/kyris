// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use kyris_core::config::KyrisdConfig;

pub fn try_load_config() -> Result<KyrisdConfig, String> {
    let config_path = config_path();

    if !config_path.exists() {
        return Err(format!("config not found: {}", config_path.display()));
    }

    let contents =
        std::fs::read_to_string(&config_path).map_err(|e| format!("failed to read config: {e}"))?;

    let mut config: KyrisdConfig =
        serde_saphyr::from_str(&contents).map_err(|e| format!("failed to parse config: {e}"))?;

    validate_permissions(&config_path)?;

    if config.providers.is_empty() {
        tracing::warn!("config has no providers configured");
    }

    kyris_core::config::apply_env_overrides(&mut config);
    Ok(config)
}

pub fn load_config() -> KyrisdConfig {
    load_config_from(&config_path())
}

pub fn load_config_from(config_path: &Path) -> KyrisdConfig {
    if !config_path.exists() {
        create_default_config(&config_path.to_path_buf());
    }

    if let Err(e) = validate_permissions(config_path) {
        tracing::error!(error = %e, "config permission check failed");
        std::process::exit(1);
    }

    let contents = std::fs::read_to_string(config_path).unwrap_or_else(|e| {
        tracing::error!(path = %config_path.display(), error = %e, "failed to read config");
        std::process::exit(1);
    });

    let mut config: KyrisdConfig = serde_saphyr::from_str(&contents).unwrap_or_else(|e| {
        tracing::error!(path = %config_path.display(), error = %e, "failed to parse config");
        std::process::exit(1);
    });

    let mut changed = false;
    if config.server.inbound_key.is_empty() {
        config.server.inbound_key = generate_inbound_key();
        changed = true;
    }
    if config.server.operator_key.is_empty() {
        config.server.operator_key = generate_operator_key();
        changed = true;
    }
    if changed {
        save_config(&config_path.to_path_buf(), &config);
    }

    kyris_core::config::apply_env_overrides(&mut config);
    config
}

fn config_path() -> PathBuf {
    kyris_core::paths::config_path()
}

fn create_default_config(path: &PathBuf) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to create config directory");
            std::process::exit(1);
        });
    }
    let default_content = include_str!("../../config/default.yaml");
    std::fs::write(path, default_content).unwrap_or_else(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to write default config");
        std::process::exit(1);
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

fn validate_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use nix::sys::stat::stat;

        let file_stat = stat(path)
            .map_err(|e| format!("failed to stat config file {}: {e}", path.display()))?;

        let mode = file_stat.st_mode & 0o777;
        let world_readable = mode & 0o004 != 0;

        if world_readable {
            return Err(format!(
                "kyrisd.yaml is world-readable (mode {mode:o}). \
                 Set permissions to 0600: chmod 600 {}",
                path.display(),
            ));
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

fn generate_inbound_key() -> String {
    let mut buf = [0u8; 32];
    aws_lc_rs::rand::fill(&mut buf).expect("generate random bytes");
    let hex: String = buf.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    format!("sk-kyris-{hex}")
}

fn generate_operator_key() -> String {
    let mut buf = [0u8; 32];
    aws_lc_rs::rand::fill(&mut buf).expect("generate random bytes");
    let hex: String = buf.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    format!("sk-kyris-ops-{hex}")
}

fn save_config(path: &PathBuf, config: &KyrisdConfig) {
    let contents = serde_saphyr::to_string(config).expect("serialize config");
    std::fs::write(path, contents).unwrap_or_else(|e| {
        tracing::error!(path = %path.display(), error = %e, "failed to save config");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn testValidatePermissionsAllowsOwnerOnly() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kyrisd.yaml");
        std::fs::write(&path, "# test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(validate_permissions(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn testValidatePermissionsAllowsGroupReadable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kyrisd.yaml");
        std::fs::write(&path, "# test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(validate_permissions(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn testValidatePermissionsRejectsWorldReadable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kyrisd.yaml");
        std::fs::write(&path, "# test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(validate_permissions(&path).is_err());
    }
}
