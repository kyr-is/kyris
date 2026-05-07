// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::integration::read_json_value;
use crate::state::env_dir;

use super::profile::{AdaptedMechanism, ManagedFileFingerprint, SurfaceState};

pub struct ProbeResult {
    pub detected: bool,
    pub execution: SurfaceState,
    pub tool: SurfaceState,
    pub burn_control: SurfaceState,
    pub managed_files: Vec<ManagedFileFingerprint>,
}

pub fn sha256_file(path: &std::path::Path) -> Option<String> {
    let contents = std::fs::read(path).ok()?;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &contents);
    Some(hex_encode(digest.as_ref()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub(super) fn fingerprint(path: &std::path::Path) -> Option<ManagedFileFingerprint> {
    sha256_file(path).map(|hash| ManagedFileFingerprint {
        path: path.to_string_lossy().to_string(),
        content_hash: hash,
    })
}

pub(super) fn not_detected() -> ProbeResult {
    ProbeResult {
        detected: false,
        execution: SurfaceState::none(),
        tool: SurfaceState::none(),
        burn_control: SurfaceState::none(),
        managed_files: Vec::new(),
    }
}

pub(super) fn probe_config_rewrite_burn_control(
    config_path: Option<&std::path::Path>,
    base_url_check: impl FnOnce(&serde_json::Value) -> bool,
    agent_id: &str,
    env_var: &str,
) -> SurfaceState {
    let has_base_url =
        config_path.is_some_and(|p| read_json_value(p).is_ok_and(|v| base_url_check(&v)));
    let has_env_proxy = env_file_has_var(agent_id, env_var) && env_loader_sourced();
    if has_base_url || has_env_proxy {
        SurfaceState::adapted(AdaptedMechanism::ConfigRewrite)
    } else {
        SurfaceState::none()
    }
}

pub(super) fn json_has_mcp_wrap(path: &std::path::Path, servers_key: &str) -> bool {
    let Ok(value) = read_json_value(path) else {
        return false;
    };
    value
        .get(servers_key)
        .and_then(|s| s.as_object())
        .is_some_and(|servers| {
            servers.values().any(|s| {
                let cmd = s.get("command");
                let str_match = cmd
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c == "kyris-mcp");
                let arr_match = cmd
                    .and_then(|c| c.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .is_some_and(|first| first == "kyris-mcp");
                str_match || arr_match
            })
        })
}

pub(super) fn env_file_has_var(agent_id: &str, var_name: &str) -> bool {
    let Ok(dir) = env_dir() else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    let primary = format!("{agent_id}.sh");
    let dash_prefix = format!("{agent_id}-");
    entries.filter_map(Result::ok).any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        name.ends_with(".sh")
            && (name.as_ref() == primary || name.starts_with(dash_prefix.as_str()))
            && std::fs::read_to_string(entry.path())
                .is_ok_and(|contents| contents.contains(var_name))
    })
}

/// Returns true if the user's shell RC files source `~/.kyris/env/load.sh`,
/// meaning env-based agent configuration will actually be loaded at runtime.
pub(super) fn env_loader_sourced() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let zshrc = std::fs::read_to_string(format!("{home}/.zshrc")).unwrap_or_default();
    let bashrc = std::fs::read_to_string(format!("{home}/.bashrc")).unwrap_or_default();
    zshrc.contains(".kyris/env/load.sh") || bashrc.contains(".kyris/env/load.sh")
}
