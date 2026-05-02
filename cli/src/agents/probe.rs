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

pub(super) fn probe_live_hook_agent(
    detected: bool,
    settings_path: Option<&std::path::Path>,
    hook_phase: &str,
    hook_marker: &str,
    agent_id: &str,
    burn_control_var: &str,
) -> ProbeResult {
    if !detected {
        return not_detected();
    }

    let has_hook = settings_path.is_some_and(|p| json_has_hook(p, hook_phase, hook_marker));

    let execution = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let tool = if has_hook {
        SurfaceState::adapted(AdaptedMechanism::LiveHook)
    } else {
        SurfaceState::none()
    };
    let burn_control = if env_file_has_var(agent_id, burn_control_var) {
        SurfaceState::adapted(AdaptedMechanism::EnvVarProxy)
    } else {
        SurfaceState::none()
    };

    let mut managed_files = Vec::new();
    if let Some(path) = settings_path
        && let Some(fp) = fingerprint(path)
    {
        managed_files.push(fp);
    }

    ProbeResult {
        detected: true,
        execution,
        tool,
        burn_control,
        managed_files,
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
    let has_env_proxy = env_file_has_var(agent_id, env_var);
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
                s.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c == "kyris-mcp")
            })
        })
}

pub(super) fn env_file_has_var(agent_id: &str, var_name: &str) -> bool {
    let Ok(env_file) = env_dir().map(|d| d.join(format!("{agent_id}.sh"))) else {
        return false;
    };
    std::fs::read_to_string(env_file).is_ok_and(|contents| contents.contains(var_name))
}

fn json_has_hook(path: &std::path::Path, phase: &str, marker: &str) -> bool {
    let Ok(value) = read_json_value(path) else {
        return false;
    };
    value
        .get("hooks")
        .and_then(|h| h.get(phase))
        .and_then(|a| a.as_array())
        .is_some_and(|hooks| {
            let serialized = serde_json::to_string(hooks).unwrap_or_default();
            serialized.contains(marker)
        })
}
