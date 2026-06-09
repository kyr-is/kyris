// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::integration::read_json_value;
use crate::state::env_dir;

use super::profile::{ManagedFileFingerprint, SurfaceState};
use super::registry::{BurnControlMechanism, ExecutionMechanism, ToolMechanism};

pub struct ProbeResult {
    pub detected: bool,
    pub execution: SurfaceState<ExecutionMechanism>,
    pub tool: SurfaceState<ToolMechanism>,
    pub burn_control: SurfaceState<BurnControlMechanism>,
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
) -> SurfaceState<BurnControlMechanism> {
    let has_base_url =
        config_path.is_some_and(|p| read_json_value(p).is_ok_and(|v| base_url_check(&v)));
    let has_env_proxy = env_reaches_agent(agent_id, env_var);
    if has_base_url || has_env_proxy {
        SurfaceState::adapted(BurnControlMechanism::ConfigRewrite)
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

/// Returns true iff `path` has at least one entry under `servers_key`. Used
/// to distinguish "no MCP servers to wrap" (N/A) from "MCP servers exist but
/// aren't wrapped" (real gap).
pub(super) fn json_has_any_mcp_servers(path: &std::path::Path, servers_key: &str) -> bool {
    let Ok(value) = read_json_value(path) else {
        return false;
    };
    value
        .get(servers_key)
        .and_then(|s| s.as_object())
        .is_some_and(|servers| !servers.is_empty())
}

/// TOML analog of [`json_has_any_mcp_servers`]. Used for agents (e.g.,
/// codex-cli) whose MCP server registry lives in a TOML table.
pub(super) fn toml_has_any_mcp_servers(path: &std::path::Path, servers_key: &str) -> bool {
    let Ok(value) = crate::integration::read_toml_value(path) else {
        return false;
    };
    value
        .get(servers_key)
        .and_then(toml::Value::as_table)
        .is_some_and(|servers| !servers.is_empty())
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

/// True iff the agent's Kyris env file carries `var_name` AND that file will
/// actually be loaded when the agent runs — either because the agent's PATH
/// shim sources it (the robust, shell-independent path) or because the user's
/// shell RC sources the env loader. Replaces bare
/// `env_file_has_var && env_loader_sourced` checks, which under-reported
/// burn-control as off whenever the shim — not the shell RC — delivers the env
/// (e.g. under fish or a GUI launch, where the loader is never sourced).
pub(super) fn env_reaches_agent(agent_id: &str, var_name: &str) -> bool {
    env_file_has_var(agent_id, var_name)
        && (super::shim::shim_delivers_env(agent_id) || env_loader_sourced())
}

/// Legacy/back-compat detector: returns true if the user's shell RC files
/// source `~/.kyris/env/load.sh`. Current installs deliver env via the PATH
/// shim and no longer write this loader, but installs predating that change
/// still have it — recognize it so their burn-control isn't under-reported
/// until a reinstall refreshes the shim.
pub(super) fn env_loader_sourced() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let zshrc = std::fs::read_to_string(format!("{home}/.zshrc")).unwrap_or_default();
    let bashrc = std::fs::read_to_string(format!("{home}/.bashrc")).unwrap_or_default();
    zshrc.contains(".kyris/env/load.sh") || bashrc.contains(".kyris/env/load.sh")
}
