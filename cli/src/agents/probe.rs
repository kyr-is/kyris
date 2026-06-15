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

/// kyrisd's base URL from `kyrisd.yaml`, read-only (status must never create
/// config). `None` when kyris isn't installed/configured — in which case no
/// burn-control routing can be live, so value-aware probes report none.
pub(super) fn kyrisd_base_url() -> Option<String> {
    crate::state::load_config().ok().map(|c| c.base_url())
}

fn json_servers_at<'v>(
    value: &'v serde_json::Value,
    servers_path: &[String],
) -> Option<&'v serde_json::Map<String, serde_json::Value>> {
    let mut cur = value;
    for key in servers_path {
        cur = cur.get(key)?;
    }
    cur.as_object()
}

fn json_server_is_wrapped(server: &serde_json::Value) -> bool {
    // Read through the transport indirection so cline's nested
    // `transport.command` counts as wrapped, not just the flat form.
    let server = super::configure::json_mcp_fields(server);
    let cmd = server.get("command");
    let str_match = cmd
        .and_then(|c| c.as_str())
        .is_some_and(|c| c == "kyris-mcp");
    let arr_match = cmd
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .is_some_and(|first| first == "kyris-mcp");
    str_match || arr_match
}

pub(super) fn json_has_mcp_wrap(path: &std::path::Path, servers_path: &[String]) -> bool {
    let Ok(value) = read_json_value(path) else {
        return false;
    };
    json_servers_at(&value, servers_path)
        .is_some_and(|servers| servers.values().any(json_server_is_wrapped))
}

/// Returns true iff `path` has at least one entry under `servers_path`. Used
/// to distinguish "no MCP servers to wrap" (N/A) from "MCP servers exist but
/// aren't wrapped" (real gap).
pub(super) fn json_has_any_mcp_servers(path: &std::path::Path, servers_path: &[String]) -> bool {
    let Ok(value) = read_json_value(path) else {
        return false;
    };
    json_servers_at(&value, servers_path).is_some_and(|servers| !servers.is_empty())
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

/// `(has_wrap, has_any)` across EVERY MCP config location the agent declares —
/// the multi-scope probe core. A wrap in any scope counts as adapted; a server
/// in any scope counts as "something to wrap" (so N/A is only reported when
/// every scope is empty).
pub(super) fn mcp_locations_status(agent: &dyn super::registry::AgentDescriptor) -> (bool, bool) {
    let mut has_wrap = false;
    let mut has_any = false;
    for location in agent.mcp_configs() {
        match &location.format {
            super::registry::McpConfigFormat::Json { servers_path } => {
                has_wrap |= json_has_mcp_wrap(&location.path, servers_path);
                has_any |= json_has_any_mcp_servers(&location.path, servers_path);
            }
            super::registry::McpConfigFormat::Toml { servers_key } => {
                has_any |= toml_has_any_mcp_servers(&location.path, servers_key);
                has_wrap |= toml_has_mcp_wrap(&location.path, servers_key);
            }
        }
    }
    (has_wrap, has_any)
}

fn toml_has_mcp_wrap(path: &std::path::Path, servers_key: &str) -> bool {
    let Ok(value) = crate::integration::read_toml_value(path) else {
        return false;
    };
    value
        .get(servers_key)
        .and_then(toml::Value::as_table)
        .is_some_and(|servers| {
            servers
                .values()
                .any(|s| s.get("command").and_then(toml::Value::as_str) == Some("kyris-mcp"))
        })
}

fn agent_env_file_matches(agent_id: &str, predicate: impl Fn(&str) -> bool) -> bool {
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
            && std::fs::read_to_string(entry.path()).is_ok_and(|contents| predicate(&contents))
    })
}

/// True iff the agent's env file exports `var_name` whose VALUE is `expected`
/// — not merely that the var appears. Accepts the quoted form prestage writes
/// (`export V='url'`) and the unquoted form of pre-quoting installs.
fn env_file_exports_value(agent_id: &str, var_name: &str, expected: &str) -> bool {
    let export_prefix = format!("export {var_name}=");
    agent_env_file_matches(agent_id, |contents| {
        contents.lines().any(|line| {
            line.strip_prefix(&export_prefix)
                .is_some_and(|value| value.trim().trim_matches('\'') == expected)
        })
    })
}

/// True iff the agent's Kyris env file carries `var_name` AND that file will
/// actually be loaded when the agent runs — either because the agent's PATH
/// shim sources it (the robust, shell-independent path) or because the user's
/// shell RC sources the env loader. Replaces bare
/// `env_file_has_var && env_loader_sourced` checks, which under-reported
/// burn-control as off whenever the shim — not the shell RC — delivers the env
/// (e.g. under fish or a GUI launch, where the loader is never sourced).
fn env_delivery_reaches_agent(agent_id: &str) -> bool {
    super::shim::shim_delivers_env(agent_id) || env_loader_sourced()
}

/// Semantic burn-control probe: the env file must point `var_name` AT KYRISD
/// (not merely exist — a var pointing elsewhere is not kyris routing) and the
/// delivery vehicle must reach the agent. `kyrisd.yaml` absent → false.
pub(super) fn env_routes_to_kyrisd(agent_id: &str, var_name: &str) -> bool {
    let Some(base) = kyrisd_base_url() else {
        return false;
    };
    env_file_exports_value(agent_id, var_name, &base) && env_delivery_reaches_agent(agent_id)
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
