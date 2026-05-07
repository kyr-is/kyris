// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use regex::Regex;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::service::{ServiceKind, service_state};
use crate::state::{bin_dir, credentials_path, load_config};

#[derive(Args)]
pub struct StatusArgs {}

pub fn run(_args: StatusArgs) {
    println!("Kyris Status");
    println!("============");

    check_agentpactd();
    check_kyrisd();
    check_native_integrations();
    check_enrollment();
    check_versions();
}

fn check_agentpactd() {
    let socket_path = agentpact_socket();
    let reachable = UnixStream::connect(&socket_path).is_ok();
    println!(
        "  [{}] agentpactd ({})",
        status_marker(reachable),
        socket_path
    );
    if let Err(msg) = kyris_agentpact_client::check_protocol_compatibility() {
        println!("  [!] {msg}");
    }
}

fn check_kyrisd() {
    let base_url = load_config().map_or_else(
        |_| "http://127.0.0.1:4710".to_string(),
        |config| config.base_url(),
    );
    let state = service_state(ServiceKind::Kyrisd);
    let healthy = health_status(&base_url).is_ok_and(|status| status.is_success());
    let service = if state.managed_by_homebrew {
        format!(
            "homebrew/{}",
            state.homebrew_status.as_deref().unwrap_or("unknown")
        )
    } else if state.launchd_loaded {
        "launchd".to_string()
    } else {
        "not-loaded".to_string()
    };
    println!(
        "  [{}] kyrisd ({}, {base_url}/healthz)",
        status_marker(healthy),
        service
    );
}

fn check_native_integrations() {
    use crate::agents::profile::{AdaptedMechanism, CapLevel};

    for agent in crate::agents::registry::all_agents() {
        let probe = agent.probe();
        if !probe.detected {
            continue;
        }
        let exec_ok = probe.execution.level != CapLevel::None;
        let tool_ok = probe.tool.level != CapLevel::None;
        let burn_ok = probe.burn_control.level != CapLevel::None;
        let all_live = [&probe.execution, &probe.tool, &probe.burn_control]
            .iter()
            .all(|s| {
                s.level == CapLevel::None
                    || s.level == CapLevel::Native
                    || matches!(
                        s.mechanism,
                        Some(
                            AdaptedMechanism::LiveHook
                                | AdaptedMechanism::EnvVarProxy
                                | AdaptedMechanism::McpWrapping
                        )
                    )
            });
        let marker = if !exec_ok || !tool_ok || !burn_ok {
            "-"
        } else if all_live {
            "+"
        } else {
            "~"
        };
        let fmt = |s: &crate::agents::profile::SurfaceState| -> String {
            match s.level {
                CapLevel::None => "none".into(),
                CapLevel::Native => "native".into(),
                CapLevel::Adapted => match &s.mechanism {
                    Some(m) => format!("{m}"),
                    None => "adapted".into(),
                },
            }
        };
        println!(
            "  [{marker}] {:<14} cmd:{:<7} mcp:{:<7} burn:{}",
            agent.id(),
            fmt(&probe.execution),
            fmt(&probe.tool),
            fmt(&probe.burn_control),
        );
    }

    check_compiled_policy_degradation();
}

type PolicyCompiler = fn(Option<&std::path::Path>) -> Result<(serde_json::Value, u32), String>;

fn check_compiled_policy_degradation() {
    let compilers: &[(&str, PolicyCompiler)] = &[
        (
            "cline",
            crate::compile_policy::compile_cline_permissions_summary,
        ),
        (
            "opencode",
            crate::compile_policy::compile_opencode_permissions,
        ),
        (
            "codex-cli",
            crate::compile_policy::compile_codex_permissions,
        ),
        (
            "gemini-cli",
            crate::compile_policy::compile_gemini_permissions,
        ),
    ];
    for (agent, compiler) in compilers {
        if let Ok((_, ask_dropped)) = compiler(None)
            && ask_dropped > 0
        {
            println!("  [!] {agent} compiled policy degraded ({ask_dropped} ask rules dropped)");
        }
    }
}

fn check_enrollment() {
    let enrolled = credentials_path().is_ok_and(|path| path.exists());
    println!("  [{}] enrolled", status_marker(enrolled));
}

fn check_versions() {
    let versions = component_versions();
    let installed: Vec<(&str, String)> = versions
        .into_iter()
        .filter_map(|(name, version)| version.map(|version| (name, version)))
        .collect();

    if installed.is_empty() {
        println!("  [-] component versions unavailable");
        return;
    }

    let unique_versions: std::collections::HashSet<&str> = installed
        .iter()
        .map(|(_, version)| version.as_str())
        .collect();
    let summary = installed
        .iter()
        .map(|(name, version)| format!("{name}={version}"))
        .collect::<Vec<_>>()
        .join(", ");

    if unique_versions.len() <= 1 {
        println!("  [+] component versions aligned ({summary})");
    } else {
        println!("  [!] version skew ({summary})");
    }
}

fn agentpact_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn status_marker(condition: bool) -> &'static str {
    if condition { "+" } else { "-" }
}

fn component_versions() -> Vec<(&'static str, Option<String>)> {
    vec![
        ("kyris", Some(env!("CARGO_PKG_VERSION").to_string())),
        ("kyrisd", installed_component_version("kyrisd")),
        ("kyris-mcp", installed_component_version("kyris-mcp")),
        ("agentpactd", installed_component_version("agentpactd")),
    ]
}

fn installed_component_version(name: &str) -> Option<String> {
    let path = component_binary_path(name)?;
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    extract_version(&stdout)
}

fn component_binary_path(name: &str) -> Option<PathBuf> {
    if let Some(path) = crate::state::find_in_path(name) {
        return Some(path);
    }
    let local = bin_dir().ok()?.join(name);
    if local.exists() { Some(local) } else { None }
}

fn extract_version(output: &str) -> Option<String> {
    let regex = Regex::new(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.\-]+)?").ok()?;
    regex.find(output).map(|match_| match_.as_str().to_string())
}

fn health_status(base_url: &str) -> Result<reqwest::StatusCode, String> {
    let url = format!("{base_url}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for status: {e}"))?;
    runtime.block_on(async {
        reqwest::get(&url)
            .await
            .map(|response| response.status())
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testStatusMarker() {
        assert_eq!(status_marker(true), "+");
        assert_eq!(status_marker(false), "-");
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("kyrisd 0.1.2"), Some("0.1.2".to_string()));
    }
}
