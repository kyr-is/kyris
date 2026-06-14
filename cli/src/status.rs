// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use regex::Regex;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::agents::profile::{CapLevel, SurfaceState};
use crate::agents::registry::{MechanismLabel, plan_label};
use crate::service::{ServiceKind, service_state};
use crate::state::{bin_dir, load_config};

#[derive(Args)]
pub struct StatusArgs {}

pub fn run(_args: StatusArgs) {
    // Headline first — single-line summary of effective enforcement
    // posture (enforcing, log-only, errored, kill-switched). Replaces
    // the old "Kyris Status / ============" header and the separate
    // "[!] DISABLED via …" banner: the headline already encodes both.
    println!("{}", crate::headline::render());
    println!();

    check_agentpactd();
    check_kyrisd();
    check_sandbox();
    check_native_integrations();
    check_enrollment();
    check_versions();
    check_updates();
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

/// Session sandbox (OS jail) state. The jail is core/always-on, but only
/// enforces where an OS backend exists (macOS Seatbelt today) AND the
/// `kyris-exec` launcher is resolvable — exactly the guard the PATH shim
/// applies at launch. This line reports whether it's actually enforcing here.
fn check_sandbox() {
    let backend =
        cfg!(target_os = "macos") && std::path::Path::new("/usr/bin/sandbox-exec").exists();
    if !backend {
        println!("  [-] sandbox (OS jail): unavailable on this platform");
    } else if component_binary_path("kyris-exec").is_some() {
        println!(
            "  [{}] sandbox (OS jail): active (Seatbelt)",
            status_marker(true)
        );
    } else {
        println!("  [!] sandbox (OS jail): backend present but kyris-exec missing — reinstall");
    }
}

/// Compact `none`/`native`/`n/a`/<mechanism> cell for one surface.
fn surface_cell<M: MechanismLabel>(s: &SurfaceState<M>) -> String {
    if s.not_applicable {
        return "n/a".into();
    }
    match s.level {
        CapLevel::None => "none".into(),
        CapLevel::Native => "native".into(),
        CapLevel::Adapted => match &s.mechanism {
            Some(m) => m.short().to_string(),
            None => "adapted".into(),
        },
    }
}

/// A surface is "fully live" (in-band mediation, marker `+`) when it is
/// inert (None/Native) or realized via an in-band mechanism — as opposed to a
/// degraded compiled-policy / config-rewrite realization (marker `~`).
fn surface_fully_live<M: MechanismLabel>(s: &SurfaceState<M>) -> bool {
    s.level == CapLevel::None
        || s.level == CapLevel::Native
        || s.mechanism.as_ref().is_some_and(MechanismLabel::is_in_band)
}

fn check_native_integrations() {
    for agent in crate::agents::registry::all_agents() {
        let probe = agent.probe();
        if !probe.detected {
            continue;
        }
        let plan = agent.integration_plan();
        let exec_ok = probe.execution.level != CapLevel::None || probe.execution.not_applicable;
        let tool_ok = probe.tool.level != CapLevel::None || probe.tool.not_applicable;
        let burn_ok =
            probe.burn_control.level != CapLevel::None || probe.burn_control.not_applicable;
        let all_live = surface_fully_live(&probe.execution)
            && surface_fully_live(&probe.tool)
            && surface_fully_live(&probe.burn_control);
        let marker = if !exec_ok || !tool_ok || !burn_ok {
            "-"
        } else if all_live {
            "+"
        } else {
            "~"
        };
        let exec = format!(
            "{}/{}",
            surface_cell(&probe.execution),
            plan_label(plan.execution)
        );
        let tool = format!("{}/{}", surface_cell(&probe.tool), plan_label(plan.tool));
        let burn = format!(
            "{}/{}",
            surface_cell(&probe.burn_control),
            plan_label(plan.burn_control)
        );
        println!(
            "  [{marker}] {:<14} cmd:{:<13} mcp:{:<13} burn:{}",
            agent.id(),
            exec,
            tool,
            burn,
        );

        // Drift: the tool surface is wrapped, but extra MCP server(s) were added
        // after setup and aren't routed through kyris yet. The configure-time
        // rewrite never saw them; a reconcile will pick them up.
        if probe.tool.level == CapLevel::Adapted {
            let unwrapped = crate::agents::configure::unwrapped_mcp_server_names(agent.as_ref());
            if !unwrapped.is_empty() {
                println!(
                    "  [!] {}: MCP server(s) not routed through kyris: {} — run `kyris agent setup {}`",
                    agent.id(),
                    unwrapped.join(", "),
                    agent.id()
                );
            }
        }
    }

    check_compiled_policy_degradation();
}

type PolicyCompiler = fn(Option<&std::path::Path>) -> Result<(serde_json::Value, u32), String>;

fn check_compiled_policy_degradation() {
    // Only agents that actually EMIT a compiled policy (as a fallback/ceiling)
    // can have ask rules dropped. cline + opencode are pure live-hook now (their
    // governance is the daemon-mediated hook — no compiled command policy), so
    // they're excluded; codex + gemini still write a compiled policy alongside
    // their hook.
    let compilers: &[(&str, PolicyCompiler)] = &[
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
    let enrolled = kyris_core::credentials::load().is_some();
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

/// Show available updates inline based on the cached check result. Spawns a
/// detached background refresh when the cache is stale (>24h) or missing —
/// the network call doesn't block `kyris status` returning. Next status
/// invocation will see the refreshed cache.
fn check_updates() {
    println!();
    println!("Updates");
    println!("-------");

    let cached = crate::lifecycle::update::UpdateCheckResult::load();
    let needs_refresh = cached
        .as_ref()
        .is_none_or(|c| c.is_stale(UPDATE_CHECK_MAX_AGE_HOURS));

    match cached {
        None => {
            println!("  [?] no cached check yet — refreshing in background");
        }
        Some(cache) => {
            for status in &cache.repos {
                render_repo_update_line(status);
            }
            // Hint the freshness so users can sanity-check why an upgrade they
            // expected isn't showing up yet (e.g., they tagged the release
            // 30 minutes ago and the cache is from yesterday).
            if needs_refresh {
                println!("  (cache is stale; refreshing in background)");
            } else {
                println!("  (last checked: {})", cache.checked_at);
            }
        }
    }

    if needs_refresh {
        spawn_background_update_check();
    }
}

const UPDATE_CHECK_MAX_AGE_HOURS: i64 = 24;

fn render_repo_update_line(status: &crate::lifecycle::update::RepoUpdateStatus) {
    let mut stdout = std::io::stdout().lock();
    render_repo_update_line_io(status, &mut stdout);
}

/// Pure formatting — writes one status line to `writer`. Separated from the
/// stdout caller so unit tests can capture and assert the output.
fn render_repo_update_line_io<W: std::io::Write>(
    status: &crate::lifecycle::update::RepoUpdateStatus,
    writer: &mut W,
) {
    let line = match status.channel.as_str() {
        "brew" => {
            // Brew users have their own update mechanism; redirect them to it
            // rather than competing with `brew upgrade` from inside kyris.
            let current = status.current.as_deref().unwrap_or("?");
            format!(
                "  [b] {}: {} (Homebrew-managed — `brew outdated --cask kyr-is/tap/{}`)",
                status.repo, current, status.repo
            )
        }
        "missing" => format!("  [-] {}: not installed", status.repo),
        _ => match (status.current.as_deref(), status.latest.as_deref()) {
            (Some(c), Some(l)) if status.has_script_update() => format!(
                "  [!] {}: {} → {} available  (run: kyris update)",
                status.repo, c, l
            ),
            (Some(c), Some(_)) => format!("  [+] {}: {} (up to date)", status.repo, c),
            (Some(c), None) => format!(
                "  [?] {}: {} (latest version unknown — last check failed)",
                status.repo, c
            ),
            (None, _) => format!("  [?] {}: version unknown", status.repo),
        },
    };
    let _ = writeln!(writer, "{line}");
}

/// Spawn `kyris update --background` as a detached child so the network check
/// happens off the critical path. Returns immediately — `kyris status` is
/// expected to be fast even on first run with stale or missing cache.
fn spawn_background_update_check() {
    let Ok(self_path) = std::env::current_exe() else {
        return;
    };
    let _ = std::process::Command::new(self_path)
        .args(["update", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
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

    use crate::lifecycle::update::RepoUpdateStatus;

    fn render(status: &RepoUpdateStatus) -> String {
        let mut buf: Vec<u8> = Vec::new();
        render_repo_update_line_io(status, &mut buf);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn testRenderUpdateAvailableLineIncludesArrowAndCommandHint() {
        let status = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.6".into()),
            latest: Some("0.1.7".into()),
            channel: "script".into(),
        };
        let line = render(&status);
        assert!(line.contains("kyris"), "missing repo name in: {line}");
        assert!(line.contains("0.1.6"), "missing current version in: {line}");
        assert!(line.contains("0.1.7"), "missing latest version in: {line}");
        assert!(line.contains("→"), "missing arrow in: {line}");
        assert!(
            line.contains("kyris update"),
            "missing command hint in: {line}"
        );
    }

    #[test]
    fn testRenderUpToDateLineMarksWithPlusAndOmitsCommand() {
        let status = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.7".into()),
            latest: Some("0.1.7".into()),
            channel: "script".into(),
        };
        let line = render(&status);
        assert!(line.contains("[+]"), "missing up-to-date marker in: {line}");
        assert!(line.contains("0.1.7"));
        assert!(
            !line.contains("kyris update"),
            "should not nag when up to date: {line}"
        );
    }

    #[test]
    fn testRenderBrewLineRedirectsToBrewCommand() {
        let status = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.6".into()),
            latest: None,
            channel: "brew".into(),
        };
        let line = render(&status);
        assert!(
            line.contains("Homebrew-managed"),
            "missing brew label in: {line}"
        );
        assert!(
            line.contains("brew outdated"),
            "missing brew command hint in: {line}"
        );
        assert!(
            !line.contains("kyris update"),
            "should not suggest `kyris update` for brew installs: {line}"
        );
    }

    #[test]
    fn testRenderMissingLineSaysNotInstalled() {
        let status = RepoUpdateStatus {
            repo: "agentpact".into(),
            current: None,
            latest: None,
            channel: "missing".into(),
        };
        let line = render(&status);
        assert!(line.contains("agentpact"));
        assert!(line.contains("not installed"), "got: {line}");
    }

    #[test]
    fn testRenderUnknownLatestExplainsCheckFailed() {
        let status = RepoUpdateStatus {
            repo: "kyris".into(),
            current: Some("0.1.6".into()),
            latest: None,
            channel: "script".into(),
        };
        let line = render(&status);
        assert!(line.contains("0.1.6"));
        assert!(line.contains("check failed"), "got: {line}");
    }
}
