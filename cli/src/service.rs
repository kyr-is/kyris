// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    Kyrisd,
    Agentpactd,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceState {
    pub managed_by_homebrew: bool,
    pub homebrew_status: Option<String>,
    pub launchd_loaded: bool,
}

pub fn start_service(kind: ServiceKind) -> Result<(), String> {
    if let Some(prefix) = homebrew_prefix_for(kind) {
        run_command(
            "brew",
            &["services", "start", kind.formula_name()],
            Some(prefix),
        )
    } else {
        let plist = plist_path(kind);
        if !plist.exists() {
            return Err(format!(
                "LaunchAgent plist not found at {}",
                plist.display()
            ));
        }
        let domain = format!("gui/{}", uid());
        let plist_string = plist.to_string_lossy().to_string();
        run_command("launchctl", &["bootstrap", &domain, &plist_string], None)
    }
}

pub fn stop_service(kind: ServiceKind) -> Result<(), String> {
    if let Some(prefix) = homebrew_prefix_for(kind) {
        run_command(
            "brew",
            &["services", "stop", kind.formula_name()],
            Some(prefix),
        )
    } else {
        let target = format!("gui/{}/{}", uid(), kind.launchd_label());
        run_command("launchctl", &["bootout", &target], None)
    }
}

pub fn restart_service(kind: ServiceKind) -> Result<(), String> {
    if let Some(prefix) = homebrew_prefix_for(kind) {
        run_command(
            "brew",
            &["services", "restart", kind.formula_name()],
            Some(prefix),
        )
    } else {
        let target = format!("gui/{}/{}", uid(), kind.launchd_label());
        run_command("launchctl", &["kickstart", "-k", &target], None)
    }
}

pub fn service_state(kind: ServiceKind) -> ServiceState {
    let homebrew_status = brew_service_status(kind);
    let launchd_loaded = std::process::Command::new("launchctl")
        .args(["print", &format!("gui/{}/{}", uid(), kind.launchd_label())])
        .output()
        .is_ok_and(|output| output.status.success());

    ServiceState {
        managed_by_homebrew: homebrew_status.is_some(),
        homebrew_status,
        launchd_loaded,
    }
}

pub fn candidate_log_paths(kind: ServiceKind) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        match kind {
            ServiceKind::Kyrisd => {
                paths.push(home.join(".kyris").join("kyrisd.stderr.log"));
                paths.push(home.join("Library").join("Logs").join("kyrisd.log"));
            }
            ServiceKind::Agentpactd => {
                paths.push(home.join(".agentpact").join("agentpactd.log"));
                paths.push(home.join("Library").join("Logs").join("agentpactd.log"));
            }
        }
    }

    for prefix in ["/opt/homebrew", "/usr/local"] {
        let prefix = PathBuf::from(prefix);
        if prefix.exists() {
            paths.push(prefix.join("var").join("log").join(kind.log_filename()));
        }
    }

    paths
}

fn homebrew_prefix_for(kind: ServiceKind) -> Option<String> {
    let output = std::process::Command::new("brew")
        .args(["list", kind.formula_name()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let prefix_output = std::process::Command::new("brew")
        .arg("--prefix")
        .output()
        .ok()?;
    if !prefix_output.status.success() {
        return None;
    }

    String::from_utf8(prefix_output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn brew_service_status(kind: ServiceKind) -> Option<String> {
    let output = std::process::Command::new("brew")
        .args(["services", "list"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout.lines().find_map(|line| {
        let mut columns = line.split_whitespace();
        let name = columns.next()?;
        if name != kind.formula_name() {
            return None;
        }
        columns.next().map(ToString::to_string)
    })
}

fn plist_path(kind: ServiceKind) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", kind.launchd_label()))
}

fn run_command(command: &str, args: &[&str], brew_prefix: Option<String>) -> Result<(), String> {
    let mut process = std::process::Command::new(command);
    process.args(args);
    if let Some(prefix) = brew_prefix {
        process.env("HOMEBREW_PREFIX", prefix);
    }
    let output = process
        .output()
        .map_err(|e| format!("Failed to run {command}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        Err(format!("{command} failed with status {}", output.status))
    } else {
        Err(stderr)
    }
}

fn uid() -> u32 {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

impl ServiceKind {
    fn formula_name(self) -> &'static str {
        match self {
            Self::Kyrisd => "kyris",
            Self::Agentpactd => "agentpact",
        }
    }

    fn launchd_label(self) -> &'static str {
        match self {
            Self::Kyrisd => "is.kyr.kyrisd",
            Self::Agentpactd => "is.kyr.agentpactd",
        }
    }

    fn log_filename(self) -> &'static str {
        match self {
            Self::Kyrisd => "kyrisd.log",
            Self::Agentpactd => "agentpact.log",
        }
    }
}
