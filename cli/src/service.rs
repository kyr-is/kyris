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

/// `launchctl disable gui/<uid>/<label>` — persistent disable. Survives
/// reboot: launchd refuses to load the service until a matching `enable`
/// is issued. Used by `kyris stop` to keep daemons down across logins.
///
/// Already-disabled or unknown-target launchctl errors are treated as
/// success — the goal is "service is disabled," and it already is.
pub fn disable_service(kind: ServiceKind) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid(), kind.launchd_label());
    run_launchctl_soft(&["disable", &target])
}

/// `launchctl enable` — inverse of `disable`. Idempotent against
/// already-enabled targets.
pub fn enable_service(kind: ServiceKind) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid(), kind.launchd_label());
    run_launchctl_soft(&["enable", &target])
}

/// `launchctl kill TERM` — send SIGTERM to the running instance. The
/// plist's `KeepAlive: { SuccessfulExit: false }` means clean exits
/// don't auto-restart, so a graceful TERM is enough. A
/// `no-such-process` error means the daemon was already stopped, which
/// is the desired end state — treated as success.
pub fn kill_service(kind: ServiceKind) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid(), kind.launchd_label());
    run_launchctl_soft(&["kill", "TERM", &target])
}

/// `launchctl kickstart` (no `-k`) — start a loaded but stopped
/// service. Used by `kyris start` after `enable` to bring the daemon
/// back up.
pub fn kickstart_service(kind: ServiceKind) -> Result<(), String> {
    let target = format!("gui/{}/{}", uid(), kind.launchd_label());
    run_command("launchctl", &["kickstart", &target], None)
}

/// Block until agentpactd's UDS socket accepts a connection, polling
/// every 250ms. Returns `true` if the socket came up before `timeout`,
/// `false` otherwise. Mirrors the responsiveness check in
/// `lifecycle/verify.rs` — a connect roundtrip is the truth, not
/// merely the socket file's existence.
#[must_use]
pub fn wait_for_agentpactd(timeout: std::time::Duration) -> bool {
    let socket_path = std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    });
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Block until kyrisd's `/healthz` returns 2xx, polling every 250ms.
/// Returns `true` if healthy before `timeout`, `false` otherwise.
#[must_use]
pub fn wait_for_kyrisd(timeout: std::time::Duration) -> bool {
    let base_url = crate::state::load_config()
        .map_or_else(|_| "http://127.0.0.1:4710".to_string(), |c| c.base_url());
    let url = format!("{base_url}/healthz");
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    let deadline = std::time::Instant::now() + timeout;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .ok();
        loop {
            if let Some(c) = &client
                && c.get(&url)
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    })
}

/// Run launchctl, treating "already in the desired state" stderr
/// messages as success. Real failures still propagate.
fn run_launchctl_soft(args: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run launchctl: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let benign = stderr.contains("could not find service")
        || stderr.contains("No such process")
        || stderr.contains("Service is disabled")
        || stderr.contains("Operation already in progress")
        || stderr.contains("Already disabled")
        || stderr.contains("Already enabled");
    if benign {
        Ok(())
    } else if stderr.is_empty() {
        Err(format!("launchctl failed with status {}", output.status))
    } else {
        Err(stderr)
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

pub fn uid() -> u32 {
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

    pub fn launchd_label(self) -> &'static str {
        match self {
            Self::Kyrisd => "is.kyr.kyrisd",
            Self::Agentpactd => "is.kyr.agentpactd",
        }
    }
}
