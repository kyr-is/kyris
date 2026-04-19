// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

pub fn is_managed_by_homebrew() -> bool {
    Command::new("brew")
        .args(["services", "list"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|out| out.contains("kyris"))
}

pub fn start_service() -> std::io::Result<()> {
    if is_managed_by_homebrew() {
        Command::new("brew")
            .args(["services", "start", "kyris"])
            .status()
            .map(|_| ())
    } else {
        let uid = get_uid();
        Command::new("launchctl")
            .args(["bootstrap", &format!("gui/{uid}"), &plist_path()])
            .status()
            .map(|_| ())
    }
}

pub fn stop_service() -> std::io::Result<()> {
    if is_managed_by_homebrew() {
        Command::new("brew")
            .args(["services", "stop", "kyris"])
            .status()
            .map(|_| ())
    } else {
        let uid = get_uid();
        Command::new("launchctl")
            .args(["bootout", &format!("gui/{uid}/so.kyri.kyrisd")])
            .status()
            .map(|_| ())
    }
}

pub fn restart_agentpactd() -> std::io::Result<()> {
    let uid = get_uid();
    Command::new("launchctl")
        .args(["kickstart", "-k", &format!("gui/{uid}/so.kyri.agentpactd")])
        .status()
        .map(|_| ())
}

fn get_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::getuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn plist_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/Library/LaunchAgents/so.kyri.kyrisd.plist")
}
