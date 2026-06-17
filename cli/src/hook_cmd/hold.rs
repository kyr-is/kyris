// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris hook hold` (circuit-breaker no-TTY approval) and the agent-PID
//! discovery used to anchor exec tokens.

use kyris_agentpact_client::{self as pact_client};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use crate::agents::registry;

use super::HookHoldArgs;
use super::response::emit_deny;
use super::segments::{PopupResult, poll_segment};

pub(super) fn run_hold(args: HookHoldArgs) {
    let sock_path = args
        .socket
        .unwrap_or_else(|| pact_client::default_socket_path().display().to_string());
    let socket_timeout = std::time::Duration::from_secs(5);

    // Reuse poll_segment: it holds the request in kyrisd's pending system,
    // polls for developer resolution (kyrisd sends permission.respond to
    // agentpactd), and returns the outcome. The shell hook only cares about
    // the exit code, so an approval emits nothing and exits 0.
    //
    // `server` is "shell" (the popup title slot — "Kyris: Allow shell");
    // `args.display` (the verbatim command) is the segment text, which
    // becomes the popup body and the syntect-highlighted accessoryView.
    //
    // `hold` now serves only the circuit-breaker path (normal asks go through
    // `resolve-shell`), and a breaker ask never persists an override — so
    // "For session" is never offered here.
    match poll_segment(
        "shell",
        "shell",
        &sock_path,
        socket_timeout,
        &args.req_id,
        &args.token,
        &args.display,
        false,
        None,
        kyris_core::pending::NATIVE_HOOK_POLL_TIMEOUT,
    ) {
        PopupResult::Approved { .. } => std::process::exit(0),
        PopupResult::Blocked {
            exit_code, reason, ..
        } => {
            emit_deny(&reason);
            std::process::exit(exit_code);
        }
    }
}

/// Canonical `vendor/name` identity for a kyris-integrated agent id, used as
/// the DECLARED attribution identity on agentpactd requests. The hook's
/// `--agent` value was written into the agent's hook config by `kyris agent
/// setup` (install-time-owned, not chosen by the agent at runtime), so the
/// daemon can attribute exactly with zero signature-catalog knowledge of the
/// agent's install layout. Returns None for ids with no registered
/// integration — notably the shell gate's `"shell"` — which keep attributing
/// via lineage.
pub(super) fn declared_canonical_agent(agent: &str) -> Option<String> {
    registry::agent_by_id(agent).map(|a| a.canonical_id().to_string())
}

pub(super) fn discover_agent_pid() -> Option<u32> {
    // Same catalog agentpactd loads (single source): resolved via the daemon
    // config's defaults-dir logic. Discovery failing here is non-fatal — the
    // request still carries the declared `--agent` identity plus `anchor_pid`,
    // which the daemon can seed a boundary from with ancestry validation.
    let sig_table = agentpact::config::DaemonConfig::load()
        .ok()
        .map(|c| c.defaults_dir.join("agents.yaml"))
        .and_then(|p| {
            agentpact::attribution::signatures::SignatureTable::load_from_yaml(&p).ok()
        })?;
    let refresh_kind = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    let mut sys = sysinfo::System::new();

    let my_pid = std::process::id();
    let mut current = my_pid;

    for _ in 0..64 {
        if current <= 1 {
            return None;
        }
        let sysinfo_pid = Pid::from_u32(current);
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[sysinfo_pid]),
            false,
            refresh_kind,
        );
        let proc = sys.process(sysinfo_pid)?;

        let exe_str = proc
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cmd: Vec<String> = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();

        if sig_table.match_process(&exe_str, &cmd).is_some() {
            return Some(current);
        }

        current = match proc.parent() {
            Some(ppid) if ppid.as_u32() > 1 => ppid.as_u32(),
            _ => return None,
        };
    }
    None
}
