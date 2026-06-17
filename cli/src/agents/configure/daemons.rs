// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Governance-daemon reachability checks used by the setup/configure flows:
//! kyrisd health (routing/burn) and agentpactd liveness (execution/tool
//! governance), plus the pure error-message builder they share.

/// Poll `/healthz` until kyrisd responds successfully or `timeout_secs` elapses.
/// Returns `true` if kyrisd became healthy within the timeout.
pub fn wait_for_kyrisd_ready(base_url: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if verify_kyrisd_health(base_url).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

pub(super) fn verify_kyrisd_health(base_url: &str) -> Result<(), String> {
    let url = format!("{base_url}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime: {e}"))?;

    runtime.block_on(async {
        let response = reqwest::get(&url)
            .await
            .map_err(|e| format!("kyrisd is not reachable at {url}: {e}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "kyrisd health check failed at {url}: {}",
                response.status()
            ))
        }
    })
}

/// Resolve the agentpactd socket the same way `kyris status` does
/// (`AGENTPACT_SOCK` override, else `~/.agentpact/agentpact.sock`).
fn agentpactd_socket_path() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn agentpactd_reachable() -> bool {
    agentpactd_reachable_at(&agentpactd_socket_path())
}

/// True iff agentpactd answers a `daemon.health` probe at `socket_path`
/// (a real round-trip, not just a socket connect).
pub(super) fn agentpactd_reachable_at(socket_path: &str) -> bool {
    kyris_agentpact_client::probe_daemon_health(socket_path, std::time::Duration::from_secs(2))
}

/// Pure builder for the "governance not active" setup error. Returns `None`
/// when every required daemon is reachable. Split out so the message/decision
/// logic is testable without live daemons.
pub(super) fn governance_daemons_error(
    agent_id: &str,
    kyrisd_problem: Option<String>,
    agentpactd_down: bool,
) -> Option<String> {
    let mut down: Vec<String> = Vec::new();
    if let Some(problem) = kyrisd_problem {
        down.push(format!(
            "kyrisd unreachable ({problem}) — model routing / burn-control will not work \
             (try `launchctl kickstart gui/$UID/is.kyr.kyrisd` or reinstall)"
        ));
    }
    if agentpactd_down {
        down.push(
            "agentpactd unreachable — command & MCP governance will not enforce; the agent \
             would run UNGOVERNED (start agentpactd or reinstall)"
                .to_string(),
        );
    }
    if down.is_empty() {
        return None;
    }
    Some(format!(
        "{agent_id} configured, but governance is NOT active:\n  - {}\n\
         The configuration is in place — re-run `kyris agent setup {agent_id}` once the daemon(s) are up.",
        down.join("\n  - ")
    ))
}

/// Verify the daemons the just-configured surfaces depend on: kyrisd always
/// (routing/burn), and agentpactd when `check_agentpactd` (execution/tool
/// governance). Changes are already applied (kept-changes contract); this only
/// decides whether to report success or an actionable error.
pub(super) fn verify_governance_daemons(
    base_url: &str,
    agent_id: &str,
    check_agentpactd: bool,
) -> Result<(), String> {
    let kyrisd_problem = verify_kyrisd_health(base_url).err();
    let agentpactd_down = check_agentpactd && !agentpactd_reachable();
    match governance_daemons_error(agent_id, kyrisd_problem, agentpactd_down) {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
}
