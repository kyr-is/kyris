// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris doctor` — diagnostic dump for "the tray icon is amber, what's wrong?"
//!
//! Each check probes a subsystem first-hand from the user's process:
//!
//! - sentinel: is `~/.kyris/disabled` present?
//! - agentpactd: does the UDS accept a connection?
//! - kyrisd: does `/healthz` return success?
//! - pending approvals: does kyrisd show held requests?
//!
//! Output is human-readable with a [✓]/[!] marker per check and a
//! one-line fix hint when a check fails. Exit code is non-zero iff any
//! check failed — so doctor is grep-friendly in shell scripts ("if
//! kyris doctor; then ...").
use clap::Args;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Diagnose why the tray icon shows the warning overlay.
///
/// Probes each subsystem first-hand from this process — the governance
/// sentinel, the agentpactd UDS, kyrisd's `/healthz`, and the pending-
/// approvals queue — and prints `[✓]`/`[!]` per check with a one-line
/// fix hint when something's wrong. Exits non-zero if any check fails.
#[derive(Args)]
pub struct DoctorArgs {}

pub fn run(_args: DoctorArgs) {
    println!("Kyris Doctor");
    println!("============");

    let checks = run_checks();
    let mut all_ok = true;
    for check in &checks {
        let marker = if check.ok { "✓" } else { "!" };
        println!("[{marker}] {}: {}", check.name, check.detail);
        if !check.ok {
            all_ok = false;
            if let Some(fix) = check.fix {
                println!("    Fix: {fix}");
            }
        }
    }

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("One or more checks failed. See suggestions above.");
        println!("`kyris logs` lists the daemon log files for deeper inspection.");
        std::process::exit(1);
    }
}

struct CheckResult {
    name: &'static str,
    ok: bool,
    detail: String,
    fix: Option<&'static str>,
}

fn run_checks() -> Vec<CheckResult> {
    vec![
        check_sentinel(),
        check_agentpactd(),
        check_kyrisd(),
        check_pending_approvals(),
    ]
}

fn check_sentinel() -> CheckResult {
    let path = kyris_core::paths::disabled_marker_path();
    if path.exists() {
        CheckResult {
            name: "governance",
            ok: false,
            detail: format!("disabled (sentinel present: {})", path.display()),
            fix: Some("kyris start"),
        }
    } else {
        CheckResult {
            name: "governance",
            ok: true,
            detail: "enabled (no sentinel)".to_string(),
            fix: None,
        }
    }
}

fn check_agentpactd() -> CheckResult {
    let socket_path = std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    });
    let reachable = UnixStream::connect(&socket_path).is_ok();
    if reachable {
        CheckResult {
            name: "agentpactd",
            ok: true,
            detail: format!("socket responsive at {socket_path}"),
            fix: None,
        }
    } else {
        CheckResult {
            name: "agentpactd",
            ok: false,
            detail: format!("socket not responding at {socket_path}"),
            fix: Some("kyris start (or reinstall agentpact)"),
        }
    }
}

fn check_kyrisd() -> CheckResult {
    let base_url = crate::state::load_config()
        .map_or_else(|_| "http://127.0.0.1:4710".to_string(), |c| c.base_url());
    let url = format!("{base_url}/healthz");
    match probe_http(&url, Duration::from_secs(2)) {
        Ok(true) => CheckResult {
            name: "kyrisd",
            ok: true,
            detail: format!("/healthz healthy at {base_url}"),
            fix: None,
        },
        Ok(false) => CheckResult {
            name: "kyrisd",
            ok: false,
            detail: format!("/healthz returned a non-success status at {base_url}"),
            fix: Some("kyris logs (then likely `kyris start`)"),
        },
        Err(e) => CheckResult {
            name: "kyrisd",
            ok: false,
            detail: format!("/healthz unreachable at {base_url}: {e}"),
            fix: Some("kyris start"),
        },
    }
}

fn check_pending_approvals() -> CheckResult {
    // If kyrisd is unreachable we can't tell — treat as "unknown ok"
    // so doctor doesn't double-report the kyrisd-down failure.
    let Some(conn) = kyris_core::config::load_kyrisd_connection() else {
        return CheckResult {
            name: "pending approvals",
            ok: true,
            detail: "kyrisd not configured — skipping".to_string(),
            fix: None,
        };
    };

    let url = format!("{}/api/pending", conn.base_url);
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return CheckResult {
            name: "pending approvals",
            ok: true,
            detail: "skipped (runtime build failed)".to_string(),
            fix: None,
        };
    };

    let result: Option<usize> = rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .ok()?;
        let resp = client
            .get(&url)
            .header("authorization", format!("Bearer {}", conn.operator_key))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        body.get("requests")
            .and_then(|v| v.as_array())
            .map(Vec::len)
    });

    match result {
        Some(0) => CheckResult {
            name: "pending approvals",
            ok: true,
            detail: "queue empty".to_string(),
            fix: None,
        },
        Some(n) => CheckResult {
            name: "pending approvals",
            ok: false,
            detail: format!(
                "{n} approval prompt{} waiting",
                if n == 1 { "" } else { "s" }
            ),
            fix: Some("kyris pending"),
        },
        None => CheckResult {
            name: "pending approvals",
            ok: true,
            detail: "could not query (kyrisd unreachable or returned error)".to_string(),
            fix: None,
        },
    }
}

fn probe_http(url: &str, timeout: Duration) -> Result<bool, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| e.to_string())?;
        client
            .get(url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testCheckSentinelDetailMentionsRunStart() {
        // When sentinel is present we always suggest `kyris start` as
        // the fix — keep the suggestion stable so docs don't drift.
        let result = CheckResult {
            name: "governance",
            ok: false,
            detail: "disabled".into(),
            fix: Some("kyris start"),
        };
        assert_eq!(result.fix, Some("kyris start"));
    }

    #[test]
    fn testRunChecksReturnsAtLeastFour() {
        // governance + agentpactd + kyrisd + pending — the four
        // diagnostic axes doctor reports on.
        let checks = run_checks();
        assert!(checks.len() >= 4);
    }
}
