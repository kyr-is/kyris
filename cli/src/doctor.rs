// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris doctor` — diagnostic dump for "the tray icon shows the
//! warning overlay, what's wrong?"
//!
//! Each check probes a subsystem first-hand from the user's process:
//!
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
/// Probes each subsystem first-hand from this process — the
/// agentpactd UDS, kyrisd's `/healthz`, and the pending-approvals
/// queue — and prints `[✓]`/`[!]` per check with a one-line fix hint
/// when something's wrong. Exits non-zero if any check fails.
#[derive(Args)]
pub struct DoctorArgs {}

pub fn run(_args: DoctorArgs) {
    // Headline first — single-line summary of effective enforcement
    // posture so the operator knows at a glance whether kyris is
    // mediating, observing-only, or broken before reading the per-
    // check detail block below.
    println!("{}", crate::headline::render());
    println!();

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
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let mut checks = vec![
        check_agentpactd(),
        check_kyrisd(),
        check_enrollment(),
        check_pending_approvals(),
        check_directory_effective_mode(&cwd),
    ];
    checks.extend(check_repo_policy_parse(&cwd));
    checks
}

fn check_directory_effective_mode(cwd: &std::path::Path) -> CheckResult {
    use agentpact::policy::resolution::{
        ModeSource, SYSTEM_POLICY_DIR, resolve_mode_at, resolve_mode_for,
    };
    use agentpact::protocol::types::Mode;

    let Some(here) = resolve_mode_at(cwd) else {
        return CheckResult {
            name: "effective mode (this directory)",
            ok: false,
            detail: "HOME is unset — cannot resolve user policy".to_string(),
            fix: Some("ensure HOME is exported"),
        };
    };

    let user_resolution = std::env::var("HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .map(|home| {
            let user_dir = agentpact::config::default_user_policy_dir(&home);
            resolve_mode_for(
                &home,
                &home,
                &user_dir,
                std::path::Path::new(SYSTEM_POLICY_DIR),
            )
        });

    let differs = user_resolution
        .as_ref()
        .is_some_and(|u| u.mode != here.mode);

    let here_label = match here.mode {
        Mode::Enforce => "enforce",
        Mode::Log => "log",
    };
    let source = match &here.source {
        ModeSource::Repo { path } => format!("repo override at {}", path.display()),
        ModeSource::User { path } => format!("user policy at {}", path.display()),
        ModeSource::System { path } => format!("system policy at {}", path.display()),
        ModeSource::BundledDefault => "bundled default (no user policy yet)".to_string(),
    };

    let detail = if differs {
        // SAFETY: differs implies user_resolution is Some.
        let user_label = match user_resolution
            .expect("user resolution present when differs is true")
            .mode
        {
            Mode::Enforce => "enforce",
            Mode::Log => "log",
        };
        format!("{here_label} (via {source}); differs from user-level mode `{user_label}`")
    } else {
        format!("{here_label} (via {source})")
    };

    CheckResult {
        name: "effective mode (this directory)",
        // The override is informational, not an error. Always `ok`
        // — a real problem would be a parse failure (handled below).
        ok: true,
        detail,
        fix: None,
    }
}

fn check_repo_policy_parse(cwd: &std::path::Path) -> Vec<CheckResult> {
    agentpact::policy::resolution::policy_diagnostics_at(cwd)
        .into_iter()
        .filter_map(|diag| {
            let err = diag.status.err()?;
            Some(CheckResult {
                name: "policy file parse",
                ok: false,
                detail: format!("{}: {err}", diag.path.display()),
                fix: Some("fix the YAML or delete the file"),
            })
        })
        .collect()
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
            fix: Some("reinstall agentpact (try `kyris doctor` for socket diagnostics)"),
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
            fix: Some("kyris logs (kyrisd is up but unhealthy — inspect logs)"),
        },
        Err(e) => CheckResult {
            name: "kyrisd",
            ok: false,
            detail: format!("/healthz unreachable at {base_url}: {e}"),
            fix: Some("launchctl kickstart gui/$UID/is.kyr.kyrisd (or reinstall)"),
        },
    }
}

fn check_enrollment() -> CheckResult {
    // Enrolled ⟺ a valid credentials.json is present; standalone otherwise.
    // Standalone is a normal, visible state — never a hard failure.
    match kyris_core::credentials::load() {
        Some(creds) => CheckResult {
            name: "enrollment",
            ok: true,
            detail: format!("enrolled (machine {})", creds.machine_id),
            fix: None,
        },
        None => CheckResult {
            name: "enrollment",
            ok: true,
            detail: "standalone (not enrolled): event sync disabled — run `kyris enroll` (pricing works without enrollment)".to_string(),
            fix: None,
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
    fn testRunChecksReturnsAtLeastThree() {
        // agentpactd + kyrisd + pending — the three diagnostic axes
        // doctor reports on after the sentinel mechanism was retired.
        let checks = run_checks();
        assert!(checks.len() >= 3);
    }
}
