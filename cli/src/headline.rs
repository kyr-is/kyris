// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! One-line banner summarizing kyris's effective enforcement posture
//! AT the directory where `kyris status` / `kyris doctor` was invoked.
//!
//! Shown as the very first line of both commands so the operator's
//! first read tells them whether kyris is enforcing, observing-only,
//! or in trouble — without having to scan a longer diagnostic block.
//! The format is intentionally single-line and grep-friendly:
//!
//!   Kyris — enforcing
//!   Kyris — enforcement disabled — log only
//!   Kyris — errors encountered — may not enforce correctly
//!   Kyris — errors encountered, enforcement disabled — may not enforce correctly
//!
//! When the **directory's** effective mode differs from the
//! **user-level** mode (i.e., a repo-local `.agentpact/policy/pact.yaml`
//! overrides for this tree), an extra clause is appended:
//!
//!   Kyris — enforcing  (this directory: log only via repo override at /path/.agentpact/policy/pact.yaml)
//!
//! Mode is resolved via [`agentpact::policy::resolution`] — same walk-up
//! the daemon uses. The reader works whether or not `agentpactd` is
//! running, which matters for `kyris doctor` (whose job includes
//! diagnosing a down daemon).
//!
//! Errors and log-mode are reported additively because they have
//! distinct fix paths — a stopped agentpactd is unrelated to whether
//! the user's policy file is set to `log`.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use agentpact::policy::resolution::{
    ModeResolution, ModeSource, SYSTEM_POLICY_DIR, resolve_mode_at, resolve_mode_for,
};
use kyris_core::agentpact::Mode;

/// Render the headline string for the current working directory.
///
/// Performs two probes (agentpactd socket, kyrisd `/healthz`) plus a
/// small walk-up YAML scan; total cost is bounded by the kyrisd HTTP
/// timeout (2s) below.
#[must_use]
pub fn render() -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    render_at(&cwd)
}

/// Render the headline as if invoked from `cwd`. Split from `render`
/// so smoke tests + future callers can drive the formatter
/// deterministically.
#[must_use]
pub fn render_at(cwd: &Path) -> String {
    let has_errors = !agentpactd_reachable() || !kyrisd_reachable();
    let cwd_mode = resolve_mode_at(cwd);
    let user_mode = std::env::var("HOME")
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

    compose(has_errors, cwd_mode.as_ref(), user_mode.as_ref())
}

/// Pure formatter — split out so tests can drive every state without
/// touching disk or network. The first argument is the error flag; the
/// next two are the resolved effective mode at the cwd and at the user
/// level (both `None` only when `HOME` is unset).
///
/// Precedence rules:
/// 1. Errors win the consequence clause unconditionally.
/// 2. The user-level mode shapes the headline's first half
///    (enforcing vs. enforcement disabled).
/// 3. If `cwd_mode != user_mode`, the directory override is appended
///    in parentheses with the source file path so the operator can
///    locate the file driving the difference.
fn compose(
    has_errors: bool,
    cwd_mode: Option<&ModeResolution>,
    user_mode: Option<&ModeResolution>,
) -> String {
    let user_log = user_mode.is_some_and(|r| r.mode == Mode::Log);

    let mut states: Vec<&'static str> = Vec::new();
    if has_errors {
        states.push("errors encountered");
    }
    if user_log {
        states.push("enforcement disabled");
    }

    let mut base = if states.is_empty() {
        "Kyris — enforcing".to_string()
    } else {
        // "may not enforce correctly" subsumes "log only" — if the
        // daemons aren't healthy, the user can't trust the mode
        // anyway, so report the stronger consequence.
        let consequence = if has_errors {
            "may not enforce correctly"
        } else {
            "log only"
        };
        format!("Kyris — {} — {}", states.join(", "), consequence)
    };

    if let Some(override_clause) = directory_override_clause(cwd_mode, user_mode) {
        base.push_str("  (");
        base.push_str(&override_clause);
        base.push(')');
    }
    base
}

/// If `cwd_mode` differs from `user_mode` in either direction, render
/// the user-facing "this directory: X via repo override at PATH" line.
/// Otherwise return `None` so the headline stays single-clause.
fn directory_override_clause(
    cwd_mode: Option<&ModeResolution>,
    user_mode: Option<&ModeResolution>,
) -> Option<String> {
    let cwd_mode = cwd_mode?;
    let user_mode = user_mode?;
    if cwd_mode.mode == user_mode.mode {
        return None;
    }
    let phrase = match cwd_mode.mode {
        Mode::Enforce => "enforcing",
        Mode::Log => "log only",
    };
    let source = match &cwd_mode.source {
        ModeSource::Repo { path } => format!("repo override at {}", path.display()),
        ModeSource::User { path } => format!("user override at {}", path.display()),
        ModeSource::System { path } => format!("system override at {}", path.display()),
        ModeSource::BundledDefault => "bundled default".to_string(),
    };
    Some(format!("this directory: {phrase} via {source}"))
}

fn agentpactd_reachable() -> bool {
    let socket = std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    });
    UnixStream::connect(&socket).is_ok()
}

fn kyrisd_reachable() -> bool {
    let base_url = crate::state::load_config()
        .map_or_else(|_| "http://127.0.0.1:4710".to_string(), |c| c.base_url());
    let url = format!("{base_url}/healthz");
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(async {
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
        else {
            return false;
        };
        client
            .get(&url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn user_at(mode: Mode) -> ModeResolution {
        ModeResolution {
            mode,
            source: ModeSource::User {
                path: PathBuf::from("/u/pact.yaml"),
            },
        }
    }

    fn repo_at(mode: Mode, path: &str) -> ModeResolution {
        ModeResolution {
            mode,
            source: ModeSource::Repo {
                path: PathBuf::from(path),
            },
        }
    }

    #[test]
    fn testComposeAllGoodEnforcing() {
        let user = user_at(Mode::Enforce);
        assert_eq!(
            compose(false, Some(&user), Some(&user)),
            "Kyris — enforcing"
        );
    }

    #[test]
    fn testComposeLogOnly() {
        let user = user_at(Mode::Log);
        assert_eq!(
            compose(false, Some(&user), Some(&user)),
            "Kyris — enforcement disabled — log only"
        );
    }

    #[test]
    fn testComposeErrorsOnly() {
        let user = user_at(Mode::Enforce);
        assert_eq!(
            compose(true, Some(&user), Some(&user)),
            "Kyris — errors encountered — may not enforce correctly"
        );
    }

    #[test]
    fn testComposeErrorsAndLogModeReportBothCausesOneConsequence() {
        let user = user_at(Mode::Log);
        assert_eq!(
            compose(true, Some(&user), Some(&user)),
            "Kyris — errors encountered, enforcement disabled — may not enforce correctly"
        );
    }

    #[test]
    fn testComposeAppendsRepoOverrideWhenCwdModeDiffers() {
        let user = user_at(Mode::Enforce);
        let cwd = repo_at(Mode::Log, "/repo/.agentpact/policy/pact.yaml");
        let line = compose(false, Some(&cwd), Some(&user));
        assert!(line.starts_with("Kyris — enforcing"), "{line}");
        assert!(
            line.contains(
                "(this directory: log only via repo override at /repo/.agentpact/policy/pact.yaml)"
            ),
            "{line}"
        );
    }

    #[test]
    fn testComposeOverrideAppendsAfterErrorClause() {
        // Both errors AND directory override → the override clause
        // sits at the end of the line, after the consequence.
        let user = user_at(Mode::Enforce);
        let cwd = repo_at(Mode::Log, "/r/pact.yaml");
        let line = compose(true, Some(&cwd), Some(&user));
        assert!(
            line.starts_with("Kyris — errors encountered — may not enforce correctly"),
            "{line}"
        );
        assert!(
            line.contains("(this directory: log only via repo"),
            "{line}"
        );
    }

    #[test]
    fn testComposeOmitsOverrideWhenModesAgree() {
        let user = user_at(Mode::Enforce);
        let cwd = repo_at(Mode::Enforce, "/r/pact.yaml");
        let line = compose(false, Some(&cwd), Some(&user));
        assert_eq!(line, "Kyris — enforcing");
        assert!(!line.contains("(this directory"), "{line}");
    }

    #[test]
    fn testComposeRendersEvenWhenUserModeMissing() {
        // HOME unset → user_mode is None. We can't compare against
        // anything, so the override clause is suppressed but the
        // base line still renders as "enforcing" (the safe stance).
        let line = compose(false, None, None);
        assert_eq!(line, "Kyris — enforcing");
    }
}
