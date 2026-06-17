// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris policy check` — a side-effect-free preview of how agentpactd would
//! classify a command. This is purely a presentation layer: all wire
//! construction, socket I/O, response parsing, and socket-path resolution live
//! in `kyris-agentpact-client` (per BOUNDARY.md, only that crate talks to
//! agentpactd). Here we resolve the cwd, call the client, render the result,
//! and map it to an exit code.
use agentpact::catalog::commands::id_to_shell;
use clap::Args;
use kyris_agentpact_client as pact_client;
use std::time::Duration;

/// How long to wait on the agentpactd socket for a `check` preview before
/// giving up. A `check` is interactive and read-only, so a short bound keeps a
/// stuck daemon from hanging the CLI.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Args)]
pub struct CheckArgs {
    pub command: String,
}

pub fn run(args: CheckArgs) {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let sock = pact_client::default_socket_path();

    let check = match pact_client::check_command(
        &sock.to_string_lossy(),
        &args.command,
        Some(&cwd),
        CHECK_TIMEOUT,
    ) {
        Ok(check) => check,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    println!("Decision: {}", check.decision);
    if let Some(rule) = &check.matched_rule {
        println!("Matched rule: {}", id_to_shell(rule));
    }
    if let Some(reason) = &check.reason {
        println!("Reason: {reason}");
    }

    std::process::exit(decision_to_exit_code(&check.decision));
}

fn decision_to_exit_code(decision: &str) -> i32 {
    match decision {
        "auto" | "inform" => 0,
        "ask" => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testDecisionToExitCodeAuto() {
        assert_eq!(decision_to_exit_code("auto"), 0);
        assert_eq!(decision_to_exit_code("inform"), 0);
    }

    #[test]
    fn testDecisionToExitCodeDeny() {
        assert_eq!(decision_to_exit_code("deny"), 1);
        assert_eq!(decision_to_exit_code("unknown"), 1);
        assert_eq!(decision_to_exit_code(""), 1);
    }

    #[test]
    fn testDecisionToExitCodeAsk() {
        assert_eq!(decision_to_exit_code("ask"), 2);
    }
}
