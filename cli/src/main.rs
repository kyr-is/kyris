// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Kyris CLI (`kyris`). Developer-facing tool for agent governance:
//! event timeline/replay queries, security scanning, daemon lifecycle
//! management, agent integration, and `AgentPact` policy compilation.
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
// Crate-level allows. These are deliberate trade-offs for a CLI binary
// rather than a general-purpose library:
// - needless_pass_by_value: every `run(args: XArgs)` handler consumes its
//   Args struct top-to-bottom; passing by reference would force lifetime
//   annotations everywhere with no ergonomic gain.
// - missing_errors_doc / missing_panics_doc: pedantic lints intended for
//   library APIs that downstream crates document. `kyris` is a binary; the
//   public-ish `pub fn run(...)` surface is internal to this crate and is
//   only invoked from `main`. Adding `# Errors` / `# Panics` sections to
//   every internal entry point would be docs-cargo-culting.
// - must_use_candidate: `Result`-returning helpers are always consumed by
//   `?` or explicit match in the same crate; tagging them `#[must_use]`
//   adds noise without catching real bugs.
#![allow(
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]
#![cfg_attr(test, allow(non_snake_case))]

mod agents;
mod always_cmd;
mod check;
mod compile_policy;
mod config_writer;
mod continue_cmd;
mod diag_cmd;
mod doctor;
mod headline;
mod hook_cmd;
mod integration;
mod json_patch_ops;
mod lifecycle;
mod logs_cmd;
mod mcp_cmd;
mod pending;
mod query;
mod scan;
mod service;
mod state;
mod status;
mod toml_patch;
mod version;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kyris", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Agents(agents::AgentsArgs),
    Always(always_cmd::AlwaysArgs),
    Approvals(query::approvals::ApprovalsArgs),
    Timeline(query::timeline::TimelineArgs),
    Replay(query::replay::ReplayArgs),
    Stats(query::stats::StatsArgs),
    History(query::history::HistoryArgs),
    Check(check::CheckArgs),
    CompilePolicy(compile_policy::CompilePolicyArgs),
    Diag(diag_cmd::DiagArgs),
    Hook(hook_cmd::HookArgs),
    Pending(pending::PendingArgs),
    Continue(continue_cmd::ContinueArgs),
    Doctor(doctor::DoctorArgs),
    Scan(scan::ScanArgs),
    Install,
    Enroll(lifecycle::enroll::EnrollArgs),
    Update(lifecycle::update::UpdateArgs),
    Daemon(lifecycle::daemon_cmd::DaemonArgs),
    Logs(logs_cmd::LogsArgs),
    Mcp(mcp_cmd::McpArgs),
    Disable(lifecycle::run_state::DisableArgs),
    Enable(lifecycle::run_state::EnableArgs),
    Uninstall(lifecycle::uninstall::UninstallArgs),
    Verify(lifecycle::verify::VerifyArgs),
    Status(status::StatusArgs),
    Version(version::VersionArgs),
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Agents(args) => agents::run(args),
        Command::Always(args) => always_cmd::run(args),
        Command::Approvals(args) => query::approvals::run(args),
        Command::Timeline(args) => query::timeline::run(args),
        Command::Replay(args) => query::replay::run(args),
        Command::Stats(args) => query::stats::run(args),
        Command::History(args) => query::history::run(args),
        Command::Check(args) => check::run(args),
        Command::CompilePolicy(args) => compile_policy::run(args),
        Command::Diag(args) => diag_cmd::run(args),
        Command::Hook(args) => hook_cmd::run(args),
        Command::Pending(args) => pending::run(args),
        Command::Continue(args) => continue_cmd::run(args),
        Command::Doctor(args) => doctor::run(args),
        Command::Scan(args) => scan::run(args),
        Command::Install => lifecycle::install::run(),
        Command::Enroll(args) => lifecycle::enroll::run(args),
        Command::Update(args) => lifecycle::update::run(args),
        Command::Daemon(args) => lifecycle::daemon_cmd::run(args),
        Command::Logs(args) => logs_cmd::run(args),
        Command::Mcp(args) => mcp_cmd::run(args),
        Command::Disable(args) => lifecycle::run_state::run_disable(args),
        Command::Enable(args) => lifecycle::run_state::run_enable(args),
        Command::Uninstall(args) => lifecycle::uninstall::run(args),
        Command::Verify(args) => lifecycle::verify::run(args),
        Command::Status(args) => status::run(args),
        Command::Version(args) => version::run(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn try_parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("kyris").chain(args.iter().copied()))
    }

    #[test]
    fn testParseVersion() {
        assert!(try_parse(&["version"]).is_ok());
    }

    #[test]
    fn testParseStatus() {
        assert!(try_parse(&["status"]).is_ok());
    }

    #[test]
    fn testParsePending() {
        assert!(try_parse(&["pending"]).is_ok());
    }

    #[test]
    fn testParseContinueNoArgsResetsAll() {
        // No session arg = reset every currently-tripped session.
        assert!(try_parse(&["continue"]).is_ok());
    }

    #[test]
    fn testParseContinueWithSession() {
        assert!(try_parse(&["continue", "sess-123"]).is_ok());
    }

    #[test]
    fn testParseCheck() {
        assert!(try_parse(&["check", "git status"]).is_ok());
    }

    #[test]
    fn testParseAgents() {
        assert!(try_parse(&["agents"]).is_ok());
    }

    #[test]
    fn testParseAgentsSetup() {
        assert!(try_parse(&["agents", "setup", "claude-code"]).is_ok());
    }

    #[test]
    fn testParseAgentsReconcile() {
        assert!(try_parse(&["agents", "reconcile"]).is_ok());
    }

    #[test]
    fn testParseMcpWrap() {
        assert!(try_parse(&["mcp", "wrap", "node", "server.js"]).is_ok());
    }

    #[test]
    fn testParseHookCheck() {
        assert!(try_parse(&["hook", "check", "--agent", "claude-code"]).is_ok());
    }

    #[test]
    fn testParseHookCheckMissingAgent() {
        assert!(try_parse(&["hook", "check"]).is_err());
    }

    #[test]
    fn testParseDisable() {
        assert!(try_parse(&["disable"]).is_ok());
    }

    #[test]
    fn testParseEnable() {
        assert!(try_parse(&["enable"]).is_ok());
    }

    #[test]
    fn testParseStopAndStartAreGone() {
        // Renamed to `disable`/`enable` when the sentinel mechanism
        // was retired in favor of a pure `mode: log` ↔ `mode: enforce`
        // toggle. Old verbs must not silently accept.
        assert!(try_parse(&["stop"]).is_err());
        assert!(try_parse(&["start"]).is_err());
    }

    #[test]
    fn testParseDaemonOnlyHasStatus() {
        // `kyris daemon start|stop` were replaced by top-level
        // `kyris disable|enable` (policy mode toggle). `kyris daemon
        // logs` was replaced by top-level `kyris logs` (all log files).
        // What remains is the focused kyrisd service probe.
        assert!(try_parse(&["daemon", "start"]).is_err());
        assert!(try_parse(&["daemon", "stop"]).is_err());
        assert!(try_parse(&["daemon", "logs"]).is_err());
        assert!(try_parse(&["daemon", "status"]).is_ok());
    }

    #[test]
    fn testParseDoctor() {
        assert!(try_parse(&["doctor"]).is_ok());
    }

    #[test]
    fn testParseLogs() {
        assert!(try_parse(&["logs"]).is_ok());
    }

    #[test]
    fn testParseLogsTrace() {
        assert!(try_parse(&["logs", "trace", "abc-123"]).is_ok());
    }

    #[test]
    fn testParseVerify() {
        assert!(try_parse(&["verify"]).is_ok());
    }

    #[test]
    fn testParseVerifyPostInstall() {
        assert!(try_parse(&["verify", "--post-install"]).is_ok());
    }

    #[test]
    fn testParseVerifyPostUninstall() {
        assert!(try_parse(&["verify", "--post-uninstall"]).is_ok());
    }

    #[test]
    fn testParseAlwaysList() {
        assert!(try_parse(&["always", "list"]).is_ok());
    }

    #[test]
    fn testParseAlwaysRevokeNamed() {
        assert!(try_parse(&["always", "revoke", "git·status"]).is_ok());
    }

    #[test]
    fn testParseAlwaysRevokeLast() {
        assert!(try_parse(&["always", "revoke", "--last"]).is_ok());
    }

    #[test]
    fn testParseAlwaysRevokeNoArgsFails() {
        assert!(try_parse(&["always", "revoke"]).is_err());
    }

    #[test]
    fn testParseAlwaysRevokeBothArgsFails() {
        assert!(try_parse(&["always", "revoke", "--last", "git·status"]).is_err());
    }

    #[test]
    fn testParseAlwaysNoSubcommandFails() {
        assert!(try_parse(&["always"]).is_err());
    }

    #[test]
    fn testParseUnknownSubcommandFails() {
        assert!(try_parse(&["nonexistent"]).is_err());
    }

    #[test]
    fn testParseNoArgsFails() {
        assert!(try_parse(&[]).is_err());
    }
}
