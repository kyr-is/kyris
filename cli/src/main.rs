// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Kyris CLI (`kyris`). Developer-facing tool for agent governance:
//! event timeline/replay queries, security scanning, daemon lifecycle
//! management, agent setup, and `AgentPact` policy compilation.
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]
#![cfg_attr(test, allow(non_snake_case))]

mod check;
mod compile_policy;
mod continue_cmd;
mod integration;
mod lifecycle;
mod mcp_cmd;
mod pending;
mod query;
mod scan;
mod service;
mod setup;
mod state;
mod status;
mod version;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kyris")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Timeline(query::timeline::TimelineArgs),
    Replay(query::replay::ReplayArgs),
    Stats(query::stats::StatsArgs),
    History(query::history::HistoryArgs),
    Check(check::CheckArgs),
    CompilePolicy(compile_policy::CompilePolicyArgs),
    Pending(pending::PendingArgs),
    Continue(continue_cmd::ContinueArgs),
    Scan(scan::ScanArgs),
    Install(lifecycle::install::InstallArgs),
    Enroll(lifecycle::enroll::EnrollArgs),
    Setup(setup::SetupArgs),
    Update(lifecycle::update::UpdateArgs),
    Daemon(lifecycle::daemon_cmd::DaemonArgs),
    Mcp(mcp_cmd::McpArgs),
    Uninstall(lifecycle::uninstall::UninstallArgs),
    Status(status::StatusArgs),
    Version(version::VersionArgs),
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Timeline(args) => query::timeline::run(args),
        Command::Replay(args) => query::replay::run(args),
        Command::Stats(args) => query::stats::run(args),
        Command::History(args) => query::history::run(args),
        Command::Check(args) => check::run(args),
        Command::CompilePolicy(args) => compile_policy::run(args),
        Command::Pending(args) => pending::run(args),
        Command::Continue(args) => continue_cmd::run(args),
        Command::Scan(args) => scan::run(args),
        Command::Install(args) => lifecycle::install::run(args),
        Command::Enroll(args) => lifecycle::enroll::run(args),
        Command::Setup(args) => setup::run(args),
        Command::Update(args) => lifecycle::update::run(args),
        Command::Daemon(args) => lifecycle::daemon_cmd::run(args),
        Command::Mcp(args) => mcp_cmd::run(args),
        Command::Uninstall(args) => lifecycle::uninstall::run(args),
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
    fn testParseContinue() {
        assert!(try_parse(&["continue"]).is_err());
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
    fn testParseSetup() {
        assert!(try_parse(&["setup", "claude-code"]).is_ok());
    }

    #[test]
    fn testParseSetupList() {
        assert!(try_parse(&["setup", "--list"]).is_ok());
    }

    #[test]
    fn testParseMcpWrap() {
        assert!(try_parse(&["mcp", "wrap", "node", "server.js"]).is_ok());
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
