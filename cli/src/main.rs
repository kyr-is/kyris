// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)]
#![cfg_attr(test, allow(non_snake_case))]

mod check;
mod compile_policy;
mod continue_cmd;
mod daemon_cmd;
mod enroll;
mod history;
mod install;
mod integration;
mod mcp_cmd;
mod pending;
mod replay;
mod scan;
mod service;
mod setup;
mod state;
mod stats;
mod status;
mod timeline;
mod uninstall;
mod update;
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
    Timeline(timeline::TimelineArgs),
    Replay(replay::ReplayArgs),
    Stats(stats::StatsArgs),
    History(history::HistoryArgs),
    Check(check::CheckArgs),
    CompilePolicy(compile_policy::CompilePolicyArgs),
    Pending(pending::PendingArgs),
    Continue(continue_cmd::ContinueArgs),
    Scan(scan::ScanArgs),
    Install(install::InstallArgs),
    Enroll(enroll::EnrollArgs),
    Setup(setup::SetupArgs),
    Update(update::UpdateArgs),
    Daemon(daemon_cmd::DaemonArgs),
    Mcp(mcp_cmd::McpArgs),
    Uninstall(uninstall::UninstallArgs),
    Status(status::StatusArgs),
    Version(version::VersionArgs),
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Timeline(args) => timeline::run(args),
        Command::Replay(args) => replay::run(args),
        Command::Stats(args) => stats::run(args),
        Command::History(args) => history::run(args),
        Command::Check(args) => check::run(args),
        Command::CompilePolicy(args) => compile_policy::run(args),
        Command::Pending(args) => pending::run(args),
        Command::Continue(args) => continue_cmd::run(args),
        Command::Scan(args) => scan::run(args),
        Command::Install(args) => install::run(args),
        Command::Enroll(args) => enroll::run(args),
        Command::Setup(args) => setup::run(args),
        Command::Update(args) => update::run(args),
        Command::Daemon(args) => daemon_cmd::run(args),
        Command::Mcp(args) => mcp_cmd::run(args),
        Command::Uninstall(args) => uninstall::run(args),
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
