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

mod activity;
mod agents;
mod audit;
mod check;
mod compile_policy;
mod config_writer;
mod debug;
mod diag_cmd;
mod doctor;
mod headline;
mod hook_cmd;
mod integration;
mod json_patch_ops;
mod lifecycle;
mod logs_cmd;
mod mcp_cmd;
mod operator;
mod policy;
mod query;
mod recent_approvals;
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
    // ── Setup ────────────────────────────────────────────────────────────
    /// Install Kyris local components
    Install,
    /// Remove Kyris local integrations
    Uninstall(lifecycle::uninstall::UninstallArgs),
    /// Update installed Kyris binaries
    Update(lifecycle::update::UpdateArgs),
    /// Enroll this machine with the hosted relay
    Enroll(lifecycle::enroll::EnrollArgs),

    // ── Daily use ────────────────────────────────────────────────────────
    /// Show effective posture and component health
    Status(status::StatusArgs),
    /// Manage supported agent integrations
    Agent(agents::AgentArgs),
    /// Inspect governed commands, tool calls, and model usage
    Activity(activity::ActivityArgs),
    /// Check and change policy behavior
    Policy(policy::PolicyArgs),

    // ── Support ──────────────────────────────────────────────────────────
    /// Diagnose local problems
    Doctor(doctor::DoctorArgs),
    /// Show log file locations
    Logs(logs_cmd::LogsArgs),
    /// Advanced diagnostics and support commands
    Debug(debug::DebugArgs),
    /// Print version information
    Version(version::VersionArgs),

    // ── Runtime ABI (hidden; invoked by generated agent configs) ─────────
    #[command(hide = true)]
    Hook(hook_cmd::HookArgs),
    #[command(hide = true)]
    Mcp(mcp_cmd::McpArgs),
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Install => lifecycle::install::run(),
        Command::Uninstall(args) => lifecycle::uninstall::run(args),
        Command::Update(args) => lifecycle::update::run(args),
        Command::Enroll(args) => lifecycle::enroll::run(args),
        Command::Status(args) => status::run(args),
        Command::Agent(args) => agents::run(args),
        Command::Activity(args) => activity::run(args),
        Command::Policy(args) => policy::run(args),
        Command::Doctor(args) => doctor::run(args),
        Command::Logs(args) => logs_cmd::run(args),
        Command::Debug(args) => debug::run(args),
        Command::Version(args) => version::run(args),
        Command::Hook(args) => hook_cmd::run(args),
        Command::Mcp(args) => mcp_cmd::run(args),
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

    // ── agent group ──────────────────────────────────────────────────────
    #[test]
    fn testParseAgentBareAndList() {
        assert!(try_parse(&["agent"]).is_ok());
        assert!(try_parse(&["agent", "list"]).is_ok());
    }

    #[test]
    fn testParseAgentStatusAndShorthand() {
        assert!(try_parse(&["agent", "status"]).is_ok());
        assert!(try_parse(&["agent", "status", "claude-code"]).is_ok());
        // bare `kyris agent <id>` is shorthand for status of that agent.
        assert!(try_parse(&["agent", "claude-code"]).is_ok());
    }

    #[test]
    fn testParseAgentSetup() {
        assert!(try_parse(&["agent", "setup", "claude-code"]).is_ok());
        assert!(try_parse(&["agent", "setup", "--all"]).is_ok());
        assert!(try_parse(&["agent", "setup", "codex-cli", "--set", "max-turns=100"]).is_ok());
    }

    #[test]
    fn testParseAgentDisconnect() {
        assert!(try_parse(&["agent", "disconnect", "claude-code"]).is_ok());
        // disconnect targets one agent; no bare form.
        assert!(try_parse(&["agent", "disconnect"]).is_err());
    }

    // ── activity group ───────────────────────────────────────────────────
    #[test]
    fn testParseActivity() {
        assert!(try_parse(&["activity"]).is_ok());
        assert!(try_parse(&["activity", "--last", "5"]).is_ok());
        assert!(try_parse(&["activity", "--agent", "claude-code", "--decision", "ask"]).is_ok());
        assert!(try_parse(&["activity", "stats"]).is_ok());
        assert!(try_parse(&["activity", "replay", "sess-1"]).is_ok());
        assert!(try_parse(&["activity", "trace", "abc-123"]).is_ok());
        assert!(try_parse(&["activity", "approvals"]).is_ok());
    }

    // ── policy group ─────────────────────────────────────────────────────
    #[test]
    fn testParsePolicy() {
        assert!(try_parse(&["policy", "check", "git status"]).is_ok());
        assert!(try_parse(&["policy", "enable"]).is_ok());
        assert!(try_parse(&["policy", "disable"]).is_ok());
        assert!(try_parse(&["policy", "compile", "--agent", "codex-cli"]).is_ok());
        // bare `policy` shows help (arg_required_else_help) rather than running.
        assert!(try_parse(&["policy"]).is_err());
    }

    // ── debug group ──────────────────────────────────────────────────────
    #[test]
    fn testParseDebug() {
        assert!(try_parse(&["debug", "trace-on"]).is_ok());
        assert!(try_parse(&["debug", "trace-off"]).is_ok());
        assert!(try_parse(&["debug", "trace-status"]).is_ok());
        assert!(try_parse(&["debug", "verify"]).is_ok());
        assert!(try_parse(&["debug", "verify", "--post-install"]).is_ok());
        assert!(try_parse(&["debug", "verify", "--post-uninstall"]).is_ok());
        assert!(try_parse(&["debug", "audit"]).is_ok());
        assert!(try_parse(&["debug"]).is_err());
    }

    // ── hidden ABI commands still parse ──────────────────────────────────
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
    fn testParseDoctorAndLogs() {
        assert!(try_parse(&["doctor"]).is_ok());
        assert!(try_parse(&["logs"]).is_ok());
    }

    #[test]
    fn testDeletedCommandsRejected() {
        // The reshape removed/regrouped these; they must NOT silently parse.
        for old in [
            "agents",
            "pending",
            "approvals",
            "continue",
            "timeline",
            "history",
            "stats",
            "replay",
            "check",
            "enable",
            "disable",
            "compile-policy",
            "daemon",
            "diag",
            "verify",
            "scan",
            "sandbox",
            "stop",
            "start",
        ] {
            assert!(
                try_parse(&[old]).is_err(),
                "deleted top-level command `{old}` must not parse"
            );
        }
        // `logs trace` moved to `activity trace`.
        assert!(try_parse(&["logs", "trace", "abc-123"]).is_err());
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
