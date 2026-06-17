// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris policy` — check and change `AgentPact` policy behavior.
//!
//! - `check <command>` simulates a decision for a shell command.
//! - `enable` / `disable` toggle the user policy's enforcement mode
//!   (`enforce` ↔ `log`). Current mode is shown by `kyris status`.
//! - `compile` renders the compiled command-policy artifacts for an agent.
use clap::{Args, Subcommand};

#[derive(Args)]
#[command(arg_required_else_help = true)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Simulate the decision `AgentPact` would make for a shell command
    Check(crate::check::CheckArgs),
    /// Switch governance into enforce mode
    Enable(crate::lifecycle::run_state::EnableArgs),
    /// Switch governance into log-only mode
    Disable(crate::lifecycle::run_state::DisableArgs),
    /// Compile an agent's command policy and render the artifacts
    Compile(crate::compile_policy::CompilePolicyArgs),
}

pub fn run(args: PolicyArgs) {
    match args.command {
        PolicyCommand::Check(a) => crate::check::run(a),
        PolicyCommand::Enable(a) => crate::lifecycle::run_state::run_enable(a),
        PolicyCommand::Disable(a) => crate::lifecycle::run_state::run_disable(a),
        PolicyCommand::Compile(a) => crate::compile_policy::run(a),
    }
}
