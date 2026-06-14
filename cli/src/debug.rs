// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris debug` — advanced diagnostics and support commands. Not part of the
//! command set normal users are expected to learn; run `status`, `doctor`, and
//! `logs` first. Covers runtime log-filter control, install/uninstall
//! verification, and the governance-coverage audit.
use clap::{Args, Subcommand};

use crate::diag_cmd::{self, DiagArgs, DiagCommand};

#[derive(Args)]
#[command(arg_required_else_help = true)]
pub struct DebugArgs {
    #[command(subcommand)]
    pub command: DebugCommand,
}

#[derive(Subcommand)]
pub enum DebugCommand {
    /// Flip kyrisd's log filter to a verbose preset for a bounded window
    TraceOn(crate::diag_cmd::TraceOnArgs),
    /// Revert kyrisd's log filter to the baseline immediately
    TraceOff,
    /// Show the currently-active log filter
    TraceStatus,
    /// Verify install/uninstall completed correctly (exit non-zero on failure)
    Verify(crate::lifecycle::verify::VerifyArgs),
    /// Forensic: detect LLM traffic bypassing kyris governance
    Audit(crate::audit::AuditArgs),
}

pub fn run(args: DebugArgs) {
    match args.command {
        DebugCommand::TraceOn(a) => diag_cmd::run(DiagArgs {
            command: DiagCommand::TraceOn(a),
        }),
        DebugCommand::TraceOff => diag_cmd::run(DiagArgs {
            command: DiagCommand::TraceOff,
        }),
        DebugCommand::TraceStatus => diag_cmd::run(DiagArgs {
            command: DiagCommand::Status,
        }),
        DebugCommand::Verify(a) => crate::lifecycle::verify::run(a),
        DebugCommand::Audit(a) => crate::audit::run(a),
    }
}
