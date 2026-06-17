// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris hook check` — native agent hook adapter. Reads an agent's hook
//! payload from stdin, maps it through the agent's `HookProtocol`, round-trips
//! to `agentpactd`, and handles `PACT_ASK` via `kyrisd`'s pending-approval
//! system. Writes the agent-native response (JSON or text) to stdout.
//!
//! This replaces `kyris-hook check-hook` for native agent hooks (Claude Code
//! `PreToolUse`, Codex CLI `PreToolUse`, Gemini CLI `BeforeTool`). Shell hooks
//! continue to use `kyris-hook check` for the fast synchronous path.

use clap::Args;

mod audit;
mod hold;
mod payload;
mod request;
mod resolve_shell;
mod response;
mod segments;

#[cfg(test)]
mod tests;

use hold::run_hold;
use request::run_check;
use resolve_shell::run_resolve_shell;

// Re-exported into module scope so `hook_cmd/tests.rs` (which keeps
// `use super::*`) can reach the items it exercises across every submodule.
#[cfg(test)]
use crate::agents::registry::{self, AllowResponse, HookProtocol, ToolMapping};
#[cfg(test)]
use payload::{derive_session_cwd, map_payload, parse_apply_patch_paths, resolve_relative_path};
#[cfg(test)]
use resolve_shell::read_tty_line;
#[cfg(test)]
use response::{agent_prompt_for, effective_allow_response, non_governed_response};
#[cfg(test)]
use segments::{PopupResult, SegClass, block_from_daemon_unavailable, run_segments};

#[derive(Args)]
pub struct HookArgs {
    #[command(subcommand)]
    pub command: HookCommand,
}

#[derive(clap::Subcommand)]
pub enum HookCommand {
    Check(HookCheckArgs),
    /// Delegate a `PACT_ASK` or circuit-breaker approval to kyrisd's
    /// pending-approval system. Used by shell hooks in non-interactive
    /// (no-TTY) shells where prompting is impossible. Blocks until the
    /// developer resolves the request via the approval popup, tray, or app,
    /// then sends
    /// `permission.respond` to agentpactd and exits 0 (approved) or
    /// non-zero (denied/failed).
    Hold(HookHoldArgs),
    /// Resolve an interactive shell-hook approval **per compound segment**.
    /// Invoked by the zsh/bash preexec hooks when `kyris-hook check` returns
    /// a normal ask (exit 2). Re-derives the compound split with a
    /// side-effect-free preview, then issues one real token-bearing request
    /// per segment: auto segments run silently, and each segment that needs
    /// approval gets its own prompt and its own "always" — on the TTY when
    /// one is available, else via kyrisd's pending-approval system. Exits 0
    /// (every segment allowed) or non-zero (a segment was denied/blocked).
    ResolveShell(HookResolveShellArgs),
}

#[derive(Args)]
pub struct HookHoldArgs {
    /// Approval ID from agentpactd (`req_id` field in kyris-hook output).
    #[arg(long)]
    pub req_id: String,
    /// Approval token from agentpactd.
    #[arg(long)]
    pub token: String,
    /// Human-readable description shown in the approval popup (the command text).
    #[arg(long)]
    pub display: String,
    /// Path to the agentpactd UDS socket (defaults to the standard location).
    #[arg(long)]
    pub socket: Option<String>,
}

#[derive(Args)]
pub struct HookCheckArgs {
    #[arg(long)]
    pub agent: String,
}

#[derive(Args)]
pub struct HookResolveShellArgs {
    /// The full shell command line the preexec hook intercepted.
    #[arg(long)]
    pub cmd: String,
    /// The shell's working directory (the request's `working_dir`).
    #[arg(long)]
    pub cwd: Option<String>,
    /// Path to the agentpactd UDS socket (defaults to the standard location).
    #[arg(long)]
    pub socket: Option<String>,
}

pub fn run(args: HookArgs) {
    match args.command {
        HookCommand::Check(check_args) => run_check(check_args),
        HookCommand::Hold(hold_args) => run_hold(hold_args),
        HookCommand::ResolveShell(resolve_args) => run_resolve_shell(resolve_args),
    }
}
