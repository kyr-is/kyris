// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris sandbox` — toggle the OS session sandbox (experimental).
//!
//! When enabled, the per-agent PATH shims launch each agent inside an OS
//! sandbox (macOS Seatbelt) via `kyris-exec`, jailing the whole agent process
//! tree to its launch directory plus the agent's own dirs and temp. Inside a
//! verified jail, `agentpactd` relaxes workspace writes from Ask to Auto —
//! the prompt-reduction payoff — because the kernel already bounds the blast
//! radius.
//!
//! The switch is a single marker file, `~/.kyris/sandbox.on`, that the shim
//! checks on every launch (absent by default → no sandboxing). No daemon
//! restart is involved: the next agent you launch picks up the change.
//!
//! EXPERIMENTAL: the per-agent writable-dir carveout list (in `kyris-exec`)
//! is not yet validated against every real agent, so an agent may hit
//! "Operation not permitted" writing one of its own files until the list is
//! tuned. Enabling prints this caveat. Disable to return to advisory-only
//! governance instantly.

use clap::Args;

use crate::state::kyris_home;

#[derive(Args)]
pub struct SandboxArgs {
    #[command(subcommand)]
    pub command: SandboxCommand,
}

#[derive(clap::Subcommand)]
pub enum SandboxCommand {
    /// Turn the OS session sandbox on (writes `~/.kyris/sandbox.on`).
    Enable,
    /// Turn the OS session sandbox off (removes the marker).
    Disable,
    /// Report whether the sandbox is currently enabled.
    Status,
}

const MARKER_FILE: &str = "sandbox.on";

fn marker_path() -> Result<std::path::PathBuf, String> {
    Ok(kyris_home()?.join(MARKER_FILE))
}

pub fn run(args: SandboxArgs) {
    let result = match args.command {
        SandboxCommand::Enable => enable(),
        SandboxCommand::Disable => disable(),
        SandboxCommand::Status => status(),
    };
    if let Err(e) = result {
        eprintln!("[kyris] sandbox: {e}");
        std::process::exit(1);
    }
}

fn enable() -> Result<(), String> {
    let path = marker_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, b"")
        .map_err(|e| format!("cannot write marker {}: {e}", path.display()))?;
    println!("OS session sandbox ENABLED.");
    println!("  Newly launched agents will run jailed to their launch directory.");
    println!(
        "  Workspace writes auto-allow inside the jail; writes outside it are \
         blocked by the kernel."
    );
    println!();
    println!(
        "  EXPERIMENTAL: an agent may fail to write one of its own files if a \
         carveout is missing."
    );
    println!("  If an agent misbehaves, run `kyris sandbox disable` to revert instantly.");
    Ok(())
}

fn disable() -> Result<(), String> {
    let path = marker_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => {
            println!("OS session sandbox DISABLED. Newly launched agents run unsandboxed.");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("OS session sandbox already disabled.");
            Ok(())
        }
        Err(e) => Err(format!("cannot remove marker {}: {e}", path.display())),
    }
}

fn status() -> Result<(), String> {
    let path = marker_path()?;
    if path.exists() {
        println!("OS session sandbox: ENABLED ({})", path.display());
    } else {
        println!("OS session sandbox: disabled");
    }
    Ok(())
}
