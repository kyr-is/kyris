// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris always` — manage `agentpactd` "always" overrides stored in
//! `.agentpact/policy/commands.local.yaml`. The CLI edits the file directly;
//! the running daemon re-reads policy on every `permission.request`, so
//! changes take effect immediately without a reload.
use std::path::PathBuf;

use agentpact::policy::always::{self, AlwaysError, OverrideSection, RevokeTarget};
use clap::{ArgGroup, Args, Subcommand};

#[derive(Args)]
pub struct AlwaysArgs {
    #[command(subcommand)]
    pub command: AlwaysCommand,
}

#[derive(Subcommand)]
pub enum AlwaysCommand {
    /// Show active overrides with file paths and `created_at`.
    List,
    /// Revoke an active override.
    Revoke(RevokeArgs),
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(["selector", "last"]),
))]
pub struct RevokeArgs {
    /// Command or path selector to revoke.
    pub selector: Option<String>,
    /// Revoke the most recently created override (by `created_at`).
    #[arg(long, conflicts_with = "selector")]
    pub last: bool,
}

pub fn run(args: AlwaysArgs) {
    let result = match args.command {
        AlwaysCommand::List => run_list(),
        AlwaysCommand::Revoke(revoke) => run_revoke(revoke),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_list() -> Result<(), String> {
    let (working_dir, home_dir) = resolve_dirs()?;
    let user_policy_dir = agentpact::config::default_user_policy_dir(&home_dir);
    let overrides = always::list_overrides(&working_dir, &home_dir, &user_policy_dir)
        .map_err(|e| e.to_string())?;
    if overrides.is_empty() {
        println!("No active overrides.");
        return Ok(());
    }

    for entry in overrides {
        let kind = match entry.section {
            OverrideSection::Command => "command",
            OverrideSection::Path => "path",
            OverrideSection::Mcp => "mcp",
        };
        println!(
            "{kind}\t{}\t{}\t{}",
            entry.selector,
            entry.created_at.to_rfc3339(),
            entry.file_path.display(),
        );
    }
    Ok(())
}

fn run_revoke(args: RevokeArgs) -> Result<(), String> {
    let (working_dir, home_dir) = resolve_dirs()?;
    let (target, target_label) = if args.last {
        (RevokeTarget::Last, "--last".to_string())
    } else {
        let selector = args
            .selector
            .expect("clap arg group enforces selector or --last");
        (RevokeTarget::Named(selector.clone()), selector)
    };

    let user_policy_dir = agentpact::config::default_user_policy_dir(&home_dir);
    let written_path = always::revoke_override(&working_dir, target, &home_dir, &user_policy_dir)
        .map_err(|e: AlwaysError| e.to_string())?;
    println!("Revoked {target_label} in {}", written_path.display());
    Ok(())
}

fn resolve_dirs() -> Result<(PathBuf, PathBuf), String> {
    let working_dir = std::env::current_dir().map_err(|err| format!("current_dir: {err}"))?;
    let home_dir = std::env::var("HOME").map_or_else(|_| PathBuf::from("/"), PathBuf::from);
    Ok((working_dir, home_dir))
}
