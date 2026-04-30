// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
pub mod apply;
pub mod display;
pub mod probe;
pub mod profile;
pub mod reconcile;
pub mod registry;
pub mod undo;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub command: Option<AgentsCommand>,

    /// Show detail for a specific agent (shorthand for `kyris agents status <agent>`)
    pub agent: Option<String>,
}

#[derive(Subcommand)]
pub enum AgentsCommand {
    /// Show agent status (default when no subcommand given)
    Status { agent: Option<String> },
    /// Reconcile agent integrations (detect reinstalls, repair config)
    Reconcile {
        agent: Option<String>,
        #[arg(long)]
        auto: bool,
    },
    /// Configure an agent to route through Kyris
    Setup {
        agent: Option<String>,
        #[arg(long)]
        auto: bool,
    },
    /// Remove all Kyris integrations for an agent
    Undo { agent: String },
}

pub fn run(args: AgentsArgs) {
    let result = match args.command {
        Some(AgentsCommand::Status { agent }) => run_status(agent),
        Some(AgentsCommand::Reconcile { agent, auto }) => run_reconcile(agent, auto),
        Some(AgentsCommand::Setup { agent, auto }) => run_setup(agent, auto),
        Some(AgentsCommand::Undo { agent }) => run_undo(&agent),
        None => {
            if let Some(agent) = args.agent {
                run_status(Some(agent))
            } else {
                run_status(None)
            }
        }
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_status(agent: Option<String>) -> Result<(), String> {
    let results = reconcile::reconcile_all(true)?;

    if let Some(agent_id) = agent {
        let (descriptor, profile) = results
            .into_iter()
            .find(|(d, _)| d.id() == agent_id)
            .ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
        display::print_detail(descriptor.as_ref(), &profile);
    } else {
        let refs: Vec<_> = results
            .iter()
            .map(|(d, p)| {
                let boxed: Box<dyn registry::AgentDescriptor> =
                    registry::agent_by_id(d.id()).expect("known agent");
                (boxed, p.clone())
            })
            .collect();
        display::print_summary(&refs);
    }
    Ok(())
}

fn run_reconcile(agent: Option<String>, auto: bool) -> Result<(), String> {
    if let Some(agent_id) = agent {
        let profile = reconcile::reconcile_one(&agent_id)?;
        let descriptor =
            registry::agent_by_id(&agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
        display::print_detail(descriptor.as_ref(), &profile);
    } else {
        let results = reconcile::reconcile_all(auto)?;
        if !auto {
            let refs: Vec<_> = results
                .iter()
                .map(|(d, p)| {
                    let boxed: Box<dyn registry::AgentDescriptor> =
                        registry::agent_by_id(d.id()).expect("known agent");
                    (boxed, p.clone())
                })
                .collect();
            display::print_summary(&refs);
        }
    }
    Ok(())
}

fn run_setup(agent: Option<String>, auto: bool) -> Result<(), String> {
    if auto {
        apply::apply_all()
    } else if let Some(agent_id) = agent {
        apply::apply_agent(&agent_id)
    } else {
        Err("Usage: kyris agents setup <agent> or kyris agents setup --auto".to_string())
    }
}

fn run_undo(agent_id: &str) -> Result<(), String> {
    undo::undo_agent(agent_id)
}
