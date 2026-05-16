// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
pub mod claude_code;
pub mod cline;
pub mod codex_cli;
pub mod codex_cli_schema;
pub mod configure;
pub mod display;
pub mod gemini_cli;
pub mod opencode;
pub mod prestage;
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
        /// Agent-specific settings as key=value pairs (e.g. --set max-budget-usd=50)
        #[arg(long = "set", value_name = "KEY=VALUE")]
        settings: Vec<String>,
    },
    /// Remove all Kyris integrations for an agent
    Undo { agent: String },
}

pub fn run(args: AgentsArgs) {
    let result = match args.command {
        Some(AgentsCommand::Status { agent }) => run_status(agent),
        Some(AgentsCommand::Reconcile { agent, auto }) => run_reconcile(agent, auto),
        Some(AgentsCommand::Setup {
            agent,
            auto,
            settings,
        }) => run_setup(agent, auto, settings),
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
    let results = reconcile::reconcile_all(true, None)?;

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
        let results = reconcile::reconcile_all(auto, None)?;
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

fn parse_settings(raw: Vec<String>) -> Result<std::collections::HashMap<String, String>, String> {
    let mut map = std::collections::HashMap::new();
    for entry in raw {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| format!("Invalid --set value '{entry}': expected KEY=VALUE"))?;
        if k.is_empty() {
            return Err(format!("Invalid --set value '{entry}': empty key"));
        }
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

fn run_setup(agent: Option<String>, auto: bool, settings: Vec<String>) -> Result<(), String> {
    let agent_specific = parse_settings(settings)?;
    if auto {
        if !agent_specific.is_empty() {
            return Err("--set cannot be used with --auto".to_string());
        }
        prestage::prestage_all(None)?;
        for agent in registry::all_agents() {
            if agent.is_installed()
                && let Err(e) = configure::configure_agent(
                    agent.id(),
                    &std::collections::HashMap::new(),
                    false,
                    None,
                )
            {
                eprintln!("{e}");
            }
        }
        Ok(())
    } else if let Some(agent_id) = agent {
        configure::setup_agent(&agent_id, &agent_specific)
    } else {
        Err("Usage: kyris agents setup <agent> or kyris agents setup --auto".to_string())
    }
}

fn run_undo(agent_id: &str) -> Result<(), String> {
    undo::undo_agent(agent_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testParseSettingsValid() {
        let result = parse_settings(vec![
            "max-budget-usd=50".to_string(),
            "max-turns=100".to_string(),
        ]);
        let map = result.unwrap();
        assert_eq!(map.get("max-budget-usd").unwrap(), "50");
        assert_eq!(map.get("max-turns").unwrap(), "100");
    }

    #[test]
    fn testParseSettingsEmpty() {
        let result = parse_settings(vec![]);
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn testParseSettingsMissingEquals() {
        let result = parse_settings(vec!["no-equals".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn testParseSettingsEmptyKey() {
        let result = parse_settings(vec!["=value".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn testParseSettingsEmptyValue() {
        let result = parse_settings(vec!["key=".to_string()]);
        let map = result.unwrap();
        assert_eq!(map.get("key").unwrap(), "");
    }

    #[test]
    fn testParseSettingsValueWithEquals() {
        let result = parse_settings(vec!["key=a=b".to_string()]);
        let map = result.unwrap();
        assert_eq!(map.get("key").unwrap(), "a=b");
    }
}
