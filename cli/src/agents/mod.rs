// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
pub mod adaptation;
pub mod capabilities;
// codex's irreducible governance realization is kept (delegated by its document
// via `GenericAgent`); the other four agents are now their JSON documents only.
pub mod codex_cli;
pub mod codex_cli_schema;
pub mod configure;
pub mod display;
pub mod documents;
pub mod engine;
pub mod generic;
pub mod manifest;
pub mod prestage;
pub mod probe;
pub mod profile;
pub mod reconcile;
pub mod registry;
pub mod shim;
pub mod templates;
pub mod undo;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: Option<AgentCommand>,

    /// Show detail for a specific agent (shorthand for `kyris agent status <agent>`)
    pub agent: Option<String>,
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// List supported agents and their integration status (default)
    List,
    /// Show agent status
    Status { agent: Option<String> },
    /// Configure an agent to route through Kyris. Idempotent: re-running
    /// repairs drift and re-integrates a disconnected agent. With `--all`,
    /// configures every detected agent (skipping disconnected ones).
    Setup {
        agent: Option<String>,
        #[arg(long)]
        all: bool,
        /// Agent-specific settings as key=value pairs (e.g. --set max-budget-usd=50)
        #[arg(long = "set", value_name = "KEY=VALUE")]
        settings: Vec<String>,
    },
    /// Remove Kyris's integration from an agent (the agent itself stays
    /// installed; it just stops being governed until you `setup` it again).
    Disconnect { agent: String },
}

pub fn run(args: AgentArgs) {
    let result = match args.command {
        Some(AgentCommand::List) | None if args.agent.is_none() => run_status(None),
        None => run_status(args.agent),
        Some(AgentCommand::List) => run_status(None),
        Some(AgentCommand::Status { agent }) => run_status(agent),
        Some(AgentCommand::Setup {
            agent,
            all,
            settings,
        }) => run_setup(agent, all, settings),
        Some(AgentCommand::Disconnect { agent }) => run_disconnect(&agent),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_status(agent: Option<String>) -> Result<(), String> {
    // Status is read-only: snapshot persisted profile + live probe, never
    // configure/repair/persist. Mutating reconcile is the daemon's job (plus
    // explicit `kyris agent setup` / `reconcile`). See `status_snapshot_all`.
    let results = reconcile::status_snapshot_all()?;

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

fn run_setup(agent: Option<String>, all: bool, settings: Vec<String>) -> Result<(), String> {
    let agent_specific = parse_settings(settings)?;
    if all {
        if !agent_specific.is_empty() {
            return Err("--set cannot be used with --all".to_string());
        }
        // Configure + repair + promote every detected agent in one pass. This is
        // the full evidence-based reconcile (auto-configure new agents, repair
        // drift, promote adapted→native), which skips agents the user
        // disconnected (`reconcile_agent` honors `profile.disconnected`). It's also
        // the entry point the reconcile watcher drives, so bulk setup and the
        // watcher share one code path.
        prestage::prestage_all(None)?;
        reconcile::reconcile_all(false, None).map(|_| ())
    } else if let Some(agent_id) = agent {
        // setup_agent applies settings + (re)configures surfaces; reconcile_one
        // then runs the evidence-based pass (native promotion + drift repair) so
        // a single `setup` fully subsumes the old `reconcile` verb. The second
        // pass is silent when there's nothing to promote/repair.
        configure::setup_agent(&agent_id, &agent_specific)?;
        reconcile::reconcile_one(&agent_id).map(|_| ())
    } else {
        Err("Usage: kyris agent setup <agent> or kyris agent setup --all".to_string())
    }
}

fn run_disconnect(agent_id: &str) -> Result<(), String> {
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
