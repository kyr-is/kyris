// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;

use super::profile::{AgentProfile, CapLevel, SurfaceState};
use super::registry::AgentDescriptor;

const STALE_THRESHOLD_MINUTES: i64 = 30;

fn format_surface_short(state: &SurfaceState) -> String {
    match state.level {
        CapLevel::None => "-".to_string(),
        CapLevel::Native => "native".to_string(),
        CapLevel::Adapted => match &state.mechanism {
            Some(mech) => format!("{mech}"),
            None => "adapted".to_string(),
        },
    }
}

fn format_agent_specific(profile: &AgentProfile) -> String {
    if profile.agent_specific.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<_> = profile.agent_specific.iter().collect();
    pairs.sort_by_key(|(k, _)| k.as_str());
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn print_summary(agents: &[(Box<dyn AgentDescriptor>, AgentProfile)]) {
    println!(
        " {:<14} {:<12} {:<12} {:<12} {:<30} Status",
        "Agent", "Command", "MCP", "Burn", "Agent-Specific"
    );
    for (descriptor, profile) in agents {
        if !profile.detected {
            println!(" {:<14} not found", descriptor.id());
            continue;
        }
        let (need_exec, need_tool, need_burn) = descriptor.expected_surfaces();
        let exec_met = !need_exec || profile.execution.level != CapLevel::None;
        let tool_met = !need_tool || profile.tool.level != CapLevel::None;
        let burn_met = !need_burn || profile.burn_control.level != CapLevel::None;
        let has_compiled_only = profile.execution.is_compiled_only()
            || profile.tool.is_compiled_only()
            || profile.burn_control.is_compiled_only();
        let is_stale = profile
            .last_reconciled
            .is_some_and(|ts| (Utc::now() - ts).num_minutes() > STALE_THRESHOLD_MINUTES);
        let status = if exec_met && tool_met && burn_met && !has_compiled_only {
            if is_stale {
                "ok (stale)".to_string()
            } else {
                "ok".to_string()
            }
        } else if exec_met && tool_met && burn_met && has_compiled_only {
            if is_stale {
                "compiled-only (stale)".to_string()
            } else {
                "compiled-only".to_string()
            }
        } else if profile.execution.level == CapLevel::None
            && profile.tool.level == CapLevel::None
            && profile.burn_control.level == CapLevel::None
        {
            "detected, not configured".to_string()
        } else {
            "incomplete".to_string()
        };
        println!(
            " {:<14} {:<12} {:<12} {:<12} {:<30} {}",
            descriptor.id(),
            format_surface_short(&profile.execution),
            format_surface_short(&profile.tool),
            format_surface_short(&profile.burn_control),
            format_agent_specific(profile),
            status,
        );
    }
}

pub fn print_detail(descriptor: &dyn AgentDescriptor, profile: &AgentProfile) {
    println!("{}", descriptor.id());
    if !profile.detected {
        println!("  Status: not found");
        return;
    }
    let has_native = profile.execution.level == CapLevel::Native
        || profile.tool.level == CapLevel::Native
        || profile.burn_control.level == CapLevel::Native;
    if has_native {
        println!("  native support:    active");
    } else {
        println!("  native support:    - (no agent support)");
    }
    println!(
        "  command control:   {}",
        format_control_line(&profile.execution)
    );
    println!(
        "  mcp control:       {}",
        format_control_line(&profile.tool)
    );
    println!(
        "  burn control:      {}",
        format_control_line(&profile.burn_control)
    );
    if !profile.agent_specific.is_empty() {
        let mut pairs: Vec<_> = profile.agent_specific.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in &pairs {
            println!("  {k}:  {v}");
        }
    }
    if let Some(ts) = profile.last_reconciled {
        let age_mins = (Utc::now() - ts).num_minutes();
        if age_mins > STALE_THRESHOLD_MINUTES {
            println!("  Reconciled:  {ts} (stale — {age_mins}m ago, daemon may not be running)");
        } else {
            println!("  Reconciled:  {ts}");
        }
    }
    if !profile.compilation_gaps.is_empty() {
        println!("  Compilation gaps:");
        for gap in &profile.compilation_gaps {
            println!("    - {gap}");
        }
    }
    if !profile.managed_files.is_empty() {
        println!("  Managed files:");
        for fp in &profile.managed_files {
            println!("    {}", fp.path);
        }
    }
}

fn format_control_line(state: &SurfaceState) -> String {
    match state.level {
        CapLevel::None => "-".to_string(),
        CapLevel::Native => "active (native)".to_string(),
        CapLevel::Adapted => {
            let via = match &state.mechanism {
                Some(mech) => format!("active via {}", mechanism_description(mech)),
                None => "active".to_string(),
            };
            if state.is_compiled_only() {
                format!("{via} (compiled-only, no in-band mediation)")
            } else {
                via
            }
        }
    }
}

fn mechanism_description(mech: &super::profile::AdaptedMechanism) -> &'static str {
    use super::profile::AdaptedMechanism;
    match mech {
        AdaptedMechanism::LiveHook => "hook",
        AdaptedMechanism::CompiledPolicy => "compiled policy",
        AdaptedMechanism::EnvVarProxy => "env shim",
        AdaptedMechanism::ConfigRewrite => "config rewrite",
        AdaptedMechanism::McpWrapping => "mcp wrapper",
    }
}
