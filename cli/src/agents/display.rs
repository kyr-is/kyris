// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::profile::{AgentProfile, CapLevel, SurfaceState};
use super::registry::AgentDescriptor;

fn format_surface(state: &SurfaceState) -> String {
    match state.level {
        CapLevel::None => "none".to_string(),
        CapLevel::Adapted => match &state.mechanism {
            Some(mech) => format!("adapted({mech})"),
            None => "adapted".to_string(),
        },
        CapLevel::Native => "native".to_string(),
    }
}

pub fn print_summary(agents: &[(Box<dyn AgentDescriptor>, AgentProfile)]) {
    println!(
        " {:<14} {:<18} {:<18} {:<18} Status",
        "Agent", "Execution", "Tool", "Burn-Control"
    );
    for (descriptor, profile) in agents {
        if !profile.detected {
            println!(" {:<14} not found", descriptor.id());
            continue;
        }
        let status = if profile.execution.level == CapLevel::None
            && profile.tool.level == CapLevel::None
            && profile.burn_control.level == CapLevel::None
        {
            "detected, not configured".to_string()
        } else {
            "ok".to_string()
        };
        println!(
            " {:<14} {:<18} {:<18} {:<18} {}",
            descriptor.id(),
            format_surface(&profile.execution),
            format_surface(&profile.tool),
            format_surface(&profile.burn_control),
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
    println!(
        "  Execution:   {}",
        format_surface_detail(&profile.execution)
    );
    println!("  Tool:        {}", format_surface_detail(&profile.tool));
    println!(
        "  Burn-ctrl:   {}",
        format_surface_detail(&profile.burn_control)
    );
    match &profile.last_native_seen {
        Some(ts) => println!("  Native:      observed at {ts}"),
        None => println!("  Native:      not observed"),
    }
    if let Some(ts) = &profile.last_reconciled {
        println!("  Reconciled:  {ts}");
    }
    if !profile.managed_files.is_empty() {
        println!("  Managed files:");
        for fp in &profile.managed_files {
            println!("    {}", fp.path);
        }
    }
}

fn format_surface_detail(state: &SurfaceState) -> String {
    match state.level {
        CapLevel::None => "none".to_string(),
        CapLevel::Adapted => match &state.mechanism {
            Some(mech) => format!("adapted — {mech}"),
            None => "adapted".to_string(),
        },
        CapLevel::Native => "native".to_string(),
    }
}
