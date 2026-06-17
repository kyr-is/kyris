// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;

use super::profile::{AgentProfile, CapLevel, CoverageCeiling, SurfaceState};
use super::registry::{AgentDescriptor, MechanismLabel, SurfaceIntegration, plan_label};

const STALE_THRESHOLD_MINUTES: i64 = 30;

fn format_surface_short<M: MechanismLabel>(state: &SurfaceState<M>) -> String {
    if state.not_applicable {
        return "n/a".to_string();
    }
    match state.level {
        CapLevel::None => "-".to_string(),
        CapLevel::Native => "native".to_string(),
        CapLevel::Adapted => match &state.mechanism {
            Some(mech) => mech.short().to_string(),
            None => "adapted".to_string(),
        },
    }
}

fn format_surface_with_plan<M: MechanismLabel>(
    state: &SurfaceState<M>,
    plan: SurfaceIntegration<M>,
) -> String {
    format!("{}/{}", format_surface_short(state), plan_label(&plan))
}

fn is_compiled_degradation<M>(state: &SurfaceState<M>, design: Option<CoverageCeiling>) -> bool {
    state.is_compiled_only() && design != Some(CoverageCeiling::Compiled)
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
        " {:<14} {:<16} {:<16} {:<16} {:<30} Status",
        "Agent", "Command obs/plan", "MCP obs/plan", "Burn obs/plan", "Agent-Specific"
    );
    for (descriptor, profile) in agents {
        if !profile.detected {
            println!(" {:<14} not found", descriptor.id());
            continue;
        }
        let plan = descriptor.integration_plan();
        let (need_exec, need_tool, need_burn) = descriptor.expected_surfaces();
        let exec_met = !need_exec
            || profile.execution.level != CapLevel::None
            || profile.execution.not_applicable;
        let tool_met =
            !need_tool || profile.tool.level != CapLevel::None || profile.tool.not_applicable;
        let burn_met = !need_burn
            || profile.burn_control.level != CapLevel::None
            || profile.burn_control.not_applicable;
        let (design_exec_ceiling, design_tool_ceiling, design_burn_ceiling) =
            descriptor.surface_design_ceilings();
        let has_compiled_only = is_compiled_degradation(&profile.execution, design_exec_ceiling)
            || is_compiled_degradation(&profile.tool, design_tool_ceiling)
            || is_compiled_degradation(&profile.burn_control, design_burn_ceiling);
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
            " {:<14} {:<16} {:<16} {:<16} {:<30} {}",
            descriptor.id(),
            format_surface_with_plan(&profile.execution, plan.execution),
            format_surface_with_plan(&profile.tool, plan.tool),
            format_surface_with_plan(&profile.burn_control, plan.burn_control),
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
    let plan = descriptor.integration_plan();
    let expects_native = plan.execution == SurfaceIntegration::AgentPactNative
        || plan.tool == SurfaceIntegration::AgentPactNative
        || plan.burn_control == SurfaceIntegration::AgentPactNative;
    let has_native = profile.execution.level == CapLevel::Native
        || profile.tool.level == CapLevel::Native
        || profile.burn_control.level == CapLevel::Native;
    if has_native {
        println!("  native support:    active");
    } else if expects_native {
        println!("  native support:    expected, not observed");
    } else {
        println!("  native support:    - (adapted integration)");
    }
    println!(
        "  command control:   {}",
        format_control_line(
            &profile.execution,
            plan.execution,
            profile.live_evidence.execution
        )
    );
    println!(
        "  mcp control:       {}",
        format_control_line(&profile.tool, plan.tool, profile.live_evidence.tool)
    );
    println!(
        "  burn control:      {}",
        format_control_line(
            &profile.burn_control,
            plan.burn_control,
            profile.live_evidence.burn_control
        )
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

/// `live` is the surface's last `.live-seen` breadcrumb. Only an ADAPTED
/// surface gets the annotation: "configured" is a filesystem claim, "live" is
/// observed behavior — the distinction the agent-interface review's fourth gap
/// called for (probes alone over-claim on artifact existence).
fn format_control_line<M: MechanismLabel>(
    state: &SurfaceState<M>,
    plan: SurfaceIntegration<M>,
    live: Option<chrono::DateTime<Utc>>,
) -> String {
    let planned = plan_label(&plan);
    if state.not_applicable {
        return format!("n/a (nothing to mediate; plan: {planned})");
    }
    let observed = match state.level {
        CapLevel::None => "-".to_string(),
        CapLevel::Native => "active (native)".to_string(),
        CapLevel::Adapted => {
            let via = match &state.mechanism {
                Some(mech) => format!("active via {}", mech.detail()),
                None => "active".to_string(),
            };
            let via = if state.is_compiled_only() {
                format!("{via} (compiled-only, no in-band mediation)")
            } else {
                via
            };
            match live {
                Some(ts) => format!("{via}, live {}", format_age(ts)),
                None => format!("{via}, not yet observed live"),
            }
        }
    };
    format!("{observed} (plan: {planned})")
}

/// Compact "Xm/Xh/Xd ago" for live-evidence timestamps.
fn format_age(ts: chrono::DateTime<Utc>) -> String {
    let mins = (Utc::now() - ts).num_minutes().max(0);
    if mins < 60 {
        format!("{mins}m ago")
    } else if mins < 48 * 60 {
        format!("{}h ago", mins / 60)
    } else {
        format!("{}d ago", mins / (24 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::registry::ExecutionMechanism;

    #[test]
    fn testFormatControlLineShowsNativeExpectedButNotObserved() {
        let line = format_control_line(
            &SurfaceState::<ExecutionMechanism>::none(),
            SurfaceIntegration::AgentPactNative,
            None,
        );

        assert_eq!(line, "- (plan: native)");
    }

    #[test]
    fn testFormatControlLineShowsObservedAndAdaptedPlan() {
        // Adapted-without-live-evidence must say so — "configured" is a
        // filesystem claim, not proof the surface works (fourth-gap honesty).
        let line = format_control_line(
            &SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter),
            SurfaceIntegration::adapted(vec![ExecutionMechanism::LiveHookAdapter]),
            None,
        );

        assert_eq!(line, "active via hook, not yet observed live (plan: hook)");
    }

    #[test]
    fn testFormatControlLineShowsLiveEvidenceAge() {
        let line = format_control_line(
            &SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter),
            SurfaceIntegration::adapted(vec![ExecutionMechanism::LiveHookAdapter]),
            Some(Utc::now() - chrono::Duration::minutes(5)),
        );

        assert_eq!(line, "active via hook, live 5m ago (plan: hook)");
    }

    #[test]
    fn testFormatSurfaceWithPlanShowsObservedAndPlanWhenTheyDiffer() {
        // A real obs≠plan case: codex/gemini execution falls back to compiled
        // policy when the live hook isn't active. The observed mechanism
        // (policy) legitimately differs from the multi-mechanism plan
        // (hook+policy), and the formatter surfaces both. Both labels now come
        // from the SAME per-surface vocabulary, so a `config/provider`-style skew
        // for a correctly-configured surface is impossible by construction —
        // which is why the old label-alignment test is gone.
        let line = format_surface_with_plan(
            &SurfaceState::adapted(ExecutionMechanism::CompiledPolicy),
            SurfaceIntegration::adapted(vec![
                ExecutionMechanism::LiveHookAdapter,
                ExecutionMechanism::CompiledPolicy,
            ]),
        );

        assert_eq!(line, "policy/hook+policy");
    }
}
