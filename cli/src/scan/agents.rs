// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write;

use crate::agents::profile::{AdaptedMechanism, CapLevel, SurfaceState};
use crate::agents::registry;

use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

pub fn scan() -> Vec<Finding> {
    let mut findings = Vec::new();

    for agent in registry::all_agents() {
        let probe = agent.probe();
        if !probe.detected {
            continue;
        }

        let exec_ok = probe.execution.level != CapLevel::None;
        let tool_ok = probe.tool.level != CapLevel::None;
        let burn_ok = probe.burn_control.level != CapLevel::None;

        if !exec_ok || !tool_ok || !burn_ok {
            let mut missing = Vec::new();
            if !exec_ok {
                missing.push("execution hooks");
            }
            if !tool_ok {
                missing.push("tool governance");
            }
            if !burn_ok {
                missing.push("traffic routing");
            }

            findings.push(Finding {
                category: FindingCategory::UngoverndAgent,
                severity: Severity::High,
                title: format!(
                    "{} is installed without full kyris integration",
                    agent.display_name()
                ),
                description: format!(
                    "{} is installed but missing: {}.",
                    agent.display_name(),
                    missing.join(", ")
                ),
                location: FindingLocation {
                    path: agent.id().to_string(),
                    line: None,
                },
                evidence: None,
                remediation: format!(
                    "Run `kyris agents setup {}` or wait for automatic reconciliation.",
                    agent.id()
                ),
            });
            continue;
        }

        scan_degraded_surfaces(agent.as_ref(), &probe, &mut findings);
    }

    findings
}

fn is_static_mechanism(state: &SurfaceState) -> bool {
    matches!(
        state.mechanism,
        Some(AdaptedMechanism::CompiledPolicy | AdaptedMechanism::ConfigRewrite)
    )
}

fn scan_degraded_surfaces(
    agent: &dyn registry::AgentDescriptor,
    probe: &crate::agents::probe::ProbeResult,
    findings: &mut Vec<Finding>,
) {
    let mut static_surfaces = Vec::new();
    if is_static_mechanism(&probe.execution) {
        static_surfaces.push(("execution", &probe.execution));
    }
    if is_static_mechanism(&probe.tool) {
        static_surfaces.push(("tool", &probe.tool));
    }
    if is_static_mechanism(&probe.burn_control) {
        static_surfaces.push(("burn-control", &probe.burn_control));
    }

    if static_surfaces.is_empty() {
        return;
    }

    let labels: Vec<String> = static_surfaces
        .iter()
        .map(|(name, s)| {
            let mech = s.mechanism.as_ref().unwrap();
            format!("{name}:{mech}")
        })
        .collect();

    let ask_dropped = check_ask_dropped(agent.id());
    if ask_dropped > 0 {
        findings.push(Finding {
            category: FindingCategory::DegradedAgent,
            severity: Severity::Medium,
            title: format!(
                "{} uses static policy with {} ask rules dropped",
                agent.display_name(),
                ask_dropped
            ),
            description: format!(
                "{} surfaces [{}] use static enforcement. {} ask rules cannot be expressed \
                 and were dropped, reducing policy fidelity.",
                agent.display_name(),
                labels.join(", "),
                ask_dropped,
            ),
            location: FindingLocation {
                path: agent.id().to_string(),
                line: None,
            },
            evidence: None,
            remediation: format!(
                "Review dropped rules with `kyris compile-policy --agent {}`. \
                 Consider switching to an agent with live hook support for full ask semantics.",
                agent.id()
            ),
        });
    } else {
        let compilation_gaps = check_compilation_gaps(agent.id());
        let severity = if compilation_gaps.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        };
        let mut description = format!(
            "{} surfaces [{}] rely on compiled policy or config rewrite, not live daemon mediation. \
             Policy changes require re-running setup.",
            agent.display_name(),
            labels.join(", "),
        );
        if !compilation_gaps.is_empty() {
            let _ = write!(
                description,
                " Additionally, {} policy dimensions cannot be expressed in compiled mode: {}.",
                compilation_gaps.len(),
                compilation_gaps.join("; ")
            );
        }
        findings.push(Finding {
            category: FindingCategory::DegradedAgent,
            severity,
            title: format!(
                "{} uses static enforcement on {}",
                agent.display_name(),
                labels.join(", ")
            ),
            description,
            location: FindingLocation {
                path: agent.id().to_string(),
                line: None,
            },
            evidence: None,
            remediation: format!(
                "Run `kyris agents setup {}` after policy changes to recompile.",
                agent.id()
            ),
        });
    }
}

fn check_compilation_gaps(agent_id: &str) -> Vec<String> {
    match agent_id {
        "codex-cli" => crate::compile_policy::detect_codex_gaps(None),
        _ => Vec::new(),
    }
}

fn check_ask_dropped(agent_id: &str) -> u32 {
    type Compiler = fn(Option<&std::path::Path>) -> Result<(serde_json::Value, u32), String>;
    let compiler: Option<Compiler> = match agent_id {
        "cline" => Some(crate::compile_policy::compile_cline_permissions_summary),
        "opencode" => Some(crate::compile_policy::compile_opencode_permissions),
        "codex-cli" => Some(crate::compile_policy::compile_codex_permissions),
        "gemini-cli" => Some(crate::compile_policy::compile_gemini_permissions),
        _ => None,
    };
    compiler
        .and_then(|c| c(None).ok())
        .map_or(0, |(_, dropped)| dropped)
}
