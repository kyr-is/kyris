// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::agents::profile::CapLevel;
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
        let burn_ok = probe.burn_control.level != CapLevel::None;

        if !exec_ok || !burn_ok {
            let mut missing = Vec::new();
            if !exec_ok {
                missing.push("execution hooks");
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
                remediation: format!("Run `kyris agents setup {}` to configure.", agent.id()),
            });
        }
    }

    findings
}
