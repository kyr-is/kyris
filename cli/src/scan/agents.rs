// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write;

use crate::agents::profile::{CapLevel, SurfaceState};
use crate::agents::registry;
use crate::agents::registry::MechanismLabel;

use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

// ---------------------------------------------------------------------------
// Vendor-native governance detection
// ---------------------------------------------------------------------------

/// An agent that ships with its own vendor-managed governance system (e.g.
/// Cursor Business admin controls, Windsurf Teams, GitHub org Copilot policy).
/// These are neither Kyris-governed nor ungoverned — they belong to a third
/// category that the scan must surface distinctly.
struct VendorAgent {
    id: &'static str,
    display_name: &'static str,
    /// Describes the vendor governance mechanism available for this agent.
    governance_note: &'static str,
    /// Phase roadmap note (Phase 2 target vs permanently out of scope).
    phase_note: &'static str,
}

const VENDOR_AGENTS: &[VendorAgent] = &[
    VendorAgent {
        id: "cursor",
        display_name: "Cursor",
        governance_note: "Cursor Business/Enterprise provides admin-level usage controls and audit \
             export (CSV). These controls are vendor-managed and invisible to Kyris.",
        phase_note: "Kyris does not govern Cursor in Phase 1.",
    },
    VendorAgent {
        id: "windsurf",
        display_name: "Windsurf",
        governance_note: "Windsurf Teams provides some admin controls. Kyris Phase 2 plans live \
             native hook integration for Windsurf.",
        phase_note: "Kyris support for Windsurf is a Phase 2 target.",
    },
    VendorAgent {
        id: "github-copilot",
        display_name: "GitHub Copilot",
        governance_note: "GitHub Copilot governance is configured via GitHub organisation settings \
             (policy controls, allowed models, seat management). Activity is audited \
             through GitHub's own audit log, not through Kyris.",
        phase_note: "Kyris does not govern GitHub Copilot in Phase 1.",
    },
];

fn is_vendor_agent_installed(agent: &VendorAgent) -> bool {
    match agent.id {
        "cursor" => {
            std::path::Path::new("/Applications/Cursor.app").exists()
                || crate::state::find_in_path("cursor").is_some()
        }
        "windsurf" => {
            std::path::Path::new("/Applications/Windsurf.app").exists()
                || crate::state::find_in_path("windsurf").is_some()
        }
        "github-copilot" => {
            let home = std::env::var("HOME").unwrap_or_default();
            // Copilot CLI via gh extension
            std::path::Path::new(&format!("{home}/.config/gh/extensions/gh-copilot")).exists()
            // Copilot IDE via VS Code extension directory
            || copilot_vscode_extension_exists(&home)
        }
        _ => false,
    }
}

fn copilot_vscode_extension_exists(home: &str) -> bool {
    let ext_dir = std::path::PathBuf::from(format!("{home}/.vscode/extensions"));
    std::fs::read_dir(ext_dir).ok().is_some_and(|entries| {
        entries.flatten().any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("github.copilot")
        })
    })
}

fn build_vendor_finding(agent: &VendorAgent) -> Finding {
    Finding {
        category: FindingCategory::VendorNativeAgent,
        // Info: the agent has SOME governance — it is not ungoverned. The gap
        // is that Kyris cannot audit or enforce policy for it.
        severity: Severity::Info,
        title: format!("{} is not governed by Kyris", agent.display_name),
        description: format!(
            "{} is installed but operates outside Kyris governance. {}",
            agent.display_name, agent.governance_note,
        ),
        location: FindingLocation {
            path: agent.id.to_string(),
            line: None,
        },
        evidence: None,
        remediation: format!(
            "{} For full Kyris audit coverage, use a Kyris-compatible agent \
             (claude-code, codex-cli, gemini-cli, cline, opencode).",
            agent.phase_note,
        ),
    }
}

/// Scans for installed agents that use vendor-native governance.
/// Separated from the main detection loop so it can be called with
/// injected detection results in tests.
fn scan_vendor_native_impl<F>(detect: F, findings: &mut Vec<Finding>)
where
    F: Fn(&VendorAgent) -> bool,
{
    for agent in VENDOR_AGENTS {
        if detect(agent) {
            findings.push(build_vendor_finding(agent));
        }
    }
}

fn scan_vendor_native(findings: &mut Vec<Finding>) {
    scan_vendor_native_impl(is_vendor_agent_installed, findings);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

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

    scan_vendor_native(&mut findings);

    findings
}

/// A surface is "static" when realized via an out-of-band mechanism (compiled
/// policy, config rewrite, kyrisd model provider) — i.e. not `is_in_band`.
fn is_static_mechanism<M: MechanismLabel>(state: &SurfaceState<M>) -> bool {
    state.mechanism.as_ref().is_some_and(|m| !m.is_in_band())
}

/// `"<name>:<mechanism>"` if the surface is statically enforced, else `None`.
fn static_surface_label<M: MechanismLabel>(name: &str, s: &SurfaceState<M>) -> Option<String> {
    is_static_mechanism(s)
        .then(|| {
            s.mechanism
                .as_ref()
                .map(|m| format!("{name}:{}", m.short()))
        })
        .flatten()
}

fn scan_degraded_surfaces(
    agent: &dyn registry::AgentDescriptor,
    probe: &crate::agents::probe::ProbeResult,
    findings: &mut Vec<Finding>,
) {
    let labels: Vec<String> = [
        static_surface_label("execution", &probe.execution),
        static_surface_label("tool", &probe.tool),
        static_surface_label("burn-control", &probe.burn_control),
    ]
    .into_iter()
    .flatten()
    .collect();

    if labels.is_empty() {
        return;
    }

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
    // cline + opencode are live-hook now (no compiled COMMAND policy → the hook
    // handles `ask`); only codex + gemini emit a compiled policy that can drop ask.
    let compiler: Option<Compiler> = match agent_id {
        "codex-cli" => Some(crate::compile_policy::compile_codex_permissions),
        "gemini-cli" => Some(crate::compile_policy::compile_gemini_permissions),
        _ => None,
    };
    compiler
        .and_then(|c| c(None).ok())
        .map_or(0, |(_, dropped)| dropped)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn first_vendor_agent() -> &'static VendorAgent {
        &VENDOR_AGENTS[0]
    }

    #[test]
    fn testVendorAgentsListIsNonEmpty() {
        assert!(!VENDOR_AGENTS.is_empty());
    }

    #[test]
    fn testVendorAgentsIncludeCursorWindsurfCopilot() {
        let ids: Vec<&str> = VENDOR_AGENTS.iter().map(|a| a.id).collect();
        assert!(ids.contains(&"cursor"));
        assert!(ids.contains(&"windsurf"));
        assert!(ids.contains(&"github-copilot"));
    }

    #[test]
    fn testBuildVendorFindingCategory() {
        let finding = build_vendor_finding(first_vendor_agent());
        assert_eq!(finding.category, FindingCategory::VendorNativeAgent);
    }

    #[test]
    fn testBuildVendorFindingSeverityIsInfo() {
        // Vendor-native agents have some governance — not Critical or High.
        let finding = build_vendor_finding(first_vendor_agent());
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn testBuildVendorFindingTitleMentionsAgentName() {
        let finding = build_vendor_finding(first_vendor_agent());
        assert!(finding.title.contains("Cursor"));
        assert!(finding.title.contains("Kyris"));
    }

    #[test]
    fn testBuildVendorFindingDescriptionMentionsGovernanceNote() {
        let finding = build_vendor_finding(first_vendor_agent());
        assert!(finding.description.contains("Cursor Business"));
    }

    #[test]
    fn testBuildVendorFindingRemediationMentionsPhaseNote() {
        let finding = build_vendor_finding(first_vendor_agent());
        assert!(finding.remediation.contains("Phase 1"));
    }

    #[test]
    fn testBuildVendorFindingRemediationMentionsCompatibleAgents() {
        let finding = build_vendor_finding(first_vendor_agent());
        assert!(finding.remediation.contains("claude-code"));
    }

    #[test]
    fn testBuildVendorFindingLocationIsAgentId() {
        let finding = build_vendor_finding(first_vendor_agent());
        assert_eq!(finding.location.path, "cursor");
        assert!(finding.location.line.is_none());
    }

    #[test]
    fn testScanVendorNativeImplNoneDetected() {
        let mut findings = Vec::new();
        scan_vendor_native_impl(|_| false, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanVendorNativeImplAllDetected() {
        let mut findings = Vec::new();
        scan_vendor_native_impl(|_| true, &mut findings);
        assert_eq!(findings.len(), VENDOR_AGENTS.len());
        assert!(
            findings
                .iter()
                .all(|f| f.category == FindingCategory::VendorNativeAgent)
        );
    }

    #[test]
    fn testScanVendorNativeImplSingleDetected() {
        let mut findings = Vec::new();
        // Only detect Windsurf.
        scan_vendor_native_impl(|a| a.id == "windsurf", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.path, "windsurf");
    }

    #[test]
    fn testAllVendorAgentsHaveNonEmptyFields() {
        for agent in VENDOR_AGENTS {
            assert!(!agent.id.is_empty(), "empty id");
            assert!(!agent.display_name.is_empty(), "empty display_name");
            assert!(!agent.governance_note.is_empty(), "empty governance_note");
            assert!(!agent.phase_note.is_empty(), "empty phase_note");
        }
    }
}
