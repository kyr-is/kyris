// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use console::Style;

use crate::scan::scanner::{Finding, FindingCategory, RiskLevel, Severity, risk_level};

pub fn render(findings: &[Finding]) {
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!("{}", bold.apply_to("Kyris Security Scan Report"));
    println!("{}", bold.apply_to("========================="));
    println!();

    if findings.is_empty() {
        println!(
            "{}",
            Style::new()
                .green()
                .apply_to("No findings. Environment looks good.")
        );
        return;
    }

    let total_score: u32 = findings.iter().map(|f| f.severity as u32).sum();
    let level = risk_level(total_score);

    // Group by category
    let categories = [
        (FindingCategory::ApiKey, "API Keys"),
        (FindingCategory::UngoverndAgent, "Ungoverned Agents"),
        (FindingCategory::UngoverndMcp, "Ungoverned MCP Servers"),
        (FindingCategory::LlmTraffic, "LLM Traffic"),
    ];

    for (cat, label) in &categories {
        let cat_findings: Vec<&Finding> = findings.iter().filter(|f| f.category == *cat).collect();

        if cat_findings.is_empty() {
            continue;
        }

        println!(
            "{}",
            bold.apply_to(format!("[{label}] ({} findings)", cat_findings.len()))
        );

        for f in &cat_findings {
            let severity_style = severity_style(f.severity);
            let sev_label = severity_label(f.severity);
            println!(
                "  {} {}",
                severity_style.apply_to(format!("[{sev_label}]")),
                f.title
            );
            println!("    {}", dim.apply_to(&f.description));
            println!(
                "    Location: {}{}",
                f.location.path,
                match f.location.line {
                    Some(l) => format!(":{l}"),
                    None => String::new(),
                }
            );
            if let Some(ref ev) = f.evidence {
                println!("    Evidence: {}", dim.apply_to(ev));
            }
            println!("    Fix: {}", f.remediation);
            println!();
        }
    }

    let level_style = risk_level_style(level);
    let level_label = risk_level_label(level);
    println!(
        "Risk score: {} ({})",
        total_score,
        level_style.apply_to(level_label)
    );
    println!("Total findings: {}", findings.len());
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::new().red().bold(),
        Severity::High => Style::new().yellow().bold(),
        Severity::Medium => Style::new().blue(),
        Severity::Low => Style::new().cyan(),
        Severity::Info => Style::new().dim(),
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn risk_level_style(level: RiskLevel) -> Style {
    match level {
        RiskLevel::Critical => Style::new().red().bold(),
        RiskLevel::High => Style::new().yellow().bold(),
        RiskLevel::Medium => Style::new().blue(),
        RiskLevel::Low => Style::new().green(),
    }
}

fn risk_level_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "CRITICAL",
        RiskLevel::High => "HIGH",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::Low => "LOW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testSeverityLabelAll() {
        assert_eq!(severity_label(Severity::Critical), "CRITICAL");
        assert_eq!(severity_label(Severity::High), "HIGH");
        assert_eq!(severity_label(Severity::Medium), "MEDIUM");
        assert_eq!(severity_label(Severity::Low), "LOW");
        assert_eq!(severity_label(Severity::Info), "INFO");
    }

    #[test]
    fn testRiskLevelLabelAll() {
        assert_eq!(risk_level_label(RiskLevel::Critical), "CRITICAL");
        assert_eq!(risk_level_label(RiskLevel::High), "HIGH");
        assert_eq!(risk_level_label(RiskLevel::Medium), "MEDIUM");
        assert_eq!(risk_level_label(RiskLevel::Low), "LOW");
    }

    #[test]
    fn testSeverityStyleReturnsStyle() {
        let _ = severity_style(Severity::Critical);
        let _ = severity_style(Severity::High);
        let _ = severity_style(Severity::Medium);
        let _ = severity_style(Severity::Low);
        let _ = severity_style(Severity::Info);
    }

    #[test]
    fn testRiskLevelStyleReturnsStyle() {
        let _ = risk_level_style(RiskLevel::Critical);
        let _ = risk_level_style(RiskLevel::High);
        let _ = risk_level_style(RiskLevel::Medium);
        let _ = risk_level_style(RiskLevel::Low);
    }
}
