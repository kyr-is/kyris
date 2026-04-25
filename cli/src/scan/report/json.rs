// SPDX-License-Identifier: Apache-2.0
use crate::scan::scanner::{Finding, Severity, risk_level};

pub fn render(findings: &[Finding]) {
    let total_score: u32 = findings.iter().map(|f| f.severity as u32).sum();
    let level = risk_level(total_score);

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "category": format!("{:?}", f.category),
                "severity": severity_str(f.severity),
                "title": f.title,
                "description": f.description,
                "location": {
                    "path": f.location.path,
                    "line": f.location.line,
                },
                "evidence": f.evidence,
                "remediation": f.remediation,
            })
        })
        .collect();

    let output = serde_json::json!({
        "scan_time": chrono::Utc::now().to_rfc3339(),
        "total_findings": findings.len(),
        "risk_score": total_score,
        "risk_level": format!("{level:?}"),
        "findings": findings_json,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("serialize scan report")
    );
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testSeverityStrAll() {
        assert_eq!(severity_str(Severity::Critical), "critical");
        assert_eq!(severity_str(Severity::High), "high");
        assert_eq!(severity_str(Severity::Medium), "medium");
        assert_eq!(severity_str(Severity::Low), "low");
        assert_eq!(severity_str(Severity::Info), "info");
    }
}
