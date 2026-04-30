// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct Finding {
    pub category: FindingCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: FindingLocation,
    pub evidence: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    ApiKey,
    UngoverndAgent,
    UngoverndMcp,
    LlmTraffic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    #[allow(dead_code)]
    Low = 2,
    #[allow(dead_code)]
    Medium = 4,
    High = 7,
    Critical = 10,
}

#[derive(Debug, Clone)]
pub struct FindingLocation {
    pub path: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub fn risk_level(total_score: u32) -> RiskLevel {
    match total_score {
        0..=19 => RiskLevel::Low,
        20..=39 => RiskLevel::Medium,
        40..=69 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRiskLevelBoundaries() {
        assert_eq!(risk_level(0), RiskLevel::Low);
        assert_eq!(risk_level(19), RiskLevel::Low);
        assert_eq!(risk_level(20), RiskLevel::Medium);
        assert_eq!(risk_level(39), RiskLevel::Medium);
        assert_eq!(risk_level(40), RiskLevel::High);
        assert_eq!(risk_level(69), RiskLevel::High);
        assert_eq!(risk_level(70), RiskLevel::Critical);
        assert_eq!(risk_level(100), RiskLevel::Critical);
    }
}
