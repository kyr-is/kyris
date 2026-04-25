// SPDX-License-Identifier: Apache-2.0
use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

struct TrafficCheck {
    agent: &'static str,
    env_var: &'static str,
    expected_prefix: &'static str,
    setup_cmd: &'static str,
}

const CHECKS: &[TrafficCheck] = &[
    TrafficCheck {
        agent: "Claude Code / Anthropic",
        env_var: "ANTHROPIC_BASE_URL",
        expected_prefix: "http://127.0.0.1:4710",
        setup_cmd: "kyris setup claude-code",
    },
    TrafficCheck {
        agent: "Codex CLI / OpenAI",
        env_var: "OPENAI_BASE_URL",
        expected_prefix: "http://127.0.0.1:4710",
        setup_cmd: "kyris setup codex-cli",
    },
    TrafficCheck {
        agent: "Gemini CLI / Google",
        env_var: "GOOGLE_GEMINI_BASE_URL",
        expected_prefix: "http://127.0.0.1:4710",
        setup_cmd: "kyris setup gemini-cli",
    },
];

enum TrafficResult {
    Routed,
    Misrouted(String),
    Unset,
}

fn evaluate_check(check: &TrafficCheck, env_value: Option<&str>) -> TrafficResult {
    match env_value {
        Some(val) if val.starts_with(check.expected_prefix) => TrafficResult::Routed,
        Some(val) => TrafficResult::Misrouted(val.to_string()),
        None => TrafficResult::Unset,
    }
}

pub fn scan() -> Vec<Finding> {
    let mut findings = Vec::new();

    for check in CHECKS {
        let env_val = std::env::var(check.env_var).ok();
        match evaluate_check(check, env_val.as_deref()) {
            TrafficResult::Routed => {}
            TrafficResult::Misrouted(val) => {
                findings.push(Finding {
                    category: FindingCategory::LlmTraffic,
                    severity: Severity::High,
                    title: format!("{} traffic not routed through kyrisd", check.agent),
                    description: format!(
                        "{} is set to \"{}\" instead of the kyrisd proxy.",
                        check.env_var, val
                    ),
                    location: FindingLocation {
                        path: format!("env:{}", check.env_var),
                        line: None,
                    },
                    evidence: Some(format!("{}={}", check.env_var, val)),
                    remediation: format!("Run `{}`.", check.setup_cmd),
                });
            }
            TrafficResult::Unset => {
                findings.push(Finding {
                    category: FindingCategory::LlmTraffic,
                    severity: Severity::Info,
                    title: format!("{} not configured", check.env_var),
                    description: format!(
                        "{} is not set. If {} is installed, traffic goes directly to the provider.",
                        check.env_var, check.agent
                    ),
                    location: FindingLocation {
                        path: format!("env:{}", check.env_var),
                        line: None,
                    },
                    evidence: None,
                    remediation: format!("Run `{}` if the agent is in use.", check.setup_cmd),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_check() -> TrafficCheck {
        TrafficCheck {
            agent: "Test Agent",
            env_var: "TEST_BASE_URL",
            expected_prefix: "http://127.0.0.1:4710",
            setup_cmd: "kyris setup test",
        }
    }

    #[test]
    fn testEvaluateCheckRouted() {
        let check = test_check();
        assert!(matches!(
            evaluate_check(&check, Some("http://127.0.0.1:4710/v1")),
            TrafficResult::Routed
        ));
    }

    #[test]
    fn testEvaluateCheckMisrouted() {
        let check = test_check();
        assert!(matches!(
            evaluate_check(&check, Some("https://api.example.com")),
            TrafficResult::Misrouted(_)
        ));
    }

    #[test]
    fn testEvaluateCheckUnset() {
        let check = test_check();
        assert!(matches!(evaluate_check(&check, None), TrafficResult::Unset));
    }

    #[test]
    fn testEvaluateCheckExactPrefix() {
        let check = test_check();
        assert!(matches!(
            evaluate_check(&check, Some("http://127.0.0.1:4710")),
            TrafficResult::Routed
        ));
    }

    #[test]
    fn testChecksNotEmpty() {
        assert!(!CHECKS.is_empty());
    }
}
