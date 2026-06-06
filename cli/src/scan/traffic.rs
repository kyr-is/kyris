// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

// ---------------------------------------------------------------------------
// Routing config checks (env vars)
// ---------------------------------------------------------------------------

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
        setup_cmd: "kyris agents setup claude-code",
    },
    TrafficCheck {
        agent: "Codex CLI / OpenAI",
        env_var: "OPENAI_BASE_URL",
        expected_prefix: "http://127.0.0.1:4710",
        setup_cmd: "kyris agents setup codex-cli",
    },
    TrafficCheck {
        agent: "Gemini CLI / Google",
        env_var: "GOOGLE_GEMINI_BASE_URL",
        expected_prefix: "http://127.0.0.1:4710",
        setup_cmd: "kyris agents setup gemini-cli",
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

// ---------------------------------------------------------------------------
// Shell history scanning
// ---------------------------------------------------------------------------

/// LLM provider API hostnames. A command referencing one of these directly
/// bypasses kyrisd governance entirely.
struct HistoryProvider {
    name: &'static str,
    hostname: &'static str,
}

const HISTORY_PROVIDERS: &[HistoryProvider] = &[
    HistoryProvider {
        name: "Anthropic",
        hostname: "api.anthropic.com",
    },
    HistoryProvider {
        name: "OpenAI",
        hostname: "api.openai.com",
    },
    HistoryProvider {
        name: "Google Gemini",
        hostname: "generativelanguage.googleapis.com",
    },
];

#[derive(Clone, Copy)]
enum HistoryFormat {
    /// `~/.zsh_history` — extended format `: timestamp:elapsed;command`,
    /// falling back to bare commands for basic (non-extended) format.
    Zsh,
    /// `~/.bash_history` — one bare command per line.
    Bash,
    /// `~/.config/fish/fish_history` — YAML-ish: `- cmd: command` / `  when: …`
    Fish,
}

fn history_files() -> Vec<(PathBuf, HistoryFormat)> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![
        (
            PathBuf::from(format!("{home}/.zsh_history")),
            HistoryFormat::Zsh,
        ),
        (
            PathBuf::from(format!("{home}/.bash_history")),
            HistoryFormat::Bash,
        ),
        (
            PathBuf::from(format!("{home}/.config/fish/fish_history")),
            HistoryFormat::Fish,
        ),
    ]
}

/// Extracts the command text from a raw history line.
/// Returns `None` for lines that carry no command (fish metadata lines).
fn parse_history_line(raw_line: &str, format: HistoryFormat) -> Option<&str> {
    match format {
        HistoryFormat::Zsh => {
            // Extended format: ": 1715000000:0;curl https://api.anthropic.com/…"
            if let Some(rest) = raw_line.strip_prefix(": ")
                && let Some(semicolon) = rest.find(';')
            {
                return Some(&rest[semicolon + 1..]);
            }
            Some(raw_line) // Basic (non-extended) format: bare command
        }
        HistoryFormat::Bash => Some(raw_line),
        HistoryFormat::Fish => {
            // "- cmd: curl https://…"  or  "  when: 1715000000"
            let trimmed = raw_line.trim_start();
            trimmed
                .strip_prefix("- cmd: ")
                .or_else(|| trimmed.strip_prefix("cmd: "))
        }
    }
}

/// Truncates evidence to a safe display length, respecting UTF-8 char boundaries.
fn truncate_evidence(cmd: &str) -> String {
    const MAX_LEN: usize = 120;
    let clean = cmd.trim();
    if clean.len() <= MAX_LEN {
        return clean.to_string();
    }
    let mut end = MAX_LEN;
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &clean[..end])
}

/// Core scanner: takes file content as a `&str` so tests can inject controlled
/// input without touching the filesystem.
fn scan_history_contents(
    path: &Path,
    format: HistoryFormat,
    contents: &str,
    findings: &mut Vec<Finding>,
) {
    // One slot per provider: tracks (first_line_number, evidence_string).
    let mut first_hit: Vec<Option<(usize, String)>> = vec![None; HISTORY_PROVIDERS.len()];

    for (line_idx, raw_line) in contents.lines().enumerate() {
        let Some(command) = parse_history_line(raw_line, format) else {
            continue;
        };

        for (i, provider) in HISTORY_PROVIDERS.iter().enumerate() {
            if first_hit[i].is_some() {
                continue; // Already recorded — one finding per provider per file.
            }
            if command.contains(provider.hostname) {
                first_hit[i] = Some((line_idx + 1, truncate_evidence(command)));
            }
        }
    }

    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    for (i, provider) in HISTORY_PROVIDERS.iter().enumerate() {
        if let Some((line_num, evidence)) = &first_hit[i] {
            findings.push(Finding {
                category: FindingCategory::LlmTraffic,
                severity: Severity::High,
                title: format!("Direct {} API calls in shell history", provider.name),
                description: format!(
                    "{file_name} contains commands making direct calls to {}, \
                     bypassing kyrisd governance.",
                    provider.hostname
                ),
                location: FindingLocation {
                    path: path.display().to_string(),
                    line: Some(*line_num),
                },
                evidence: Some(evidence.clone()),
                remediation: "Route LLM traffic through kyrisd. \
                              Run `kyris agents setup <agent>` to configure your agent."
                    .to_string(),
            });
        }
    }
}

fn scan_history_file(path: &Path, format: HistoryFormat, findings: &mut Vec<Finding>) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return; // Missing or unreadable — silently skip.
    };
    scan_history_contents(path, format, &contents, findings);
}

fn scan_history(findings: &mut Vec<Finding>) {
    for (path, format) in history_files() {
        scan_history_file(&path, format, findings);
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn scan() -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Routing config: check whether provider base-URL env vars point at kyrisd.
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

    // 2. Shell history: look for direct provider API calls.
    scan_history(&mut findings);

    findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fake_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/fake/{name}"))
    }

    // --- evaluate_check ---

    fn test_check() -> TrafficCheck {
        TrafficCheck {
            agent: "Test Agent",
            env_var: "TEST_BASE_URL",
            expected_prefix: "http://127.0.0.1:4710",
            setup_cmd: "kyris agents setup test",
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

    // --- parse_history_line ---

    #[test]
    fn testParseHistoryLineZshExtended() {
        let line = ": 1715000000:0;curl https://api.anthropic.com/v1/messages";
        let cmd = parse_history_line(line, HistoryFormat::Zsh).unwrap();
        assert_eq!(cmd, "curl https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn testParseHistoryLineZshBasicFallback() {
        // Without the ": timestamp:0;" prefix — basic (non-extended) format.
        let line = "curl https://api.openai.com/v1/chat/completions";
        let cmd = parse_history_line(line, HistoryFormat::Zsh).unwrap();
        assert_eq!(cmd, "curl https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn testParseHistoryLineBash() {
        let line = "curl https://api.openai.com/v1/chat";
        let cmd = parse_history_line(line, HistoryFormat::Bash).unwrap();
        assert_eq!(cmd, "curl https://api.openai.com/v1/chat");
    }

    #[test]
    fn testParseHistoryLineFishCmdLine() {
        let line = "- cmd: curl https://generativelanguage.googleapis.com/v1beta/models";
        let cmd = parse_history_line(line, HistoryFormat::Fish).unwrap();
        assert_eq!(
            cmd,
            "curl https://generativelanguage.googleapis.com/v1beta/models"
        );
    }

    #[test]
    fn testParseHistoryLineFishWhenLineSkipped() {
        let line = "  when: 1715000000";
        assert!(parse_history_line(line, HistoryFormat::Fish).is_none());
    }

    #[test]
    fn testParseHistoryLineFishBlankSkipped() {
        assert!(parse_history_line("", HistoryFormat::Fish).is_none());
    }

    #[test]
    fn testParseHistoryLineZshSemicolonInCommand() {
        // The semicolon search finds the FIRST ';', so a command with a semicolon works.
        let line = ": 1715000000:0;echo hello; curl https://api.anthropic.com";
        let cmd = parse_history_line(line, HistoryFormat::Zsh).unwrap();
        assert_eq!(cmd, "echo hello; curl https://api.anthropic.com");
    }

    // --- truncate_evidence ---

    #[test]
    fn testTruncateEvidenceShortPassthrough() {
        let s = "curl https://api.openai.com";
        assert_eq!(truncate_evidence(s), s);
    }

    #[test]
    fn testTruncateEvidenceLongIsTruncated() {
        let long = "x".repeat(200);
        let result = truncate_evidence(&long);
        assert!(result.len() < 130); // 120 chars + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn testTruncateEvidenceTrimsWhitespace() {
        assert_eq!(truncate_evidence("  hello  "), "hello");
    }

    // --- scan_history_contents ---

    fn scan_contents(path_name: &str, format: HistoryFormat, contents: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path = fake_path(path_name);
        scan_history_contents(&path, format, contents, &mut findings);
        findings
    }

    #[test]
    fn testScanHistoryContentsDetectsAnthropicInBash() {
        let contents = "ls -la\ncurl https://api.anthropic.com/v1/messages -d '{\"model\":\"claude-3\"}'\necho done\n";
        let findings = scan_contents(".bash_history", HistoryFormat::Bash, contents);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Anthropic"));
        assert_eq!(findings[0].location.line, Some(2));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].category, FindingCategory::LlmTraffic);
    }

    #[test]
    fn testScanHistoryContentsDetectsOpenAIInZsh() {
        let contents = ": 1715000000:0;curl https://api.openai.com/v1/chat/completions\n";
        let findings = scan_contents(".zsh_history", HistoryFormat::Zsh, contents);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("OpenAI"));
        assert_eq!(findings[0].location.line, Some(1));
    }

    #[test]
    fn testScanHistoryContentsDetectsGeminiInFish() {
        let contents = "- cmd: curl https://generativelanguage.googleapis.com/v1beta/models\n  when: 1715000000\n";
        let findings = scan_contents("fish_history", HistoryFormat::Fish, contents);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Gemini"));
        assert_eq!(findings[0].location.line, Some(1));
    }

    #[test]
    fn testScanHistoryContentsCleanHistory() {
        let contents = "ls -la\ngit status\necho hello\n";
        let findings = scan_contents(".bash_history", HistoryFormat::Bash, contents);
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanHistoryContentsDeduplicatesSameProvider() {
        // Two lines both hitting api.anthropic.com — should produce exactly one finding.
        let contents = "curl https://api.anthropic.com/v1/messages\ncurl https://api.anthropic.com/v1/complete\n";
        let findings = scan_contents(".bash_history", HistoryFormat::Bash, contents);
        assert_eq!(
            findings.len(),
            1,
            "expected one finding per provider, not one per line"
        );
        assert_eq!(findings[0].location.line, Some(1)); // first occurrence
    }

    #[test]
    fn testScanHistoryContentsReportsAllThreeProviders() {
        let contents = [
            "curl https://api.anthropic.com/v1/messages",
            "curl https://api.openai.com/v1/chat",
            "curl https://generativelanguage.googleapis.com/v1beta/models",
        ]
        .join("\n");
        let findings = scan_contents(".bash_history", HistoryFormat::Bash, &contents);
        assert_eq!(findings.len(), 3);
        let providers: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(providers.iter().any(|t| t.contains("Anthropic")));
        assert!(providers.iter().any(|t| t.contains("OpenAI")));
        assert!(providers.iter().any(|t| t.contains("Gemini")));
    }

    #[test]
    fn testScanHistoryContentsEvidenceIncludesCommand() {
        let contents = "curl https://api.anthropic.com/v1/messages -H 'accept: application/json'\n";
        let findings = scan_contents(".bash_history", HistoryFormat::Bash, contents);
        assert_eq!(findings.len(), 1);
        let evidence = findings[0].evidence.as_deref().unwrap_or("");
        assert!(evidence.contains("api.anthropic.com"));
    }

    #[test]
    fn testScanHistoryContentsRemediationMentionsAgentsSetup() {
        let contents = "curl https://api.openai.com/v1/chat\n";
        let findings = scan_contents(".bash_history", HistoryFormat::Bash, contents);
        assert!(!findings.is_empty());
        assert!(findings[0].remediation.contains("kyris agents setup"));
    }

    #[test]
    fn testScanHistoryFileMissingFileSkipped() {
        let mut findings = Vec::new();
        scan_history_file(
            Path::new("/nonexistent/.bash_history"),
            HistoryFormat::Bash,
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    // --- history_files ---

    #[test]
    fn testHistoryFilesIncludeZshBashFish() {
        let home = std::env::var("HOME").unwrap_or_default();
        let files = history_files();
        let paths: Vec<String> = files.iter().map(|(p, _)| p.display().to_string()).collect();
        assert!(paths.iter().any(|p| p.contains(".zsh_history")));
        assert!(paths.iter().any(|p| p.contains(".bash_history")));
        assert!(paths.iter().any(|p| p.contains("fish/fish_history")));
        // All paths should be under $HOME
        for path in &paths {
            assert!(path.starts_with(&home), "expected path under $HOME: {path}");
        }
    }
}
