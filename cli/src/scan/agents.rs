// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

pub fn scan() -> Vec<Finding> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut findings = Vec::new();

    // Claude Code
    let claude_dir = format!("{home}/.claude");
    if std::path::Path::new(&claude_dir).is_dir() && !is_hooked("ANTHROPIC_BASE_URL") {
        findings.push(Finding {
            category: FindingCategory::UngoverndAgent,
            severity: Severity::High,
            title: "Claude Code is not routed through kyrisd".to_string(),
            description: "Claude Code is installed but ANTHROPIC_BASE_URL is not set to \
                              the kyrisd proxy."
                .to_string(),
            location: FindingLocation {
                path: claude_dir,
                line: None,
            },
            evidence: None,
            remediation: "Run `kyris setup claude-code` to configure routing.".to_string(),
        });
    }

    // Codex CLI
    let codex_dir = format!("{home}/.codex");
    if std::path::Path::new(&codex_dir).is_dir() && !is_hooked("OPENAI_BASE_URL") {
        findings.push(Finding {
            category: FindingCategory::UngoverndAgent,
            severity: Severity::High,
            title: "Codex CLI is not routed through kyrisd".to_string(),
            description: "Codex CLI is installed but OPENAI_BASE_URL is not set to \
                              the kyrisd proxy."
                .to_string(),
            location: FindingLocation {
                path: codex_dir,
                line: None,
            },
            evidence: None,
            remediation: "Run `kyris setup codex-cli` to configure routing.".to_string(),
        });
    }

    // Gemini CLI
    if which_exists("gemini") && !is_hooked("GOOGLE_GEMINI_BASE_URL") {
        findings.push(Finding {
            category: FindingCategory::UngoverndAgent,
            severity: Severity::High,
            title: "Gemini CLI is not routed through kyrisd".to_string(),
            description: "Gemini CLI is installed but GOOGLE_GEMINI_BASE_URL is not set to \
                          the kyrisd proxy."
                .to_string(),
            location: FindingLocation {
                path: "gemini (PATH)".to_string(),
                line: None,
            },
            evidence: None,
            remediation: "Run `kyris setup gemini-cli` to configure routing.".to_string(),
        });
    }

    // Cline
    let vscode_ext_dir = format!("{home}/.vscode/extensions");
    if std::path::Path::new(&vscode_ext_dir).is_dir() {
        let has_cline = std::fs::read_dir(&vscode_ext_dir).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("saoudrizwan.claude-dev")
            })
        });

        if has_cline {
            findings.push(Finding {
                category: FindingCategory::UngoverndAgent,
                severity: Severity::Medium,
                title: "Cline extension detected without kyris hooks".to_string(),
                description: "Cline VS Code extension is installed. Verify it routes through \
                              kyrisd."
                    .to_string(),
                location: FindingLocation {
                    path: vscode_ext_dir,
                    line: None,
                },
                evidence: None,
                remediation: "Configure Cline's apiBaseUrl in VS Code settings to \
                              http://127.0.0.1:4710."
                    .to_string(),
            });
        }
    }

    findings
}

fn is_hooked(env_var: &str) -> bool {
    std::env::var(env_var).is_ok_and(|v| is_kyris_proxy_url(&v))
}

fn is_kyris_proxy_url(value: &str) -> bool {
    value.contains("127.0.0.1:4710")
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testIsKyrisProxyUrlValid() {
        assert!(is_kyris_proxy_url("http://127.0.0.1:4710"));
        assert!(is_kyris_proxy_url("http://127.0.0.1:4710/v1"));
    }

    #[test]
    fn testIsKyrisProxyUrlInvalid() {
        assert!(!is_kyris_proxy_url("http://localhost:8080"));
        assert!(!is_kyris_proxy_url("https://api.anthropic.com"));
        assert!(!is_kyris_proxy_url(""));
    }
}
