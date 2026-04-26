// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

pub fn scan() -> Vec<Finding> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut findings = Vec::new();

    scan_claude_mcp_config(&home, &mut findings);
    scan_codex_mcp_config(&home, &mut findings);

    findings
}

fn scan_claude_mcp_config(home: &str, findings: &mut Vec<Finding>) {
    let settings_path = format!("{home}/.claude/settings.json");
    scan_claude_mcp_file(&settings_path, findings);
}

fn scan_claude_mcp_file(settings_path: &str, findings: &mut Vec<Finding>) {
    let Ok(contents) = std::fs::read_to_string(settings_path) else {
        return;
    };

    let Ok(parsed): Result<serde_json::Value, _> = serde_json::from_str(&contents) else {
        return;
    };

    let Some(mcp_servers) = parsed.get("mcpServers").and_then(|v| v.as_object()) else {
        return;
    };

    for (name, config) in mcp_servers {
        let cmd = config.get("command").and_then(|v| v.as_str()).unwrap_or("");

        if !cmd.contains("kyris-mcp") && !cmd.contains("kyrisd") {
            findings.push(Finding {
                category: FindingCategory::UngoverndMcp,
                severity: Severity::High,
                title: format!("Unwrapped MCP server: {name}"),
                description: format!(
                    "Claude Code MCP server \"{name}\" is not routed through kyris-mcp."
                ),
                location: FindingLocation {
                    path: settings_path.to_string(),
                    line: None,
                },
                evidence: Some(format!("command: {cmd}")),
                remediation: format!("Wrap with: kyris mcp wrap --server {name} {cmd}"),
            });
        }
    }
}

fn scan_codex_mcp_config(home: &str, findings: &mut Vec<Finding>) {
    let config_path = format!("{home}/.codex/config.toml");
    scan_codex_mcp_file(&config_path, findings);
}

fn scan_codex_mcp_file(config_path: &str, findings: &mut Vec<Finding>) {
    let Ok(contents) = std::fs::read_to_string(config_path) else {
        return;
    };

    let Ok(parsed): Result<toml::Value, _> = contents.parse() else {
        return;
    };

    let Some(servers) = parsed.get("mcp_servers").and_then(|v| v.as_table()) else {
        return;
    };

    for (name, config) in servers {
        let cmd = config.get("command").and_then(|v| v.as_str()).unwrap_or("");

        if !cmd.contains("kyris-mcp") && !cmd.contains("kyrisd") {
            findings.push(Finding {
                category: FindingCategory::UngoverndMcp,
                severity: Severity::High,
                title: format!("Unwrapped MCP server: {name}"),
                description: format!(
                    "Codex CLI MCP server \"{name}\" is not routed through kyris-mcp."
                ),
                location: FindingLocation {
                    path: config_path.to_string(),
                    line: None,
                },
                evidence: Some(format!("command: {cmd}")),
                remediation: format!("Wrap with: kyris mcp wrap --server {name} {cmd}"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testClaudeUnwrappedServerDetected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"github": {"command": "npx github-mcp"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_claude_mcp_file(path.to_str().unwrap(), &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::UngoverndMcp);
        assert!(findings[0].title.contains("github"));
    }

    #[test]
    fn testClaudeWrappedServerIgnored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"github": {"command": "kyris-mcp wrap --server github npx github-mcp"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_claude_mcp_file(path.to_str().unwrap(), &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testClaudeNoMcpServersKey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"theme": "dark"}"#).unwrap();

        let mut findings = Vec::new();
        scan_claude_mcp_file(path.to_str().unwrap(), &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testClaudeMissingFileNoFindings() {
        let mut findings = Vec::new();
        scan_claude_mcp_file("/nonexistent/settings.json", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testCodexUnwrappedServerDetected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[mcp_servers.filesystem]
command = "npx filesystem-mcp"
"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_codex_mcp_file(path.to_str().unwrap(), &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("Codex"));
    }

    #[test]
    fn testCodexWrappedServerIgnored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[mcp_servers.filesystem]
command = "kyris-mcp wrap --server filesystem npx filesystem-mcp"
"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_codex_mcp_file(path.to_str().unwrap(), &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testClaudeMultipleServersOnlyUnwrappedReported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {
                "wrapped": {"command": "kyris-mcp wrap --server wrapped npx a"},
                "unwrapped1": {"command": "npx b"},
                "unwrapped2": {"command": "npx c"}
            }}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_claude_mcp_file(path.to_str().unwrap(), &mut findings);
        assert_eq!(findings.len(), 2);
    }
}
