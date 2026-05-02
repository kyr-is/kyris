// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::agents::registry::{self, McpConfigFormat};

use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

pub fn scan() -> Vec<Finding> {
    let mut findings = Vec::new();

    for agent in registry::all_agents() {
        let Some(mcp) = agent.mcp_config() else {
            continue;
        };
        if !mcp.path.exists() {
            continue;
        }
        let path_str = mcp.path.to_string_lossy().to_string();
        match mcp.format {
            McpConfigFormat::Json { servers_path } => {
                scan_json_mcp_servers(
                    &path_str,
                    &servers_path,
                    agent.display_name(),
                    &mut findings,
                );
            }
            McpConfigFormat::Toml { servers_key } => {
                scan_toml_mcp_servers(&path_str, servers_key, agent.display_name(), &mut findings);
            }
        }
    }

    findings
}

fn is_governed(command: &str) -> bool {
    command.contains("kyris-mcp") || command.contains("kyrisd")
}

fn is_routed_url(url: &str) -> bool {
    url.contains("kyris") || url.contains("kyrisd") || url.contains("/mcp/")
}

fn scan_json_mcp_servers(
    config_path: &str,
    servers_path: &[&str],
    agent_name: &str,
    findings: &mut Vec<Finding>,
) {
    let Ok(contents) = std::fs::read_to_string(config_path) else {
        return;
    };
    let Ok(parsed): Result<serde_json::Value, _> = serde_json::from_str(&contents) else {
        return;
    };

    let mut cursor = Some(&parsed);
    for key in servers_path {
        cursor = cursor.and_then(|v| v.get(*key));
    }
    let Some(servers) = cursor.and_then(|v| v.as_object()) else {
        return;
    };

    for (name, config) in servers {
        let cmd = config.get("command").and_then(|v| v.as_str());
        let url = config.get("url").and_then(|v| v.as_str());

        match (cmd, url) {
            (Some(command), _) if is_governed(command) => {}
            (Some(command), _) => {
                findings.push(Finding {
                    category: FindingCategory::UngoverndMcp,
                    severity: Severity::High,
                    title: format!("Unwrapped MCP server: {name}"),
                    description: format!(
                        "{agent_name} MCP server \"{name}\" is not routed through kyris-mcp."
                    ),
                    location: FindingLocation {
                        path: config_path.to_string(),
                        line: None,
                    },
                    evidence: Some(format!("command: {command}")),
                    remediation: format!("Wrap with: kyris mcp wrap --server {name} {command}"),
                });
            }
            (None, Some(url)) if is_routed_url(url) => {}
            (None, Some(url)) => {
                findings.push(Finding {
                    category: FindingCategory::UngoverndMcp,
                    severity: Severity::High,
                    title: format!("Unrouted remote MCP server: {name}"),
                    description: format!(
                        "{agent_name} remote MCP server \"{name}\" is not routed through kyrisd."
                    ),
                    location: FindingLocation {
                        path: config_path.to_string(),
                        line: None,
                    },
                    evidence: Some(format!("url: {url}")),
                    remediation: format!("Route through kyrisd: kyris mcp route --server {name}"),
                });
            }
            _ => {}
        }
    }
}

fn scan_toml_mcp_servers(
    config_path: &str,
    servers_key: &str,
    agent_name: &str,
    findings: &mut Vec<Finding>,
) {
    let Ok(contents) = std::fs::read_to_string(config_path) else {
        return;
    };
    let Ok(parsed): Result<toml::Table, _> = toml::from_str(&contents) else {
        return;
    };
    let Some(servers) = parsed.get(servers_key).and_then(|v| v.as_table()) else {
        return;
    };

    for (name, config) in servers {
        let cmd = config.get("command").and_then(|v| v.as_str());
        let url = config.get("url").and_then(|v| v.as_str());

        match (cmd, url) {
            (Some(command), _) if is_governed(command) => {}
            (Some(command), _) => {
                findings.push(Finding {
                    category: FindingCategory::UngoverndMcp,
                    severity: Severity::High,
                    title: format!("Unwrapped MCP server: {name}"),
                    description: format!(
                        "{agent_name} MCP server \"{name}\" is not routed through kyris-mcp."
                    ),
                    location: FindingLocation {
                        path: config_path.to_string(),
                        line: None,
                    },
                    evidence: Some(format!("command: {command}")),
                    remediation: format!("Wrap with: kyris mcp wrap --server {name} {command}"),
                });
            }
            (None, Some(url)) if is_routed_url(url) => {}
            (None, Some(url)) => {
                findings.push(Finding {
                    category: FindingCategory::UngoverndMcp,
                    severity: Severity::High,
                    title: format!("Unrouted remote MCP server: {name}"),
                    description: format!(
                        "{agent_name} remote MCP server \"{name}\" is not routed through kyrisd."
                    ),
                    location: FindingLocation {
                        path: config_path.to_string(),
                        line: None,
                    },
                    evidence: Some(format!("url: {url}")),
                    remediation: format!("Route through kyrisd: kyris mcp route --server {name}"),
                });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testJsonUnwrappedStdioDetected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"github": {"command": "npx github-mcp"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(
            path.to_str().unwrap(),
            &["mcpServers"],
            "Claude Code",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::UngoverndMcp);
        assert!(findings[0].title.contains("github"));
        assert!(findings[0].remediation.contains("kyris mcp wrap"));
    }

    #[test]
    fn testJsonWrappedStdioIgnored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"github": {"command": "kyris-mcp wrap --server github npx github-mcp"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(
            path.to_str().unwrap(),
            &["mcpServers"],
            "Claude Code",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn testJsonUnroutedHttpDetected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"remote": {"url": "https://example.com/mcp"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(
            path.to_str().unwrap(),
            &["mcpServers"],
            "Cline",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Unrouted remote"));
        assert!(findings[0].remediation.contains("kyris mcp route"));
    }

    #[test]
    fn testJsonRoutedHttpIgnored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {"remote": {"url": "http://127.0.0.1:4710/mcp/remote/"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(
            path.to_str().unwrap(),
            &["mcpServers"],
            "Cline",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn testJsonNoServersKeyNoFindings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"theme": "dark"}"#).unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(
            path.to_str().unwrap(),
            &["mcpServers"],
            "Claude Code",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn testJsonMissingFileNoFindings() {
        let mut findings = Vec::new();
        scan_json_mcp_servers(
            "/nonexistent/settings.json",
            &["mcpServers"],
            "Claude Code",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn testJsonNestedServersPath() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        std::fs::write(
            &path,
            r#"{"mcp": {"github": {"command": "npx github-mcp"}}}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(path.to_str().unwrap(), &["mcp"], "OpenCode", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("OpenCode"));
    }

    #[test]
    fn testJsonMultipleServersMixedState() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"mcpServers": {
                "wrapped": {"command": "kyris-mcp wrap --server wrapped npx a"},
                "unwrapped": {"command": "npx b"},
                "routed": {"url": "http://127.0.0.1:4710/mcp/routed/"},
                "unrouted": {"url": "https://example.com/mcp"}
            }}"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_json_mcp_servers(
            path.to_str().unwrap(),
            &["mcpServers"],
            "Test",
            &mut findings,
        );
        assert_eq!(findings.len(), 2);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("unwrapped")));
        assert!(titles.iter().any(|t| t.contains("unrouted")));
    }

    #[test]
    fn testTomlUnwrappedStdioDetected() {
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
        scan_toml_mcp_servers(
            path.to_str().unwrap(),
            "mcp_servers",
            "Codex CLI",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("Codex CLI"));
        assert!(findings[0].remediation.contains("kyris mcp wrap"));
    }

    #[test]
    fn testTomlWrappedStdioIgnored() {
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
        scan_toml_mcp_servers(
            path.to_str().unwrap(),
            "mcp_servers",
            "Codex CLI",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn testTomlUnroutedHttpDetected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[mcp_servers.remote]
url = "https://example.com/mcp"
"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_toml_mcp_servers(
            path.to_str().unwrap(),
            "mcp_servers",
            "Codex CLI",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Unrouted remote"));
        assert!(findings[0].remediation.contains("kyris mcp route"));
    }

    #[test]
    fn testTomlRoutedHttpIgnored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[mcp_servers.remote]
url = "http://127.0.0.1:4710/mcp/remote/"
"#,
        )
        .unwrap();

        let mut findings = Vec::new();
        scan_toml_mcp_servers(
            path.to_str().unwrap(),
            "mcp_servers",
            "Codex CLI",
            &mut findings,
        );
        assert!(findings.is_empty());
    }
}
