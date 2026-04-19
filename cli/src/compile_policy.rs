// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct CompilePolicyArgs {
    #[arg(long)]
    pub agent: String,
    #[arg(long)]
    pub policy: Option<String>,
}

pub fn run(args: CompilePolicyArgs) {
    match args.agent.as_str() {
        "cline" => print_cline(args.policy.as_deref()),
        other => {
            eprintln!("Unsupported agent for policy compilation: {other}");
            eprintln!("Supported: cline");
            std::process::exit(1);
        }
    }
}

fn print_cline(policy_path: Option<&str>) {
    match compile_cline_permissions(policy_path.map(Path::new)) {
        Ok((output, ask_dropped)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serialize")
            );
            if ask_dropped > 0 {
                eprintln!(
                    "Warning: {ask_dropped} ask rules dropped \
                     -- Cline native permissions support allow/deny only."
                );
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

pub fn compile_cline_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let policy_dir = format!("{home}/.agentpact/policy");

    let path = if let Some(p) = policy_path {
        p.to_path_buf()
    } else {
        let caps_path = format!("{policy_dir}/caps.yaml");
        let pact_path = format!("{policy_dir}/pact.yaml");
        if std::path::Path::new(&caps_path).exists() {
            PathBuf::from(caps_path)
        } else if std::path::Path::new(&pact_path).exists() {
            PathBuf::from(pact_path)
        } else {
            return Err(format!(
                "No policy file found. Looked for caps.yaml and pact.yaml in {policy_dir}"
            ));
        }
    };

    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;

    let mut allow_rules: Vec<String> = Vec::new();
    let mut deny_rules: Vec<String> = Vec::new();
    let mut ask_dropped = 0u32;

    // Parse YAML execute rules using basic text parsing (serde_yml is banned).
    // We look for blocks like:
    //   - action: execute
    //     pattern: "some-pattern"
    //     decision: auto|deny|ask
    let mut current_action = String::new();
    let mut current_pattern = String::new();
    let mut current_decision = String::new();

    for line in contents.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("- action:") {
            // Flush previous rule if any
            flush_rule(
                &current_action,
                &current_pattern,
                &current_decision,
                &mut allow_rules,
                &mut deny_rules,
                &mut ask_dropped,
            );
            current_action = extract_value(trimmed, "- action:");
            current_pattern.clear();
            current_decision.clear();
        } else if trimmed.starts_with("pattern:") {
            current_pattern = extract_value(trimmed, "pattern:");
        } else if trimmed.starts_with("decision:") {
            current_decision = extract_value(trimmed, "decision:");
        }
    }
    // Flush last rule
    flush_rule(
        &current_action,
        &current_pattern,
        &current_decision,
        &mut allow_rules,
        &mut deny_rules,
        &mut ask_dropped,
    );

    let output = serde_json::json!({
        "allow": allow_rules,
        "deny": deny_rules,
    });
    Ok((output, ask_dropped))
}

fn flush_rule(
    action: &str,
    pattern: &str,
    decision: &str,
    allow_rules: &mut Vec<String>,
    deny_rules: &mut Vec<String>,
    ask_dropped: &mut u32,
) {
    if action != "execute" || pattern.is_empty() {
        return;
    }
    match decision {
        "auto" => allow_rules.push(pattern.to_string()),
        "deny" => deny_rules.push(pattern.to_string()),
        "ask" => *ask_dropped += 1,
        _ => {}
    }
}

fn extract_value(line: &str, prefix: &str) -> String {
    line.trim_start_matches(prefix)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testExtractValueUnquoted() {
        assert_eq!(extract_value("- action: execute", "- action:"), "execute");
    }

    #[test]
    fn testExtractValueDoubleQuoted() {
        assert_eq!(
            extract_value(r#"pattern: "npm install""#, "pattern:"),
            "npm install"
        );
    }

    #[test]
    fn testExtractValueSingleQuoted() {
        assert_eq!(
            extract_value("pattern: 'git push'", "pattern:"),
            "git push"
        );
    }

    #[test]
    fn testFlushRuleAutoAddsToAllow() {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        let mut ask = 0;
        flush_rule("execute", "ls *", "auto", &mut allow, &mut deny, &mut ask);
        assert_eq!(allow, vec!["ls *"]);
        assert!(deny.is_empty());
        assert_eq!(ask, 0);
    }

    #[test]
    fn testFlushRuleDenyAddsToDeny() {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        let mut ask = 0;
        flush_rule("execute", "rm -rf", "deny", &mut allow, &mut deny, &mut ask);
        assert!(allow.is_empty());
        assert_eq!(deny, vec!["rm -rf"]);
    }

    #[test]
    fn testFlushRuleAskIsDropped() {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        let mut ask = 0;
        flush_rule("execute", "curl *", "ask", &mut allow, &mut deny, &mut ask);
        assert!(allow.is_empty());
        assert!(deny.is_empty());
        assert_eq!(ask, 1);
    }

    #[test]
    fn testFlushRuleIgnoresNonExecuteActions() {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        let mut ask = 0;
        flush_rule("read", "cat /etc/*", "auto", &mut allow, &mut deny, &mut ask);
        assert!(allow.is_empty());
        assert!(deny.is_empty());
    }

    #[test]
    fn testFlushRuleIgnoresEmptyPattern() {
        let mut allow = Vec::new();
        let mut deny = Vec::new();
        let mut ask = 0;
        flush_rule("execute", "", "auto", &mut allow, &mut deny, &mut ask);
        assert!(allow.is_empty());
    }

    #[test]
    fn testCompileClinePermissionsFromFile() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("test-policy.yaml");
        std::fs::write(
            &policy_path,
            r#"rules:
  - action: execute
    pattern: "npm install"
    decision: auto
  - action: execute
    pattern: "rm -rf /"
    decision: deny
  - action: execute
    pattern: "docker build"
    decision: ask
  - action: read
    pattern: "cat /etc/passwd"
    decision: auto
"#,
        )
        .unwrap();

        let (output, ask_dropped) = compile_cline_permissions(Some(policy_path.as_path())).unwrap();
        assert_eq!(output["allow"], serde_json::json!(["npm install"]));
        assert_eq!(output["deny"], serde_json::json!(["rm -rf /"]));
        assert_eq!(ask_dropped, 1);
    }

    #[test]
    fn testCompileClinePermissionsEmptyFile() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("empty.yaml");
        std::fs::write(&policy_path, "").unwrap();

        let (output, ask_dropped) = compile_cline_permissions(Some(policy_path.as_path())).unwrap();
        assert_eq!(output["allow"], serde_json::json!([]));
        assert_eq!(output["deny"], serde_json::json!([]));
        assert_eq!(ask_dropped, 0);
    }

    #[test]
    fn testCompileClinePermissionsMissingFile() {
        let result = compile_cline_permissions(Some(Path::new("/nonexistent/policy.yaml")));
        assert!(result.is_err());
    }

    #[test]
    fn testCompileClinePermissionsMultipleRulesSameDecision() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("multi.yaml");
        std::fs::write(
            &policy_path,
            r#"rules:
  - action: execute
    pattern: "npm install"
    decision: auto
  - action: execute
    pattern: "npm test"
    decision: auto
  - action: execute
    pattern: "npm publish"
    decision: deny
"#,
        )
        .unwrap();

        let (output, _) = compile_cline_permissions(Some(policy_path.as_path())).unwrap();
        let allow = output["allow"].as_array().unwrap();
        assert_eq!(allow.len(), 2);
        assert_eq!(output["deny"], serde_json::json!(["npm publish"]));
    }
}
