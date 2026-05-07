// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::collections::HashMap;
use std::path::Path;

use agentpact::catalog::commands::id_to_shell;
use agentpact::policy::loader::{
    PolicyLevel, load_policy_dir, parse_policy_level, resolve_walk_up,
};
use agentpact::protocol::types::Permission;

#[derive(Args)]
pub struct CompilePolicyArgs {
    #[arg(long)]
    pub agent: String,
    #[arg(long)]
    pub policy: Option<String>,
}

pub fn run(args: CompilePolicyArgs) {
    match args.agent.as_str() {
        "cline" => print_compiled_cline(args.policy.as_deref()),
        "opencode" => print_compiled(args.policy.as_deref(), compile_opencode_permissions),
        "codex-cli" => print_compiled(args.policy.as_deref(), compile_codex_permissions),
        "gemini-cli" => print_compiled(args.policy.as_deref(), compile_gemini_permissions),
        other => {
            eprintln!("Unsupported agent for policy compilation: {other}");
            eprintln!("Supported: cline, opencode, codex-cli, gemini-cli");
            std::process::exit(1);
        }
    }
}

fn print_compiled_cline(policy_path: Option<&str>) {
    match compile_cline_permissions(policy_path.map(Path::new)) {
        Ok((output, gaps)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serialize")
            );
            if !gaps.ask_dropped.is_empty() {
                eprintln!(
                    "Warning: {} ask rules dropped: {}",
                    gaps.ask_dropped.len(),
                    gaps.ask_dropped.join(", ")
                );
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

type PolicyCompiler = fn(Option<&Path>) -> Result<(serde_json::Value, u32), String>;

fn print_compiled(policy_path: Option<&str>, compiler: PolicyCompiler) {
    match compiler(policy_path.map(Path::new)) {
        Ok((output, ask_dropped)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("serialize")
            );
            if ask_dropped > 0 {
                eprintln!("Warning: {ask_dropped} ask rules were dropped.");
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn load_merged_policy(policy_dir: Option<&Path>) -> Result<PolicyLevel, String> {
    let home = dirs_home()?;

    if let Some(dir) = policy_dir {
        let files = load_policy_dir(dir)?;
        if files.is_empty() {
            return Err(format!("No policy files found in {}", dir.display()));
        }
        return parse_policy_level(&files, Some(30));
    }

    let cwd =
        std::env::current_dir().map_err(|e| format!("Cannot determine working directory: {e}"))?;

    let levels = resolve_walk_up(Some(cwd.to_str().unwrap_or(".")), &home, Some(30))?;

    if levels.is_empty() {
        return Err(format!(
            "No policy files found. Looked for .agentpact/policy/ from {} up to {}",
            cwd.display(),
            home.display()
        ));
    }

    // Merge: iterate farthest-to-nearest so nearest overwrites farthest.
    let mut merged = PolicyLevel::default();
    for level in levels.iter().rev() {
        for (cmd, perm) in &level.commands {
            merged.commands.insert(cmd.clone(), *perm);
        }
        for (cmd, perm) in &level.categories {
            merged.categories.insert(cmd.clone(), *perm);
        }
        for (cmd, perm) in &level.domains {
            merged.domains.insert(cmd.clone(), *perm);
        }
        for (cmd, perm) in &level.paths {
            merged.paths.insert(cmd.clone(), *perm);
        }
        for (key, perm) in &level.mcp {
            merged.mcp.insert(key.clone(), *perm);
        }
        if level.unclassified_default.is_some() {
            merged.unclassified_default = level.unclassified_default;
        }
    }

    Ok(merged)
}

pub fn compile_cline_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, ClineCompilationGaps), String> {
    let level = load_merged_policy(policy_path)?;

    let mut allow_rules: Vec<String> = Vec::new();
    let mut deny_rules: Vec<String> = Vec::new();
    let mut ask_dropped_names: Vec<String> = Vec::new();

    for (command_id, perm) in &level.commands {
        let shell_cmd = id_to_shell(command_id);
        match perm {
            Permission::Auto | Permission::Inform => allow_rules.push(shell_cmd),
            Permission::Deny => deny_rules.push(shell_cmd),
            Permission::Ask => ask_dropped_names.push(shell_cmd),
        }
    }

    allow_rules.sort();
    deny_rules.sort();
    ask_dropped_names.sort();

    let output = serde_json::json!({
        "allow": allow_rules,
        "deny": deny_rules,
    });
    Ok((
        output,
        ClineCompilationGaps {
            ask_dropped: ask_dropped_names,
        },
    ))
}

#[derive(Debug)]
pub struct ClineCompilationGaps {
    pub ask_dropped: Vec<String>,
}

pub fn compile_cline_permissions_summary(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let (output, gaps) = compile_cline_permissions(policy_path)?;
    #[allow(clippy::cast_possible_truncation)]
    let count = gaps.ask_dropped.len() as u32;
    Ok((output, count))
}

pub fn compile_opencode_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    let perm_str = |perm: &Permission| -> &'static str {
        match perm {
            Permission::Auto | Permission::Inform => "allow",
            Permission::Deny => "deny",
            Permission::Ask => "ask",
        }
    };

    let sorted_map =
        |entries: Vec<(String, &Permission)>| -> serde_json::Map<String, serde_json::Value> {
            let mut sorted = entries;
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            sorted
                .into_iter()
                .map(|(k, p)| (k, serde_json::Value::String(perm_str(p).to_string())))
                .collect()
        };

    let bash_rules = sorted_map(
        level
            .commands
            .iter()
            .map(|(id, p)| (id_to_shell(id), p))
            .collect(),
    );
    let edit_rules = sorted_map(level.paths.iter().map(|(k, p)| (k.clone(), p)).collect());
    let webfetch_rules = sorted_map(level.domains.iter().map(|(k, p)| (k.clone(), p)).collect());

    let mut output = serde_json::Map::new();
    if !bash_rules.is_empty() {
        output.insert("bash".to_string(), serde_json::Value::Object(bash_rules));
    }
    if !edit_rules.is_empty() {
        output.insert("edit".to_string(), serde_json::Value::Object(edit_rules));
    }
    if !webfetch_rules.is_empty() {
        output.insert(
            "webfetch".to_string(),
            serde_json::Value::Object(webfetch_rules),
        );
    }
    Ok((serde_json::Value::Object(output), 0))
}

pub fn compile_codex_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    let mut rules = Vec::new();

    for (command_id, perm) in &level.commands {
        let shell_cmd = id_to_shell(command_id);
        let permission = match perm {
            Permission::Auto | Permission::Inform => "Allow",
            Permission::Deny => "Forbidden",
            Permission::Ask => "Prompt",
        };
        rules.push(serde_json::json!({
            "prefix": shell_cmd,
            "permission": permission,
        }));
    }

    rules.sort_by(|a, b| {
        a["prefix"]
            .as_str()
            .unwrap_or("")
            .cmp(b["prefix"].as_str().unwrap_or(""))
    });

    Ok((serde_json::Value::Array(rules), 0))
}

pub fn serialize_codex_rules_file(rules: &serde_json::Value) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let Some(arr) = rules.as_array() else {
        return out;
    };
    for rule in arr {
        let prefix = rule["prefix"].as_str().unwrap_or("");
        let permission = rule["permission"].as_str().unwrap_or("Prompt");
        let tokens: Vec<&str> = prefix.split_whitespace().collect();
        let pattern = tokens
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let decision = permission.to_ascii_lowercase();
        let _ = writeln!(
            out,
            "prefix_rule(pattern=[{pattern}], decision=\"{decision}\")"
        );
    }
    out
}

pub fn compile_gemini_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    let mut rules = Vec::new();

    for (command_id, perm) in &level.commands {
        let shell_cmd = id_to_shell(command_id);
        let decision = match perm {
            Permission::Auto | Permission::Inform => "ALLOW",
            Permission::Deny => "DENY",
            Permission::Ask => "ASK_USER",
        };
        let pattern = regex::escape(&shell_cmd);
        rules.push(serde_json::json!({
            "toolName": "run_shell_command",
            "argsPattern": format!("^{pattern}(\\s|$)"),
            "decision": decision,
            "priority": 5.0,
        }));
    }

    for (path_pattern, perm) in &level.paths {
        let decision = match perm {
            Permission::Auto | Permission::Inform => "ALLOW",
            Permission::Deny => "DENY",
            Permission::Ask => "ASK_USER",
        };
        let escaped = regex::escape(path_pattern).replace(r"\*", ".*");
        for tool_name in ["read_file", "write_file", "replace"] {
            rules.push(serde_json::json!({
                "toolName": tool_name,
                "argsPattern": escaped,
                "decision": decision,
                "priority": 5.0,
            }));
        }
    }

    for ((server, tool), perm) in &level.mcp {
        let decision = match perm {
            Permission::Auto | Permission::Inform => "ALLOW",
            Permission::Deny => "DENY",
            Permission::Ask => "ASK_USER",
        };
        rules.push(serde_json::json!({
            "toolName": format!("mcp_{server}_{tool}"),
            "decision": decision,
            "priority": 5.0,
        }));
    }

    rules.sort_by(|a, b| {
        let tool_cmp = a["toolName"]
            .as_str()
            .unwrap_or("")
            .cmp(b["toolName"].as_str().unwrap_or(""));
        tool_cmp.then_with(|| {
            a["argsPattern"]
                .as_str()
                .unwrap_or("")
                .cmp(b["argsPattern"].as_str().unwrap_or(""))
        })
    });

    Ok((serde_json::Value::Array(rules), 0))
}

pub fn serialize_gemini_policy_toml(rules: &serde_json::Value) -> String {
    use std::fmt::Write;
    let mut out = String::from("# Generated by Kyris — AgentPact compiled policy for Gemini CLI\n");
    out.push_str("# Admin tier (priority 5.x) — overrides all lower-priority rules\n\n");
    let Some(arr) = rules.as_array() else {
        return out;
    };
    for (i, rule) in arr.iter().enumerate() {
        let _ = writeln!(out, "[[rules]]");
        if let Some(tool_name) = rule["toolName"].as_str() {
            let _ = writeln!(out, "toolName = \"{tool_name}\"");
        }
        if let Some(pattern) = rule["argsPattern"].as_str() {
            let _ = writeln!(out, "argsPattern = '{pattern}'");
        }
        if let Some(decision) = rule["decision"].as_str() {
            let _ = writeln!(out, "decision = \"{decision}\"");
        }
        if let Some(priority) = rule["priority"].as_f64() {
            if priority.fract() == 0.0 {
                let _ = writeln!(out, "priority = {priority:.1}");
            } else {
                let _ = writeln!(out, "priority = {priority}");
            }
        }
        if i + 1 < arr.len() {
            out.push('\n');
        }
    }
    out
}

pub fn compile_mcp_tool_filters(
    policy_path: Option<&Path>,
) -> Result<HashMap<String, Vec<String>>, String> {
    let level = load_merged_policy(policy_path)?;
    let mut filters: HashMap<String, Vec<String>> = HashMap::new();

    for ((server, tool), perm) in &level.mcp {
        if *perm == Permission::Deny {
            filters
                .entry(server.clone())
                .or_default()
                .push(tool.clone());
        }
    }

    for list in filters.values_mut() {
        list.sort();
    }

    Ok(filters)
}

pub fn detect_codex_gaps(policy_path: Option<&Path>) -> Vec<String> {
    let Ok(level) = load_merged_policy(policy_path) else {
        return Vec::new();
    };
    let mut gaps = Vec::new();
    if !level.paths.is_empty() {
        let count = level.paths.len();
        gaps.push(format!(
            "file-edit policy ({count} path rules) not enforceable in compiled mode — Codex CLI has no native file permission primitive"
        ));
    }
    if !level.domains.is_empty() {
        let count = level.domains.len();
        gaps.push(format!(
            "network policy ({count} domain rules) not enforceable in compiled mode — Codex CLI has no native network permission primitive"
        ));
    }
    gaps
}

fn dirs_home() -> Result<std::path::PathBuf, String> {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| "HOME is not set".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn writeTempYaml(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn testCompileClineFromPolicyOverrideDir() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "commands.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: commands
spec:
  commands:
    "npm·install": auto
    "rm·-rf": deny
    "docker·build": ask
    "git·status": auto
"#,
        );

        let (output, gaps) = compile_cline_permissions(Some(policy_dir.as_path())).unwrap();
        let allow = output["allow"].as_array().unwrap();
        let deny = output["deny"].as_array().unwrap();
        assert_eq!(allow.len(), 2);
        assert!(allow.contains(&serde_json::json!("npm install")));
        assert!(allow.contains(&serde_json::json!("git status")));
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0], "rm -rf");
        assert_eq!(gaps.ask_dropped, vec!["docker build"]);
    }

    #[test]
    fn testCompileClineFromPactAndOverride() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "pact.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: base
spec:
  commands:
    "git·push": ask
    "rm·-rf": deny
"#,
        );

        writeTempYaml(
            &policy_dir,
            "commands.local.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: local-overrides
spec:
  commands:
    "git·push": auto
"#,
        );

        let (output, _) = compile_cline_permissions(Some(policy_dir.as_path())).unwrap();
        let allow = output["allow"].as_array().unwrap();
        let deny = output["deny"].as_array().unwrap();
        assert!(
            allow.contains(&serde_json::json!("git push")),
            "local override should relax ask → auto"
        );
        assert!(deny.contains(&serde_json::json!("rm -rf")));
    }

    #[test]
    fn testCompileClineEmptySpec() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path();
        writeTempYaml(
            policy_dir,
            "pact.yaml",
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: empty\nspec: {}\n",
        );

        let (output, gaps) = compile_cline_permissions(Some(policy_dir)).unwrap();
        assert_eq!(output["allow"], serde_json::json!([]));
        assert_eq!(output["deny"], serde_json::json!([]));
        assert!(gaps.ask_dropped.is_empty());
    }

    #[test]
    fn testCompileClineMissingDir() {
        let result = compile_cline_permissions(Some(Path::new("/nonexistent/policy")));
        assert!(result.is_err());
    }

    #[test]
    fn testCompileClineInvalidYaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.yaml"), "{{{{not yaml").unwrap();

        let result = compile_cline_permissions(Some(dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn testCompileClineInformMapsToAllow() {
        let dir = tempfile::tempdir().unwrap();
        writeTempYaml(
            dir.path(),
            "pact.yaml",
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: test\nspec:\n  commands:\n    \"git·status\": inform\n",
        );

        let (output, _) = compile_cline_permissions(Some(dir.path())).unwrap();
        assert_eq!(output["allow"], serde_json::json!(["git status"]));
    }

    #[test]
    fn testCompileOpencode() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "commands.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: commands
spec:
  commands:
    "npm·install": auto
    "rm·-rf": deny
    "docker·build": ask
"#,
        );

        let (output, ask_dropped) =
            compile_opencode_permissions(Some(policy_dir.as_path())).unwrap();
        let bash = output["bash"].as_object().unwrap();
        assert_eq!(bash["npm install"], "allow");
        assert_eq!(bash["rm -rf"], "deny");
        assert_eq!(bash["docker build"], "ask");
        assert_eq!(ask_dropped, 0);
    }

    #[test]
    fn testCompileOpencodeEditAndWebfetch() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "full.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: full
spec:
  commands:
    "ls": auto
  paths:
    "./secrets/*": deny
    "./src/*": auto
    "./config/*": ask
  domains:
    "internal.corp.example.com": auto
    "*.evil.com": deny
    "api.external.io": ask
"#,
        );

        let (output, _) = compile_opencode_permissions(Some(policy_dir.as_path())).unwrap();

        let bash = output["bash"].as_object().unwrap();
        assert_eq!(bash["ls"], "allow");

        let edit = output["edit"].as_object().unwrap();
        assert_eq!(edit["./secrets/*"], "deny");
        assert_eq!(edit["./src/*"], "allow");
        assert_eq!(edit["./config/*"], "ask");

        let webfetch = output["webfetch"].as_object().unwrap();
        assert_eq!(webfetch["internal.corp.example.com"], "allow");
        assert_eq!(webfetch["*.evil.com"], "deny");
        assert_eq!(webfetch["api.external.io"], "ask");
    }

    #[test]
    fn testCompileOpencodeOmitsEmptySections() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "commands_only.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: commands-only
spec:
  commands:
    "ls": auto
"#,
        );

        let (output, _) = compile_opencode_permissions(Some(policy_dir.as_path())).unwrap();
        assert!(output.get("bash").is_some());
        assert!(output.get("edit").is_none());
        assert!(output.get("webfetch").is_none());
    }

    #[test]
    fn testCompileCodex() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "commands.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: commands
spec:
  commands:
    "npm·install": auto
    "rm·-rf": deny
    "docker·build": ask
"#,
        );

        let (output, ask_dropped) = compile_codex_permissions(Some(policy_dir.as_path())).unwrap();
        let rules = output.as_array().unwrap();
        assert_eq!(ask_dropped, 0);
        assert_eq!(rules.len(), 3);

        let by_prefix: std::collections::HashMap<&str, &str> = rules
            .iter()
            .map(|r| {
                (
                    r["prefix"].as_str().unwrap(),
                    r["permission"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(by_prefix["npm install"], "Allow");
        assert_eq!(by_prefix["rm -rf"], "Forbidden");
        assert_eq!(by_prefix["docker build"], "Prompt");
    }

    #[test]
    fn testCompileMcpToolFilters() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "mcp.yaml",
            r"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: mcp-overrides
spec:
  mcp:
    filesystem:
      read_file: auto
      delete_file: deny
    database:
      drop_table: deny
      select: auto
",
        );

        let filters = compile_mcp_tool_filters(Some(policy_dir.as_path())).unwrap();
        let fs_tools = filters.get("filesystem").unwrap();
        assert_eq!(fs_tools, &["delete_file".to_string()]);
        let db_tools = filters.get("database").unwrap();
        assert_eq!(db_tools, &["drop_table".to_string()]);
    }

    #[test]
    fn testSerializeCodexRulesFile() {
        let rules = serde_json::json!([
            {"prefix": "docker build", "permission": "Prompt"},
            {"prefix": "npm install", "permission": "Allow"},
            {"prefix": "rm -rf", "permission": "Forbidden"},
        ]);
        let output = serialize_codex_rules_file(&rules);
        assert_eq!(
            output,
            "prefix_rule(pattern=[\"docker\", \"build\"], decision=\"prompt\")\n\
             prefix_rule(pattern=[\"npm\", \"install\"], decision=\"allow\")\n\
             prefix_rule(pattern=[\"rm\", \"-rf\"], decision=\"forbidden\")\n"
        );
    }

    #[test]
    fn testSerializeCodexRulesFileSingleToken() {
        let rules = serde_json::json!([
            {"prefix": "cat", "permission": "Allow"},
        ]);
        let output = serialize_codex_rules_file(&rules);
        assert_eq!(
            output,
            "prefix_rule(pattern=[\"cat\"], decision=\"allow\")\n"
        );
    }

    #[test]
    fn testSerializeCodexRulesFileEmpty() {
        let rules = serde_json::json!([]);
        assert_eq!(serialize_codex_rules_file(&rules), "");
    }

    #[test]
    fn testCompileGeminiPermissions() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "commands.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: commands
spec:
  commands:
    "npm·install": auto
    "rm·-rf": deny
    "docker·build": ask
"#,
        );

        let (output, ask_dropped) = compile_gemini_permissions(Some(policy_dir.as_path())).unwrap();
        let rules = output.as_array().unwrap();
        assert_eq!(ask_dropped, 0);

        let by_tool: std::collections::HashMap<&str, &serde_json::Value> = rules
            .iter()
            .filter_map(|r| r["argsPattern"].as_str().map(|p| (p, r)))
            .collect();

        let npm_pattern = format!("^{}(\\s|$)", regex::escape("npm install"));
        let rm_pattern = format!("^{}(\\s|$)", regex::escape("rm -rf"));
        let docker_pattern = format!("^{}(\\s|$)", regex::escape("docker build"));

        assert_eq!(by_tool[npm_pattern.as_str()]["decision"], "ALLOW");
        assert_eq!(by_tool[rm_pattern.as_str()]["decision"], "DENY");
        assert_eq!(by_tool[docker_pattern.as_str()]["decision"], "ASK_USER");

        for rule in rules {
            assert_eq!(rule["toolName"], "run_shell_command");
            assert_eq!(rule["priority"], 5.0);
        }
    }

    #[test]
    fn testCompileGeminiMcpRules() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "mcp.yaml",
            r"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: mcp
spec:
  mcp:
    filesystem:
      read_file: auto
      delete_file: deny
",
        );

        let (output, _) = compile_gemini_permissions(Some(policy_dir.as_path())).unwrap();
        let rules = output.as_array().unwrap();

        let by_tool: std::collections::HashMap<&str, &str> = rules
            .iter()
            .map(|r| {
                (
                    r["toolName"].as_str().unwrap(),
                    r["decision"].as_str().unwrap(),
                )
            })
            .collect();

        assert_eq!(by_tool["mcp_filesystem_delete_file"], "DENY");
        assert_eq!(by_tool["mcp_filesystem_read_file"], "ALLOW");
    }

    #[test]
    fn testCompileGeminiPathRules() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "paths.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: paths
spec:
  paths:
    "/tmp/safe/*": auto
    "/etc/secrets": deny
    "/home/user/config": ask
"#,
        );

        let (output, ask_dropped) = compile_gemini_permissions(Some(policy_dir.as_path())).unwrap();
        let rules = output.as_array().unwrap();
        assert_eq!(ask_dropped, 0);

        // 3 path patterns × 3 file tools each = 9 rules
        assert_eq!(rules.len(), 9);

        let safe_rules: Vec<_> = rules
            .iter()
            .filter(|r| r["argsPattern"].as_str().unwrap().contains("safe"))
            .collect();
        assert_eq!(safe_rules.len(), 3);
        for r in &safe_rules {
            assert_eq!(r["decision"], "ALLOW");
            assert_eq!(r["priority"], 5.0);
        }
        let safe_tools: std::collections::HashSet<&str> = safe_rules
            .iter()
            .map(|r| r["toolName"].as_str().unwrap())
            .collect();
        assert!(safe_tools.contains("read_file"));
        assert!(safe_tools.contains("write_file"));
        assert!(safe_tools.contains("replace"));

        let secrets_rules: Vec<_> = rules
            .iter()
            .filter(|r| r["argsPattern"].as_str().unwrap().contains("secrets"))
            .collect();
        assert_eq!(secrets_rules.len(), 3);
        for r in &secrets_rules {
            assert_eq!(r["decision"], "DENY");
        }

        let config_rules: Vec<_> = rules
            .iter()
            .filter(|r| r["argsPattern"].as_str().unwrap().contains("config"))
            .collect();
        assert_eq!(config_rules.len(), 3);
        for r in &config_rules {
            assert_eq!(r["decision"], "ASK_USER");
        }
    }

    #[test]
    fn testSerializeGeminiPolicyToml() {
        let rules = serde_json::json!([
            {
                "toolName": "run_shell_command",
                "argsPattern": "^npm\\ install(\\s|$)",
                "decision": "ALLOW",
                "priority": 5.0,
            },
            {
                "toolName": "run_shell_command",
                "argsPattern": "^rm\\ \\-rf(\\s|$)",
                "decision": "DENY",
                "priority": 5.0,
            },
        ]);
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(toml.contains("# Generated by Kyris"));
        assert!(toml.contains("[[rules]]"));
        assert!(toml.contains("toolName = \"run_shell_command\""));
        assert!(toml.contains("decision = \"ALLOW\""));
        assert!(toml.contains("decision = \"DENY\""));
        assert!(toml.contains("priority = 5.0"));
        let rule_count = toml.matches("[[rules]]").count();
        assert_eq!(rule_count, 2);
    }

    #[test]
    fn testSerializeGeminiPolicyTomlEmpty() {
        let rules = serde_json::json!([]);
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(toml.contains("# Generated by Kyris"));
        assert!(!toml.contains("[[rules]]"));
    }

    #[test]
    fn testSerializeGeminiPolicyTomlMcp() {
        let rules = serde_json::json!([
            {
                "toolName": "mcp_filesystem_read_file",
                "decision": "ALLOW",
                "priority": 5.0,
            },
        ]);
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(toml.contains("toolName = \"mcp_filesystem_read_file\""));
        assert!(!toml.contains("argsPattern"));
    }

    #[test]
    fn testDetectCodexGapsWithPaths() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "paths.yaml",
            r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: paths
spec:
  paths:
    "/tmp/*": auto
    "/etc/secrets": deny
  domains:
    "example.com": auto
"#,
        );

        let gaps = detect_codex_gaps(Some(policy_dir.as_path()));
        assert_eq!(gaps.len(), 2);
        assert!(gaps[0].contains("2 path rules"));
        assert!(gaps[1].contains("1 domain rules"));
    }

    #[test]
    fn testDetectCodexGapsEmpty() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "pact.yaml",
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: empty\nspec: {}\n",
        );

        let gaps = detect_codex_gaps(Some(policy_dir.as_path()));
        assert!(gaps.is_empty());
    }
}
