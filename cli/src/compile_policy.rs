// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::collections::HashMap;
use std::path::Path;

use agentpact::catalog::commands::id_to_shell;
use agentpact::policy::Permission;
use agentpact::policy::loader::{
    PolicyLevel, load_policy_dir, parse_policy_level, resolve_walk_up,
};

// Per-target compiled-policy emitters and the shared Permission→sandbox
// projection split into sibling submodules. Re-exported `pub` so external
// callers keep resolving `crate::compile_policy::<item>`.
mod codex;
mod gemini;
mod projection;
pub use codex::*;
pub use gemini::*;
pub use projection::*;

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
        return parse_policy_level(&files);
    }

    let cwd =
        std::env::current_dir().map_err(|e| format!("Cannot determine working directory: {e}"))?;

    let user_policy_dir = agentpact::config::default_user_policy_dir(&home);
    let levels = resolve_walk_up(Some(cwd.to_str().unwrap_or(".")), &home, &user_policy_dir)?;

    if levels.is_empty() {
        return Err(format!(
            "No policy files found. Looked for .agentpact/policy/ from {} up through {} and {}",
            cwd.display(),
            home.display(),
            user_policy_dir.display()
        ));
    }

    // Merge: iterate farthest-to-nearest so nearest overwrites farthest.
    let mut merged = PolicyLevel::default();
    for level in levels.iter().rev() {
        for (cmd, perm) in &level.commands {
            merged.commands.insert(cmd.clone(), *perm);
        }
        for (host, perm) in &level.urls {
            merged.urls.insert(host.clone(), *perm);
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
            Permission::Auto => allow_rules.push(shell_cmd),
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

pub fn compile_opencode_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    let perm_str = |perm: &Permission| -> &'static str {
        match perm {
            Permission::Auto => "allow",
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
    let webfetch_rules = sorted_map(level.urls.iter().map(|(k, p)| (k.clone(), p)).collect());

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

fn dirs_home() -> Result<std::path::PathBuf, String> {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| "HOME is not set".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testToCodexFsPathResolvesRelativeAndKeepsValid() {
        let base = std::path::Path::new("/work/proj");
        // Relative globs resolve against the workspace root (Codex rejects relative
        // paths); the glob tail survives.
        assert_eq!(
            to_codex_fs_path("./secrets/*", base),
            "/work/proj/secrets/*"
        );
        assert_eq!(to_codex_fs_path("src/*", base), "/work/proj/src/*");
        // Already-Codex-valid forms pass through unchanged.
        assert_eq!(to_codex_fs_path("/etc/passwd", base), "/etc/passwd");
        assert_eq!(to_codex_fs_path("~/.ssh/*", base), "~/.ssh/*");
        assert_eq!(to_codex_fs_path("~", base), "~");
        assert_eq!(
            to_codex_fs_path(":workspace_roots", base),
            ":workspace_roots"
        );
    }

    #[test]
    fn testSerializeCodexRulesEscapesQuoteTokens() {
        // A command token that is a raw quote (e.g. from `tr -d "`) must be
        // escaped, or codex fails to load the whole rules file with
        // "unfinished string literal".
        let rules = serde_json::json!([{"prefix": "tr -d \"", "permission": "Auto"}]);
        let out = serialize_codex_rules_file(&rules);
        assert!(
            !out.contains("\"\"\""),
            "unescaped quote token produced invalid `\"\"\"`: {out}"
        );
        assert!(
            out.contains("\\\""),
            "quote token should be backslash-escaped: {out}"
        );
    }
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
kind: Pact
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

        // A second authored file that sorts AFTER pact.yaml — last-writer-wins
        // in the policy dir relaxes git·push ask → auto.
        writeTempYaml(
            &policy_dir,
            "zz-overrides.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: overrides
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
            "later authored file should relax ask → auto"
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
    fn testCompileOpencode() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "commands.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
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
kind: Pact
metadata:
  name: full
spec:
  commands:
    "ls": auto
  paths:
    "./secrets/*": deny
    "./src/*": auto
    "./config/*": ask
  urls:
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
kind: Pact
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
kind: Pact
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
kind: Pact
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
kind: Pact
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
        // Ask rules are DROPPED (the live hook owns asks; a user-tier ask rule
        // would re-prompt natively and override gemini-side always-allows).
        assert_eq!(ask_dropped, 1);

        // Shell rules use gemini's own commandPrefix convenience — gemini
        // compiles it into the correct regex against its NUL-delimited
        // stable-stringified args, which a hand-built argsPattern cannot match.
        let by_prefix: std::collections::HashMap<&str, &serde_json::Value> = rules
            .iter()
            .filter_map(|r| r["commandPrefix"].as_str().map(|p| (p, r)))
            .collect();

        assert_eq!(by_prefix["npm install"]["decision"], "allow");
        assert_eq!(by_prefix["npm install"]["priority"], 100);
        assert_eq!(by_prefix["rm -rf"]["decision"], "deny");
        assert_eq!(by_prefix["rm -rf"]["priority"], 900);
        assert!(!by_prefix.contains_key("docker build"), "ask rule dropped");
        assert_eq!(rules.len(), 2);

        for rule in rules {
            assert_eq!(rule["toolName"], "run_shell_command");
            assert!(
                rule.get("argsPattern")
                    .is_none_or(serde_json::Value::is_null)
            );
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
kind: Pact
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

        assert_eq!(by_tool["mcp_filesystem_delete_file"], "deny");
        assert_eq!(by_tool["mcp_filesystem_read_file"], "allow");
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
kind: Pact
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
        // The ask path rule is dropped once per emitted-tool fan-out source.
        assert_eq!(ask_dropped, 1);

        // 2 surviving path patterns × 3 file tools each = 6 rules
        assert_eq!(rules.len(), 6);

        let safe_rules: Vec<_> = rules
            .iter()
            .filter(|r| r["argsPattern"].as_str().unwrap().contains("safe"))
            .collect();
        assert_eq!(safe_rules.len(), 3);
        for r in &safe_rules {
            assert_eq!(r["decision"], "allow");
            assert_eq!(r["priority"], 100);
            // Field-anchored so file CONTENT mentioning a path can't match.
            assert!(
                r["argsPattern"]
                    .as_str()
                    .unwrap()
                    .starts_with("\"file_path\":\""),
                "got: {}",
                r["argsPattern"]
            );
        }
        let safe_tools: std::collections::HashSet<&str> = safe_rules
            .iter()
            .map(|r| r["toolName"].as_str().unwrap())
            .collect();
        assert!(safe_tools.contains("read_file"));
        assert!(safe_tools.contains("write_file"));
        assert!(safe_tools.contains("replace"));

        // An EXACT path (no glob) is closed on both ends so it matches only
        // that path — `/etc/secrets` must not also match `/etc/secretsX`.
        for r in &safe_rules {
            // The glob `/tmp/safe/*` stays open-ended (ends with `.*"`).
            assert!(
                r["argsPattern"].as_str().unwrap().ends_with(".*\""),
                "glob rule: {}",
                r["argsPattern"]
            );
        }
        let secrets_rules: Vec<_> = rules
            .iter()
            .filter(|r| r["argsPattern"].as_str().unwrap().contains("secrets"))
            .collect();
        assert_eq!(secrets_rules.len(), 3);
        for r in &secrets_rules {
            assert_eq!(r["decision"], "deny");
            assert_eq!(r["priority"], 900);
            assert_eq!(
                r["argsPattern"].as_str().unwrap(),
                "\"file_path\":\"/etc/secrets\"",
                "exact path must be closed-anchored"
            );
        }

        // The ask path rule must not be emitted at all.
        assert!(
            !rules
                .iter()
                .any(|r| r["argsPattern"].as_str().unwrap().contains("config"))
        );
    }

    #[test]
    fn testSerializeGeminiPolicyToml() {
        let rules = serde_json::json!([
            {
                "toolName": "run_shell_command",
                "commandPrefix": "npm install",
                "decision": "allow",
                "priority": 100,
            },
            {
                "toolName": "run_shell_command",
                "commandPrefix": "rm -rf",
                "decision": "deny",
                "priority": 900,
            },
        ]);
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(toml.contains("# Generated by Kyris"));
        assert!(toml.contains("toolName = \"run_shell_command\""));
        assert!(toml.contains("commandPrefix = \"npm install\""));
        assert!(toml.contains("decision = \"allow\""));
        assert!(toml.contains("decision = \"deny\""));
        assert!(toml.contains("priority = 100"));
        assert!(toml.contains("priority = 900"));
        // Gemini's loader key is [[rule]]; [[rules]] is silently ignored.
        assert_eq!(toml.matches("[[rule]]").count(), 2);
        assert!(!toml.contains("[[rules]]"));
        assert!(gemini_policy_file_is_loadable(&toml));
    }

    #[test]
    fn testSerializeGeminiPolicyTomlEmpty() {
        let rules = serde_json::json!([]);
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(toml.contains("# Generated by Kyris"));
        assert!(!toml.contains("[[rule]]"));
    }

    #[test]
    fn testGeminiPolicyLoadableAcceptsGeminiContractShape() {
        // The shape gemini's toml-loader actually accepts: [[rule]] tables,
        // lowercase decisions, integer priority.
        let contents = r#"
[[rule]]
toolName = "run_shell_command"
commandPrefix = "git status"
decision = "allow"
priority = 100

[[rule]]
toolName = ["read_file", "write_file"]
decision = "ask_user"
priority = 10
"#;
        assert!(gemini_policy_file_is_loadable(contents));
    }

    #[test]
    fn testGeminiPolicyLoadableRejectsWrongShapes() {
        // Wrong array key ([[rules]] vs [[rule]]).
        assert!(!gemini_policy_file_is_loadable(
            "[[rules]]\ntoolName = \"x\"\ndecision = \"allow\"\npriority = 5\n"
        ));
        // Wrong decision case.
        assert!(!gemini_policy_file_is_loadable(
            "[[rule]]\ntoolName = \"x\"\ndecision = \"ALLOW\"\npriority = 5\n"
        ));
        // priority and toolName are REQUIRED — one bad rule kills the file.
        assert!(!gemini_policy_file_is_loadable(
            "[[rule]]\ntoolName = \"x\"\ndecision = \"allow\"\n"
        ));
        assert!(!gemini_policy_file_is_loadable(
            "[[rule]]\ndecision = \"allow\"\npriority = 5\n"
        ));
        // Out-of-range / fractional priority.
        assert!(!gemini_policy_file_is_loadable(
            "[[rule]]\ntoolName = \"x\"\ndecision = \"allow\"\npriority = 1000\n"
        ));
        assert!(!gemini_policy_file_is_loadable(
            "[[rule]]\ntoolName = \"x\"\ndecision = \"allow\"\npriority = 5.5\n"
        ));
        // Empty / missing rules.
        assert!(!gemini_policy_file_is_loadable("# just a comment\n"));
        // Zero-fraction float priority passes (JS Number.isInteger semantics).
        assert!(gemini_policy_file_is_loadable(
            "[[rule]]\ntoolName = \"x\"\ndecision = \"allow\"\npriority = 5.0\n"
        ));
    }

    #[test]
    fn testSerializerOutputLoadsInGemini() {
        // Finding 5 FIXED: the serializer emits gemini's real loader contract
        // ([[rule]], lowercase decisions, required integer priority), so the
        // probe validator accepts it. This locks serializer and validator
        // together — loosening either side breaks here first.
        let (rules, _) = (
            serde_json::json!([
                {"toolName": "run_shell_command", "commandPrefix": "git status",
                 "decision": "allow", "priority": 100},
                {"toolName": "read_file",
                 "argsPattern": "\"file_path\":\"/etc/secrets",
                 "decision": "deny", "priority": 900},
                {"toolName": "mcp_fs_delete", "decision": "deny", "priority": 900}
            ]),
            0,
        );
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(
            gemini_policy_file_is_loadable(&toml),
            "serializer output must satisfy the loader contract:\n{toml}"
        );
    }

    #[test]
    fn testSerializeGeminiPolicyTomlMcp() {
        let rules = serde_json::json!([
            {
                "toolName": "mcp_filesystem_read_file",
                "decision": "allow",
                "priority": 100,
            },
        ]);
        let toml = serialize_gemini_policy_toml(&rules);
        assert!(toml.contains("toolName = \"mcp_filesystem_read_file\""));
        assert!(!toml.contains("argsPattern"));
        assert!(gemini_policy_file_is_loadable(&toml));
    }

    #[test]
    fn testSerializeGeminiPolicyTomlEscapesQuotesAndBackslashes() {
        // A pattern carrying a single quote (e.g. from `tr -d "'"`) and regex
        // backslashes must still produce VALID TOML. The old `'…'` literal
        // terminated early on the quote and broke Gemini's policy load.
        let pattern = r#"^OAK=\$\(grep \| tr \-d "'"\)(\s|$)"#;
        let rules = serde_json::json!([
            {
                "toolName": "run_shell_command",
                "commandPrefix": pattern,
                "decision": "allow",
                "priority": 100,
            },
        ]);
        let serialized = serialize_gemini_policy_toml(&rules);
        let parsed: toml::Value = toml::from_str(&serialized)
            .unwrap_or_else(|e| panic!("output must be valid TOML: {e}\n{serialized}"));
        assert_eq!(
            parsed["rule"][0]["commandPrefix"].as_str(),
            Some(pattern),
            "pattern must round-trip through TOML unchanged"
        );
    }

    #[test]
    fn testDetectCodexGapsCleanPathsAndDomains() {
        // Paths and domains now compile cleanly — no gaps for these.
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "paths.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: paths
spec:
  paths:
    "/tmp/*": auto
    "/etc/secrets": deny
  urls:
    "example.com": auto
    "*.evil.com": deny
"#,
        );

        let gaps = detect_codex_gaps(Some(policy_dir.as_path()));
        assert!(
            gaps.is_empty(),
            "clean paths/domains should produce no gaps; got: {gaps:?}"
        );
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

    #[test]
    fn testDetectCodexGapsUrlPathDropped() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "domains.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: domains
spec:
  urls:
    "api.example.com/v2/*": deny
    "clean.example.com": auto
"#,
        );

        let gaps = detect_codex_gaps(Some(policy_dir.as_path()));
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].contains("URL path components stripped"));
        assert!(gaps[0].contains("api.example.com/v2/*"));
    }

    #[test]
    fn testDetectCodexGapsAskCollapsed() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();

        writeTempYaml(
            &policy_dir,
            "policy.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: asks
spec:
  paths:
    "/home/user/sensitive/*": ask
  urls:
    "internal.corp": ask
"#,
        );

        let gaps = detect_codex_gaps(Some(policy_dir.as_path()));
        assert_eq!(
            gaps.len(),
            1,
            "should report one ask-collapsed gap; got: {gaps:?}"
        );
        assert!(gaps[0].contains("ask rule(s) compiled as deny/none"));
    }

    // --- compile_codex_permissions_table ---

    #[test]
    fn testCompileCodexPermissionsTableClean() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        writeTempYaml(
            &policy_dir,
            "policy.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: mixed
spec:
  paths:
    "/tmp/safe/*": auto
    "/etc/secrets": deny
  urls:
    "api.example.com": auto
    "*.evil.com": deny
"#,
        );

        let table = compile_codex_permissions_table(Some(&policy_dir)).unwrap();
        assert_eq!(table.filesystem["/tmp/safe/*"], "write");
        assert_eq!(table.filesystem["/etc/secrets"], "none");
        assert_eq!(table.network_domains["api.example.com"], "allow");
        assert_eq!(table.network_domains["*.evil.com"], "deny");
        assert!(table.gaps.is_empty());
    }

    #[test]
    fn testCompileCodexPermissionsTableUrlPathStripped() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        writeTempYaml(
            &policy_dir,
            "policy.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: url-paths
spec:
  urls:
    "api.example.com/v2/*": deny
    "https://cdn.example.com/assets": auto
    "clean.host.com": deny
"#,
        );

        let table = compile_codex_permissions_table(Some(&policy_dir)).unwrap();
        // Host extracted, path dropped.
        assert_eq!(table.network_domains["api.example.com"], "deny");
        assert_eq!(table.network_domains["cdn.example.com"], "allow");
        assert_eq!(table.network_domains["clean.host.com"], "deny");
        // Both stripped entries are grouped into one gap message.
        assert_eq!(
            table.gaps.len(),
            1,
            "one grouped URL-path gap expected; got: {:?}",
            table.gaps
        );
        assert!(table.gaps[0].contains("URL path components stripped"));
        assert!(table.gaps[0].contains("2 domain rule(s)"));
    }

    #[test]
    fn testCompileCodexPermissionsTableAskCollapse() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        writeTempYaml(
            &policy_dir,
            "policy.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: asks
spec:
  paths:
    "/sensitive/*": ask
  urls:
    "internal.corp": ask
"#,
        );

        let table = compile_codex_permissions_table(Some(&policy_dir)).unwrap();
        assert_eq!(table.filesystem["/sensitive/*"], "none");
        assert_eq!(table.network_domains["internal.corp"], "deny");
        let combined = table.gaps.join(" ");
        assert!(combined.contains("ask rule(s) compiled as deny/none"));
    }

    #[test]
    fn testCompileCodexPermissionsTableEmpty() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        writeTempYaml(
            &policy_dir,
            "pact.yaml",
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: empty\nspec: {}\n",
        );

        let table = compile_codex_permissions_table(Some(&policy_dir)).unwrap();
        assert!(table.filesystem.is_empty());
        assert!(table.network_domains.is_empty());
        assert!(table.gaps.is_empty());
    }

    #[test]
    fn testExtractHost() {
        assert_eq!(extract_host("api.example.com"), "api.example.com");
        assert_eq!(extract_host("api.example.com/v2/*"), "api.example.com");
        assert_eq!(
            extract_host("https://cdn.example.com/assets"),
            "cdn.example.com"
        );
        assert_eq!(extract_host("http://localhost:8080/path"), "localhost:8080");
        assert_eq!(extract_host("*.evil.com"), "*.evil.com");
    }

    // --- FileAccessMode / NetworkAccess projections ---

    #[test]
    fn testFileAccessModeCodexToken() {
        assert_eq!(FileAccessMode::None.as_codex_token(), "none");
        assert_eq!(FileAccessMode::Read.as_codex_token(), "read");
        assert_eq!(FileAccessMode::Write.as_codex_token(), "write");
    }

    #[test]
    fn testNetworkAccessCodexToken() {
        assert_eq!(NetworkAccess::Allow.as_codex_token(), "allow");
        assert_eq!(NetworkAccess::Deny.as_codex_token(), "deny");
    }

    #[test]
    fn testPermissionToFileMode() {
        // Auto grants write at the compiled sandbox layer.
        assert_eq!(
            permission_to_file_mode(Permission::Auto),
            FileAccessMode::Write
        );
        // Ask fails closed at the sandbox layer (no prompt path).
        assert_eq!(
            permission_to_file_mode(Permission::Ask),
            FileAccessMode::None
        );
        assert_eq!(
            permission_to_file_mode(Permission::Deny),
            FileAccessMode::None
        );
    }

    #[test]
    fn testPermissionToNetworkAccess() {
        assert_eq!(
            permission_to_network_access(Permission::Auto),
            NetworkAccess::Allow
        );
        assert_eq!(
            permission_to_network_access(Permission::Ask),
            NetworkAccess::Deny
        );
        assert_eq!(
            permission_to_network_access(Permission::Deny),
            NetworkAccess::Deny
        );
    }

    #[test]
    fn testDetectCodexGapsNoFalsePositivesForCleanPolicy() {
        // Paths and domains compile fully — gaps only appear for precision loss
        // (URL path components, ask collapse), not for the mere presence of rules.
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".agentpact").join("policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        writeTempYaml(
            &policy_dir,
            "policy.yaml",
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: clean
spec:
  paths:
    "./scripts/deploy.sh": deny
  urls:
    "api.example.com": deny
"#,
        );
        let gaps = detect_codex_gaps(Some(policy_dir.as_path()));
        assert!(
            gaps.is_empty(),
            "clean deny rules should compile without gaps; got: {gaps:?}"
        );
    }
}
