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

/// Filesystem access mode for a single path glob, modeled after Codex CLI's
/// `FileSystemAccessMode` (`codex-rs/protocol/src/permissions.rs`). Lives in
/// kyris — not in `AgentPact` — because the value set, wire form, and the
/// fail-closed projection from `AgentPact`'s `Permission` are kyris-side
/// implementation choices, not part of the `AgentPact` standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccessMode {
    /// No access (deny both read and write).
    None,
    /// Read allowed, write denied.
    #[allow(dead_code)] // reserved for future read-only path permission
    Read,
    /// Read and write allowed.
    Write,
}

impl FileAccessMode {
    /// Canonical wire token used in Codex's `[permissions.<profile>.filesystem]`
    /// table. Matches `FileSystemAccessMode`'s `serde(rename_all = "lowercase")`.
    #[must_use]
    pub fn as_codex_token(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Network-access primitive for a single domain or URL pattern, modeled after
/// Codex CLI's `NetworkDomainPermission`. As with [`FileAccessMode`], the
/// projection lives in kyris because network egress is non-interactive at
/// the sandbox layer — `Ask` collapses to `Deny` (fail-closed). A different
/// `AgentPact` implementation might choose a different mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccess {
    Allow,
    Deny,
}

impl NetworkAccess {
    /// Canonical wire token used in Codex's `[permissions.<profile>.network.domains]`
    /// table.
    #[must_use]
    pub fn as_codex_token(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Project an `AgentPact` `Permission` onto a Codex-style filesystem access mode
/// for compiled (non-interactive) enforcement.
///
/// `Ask` fails closed at the sandbox layer because there is no prompt path
/// at file-permission decision time. When a live `PreToolUse` hook is present,
/// the hook is what interprets `Ask` interactively; the compiled config is
/// defense-in-depth for the hook-down case.
#[must_use]
pub fn permission_to_file_mode(perm: Permission) -> FileAccessMode {
    match perm {
        Permission::Auto | Permission::Inform => FileAccessMode::Write,
        Permission::Ask | Permission::Deny => FileAccessMode::None,
    }
}

/// Project an `AgentPact` `Permission` onto a Codex-style network decision.
/// See [`permission_to_file_mode`] for the fail-closed rationale.
#[must_use]
pub fn permission_to_network_access(perm: Permission) -> NetworkAccess {
    match perm {
        Permission::Auto | Permission::Inform => NetworkAccess::Allow,
        Permission::Ask | Permission::Deny => NetworkAccess::Deny,
    }
}

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

/// Output of [`compile_codex_permissions_table`]: the two permission tables
/// Codex CLI supports plus any precision-loss warnings.
pub struct CodexPermissionsTable {
    /// Entries for `[permissions.kyris.filesystem]`: path-glob → access mode.
    pub filesystem: std::collections::BTreeMap<String, String>,
    /// Entries for `[permissions.kyris.network.domains]`: hostname → "allow"|"deny".
    /// URL path components are stripped; host is extracted.
    pub network_domains: std::collections::BTreeMap<String, String>,
    /// Warnings about policy dimensions that lost precision during compilation.
    pub gaps: Vec<String>,
}

/// Compile `AgentPact` `paths` and `domains` policy into the two permission
/// tables that Codex CLI supports natively.
///
/// **Filesystem** (`paths`): direct mapping — each path glob gets a Codex
/// access mode via [`permission_to_file_mode`]. `Ask` fails closed to `none`.
///
/// **Network** (`domains`): host-only mapping — Codex matches by hostname, not
/// URL path. If a domain key includes a path component (`"api.example.com/v2/*"`)
/// the host is extracted (`"api.example.com"`) and the path is dropped with a
/// gap warning. `Ask` fails closed to `deny`.
///
/// Empty tables are omitted; callers should skip writing `[permissions.kyris]`
/// when both maps are empty.
pub fn compile_codex_permissions_table(
    policy_path: Option<&Path>,
) -> Result<CodexPermissionsTable, String> {
    let level = load_merged_policy(policy_path)?;

    let mut filesystem = std::collections::BTreeMap::new();
    let mut network_domains = std::collections::BTreeMap::new();
    let mut url_paths_dropped: Vec<String> = Vec::new();
    let mut ask_collapsed: Vec<String> = Vec::new();

    for (path_glob, perm) in &level.paths {
        if *perm == Permission::Ask {
            ask_collapsed.push(path_glob.clone());
        }
        let mode = permission_to_file_mode(*perm);
        filesystem.insert(path_glob.clone(), mode.as_codex_token().to_string());
    }

    for (domain_key, perm) in &level.domains {
        let host = extract_host(domain_key);
        if host != domain_key.as_str() {
            url_paths_dropped.push(domain_key.clone());
        }
        if *perm == Permission::Ask {
            ask_collapsed.push(domain_key.clone());
        }
        let access = permission_to_network_access(*perm);
        network_domains.insert(host, access.as_codex_token().to_string());
    }

    let mut gaps = Vec::new();
    if !url_paths_dropped.is_empty() {
        gaps.push(format!(
            "{} domain rule(s) had URL path components stripped — Codex matches host only: {}",
            url_paths_dropped.len(),
            url_paths_dropped.join(", ")
        ));
    }
    if !ask_collapsed.is_empty() {
        gaps.push(format!(
            "{} ask rule(s) compiled as deny/none in [permissions.kyris] — no prompt path at Codex sandbox layer: {}",
            ask_collapsed.len(),
            ask_collapsed.join(", ")
        ));
    }

    Ok(CodexPermissionsTable {
        filesystem,
        network_domains,
        gaps,
    })
}

/// Extract the hostname from a domain key, stripping any scheme prefix
/// and URL path component.
///
/// - `"api.example.com"`        → `"api.example.com"`
/// - `"api.example.com/v2/*"`   → `"api.example.com"`
/// - `"https://api.example.com/v2"` → `"api.example.com"`
fn extract_host(domain_key: &str) -> String {
    let without_scheme = if let Some(pos) = domain_key.find("://") {
        &domain_key[pos + 3..]
    } else {
        domain_key
    };
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
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

/// Returns precision-loss warnings from compiling the current policy into
/// Codex CLI's native permission tables.
///
/// Paths and domains are now compiled into `[permissions.kyris]` in
/// `config.toml`. This function surfaces only what was lost in translation:
/// URL path components stripped from domain keys (Codex is host-only) and
/// ask rules that collapsed to deny/none (no prompt path at the sandbox layer).
/// Returns an empty Vec when all rules compile without loss.
pub fn detect_codex_gaps(policy_path: Option<&Path>) -> Vec<String> {
    compile_codex_permissions_table(policy_path)
        .map(|table| table.gaps)
        .unwrap_or_default()
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
    fn testDetectCodexGapsCleanPathsAndDomains() {
        // Paths and domains now compile cleanly — no gaps for these.
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
kind: PolicyOverride
metadata:
  name: domains
spec:
  domains:
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
kind: PolicyOverride
metadata:
  name: asks
spec:
  paths:
    "/home/user/sensitive/*": ask
  domains:
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
kind: PolicyOverride
metadata:
  name: mixed
spec:
  paths:
    "/tmp/safe/*": auto
    "/etc/secrets": deny
  domains:
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
kind: PolicyOverride
metadata:
  name: url-paths
spec:
  domains:
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
kind: PolicyOverride
metadata:
  name: asks
spec:
  paths:
    "/sensitive/*": ask
  domains:
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
        // Auto and Inform both grant write — the "inform" log component is
        // the live hook's responsibility, not the compiled sandbox config.
        assert_eq!(
            permission_to_file_mode(Permission::Auto),
            FileAccessMode::Write
        );
        assert_eq!(
            permission_to_file_mode(Permission::Inform),
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
            permission_to_network_access(Permission::Inform),
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
  domains:
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
