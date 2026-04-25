// SPDX-License-Identifier: Apache-2.0
use clap::Args;
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
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    let mut allow_rules: Vec<String> = Vec::new();
    let mut deny_rules: Vec<String> = Vec::new();
    let mut ask_dropped = 0u32;

    for (command_id, perm) in &level.commands {
        let shell_cmd = id_to_shell(command_id);
        match perm {
            Permission::Auto | Permission::Inform => allow_rules.push(shell_cmd),
            Permission::Deny => deny_rules.push(shell_cmd),
            Permission::Ask => ask_dropped += 1,
        }
    }

    allow_rules.sort();
    deny_rules.sort();

    let output = serde_json::json!({
        "allow": allow_rules,
        "deny": deny_rules,
    });
    Ok((output, ask_dropped))
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

        let (output, ask_dropped) = compile_cline_permissions(Some(policy_dir.as_path())).unwrap();
        let allow = output["allow"].as_array().unwrap();
        let deny = output["deny"].as_array().unwrap();
        assert_eq!(allow.len(), 2);
        assert!(allow.contains(&serde_json::json!("npm install")));
        assert!(allow.contains(&serde_json::json!("git status")));
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0], "rm -rf");
        assert_eq!(ask_dropped, 1);
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

        let (output, ask_dropped) = compile_cline_permissions(Some(policy_dir)).unwrap();
        assert_eq!(output["allow"], serde_json::json!([]));
        assert_eq!(output["deny"], serde_json::json!([]));
        assert_eq!(ask_dropped, 0);
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
}
