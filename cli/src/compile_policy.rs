// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::collections::HashMap;
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

#[derive(serde::Deserialize)]
struct PolicyDoc {
    spec: Option<PolicySpec>,
}

#[derive(serde::Deserialize)]
struct PolicySpec {
    #[serde(default)]
    commands: HashMap<String, String>,
}

pub fn compile_cline_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let policy_dir = format!("{home}/.agentpact/policy");

    let path = if let Some(p) = policy_path {
        p.to_path_buf()
    } else {
        let pact_path = format!("{policy_dir}/pact.yaml");
        if std::path::Path::new(&pact_path).exists() {
            PathBuf::from(pact_path)
        } else {
            return Err(format!(
                "No policy file found. Looked for pact.yaml in {policy_dir}"
            ));
        }
    };

    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;

    let doc: PolicyDoc = serde_saphyr::from_str(&contents)
        .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?;

    let mut allow_rules: Vec<String> = Vec::new();
    let mut deny_rules: Vec<String> = Vec::new();
    let mut ask_dropped = 0u32;

    if let Some(spec) = doc.spec {
        for (command_id, decision) in &spec.commands {
            match decision.as_str() {
                "auto" | "inform" => allow_rules.push(command_id.clone()),
                "deny" => deny_rules.push(command_id.clone()),
                "ask" => ask_dropped += 1,
                _ => {}
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testCompileClinePermissionsFromRealFormat() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("pact.yaml");
        std::fs::write(
            &policy_path,
            r#"apiVersion: agentpact/v1
kind: Pact
metadata:
  name: test
spec:
  commands:
    "npm.install": auto
    "rm.-rf": deny
    "docker.build": ask
    "git.status": auto
"#,
        )
        .unwrap();

        let (output, ask_dropped) = compile_cline_permissions(Some(policy_path.as_path())).unwrap();
        let allow = output["allow"].as_array().unwrap();
        let deny = output["deny"].as_array().unwrap();
        assert_eq!(allow.len(), 2);
        assert!(allow.contains(&serde_json::json!("npm.install")));
        assert!(allow.contains(&serde_json::json!("git.status")));
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0], "rm.-rf");
        assert_eq!(ask_dropped, 1);
    }

    #[test]
    fn testCompileClinePermissionsEmptySpec() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("pact.yaml");
        std::fs::write(
            &policy_path,
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: empty\nspec: {}\n",
        )
        .unwrap();

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
    fn testCompileClinePermissionsInvalidYaml() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("bad.yaml");
        std::fs::write(&policy_path, "{{{{not yaml").unwrap();

        let result = compile_cline_permissions(Some(policy_path.as_path()));
        assert!(result.is_err());
    }

    #[test]
    fn testCompileClinePermissionsNoSpec() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("pact.yaml");
        std::fs::write(
            &policy_path,
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: bare\n",
        )
        .unwrap();

        let (output, ask_dropped) = compile_cline_permissions(Some(policy_path.as_path())).unwrap();
        assert_eq!(output["allow"], serde_json::json!([]));
        assert_eq!(output["deny"], serde_json::json!([]));
        assert_eq!(ask_dropped, 0);
    }

    #[test]
    fn testCompileClinePermissionsInformMapsToAllow() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("pact.yaml");
        std::fs::write(
            &policy_path,
            "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: test\nspec:\n  commands:\n    \"git.status\": inform\n",
        )
        .unwrap();

        let (output, _) = compile_cline_permissions(Some(policy_path.as_path())).unwrap();
        assert_eq!(output["allow"], serde_json::json!(["git.status"]));
    }
}
