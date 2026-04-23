// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use regex::Regex;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::compile_policy;
use crate::integration::{
    claude_settings_path, codex_hooks_path, gemini_settings_path, read_json_value,
};
use crate::service::{ServiceKind, service_state};
use crate::state::{bin_dir, credentials_path, env_dir, load_config};

#[derive(Args)]
pub struct StatusArgs {}

pub fn run(_args: StatusArgs) {
    println!("Kyris Status");
    println!("============");

    check_agentpactd();
    check_kyrisd();
    check_hooks();
    check_native_integrations();
    check_enrollment();
    check_versions();
}

fn check_agentpactd() {
    let socket_path = agentpact_socket();
    let reachable = UnixStream::connect(&socket_path).is_ok();
    println!(
        "  [{}] agentpactd ({})",
        status_marker(reachable),
        socket_path
    );
}

fn check_kyrisd() {
    let listen = load_config().map_or_else(
        |_| "127.0.0.1:4710".to_string(),
        |config| config.server.listen,
    );
    let state = service_state(ServiceKind::Kyrisd);
    let healthy = health_status(&listen).is_ok_and(|status| status.is_success());
    let service = if state.managed_by_homebrew {
        format!(
            "homebrew/{}",
            state.homebrew_status.as_deref().unwrap_or("unknown")
        )
    } else if state.launchd_loaded {
        "launchd".to_string()
    } else {
        "not-loaded".to_string()
    };
    println!(
        "  [{}] kyrisd ({}, http://{listen}/healthz)",
        status_marker(healthy),
        service
    );
}

fn has_shell_hooks(content: &str) -> bool {
    content.contains("kyris")
        || content.contains("agentpact")
        || content.contains("zsh_hook.sh")
        || content.contains("bash_hook.sh")
}

fn check_hooks() {
    let home = std::env::var("HOME").unwrap_or_default();
    let zshrc = std::fs::read_to_string(format!("{home}/.zshrc")).unwrap_or_default();
    let zshenv = std::fs::read_to_string(format!("{home}/.zshenv")).unwrap_or_default();
    let bashrc = std::fs::read_to_string(format!("{home}/.bashrc")).unwrap_or_default();
    println!(
        "  [{}] shell hooks",
        status_marker(
            has_shell_hooks(&zshrc) || has_shell_hooks(&zshenv) || has_shell_hooks(&bashrc)
        )
    );
}

fn check_native_integrations() {
    let claude_hook = claude_settings_path()
        .ok()
        .and_then(|path| read_json_value(&path).ok())
        .is_some_and(|settings| {
            settings["hooks"]["PreToolUse"]
                .as_array()
                .is_some_and(|hooks| !hooks.is_empty())
        });
    println!("  [{}] claude-code live hook", status_marker(claude_hook));

    let codex_hook = codex_hooks_path().ok().is_some_and(|path| path.exists());
    println!("  [{}] codex-cli live hook", status_marker(codex_hook));

    let gemini_hook = gemini_settings_path()
        .ok()
        .and_then(|path| read_json_value(&path).ok())
        .is_some_and(|settings| {
            settings["hooks"]["BeforeTool"]
                .as_array()
                .is_some_and(|hooks| !hooks.is_empty())
        });
    println!("  [{}] gemini-cli live hook", status_marker(gemini_hook));

    let cline_permissions_path = env_dir().ok().map(|dir| dir.join("cline.sh"));
    let cline_permissions = cline_permissions_path
        .as_ref()
        .is_some_and(|path| path.exists());
    if !cline_permissions {
        println!("  [-] cline compiled policy");
        return;
    }

    match cline_policy_status() {
        ClinePolicyStatus::Enforced => println!("  [+] cline compiled policy"),
        ClinePolicyStatus::Degraded { ask_rules_dropped } => {
            println!(
                "  [!] cline compiled policy degraded ({ask_rules_dropped} ask rules dropped)"
            );
        }
        ClinePolicyStatus::Unknown(error) => {
            println!("  [!] cline compiled policy (cannot evaluate active policy: {error})");
        }
    }
}

fn check_enrollment() {
    let enrolled = credentials_path().is_ok_and(|path| path.exists());
    println!("  [{}] enrolled", status_marker(enrolled));
}

fn check_versions() {
    let versions = component_versions();
    let installed: Vec<(&str, String)> = versions
        .into_iter()
        .filter_map(|(name, version)| version.map(|version| (name, version)))
        .collect();

    if installed.is_empty() {
        println!("  [-] component versions unavailable");
        return;
    }

    let unique_versions: std::collections::HashSet<&str> = installed
        .iter()
        .map(|(_, version)| version.as_str())
        .collect();
    let summary = installed
        .iter()
        .map(|(name, version)| format!("{name}={version}"))
        .collect::<Vec<_>>()
        .join(", ");

    if unique_versions.len() <= 1 {
        println!("  [+] component versions aligned ({summary})");
    } else {
        println!("  [!] version skew ({summary})");
    }
}

fn agentpact_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn status_marker(condition: bool) -> &'static str {
    if condition { "+" } else { "-" }
}

fn component_versions() -> Vec<(&'static str, Option<String>)> {
    vec![
        ("kyris", Some(env!("CARGO_PKG_VERSION").to_string())),
        ("kyrisd", installed_component_version("kyrisd")),
        ("kyris-mcp", installed_component_version("kyris-mcp")),
        ("agentpactd", installed_component_version("agentpactd")),
    ]
}

fn installed_component_version(name: &str) -> Option<String> {
    let path = component_binary_path(name)?;
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    extract_version(&stdout)
}

fn component_binary_path(name: &str) -> Option<PathBuf> {
    let which_output = std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()?;
    if which_output.status.success() {
        let path = String::from_utf8(which_output.stdout).ok()?;
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    let local = bin_dir().ok()?.join(name);
    if local.exists() { Some(local) } else { None }
}

fn extract_version(output: &str) -> Option<String> {
    let regex = Regex::new(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.\-]+)?").ok()?;
    regex.find(output).map(|match_| match_.as_str().to_string())
}

fn cline_policy_status() -> ClinePolicyStatus {
    match compile_policy::compile_cline_permissions(None) {
        Ok((_compiled, 0)) => ClinePolicyStatus::Enforced,
        Ok((_compiled, ask_rules_dropped)) => ClinePolicyStatus::Degraded { ask_rules_dropped },
        Err(error) => ClinePolicyStatus::Unknown(error),
    }
}

enum ClinePolicyStatus {
    Enforced,
    Degraded { ask_rules_dropped: u32 },
    Unknown(String),
}

fn health_status(listen: &str) -> Result<reqwest::StatusCode, String> {
    let url = format!("http://{listen}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for status: {e}"))?;
    runtime.block_on(async {
        reqwest::get(&url)
            .await
            .map(|response| response.status())
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testStatusMarker() {
        assert_eq!(status_marker(true), "+");
        assert_eq!(status_marker(false), "-");
    }

    #[test]
    fn testHasShellHooksWithKyris() {
        assert!(has_shell_hooks("eval $(kyris hook init)"));
    }

    #[test]
    fn testHasShellHooksWithAgentpact() {
        assert!(has_shell_hooks("export AGENTPACT_SOCK=agentpact.sock"));
    }

    #[test]
    fn testHasShellHooksEmpty() {
        assert!(!has_shell_hooks(""));
    }

    #[test]
    fn testHasShellHooksUnrelated() {
        assert!(!has_shell_hooks("export PATH=/usr/bin\nalias ls='ls -la'"));
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("kyrisd 0.1.2"), Some("0.1.2".to_string()));
    }
}
