// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::integration::{
    cline_settings_path, codex_config_exists, codex_config_path, gemini_settings_exists,
    opencode_config_exists, opencode_config_path, read_json_value, read_toml_value,
    set_json_string_path, write_json_value, write_toml_value,
};
use crate::state::{
    discard_manifest_entry, ensure_line, ensure_parent, env_dir, load_manifest,
    load_or_init_config, restore_manifest_entry, write_managed_file,
};

#[derive(Args)]
pub struct SetupArgs {
    pub agent: Option<String>,
    #[arg(long)]
    pub list: bool,
    #[arg(long)]
    pub undo: Option<String>,
    #[arg(long)]
    pub auto: bool,
}

const SUPPORTED_AGENTS: &[&str] = &[
    "claude-code",
    "gemini-cli",
    "codex-cli",
    "opencode",
    "cline",
];

const ENV_LOADER_SOURCE: &str = r#"# SPDX-License-Identifier: Apache-2.0
for file in "$HOME/.kyris/env/"*.sh; do
    [ -f "$file" ] || continue
    [ "$file" = "$HOME/.kyris/env/load.sh" ] && continue
    . "$file"
done
"#;

#[derive(Debug)]
struct FileSnapshot {
    path: PathBuf,
    original_contents: Option<Vec<u8>>,
    had_manifest_entry: bool,
}

struct SetupTransaction {
    snapshots: Vec<FileSnapshot>,
}

pub fn run(args: SetupArgs) {
    if args.list {
        list_agents();
        return;
    }

    if let Some(ref agent) = args.undo {
        if let Err(error) = undo_agent(agent) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }

    if args.auto {
        println!("Auto-detecting installed agents and running setup...");
        for agent in SUPPORTED_AGENTS {
            if is_agent_installed(agent) {
                println!("\nFound {agent}, configuring...");
                if let Err(error) = setup_agent(agent) {
                    eprintln!("{error}");
                }
            }
        }
        return;
    }

    let Some(ref agent) = args.agent else {
        eprintln!("Usage: kyris setup <agent> or kyris setup --list");
        std::process::exit(1);
    };

    if !SUPPORTED_AGENTS.contains(&agent.as_str()) {
        eprintln!("Unsupported agent: {agent}");
        eprintln!("Run `kyris setup --list` for supported agents.");
        std::process::exit(1);
    }

    if let Err(error) = setup_agent(agent) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn list_agents() {
    println!("Supported agents:");
    for agent in SUPPORTED_AGENTS {
        let status = if is_agent_installed(agent) {
            "installed"
        } else {
            "not found"
        };
        println!("  {agent:<15} ({status})");
    }
}

fn is_agent_installed(agent: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    match agent {
        "claude-code" => std::path::Path::new(&format!("{home}/.claude")).is_dir(),
        "codex-cli" => codex_config_exists(),
        "gemini-cli" => which_exists("gemini") || gemini_settings_exists(),
        "opencode" => which_exists("opencode") || opencode_config_exists(),
        "cline" => {
            let ext_dir = format!("{home}/.vscode/extensions");
            std::path::Path::new(&ext_dir).is_dir()
                && std::fs::read_dir(&ext_dir).is_ok_and(|entries| {
                    entries.filter_map(Result::ok).any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("saoudrizwan.claude-dev")
                    })
                })
        }
        _ => false,
    }
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn setup_agent(agent: &str) -> Result<(), String> {
    let config = load_or_init_config()?;
    let transaction = SetupTransaction::capture(agent)?;
    let mut changes = match agent {
        "claude-code" | "gemini-cli" => {
            setup_env_agent(agent, &config.server.listen, &config.server.inbound_key)?
        }
        "codex-cli" => setup_codex(&config.server.listen, &config.server.inbound_key)?,
        "opencode" => setup_opencode(&config.server.listen)?,
        "cline" => setup_cline(&config.server.listen)?,
        _ => return Err(format!("Unsupported agent: {agent}")),
    };

    if let Err(error) = verify_kyrisd_health(&config.server.listen) {
        if let Err(rollback_error) = transaction.rollback() {
            return Err(format!(
                "Setup verification failed for {agent}: {error}. Rollback also failed: {rollback_error}"
            ));
        }
        return Err(format!(
            "Setup verification failed for {agent}: {error}. Rolled back setup changes."
        ));
    }

    if changes.is_empty() {
        println!("No setup changes needed for {agent}.");
    } else {
        println!("Applied setup for {agent}:");
        for change in changes.drain(..) {
            println!("  {change}");
        }
    }

    Ok(())
}

fn agent_exports_for(
    agent: &str,
    listen: &str,
    inbound_key: &str,
) -> Result<Vec<(String, String)>, String> {
    match agent {
        "claude-code" => Ok(vec![
            ("ANTHROPIC_BASE_URL".to_string(), format!("http://{listen}")),
            ("ANTHROPIC_API_KEY".to_string(), inbound_key.to_string()),
        ]),
        "codex-cli" => Ok(vec![
            ("OPENAI_BASE_URL".to_string(), format!("http://{listen}/v1")),
            ("OPENAI_API_KEY".to_string(), inbound_key.to_string()),
        ]),
        "gemini-cli" => Ok(vec![(
            "GOOGLE_GEMINI_BASE_URL".to_string(),
            format!("http://{listen}"),
        )]),
        "opencode" | "cline" => Ok(Vec::new()),
        _ => Err(format!("Unsupported agent: {agent}")),
    }
}

fn exports_to_shell(exports: &[(String, String)]) -> String {
    let mut contents = String::from("# SPDX-License-Identifier: Apache-2.0\n");
    for (key, value) in exports {
        contents.push_str("export ");
        contents.push_str(key);
        contents.push('=');
        contents.push_str(value);
        contents.push('\n');
    }
    contents
}

fn setup_env_agent(agent: &str, listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
    let env_file = env_dir()?.join(format!("{agent}.sh"));
    let loader_path = env_dir()?.join("load.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let exports = agent_exports_for(agent, listen, inbound_key)?;
    let mut changes = Vec::new();

    if write_managed_file(&loader_path, ENV_LOADER_SOURCE, "setup", Some(0o600))? {
        changes.push(format!("wrote {}", loader_path.display()));
    }
    if write_managed_file(&env_file, &exports_to_shell(&exports), "setup", Some(0o600))? {
        changes.push(format!("wrote {}", env_file.display()));
    }

    for (path, label) in [
        (PathBuf::from(&home).join(".zshrc"), "~/.zshrc"),
        (PathBuf::from(&home).join(".bashrc"), "~/.bashrc"),
    ] {
        if ensure_line(&path, "source \"$HOME/.kyris/env/load.sh\"", "setup")? {
            changes.push(format!("updated {label}"));
        }
    }

    Ok(changes)
}

fn setup_codex(listen: &str, inbound_key: &str) -> Result<Vec<String>, String> {
    let mut changes = setup_env_agent("codex-cli", listen, inbound_key)?;
    let config_path = codex_config_path()?;
    let mut config = read_toml_value(&config_path)?;
    if rewrite_codex_mcp_servers(&mut config, listen, inbound_key) {
        write_toml_value(&config_path, &config, "setup")?;
        changes.push(format!("updated {}", config_path.display()));
    }
    Ok(changes)
}

fn setup_opencode(listen: &str) -> Result<Vec<String>, String> {
    let path = opencode_config_path()?;
    let mut config = read_json_value(&path)?;
    let mut changes = Vec::new();
    if set_json_string_path(
        &mut config,
        &["provider", "anthropic", "options", "baseURL"],
        &format!("http://{listen}"),
    ) {
        write_json_value(&path, &config, "setup")?;
        changes.push(format!("updated {}", path.display()));
    }
    Ok(changes)
}

fn setup_cline(listen: &str) -> Result<Vec<String>, String> {
    let path = cline_settings_path()?;
    let mut settings = read_json_value(&path)?;
    let mut changes = Vec::new();
    if set_json_string_path(
        &mut settings,
        &["anthropicBaseUrl"],
        &format!("http://{listen}"),
    ) {
        write_json_value(&path, &settings, "setup")?;
        changes.push(format!("updated {}", path.display()));
    }
    Ok(changes)
}

fn rewrite_codex_mcp_servers(config: &mut toml::Value, listen: &str, inbound_key: &str) -> bool {
    let Some(root) = config.as_table_mut() else {
        return false;
    };
    let Some(servers) = root
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
    else {
        return false;
    };

    let mut changed = false;
    for (name, server_value) in servers {
        let Some(server) = server_value.as_table_mut() else {
            continue;
        };

        if let Some(command) = server.get("command").and_then(toml::Value::as_str) {
            if command == "kyris-mcp" {
                continue;
            }

            let original_args = server
                .get("args")
                .and_then(toml::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut wrapped_args = vec![
                toml::Value::String("wrap".to_string()),
                toml::Value::String("--server".to_string()),
                toml::Value::String(name.to_string()),
                toml::Value::String(command.to_string()),
            ];
            wrapped_args.extend(original_args);

            server.insert(
                "command".to_string(),
                toml::Value::String("kyris-mcp".to_string()),
            );
            server.insert("args".to_string(), toml::Value::Array(wrapped_args));
            changed = true;
            continue;
        }

        if let Some(url) = server.get("url").and_then(toml::Value::as_str) {
            let routed_url = format!("http://{listen}/mcp/{name}/");
            if url != routed_url {
                server.insert("url".to_string(), toml::Value::String(routed_url));
                changed = true;
            }

            let headers = server
                .entry("http_headers".to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if !headers.is_table() {
                *headers = toml::Value::Table(toml::Table::new());
            }
            let auth_value = format!("Bearer {inbound_key}");
            let headers_table = headers.as_table_mut().expect("converted to TOML table");
            if headers_table
                .get("Authorization")
                .and_then(toml::Value::as_str)
                != Some(auth_value.as_str())
            {
                headers_table.insert("Authorization".to_string(), toml::Value::String(auth_value));
                changed = true;
            }
        }
    }

    changed
}

fn verify_kyrisd_health(listen: &str) -> Result<(), String> {
    let url = format!("http://{listen}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for setup verification: {e}"))?;

    runtime.block_on(async {
        let response = reqwest::get(&url)
            .await
            .map_err(|e| format!("kyrisd is not reachable at {url}: {e}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "kyrisd health check failed at {url}: {}",
                response.status()
            ))
        }
    })
}

fn agent_undo_vars(agent: &str) -> Vec<&'static str> {
    match agent {
        "claude-code" => vec!["ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY"],
        "codex-cli" => vec!["OPENAI_BASE_URL", "OPENAI_API_KEY"],
        "gemini-cli" => vec!["GOOGLE_GEMINI_BASE_URL"],
        _ => vec![],
    }
}

fn undo_agent(agent: &str) -> Result<(), String> {
    match agent {
        "claude-code" | "gemini-cli" => {
            let env_file = env_dir()?.join(format!("{agent}.sh"));
            if restore_manifest_entry(&env_file)? {
                println!("Reverted {}", env_file.display());
            } else if env_file.exists() {
                std::fs::remove_file(&env_file)
                    .map_err(|e| format!("Cannot remove {}: {e}", env_file.display()))?;
                println!("Removed {}", env_file.display());
            } else {
                println!("No setup file found for {agent}.");
            }
            println!("# Remove these from your current shell if already exported:");
            for var in agent_undo_vars(agent) {
                println!("unset {var}");
            }
            Ok(())
        }
        "codex-cli" => {
            let env_file = env_dir()?.join("codex-cli.sh");
            let _ = restore_manifest_entry(&env_file)?;
            let config_path = codex_config_path()?;
            if restore_manifest_entry(&config_path)? {
                println!("Reverted {}", config_path.display());
            } else {
                println!("No Codex setup backup found.");
            }
            Ok(())
        }
        "opencode" => {
            let path = opencode_config_path()?;
            if restore_manifest_entry(&path)? {
                println!("Reverted {}", path.display());
            } else {
                println!("No OpenCode setup backup found.");
            }
            Ok(())
        }
        "cline" => {
            let path = cline_settings_path()?;
            if restore_manifest_entry(&path)? {
                println!("Reverted {}", path.display());
            } else {
                println!("No Cline setup backup found.");
            }
            Ok(())
        }
        _ => Err(format!("Unknown agent: {agent}")),
    }
}

impl SetupTransaction {
    fn capture(agent: &str) -> Result<Self, String> {
        let manifest_paths: HashSet<String> = load_manifest()?
            .into_iter()
            .map(|entry| entry.path)
            .collect();
        let mut seen = HashSet::new();
        let mut snapshots = Vec::new();

        for path in setup_paths_for_agent(agent)? {
            let key = path.to_string_lossy().to_string();
            if !seen.insert(key.clone()) {
                continue;
            }
            let original_contents = if path.exists() {
                Some(
                    std::fs::read(&path)
                        .map_err(|e| format!("Cannot snapshot {}: {e}", path.display()))?,
                )
            } else {
                None
            };
            snapshots.push(FileSnapshot {
                path,
                original_contents,
                had_manifest_entry: manifest_paths.contains(&key),
            });
        }

        Ok(Self { snapshots })
    }

    fn rollback(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        for snapshot in self.snapshots.iter().rev() {
            if let Err(error) = restore_snapshot(snapshot) {
                errors.push(error);
            }
            if !snapshot.had_manifest_entry
                && let Err(error) = discard_manifest_entry(&snapshot.path)
            {
                errors.push(error);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn setup_paths_for_agent(agent: &str) -> Result<Vec<PathBuf>, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let home = PathBuf::from(home);
    let mut paths = Vec::new();

    match agent {
        "claude-code" | "gemini-cli" | "codex-cli" => {
            paths.push(env_dir()?.join("load.sh"));
            paths.push(env_dir()?.join(format!("{agent}.sh")));
            paths.push(home.join(".zshrc"));
            paths.push(home.join(".bashrc"));
        }
        _ => {}
    }

    match agent {
        "codex-cli" => paths.push(codex_config_path()?),
        "opencode" => paths.push(opencode_config_path()?),
        "cline" => paths.push(cline_settings_path()?),
        "claude-code" | "gemini-cli" => {}
        _ => return Err(format!("Unsupported agent: {agent}")),
    }

    Ok(paths)
}

fn restore_snapshot(snapshot: &FileSnapshot) -> Result<(), String> {
    match &snapshot.original_contents {
        Some(contents) => {
            ensure_parent(&snapshot.path)?;
            std::fs::write(&snapshot.path, contents)
                .map_err(|e| format!("Cannot restore {}: {e}", snapshot.path.display()))?;
        }
        None => {
            if snapshot.path.exists() {
                std::fs::remove_file(&snapshot.path)
                    .map_err(|e| format!("Cannot remove {}: {e}", snapshot.path.display()))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn testSupportedAgentsNotEmpty() {
        assert!(!SUPPORTED_AGENTS.is_empty());
    }

    #[test]
    fn testSupportedAgentsContainsExpected() {
        assert!(SUPPORTED_AGENTS.contains(&"claude-code"));
        assert!(SUPPORTED_AGENTS.contains(&"codex-cli"));
        assert!(SUPPORTED_AGENTS.contains(&"gemini-cli"));
        assert!(SUPPORTED_AGENTS.contains(&"opencode"));
        assert!(SUPPORTED_AGENTS.contains(&"cline"));
    }

    #[test]
    fn testSupportedAgentsNoDuplicates() {
        let mut sorted = SUPPORTED_AGENTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), SUPPORTED_AGENTS.len());
    }

    #[test]
    fn testAgentExportsClaudeCode() {
        let exports =
            agent_exports_for("claude-code", "127.0.0.1:4710", "sk-kyris-test").expect("exports");
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].0, "ANTHROPIC_BASE_URL");
        assert!(exports[0].1.contains("4710"));
    }

    #[test]
    fn testAgentExportsCodexCli() {
        let exports =
            agent_exports_for("codex-cli", "127.0.0.1:4710", "sk-kyris-test").expect("exports");
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].0, "OPENAI_BASE_URL");
    }

    #[test]
    fn testAgentExportsGemini() {
        let exports =
            agent_exports_for("gemini-cli", "127.0.0.1:4710", "sk-kyris-test").expect("exports");
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].0, "GOOGLE_GEMINI_BASE_URL");
    }

    #[test]
    fn testRewriteCodexMcpServers() {
        let mut config: toml::Value = r#"
            [mcp_servers.filesystem]
            command = "npx"
            args = ["-y", "server"]

            [mcp_servers.remote]
            url = "https://example.com/mcp"
        "#
        .parse()
        .expect("parse");

        assert!(rewrite_codex_mcp_servers(
            &mut config,
            "127.0.0.1:4710",
            "sk-kyris-test"
        ));

        let servers = config["mcp_servers"].as_table().expect("mcp_servers");
        assert_eq!(servers["filesystem"]["command"].as_str(), Some("kyris-mcp"));
        assert_eq!(
            servers["remote"]["url"].as_str(),
            Some("http://127.0.0.1:4710/mcp/remote/")
        );
    }

    #[test]
    fn testRestoreSnapshotRestoresOriginalContents() {
        let temp_dir = TempDir::new().expect("tempdir");
        let path = temp_dir.path().join("settings.json");
        std::fs::write(&path, "after").expect("write after");

        let snapshot = FileSnapshot {
            path: path.clone(),
            original_contents: Some(b"before".to_vec()),
            had_manifest_entry: false,
        };

        restore_snapshot(&snapshot).expect("restore snapshot");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read restored"),
            "before"
        );
    }

    #[test]
    fn testRestoreSnapshotRemovesCreatedFile() {
        let temp_dir = TempDir::new().expect("tempdir");
        let path = temp_dir.path().join("settings.json");
        std::fs::write(&path, "created").expect("write created");

        let snapshot = FileSnapshot {
            path: path.clone(),
            original_contents: None,
            had_manifest_entry: false,
        };

        restore_snapshot(&snapshot).expect("restore snapshot");
        assert!(!path.exists());
    }
}
