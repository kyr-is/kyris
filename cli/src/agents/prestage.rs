// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::NoopValidator;
use crate::lifecycle::log::InstallLog;
use crate::state::{ensure_line, env_dir, load_or_init_config, write_managed_file};

use super::registry::{self, AgentDescriptor};

const ENV_LOADER_SOURCE: &str = r#"# SPDX-License-Identifier: Apache-2.0
for file in "$HOME/.kyris/env/"*.sh; do
    [ -f "$file" ] || continue
    [ "$file" = "$HOME/.kyris/env/load.sh" ] && continue
    . "$file"
done
"#;

pub fn prestage_all(log: Option<&InstallLog>) -> Result<(), String> {
    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    for agent in registry::all_agents() {
        let changes = prestage_agent_inner(agent.as_ref(), &base_url, inbound_key)?;
        if !changes.is_empty() {
            println!("Prestaged {}:", agent.id());
            if let Some(l) = log {
                l.info(&format!("prestaged {}", agent.id()));
            }
            for change in &changes {
                println!("  {change}");
                if let Some(l) = log {
                    l.info(&format!("  {} {change}", agent.id()));
                }
            }
        }
    }
    Ok(())
}

pub fn prestage_agent(agent_id: &str) -> Result<Vec<String>, String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    let config = load_or_init_config()?;
    prestage_agent_inner(
        agent.as_ref(),
        &config.base_url(),
        &config.server.inbound_key,
    )
}

fn prestage_agent_inner(
    agent: &dyn AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    prestage_env(agent, base_url, inbound_key)
}

fn exports_to_shell(exports: &[(String, String)]) -> String {
    let mut contents = String::from("# SPDX-License-Identifier: Apache-2.0\n");
    for (key, value) in exports {
        contents.push_str("export ");
        contents.push_str(key);
        contents.push('=');
        contents.push_str(&shell_single_quote(value));
        contents.push('\n');
    }
    contents
}

/// Single-quote a value for POSIX `sh`/`bash`/`zsh` so spaces and shell
/// metacharacters survive `export KEY=VALUE` when the file is sourced.
/// Without this, a value like `x-kyris-inbound: <key>` (note the space) parses
/// as `export KEY=x-kyris-inbound:` plus a stray word, silently truncating the
/// header and breaking the agent's auth to kyrisd. Embedded single quotes use
/// the standard `'\''` close-escape-reopen idiom.
pub(crate) fn shell_single_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn prestage_env(
    agent: &dyn AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let exports = agent.env_exports(base_url, inbound_key);
    if exports.is_empty() {
        return Ok(Vec::new());
    }

    let mut changes = ensure_env_loader()?;

    let env_file = env_dir()?.join(format!("{}.sh", agent.id()));
    // Shell env file (export VAR=...) — opaque text.
    if write_managed_file(
        &env_file,
        &exports_to_shell(&exports),
        "agents",
        Some(0o600),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", env_file.display()));
    }

    Ok(changes)
}

/// Ensure `load.sh` exists and shell RC files source it.
/// Called by `prestage_env` for agents with env exports, and by
/// `configure_execution` for agents that write env files directly
/// (e.g. Cline's compiled policy).
pub fn ensure_env_loader() -> Result<Vec<String>, String> {
    let loader_path = env_dir()?.join("load.sh");
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let mut changes = Vec::new();

    // Shell loader script — opaque text.
    if write_managed_file(
        &loader_path,
        ENV_LOADER_SOURCE,
        "agents",
        Some(0o600),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", loader_path.display()));
    }

    for (path, label) in [
        (PathBuf::from(&home).join(".zshrc"), "~/.zshrc"),
        (PathBuf::from(&home).join(".bashrc"), "~/.bashrc"),
    ] {
        if ensure_line(&path, "source \"$HOME/.kyris/env/load.sh\"", "agents")? {
            changes.push(format!("updated {label}"));
        }
    }

    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testShellSingleQuoteWrapsPlainValue() {
        assert_eq!(
            shell_single_quote("http://127.0.0.1:4710"),
            "'http://127.0.0.1:4710'"
        );
    }

    #[test]
    fn testShellSingleQuotePreservesSpaces() {
        // The original regression: a space-bearing value must survive sourcing
        // as a single token, not split into `KEY=word1` + a stray `word2`.
        assert_eq!(
            shell_single_quote("x-kyris-inbound: sk-test"),
            "'x-kyris-inbound: sk-test'"
        );
    }

    #[test]
    fn testShellSingleQuoteEscapesEmbeddedQuote() {
        // `'\''` close-escape-reopen, never a bare `\'` (invalid in sh).
        assert_eq!(shell_single_quote("a'b"), r"'a'\''b'");
    }

    #[test]
    fn testExportsToShellQuotesHeaderValue() {
        let exports = vec![(
            "ANTHROPIC_CUSTOM_HEADERS".to_string(),
            "x-kyris-inbound: sk-test".to_string(),
        )];
        let out = exports_to_shell(&exports);
        assert!(
            out.contains("export ANTHROPIC_CUSTOM_HEADERS='x-kyris-inbound: sk-test'"),
            "header export must be single-quoted, got: {out}"
        );
    }
}
