// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//
// Tests for `kyris agents setup` behavior when kyrisd is unreachable.
//
// Old behavior (removed): burn-control changes were rolled back on health
// check failure.
//
// New behavior: changes are kept — the developer explicitly asked for the
// configuration. If kyrisd isn't running they start it; the configuration
// is already in place and takes effect immediately.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_kyrisd_config(home: &Path) {
    // After the XDG migration kyrisd.yaml lives under
    // $XDG_CONFIG_HOME/kyris/ (default $HOME/.config/kyris/).
    let config_dir = home.join(".config").join("kyris");
    fs::create_dir_all(&config_dir).expect("create kyris config dir");
    // Keys are not in the yaml — they live in the secret store under HOME
    // (~/.local/share/kyris/secret). listen :1 forces "kyrisd unreachable" at
    // the health check.
    fs::write(
        config_dir.join("kyrisd.yaml"),
        "apiVersion: kyris/v1\nserver:\n  listen: \"127.0.0.1:1\"\n",
    )
    .expect("write kyrisd config");
}

fn run_setup(home: &Path, cwd: &Path, agent: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(cwd)
        .env("HOME", home)
        .arg("agent")
        .arg("setup")
        .arg(agent)
        .output()
        .expect("run kyris agent setup")
}

/// An unknown `--set` key is rejected fail-fast, before any side effects, so it
/// can't be silently stored and ignored (false confidence).
#[test]
fn test_setup_rejects_unknown_set_key() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    write_kyrisd_config(home);

    let output = Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .args([
            "agent",
            "setup",
            "claude-code",
            "--set",
            "max-budget-usd=50",
        ])
        .output()
        .expect("run kyris agent setup");

    assert!(
        !output.status.success(),
        "unknown --set key should exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown --set key 'max-budget-usd'"),
        "expected unknown-key error, got: {stderr}"
    );
    // Validation runs before any config write — settings.json must not exist.
    assert!(
        !home.join(".claude").join("settings.json").exists(),
        "setup must reject before writing settings.json"
    );
}

/// When the agent is not installed (no ~/.claude/settings.json), setup exits
/// with an error as soon as the health check fails. No files are modified.
#[test]
fn test_claude_setup_errors_when_kyrisd_unreachable_and_agent_not_installed() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".zshrc"), "# zsh baseline\n").expect("write .zshrc");
    fs::write(home.join(".bashrc"), "# bash baseline\n").expect("write .bashrc");
    write_kyrisd_config(home);

    let output = run_setup(home, home, "claude-code");
    assert!(
        !output.status.success(),
        "should exit non-zero when kyrisd unreachable"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("kyrisd unreachable"),
        "expected 'kyrisd unreachable' in stderr, got: {stderr}"
    );

    // Baseline content is preserved in shell rc files (prestage may append
    // kyris lines, but the original content is not clobbered).
    assert!(
        fs::read_to_string(home.join(".zshrc"))
            .expect("read .zshrc")
            .contains("# zsh baseline"),
        "baseline content should be preserved in .zshrc"
    );
}

/// When the agent IS installed, setup applies all changes and then fails the
/// health check. Changes are kept — rollback no longer happens.
#[test]
fn test_codex_setup_keeps_changes_when_kyrisd_unreachable() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    fs::create_dir_all(home.join(".codex")).expect("create .codex");
    fs::write(home.join(".zshrc"), "# zsh baseline\n").expect("write .zshrc");
    fs::write(home.join(".bashrc"), "# bash baseline\n").expect("write .bashrc");
    fs::write(
        home.join(".codex").join("config.toml"),
        r#"[mcp_servers.filesystem]
command = "npx"
args = ["-y", "server"]
"#,
    )
    .expect("write codex config");
    write_kyrisd_config(home);

    let output = run_setup(home, home, "codex-cli");
    assert!(
        !output.status.success(),
        "should exit non-zero when kyrisd unreachable"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("kyrisd unreachable"),
        "expected 'kyrisd unreachable' in stderr, got: {stderr}"
    );

    let config_content =
        fs::read_to_string(home.join(".codex").join("config.toml")).expect("read codex config");

    // Execution surface was configured and stays configured.
    assert!(
        config_content.contains("hooks = true"),
        "execution-surface change should be kept, got: {config_content}"
    );

    // Burn-control and MCP changes are also kept (no rollback).
    assert!(
        config_content.contains("kyris-mcp")
            || config_content.contains("model_provider = \"kyris\"")
            || config_content.contains("[model_providers.kyris]"),
        "burn-control changes should be kept, got: {config_content}"
    );

    // Codex marks its exec-tool children through shell_environment_policy …
    assert!(
        config_content.contains("KYRIS_GOVERNED_SUBPROCESS"),
        "Codex shell-environment marker should be kept, got: {config_content}"
    );
    // … and ALSO gets the PATH shim: shell_environment_policy covers exec
    // children only, so the shim is the sole mechanism that marks codex's
    // HOOK children (the kyris hook spawn itself) as governed. Without it
    // the shell gate treated the hook spawn as a bare terminal and prompted
    // on the agent's own TTY (the codex composer-garbage bug).
    assert!(
        home.join(".kyris").join("bin").join("codex").exists(),
        "Codex setup should install the PATH shim"
    );

    // Original MCP server is still present (kyris wraps it, not replaces it).
    assert!(
        config_content.contains("command = \"npx\"") || config_content.contains("kyris-mcp"),
        "original or wrapped MCP server should be present, got: {config_content}"
    );
}
