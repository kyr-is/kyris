// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_kyrisd_config(home: &Path, listen: &str) {
    // After the XDG migration kyrisd.yaml lives under
    // $XDG_CONFIG_HOME/kyris/ (default $HOME/.config/kyris/). The test
    // only sets HOME, so the daemon resolves config to
    // tempdir/.config/kyris/kyrisd.yaml.
    let config_dir = home.join(".config").join("kyris");
    fs::create_dir_all(&config_dir).expect("create kyris config dir");
    fs::write(
        config_dir.join("kyrisd.yaml"),
        format!(
            "server:\n  listen: \"{listen}\"\n  inbound_key: sk-kyris-test\n  operator_key: sk-kyris-ops-test\n"
        ),
    )
    .expect("write kyrisd config");
}

fn write_fake_binary(dir: &Path, name: &str, version: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\necho \"{name} {version}\"\n")).expect("write fake binary");
    let permissions = fs::Permissions::from_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod fake binary");
}

fn run_status(home: &Path, fake_bin_dir: Option<&Path>) -> std::process::Output {
    let path = match fake_bin_dir {
        Some(fake_bin_dir) => format!(
            "{}:{}",
            fake_bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
        None => std::env::var("PATH").unwrap_or_default(),
    };

    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .env("PATH", path)
        .arg("status")
        .output()
        .expect("run kyris status")
}

#[test]
fn test_status_reports_version_skew() {
    let temp_home = TempDir::new().expect("temp home");
    let fake_bin = TempDir::new().expect("fake bin");
    write_kyrisd_config(temp_home.path(), "127.0.0.1:1");

    write_fake_binary(fake_bin.path(), "kyrisd", "0.2.0");
    write_fake_binary(fake_bin.path(), "kyris-mcp", env!("CARGO_PKG_VERSION"));
    write_fake_binary(fake_bin.path(), "agentpactd", env!("CARGO_PKG_VERSION"));

    let output = run_status(temp_home.path(), Some(fake_bin.path()));
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("version skew"), "{stdout}");
}

#[test]
fn test_status_claude_code_burn_control_none_without_loader_sourced() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".claude").join("settings.json"), "{}").expect("write settings");

    let env_dir = home.join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("claude-code.sh"),
        "export ANTHROPIC_BASE_URL=http://127.0.0.1:4710\n",
    )
    .expect("write claude env");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("claude-code") && l.contains("burn:"))
        .expect("claude-code line in status output");
    assert!(
        line.contains("burn:none"),
        "expected burn:none, got: {line}"
    );
}

#[test]
fn test_status_claude_code_burn_control_active_with_loader_sourced() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".claude").join("settings.json"), "{}").expect("write settings");

    let env_dir = home.join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("claude-code.sh"),
        "export ANTHROPIC_BASE_URL=http://127.0.0.1:4710\n",
    )
    .expect("write claude env");

    fs::write(home.join(".zshrc"), "source \"$HOME/.kyris/env/load.sh\"\n").expect("write .zshrc");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("claude-code") && l.contains("burn:"))
        .expect("claude-code line in status output");
    assert!(line.contains("proxy"), "expected burn:proxy, got: {line}");
}

#[test]
fn test_status_cline_execution_none_without_loader_sourced() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    let ext_dir = home
        .join(".vscode")
        .join("extensions")
        .join("saoudrizwan.claude-dev-3.0.0");
    fs::create_dir_all(&ext_dir).expect("create cline extension dir");

    let env_dir = home.join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("cline-policy.sh"),
        "export CLINE_COMMAND_PERMISSIONS='{\"allow\":[\"echo\"]}'\n",
    )
    .expect("write cline policy env");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("cline") && l.contains("cmd:"))
        .expect("cline line in status output");
    assert!(line.contains("cmd:none"), "expected cmd:none, got: {line}");
}

#[test]
fn test_status_cline_execution_active_with_loader_sourced() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    let ext_dir = home
        .join(".vscode")
        .join("extensions")
        .join("saoudrizwan.claude-dev-3.0.0");
    fs::create_dir_all(&ext_dir).expect("create cline extension dir");

    let env_dir = home.join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("cline-policy.sh"),
        "export CLINE_COMMAND_PERMISSIONS='{\"allow\":[\"echo\"]}'\n",
    )
    .expect("write cline policy env");

    fs::write(home.join(".zshrc"), "source \"$HOME/.kyris/env/load.sh\"\n").expect("write .zshrc");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("cline") && l.contains("cmd:"))
        .expect("cline line in status output");
    assert!(line.contains("policy"), "expected cmd:policy, got: {line}");
}

#[test]
fn test_status_cline_execution_active_via_launchd_plist() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    let ext_dir = home
        .join(".vscode")
        .join("extensions")
        .join("saoudrizwan.claude-dev-3.0.0");
    fs::create_dir_all(&ext_dir).expect("create cline extension dir");

    let env_dir = home.join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("cline-policy.sh"),
        "export CLINE_COMMAND_PERMISSIONS='{\"allow\":[\"echo\"]}'\n",
    )
    .expect("write cline policy env");

    let plist_dir = home.join("Library").join("LaunchAgents");
    fs::create_dir_all(&plist_dir).expect("create LaunchAgents dir");
    fs::write(plist_dir.join("is.kyr.cline-policy.plist"), "<plist/>\n")
        .expect("write cline plist");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("cline") && l.contains("cmd:"))
        .expect("cline line in status output");
    assert!(line.contains("policy"), "expected cmd:policy, got: {line}");
}

#[test]
fn test_status_does_not_show_shell_hooks_section() {
    let temp_home = TempDir::new().expect("temp home");
    write_kyrisd_config(temp_home.path(), "127.0.0.1:1");

    let output = run_status(temp_home.path(), None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        assert!(
            !line.to_lowercase().contains("shell hooks"),
            "status should not show 'shell hooks', found: {line}"
        );
    }
}

#[test]
fn test_status_reports_degraded_cline_policy() {
    let temp_home = TempDir::new().expect("temp home");
    write_kyrisd_config(temp_home.path(), "127.0.0.1:1");

    let env_dir = temp_home.path().join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("cline-policy.sh"),
        "export CLINE_COMMAND_PERMISSIONS='{}'\n",
    )
    .expect("write cline policy env");

    let policy_dir = temp_home.path().join(".agentpact").join("policy");
    fs::create_dir_all(&policy_dir).expect("create policy dir");
    fs::write(
        policy_dir.join("pact.yaml"),
        "apiVersion: agentpact/v1\nkind: Pact\nmetadata:\n  name: test\nspec:\n  commands:\n    \"rm·-rf·*\": ask\n",
    )
    .expect("write pact policy");

    let output = run_status(temp_home.path(), None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cline compiled policy degraded"),
        "{stdout}"
    );
    assert!(stdout.contains("ask rules dropped"), "{stdout}");
}
