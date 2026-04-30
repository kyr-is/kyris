// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_kyrisd_config(home: &Path) {
    let kyris_dir = home.join(".kyris");
    fs::create_dir_all(&kyris_dir).expect("create .kyris");
    fs::write(
        kyris_dir.join("kyrisd.yaml"),
        "server:\n  listen: \"127.0.0.1:1\"\n  inbound_key: sk-kyris-test\n  operator_key: sk-kyris-ops-test\n",
    )
    .expect("write kyrisd config");
}

fn run_setup(home: &Path, cwd: &Path, agent: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(cwd)
        .env("HOME", home)
        .arg("agents")
        .arg("setup")
        .arg(agent)
        .output()
        .expect("run kyris agents setup")
}

#[test]
fn test_claude_setup_rolls_back_when_health_check_fails() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".zshrc"), "# zsh baseline\n").expect("write .zshrc");
    fs::write(home.join(".bashrc"), "# bash baseline\n").expect("write .bashrc");
    write_kyrisd_config(home);

    let output = run_setup(home, home, "claude-code");
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Rolled back."));

    assert_eq!(
        fs::read_to_string(home.join(".zshrc")).expect("read .zshrc"),
        "# zsh baseline\n"
    );
    assert_eq!(
        fs::read_to_string(home.join(".bashrc")).expect("read .bashrc"),
        "# bash baseline\n"
    );
    assert!(
        !home
            .join(".kyris")
            .join("env")
            .join("claude-code.sh")
            .exists()
    );
    assert!(!home.join(".kyris").join("env").join("load.sh").exists());
    assert!(!home.join(".kyris").join("manifest.json").exists());
}

#[test]
fn test_codex_setup_rolls_back_config_rewrite_when_health_check_fails() {
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
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Rolled back."));

    assert_eq!(
        fs::read_to_string(home.join(".codex").join("config.toml")).expect("read codex config"),
        "[mcp_servers.filesystem]\ncommand = \"npx\"\nargs = [\"-y\", \"server\"]\n"
    );
    assert!(
        !home
            .join(".kyris")
            .join("env")
            .join("codex-cli.sh")
            .exists()
    );
    assert!(!home.join(".kyris").join("env").join("load.sh").exists());
    assert!(!home.join(".kyris").join("manifest.json").exists());
}
