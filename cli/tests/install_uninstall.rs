// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn run_kyris(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .env("KYRIS_TEST_DISABLE_SERVICE_MANAGEMENT", "1")
        .args(args)
        .output()
        .expect("run kyris")
}

#[test]
fn test_install_then_uninstall_restores_hooks_and_native_integrations() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();

    let zshrc = "# zsh baseline\n";
    let zshenv = "# zshenv baseline\n";
    let bashrc = "# bash baseline\n";
    let claude_settings = "{}\n";

    fs::write(home.join(".zshrc"), zshrc).expect("write .zshrc");
    fs::write(home.join(".zshenv"), zshenv).expect("write .zshenv");
    fs::write(home.join(".bashrc"), bashrc).expect("write .bashrc");
    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".claude").join("settings.json"), claude_settings)
        .expect("write claude settings");
    fs::create_dir_all(home.join(".agentpact").join("policy")).expect("create policy dir");
    fs::write(
        home.join(".agentpact").join("policy").join("pact.yaml"),
        r#"- action: execute
  pattern: "ls *"
  decision: auto
- action: execute
  pattern: "rm -rf *"
  decision: ask
"#,
    )
    .expect("write policy");

    let install_output = run_kyris(
        home,
        &["install", "--components", "hooks,claude-code,cline"],
    );
    assert!(install_output.status.success(), "{install_output:?}");

    assert!(
        home.join(".kyris")
            .join("hooks")
            .join("zsh_hook.sh")
            .exists()
    );
    assert!(
        home.join(".kyris")
            .join("hooks")
            .join("zshenv_hook.sh")
            .exists()
    );
    assert!(
        home.join(".kyris")
            .join("hooks")
            .join("bash_hook.sh")
            .exists()
    );
    assert!(
        home.join(".kyris")
            .join("hooks")
            .join("bash_env.sh")
            .exists()
    );
    assert!(
        home.join(".claude")
            .join("hooks")
            .join("agentpact_pretooluse.sh")
            .exists()
    );
    assert!(home.join(".kyris").join("env").join("cline.sh").exists());
    assert!(home.join(".kyris").join("env").join("load.sh").exists());
    assert!(home.join(".kyris").join("manifest.json").exists());

    let zshrc_after = fs::read_to_string(home.join(".zshrc")).expect("read .zshrc");
    assert!(zshrc_after.contains("source \"$HOME/.kyris/hooks/zsh_hook.sh\""));
    assert!(zshrc_after.contains("source \"$HOME/.kyris/env/load.sh\""));

    let zshenv_after = fs::read_to_string(home.join(".zshenv")).expect("read .zshenv");
    assert!(zshenv_after.contains("source \"$HOME/.kyris/hooks/zshenv_hook.sh\""));

    let bashrc_after = fs::read_to_string(home.join(".bashrc")).expect("read .bashrc");
    assert!(bashrc_after.contains("source \"$HOME/.kyris/hooks/bash_hook.sh\""));
    assert!(bashrc_after.contains("export BASH_ENV=\"$HOME/.kyris/hooks/bash_env.sh\""));
    assert!(bashrc_after.contains("source \"$HOME/.kyris/env/load.sh\""));

    let claude_settings_after: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude").join("settings.json"))
            .expect("read claude settings"),
    )
    .expect("parse claude settings");
    assert!(
        claude_settings_after["hooks"]["PreToolUse"]
            .as_array()
            .is_some_and(|hooks| !hooks.is_empty())
    );

    let cline_env = fs::read_to_string(home.join(".kyris").join("env").join("cline.sh"))
        .expect("read cline env");
    assert!(cline_env.contains("CLINE_COMMAND_PERMISSIONS"));

    let uninstall_output = run_kyris(home, &["uninstall"]);
    assert!(uninstall_output.status.success(), "{uninstall_output:?}");

    assert_eq!(
        fs::read_to_string(home.join(".zshrc")).expect("read restored .zshrc"),
        zshrc
    );
    assert_eq!(
        fs::read_to_string(home.join(".zshenv")).expect("read restored .zshenv"),
        zshenv
    );
    assert_eq!(
        fs::read_to_string(home.join(".bashrc")).expect("read restored .bashrc"),
        bashrc
    );
    assert_eq!(
        fs::read_to_string(home.join(".claude").join("settings.json"))
            .expect("read restored claude settings"),
        claude_settings
    );

    assert!(
        !home
            .join(".claude")
            .join("hooks")
            .join("agentpact_pretooluse.sh")
            .exists()
    );
    assert!(!home.join(".kyris").exists());
}
