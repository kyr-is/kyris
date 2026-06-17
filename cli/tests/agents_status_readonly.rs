// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//
// `kyris agent status` must be read-only. Inspecting a detected-but-unconfigured
// agent must not configure it, install a PATH shim, or otherwise mutate the
// user's agent config. Mutating (re)configuration belongs to `kyris agent setup`
// (idempotent — it also repairs drift) and the daemon's reconcile watcher.

use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn run_agents_status(home: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .args(["agent", "status"])
        .output()
        .expect("run kyris agent status")
}

#[test]
fn test_agents_status_does_not_configure_detected_agent() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();

    // Claude Code is detected (the ~/.claude dir exists) but kyris has never
    // configured it: settings.json has no PreToolUse hook and no shim exists.
    std::fs::create_dir_all(home.join(".claude")).expect("create .claude");
    let original_settings = "{}\n";
    std::fs::write(
        home.join(".claude").join("settings.json"),
        original_settings,
    )
    .expect("write settings");

    let output = run_agents_status(home);
    assert!(
        output.status.success(),
        "agents status should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // settings.json is byte-for-byte unchanged — no hook was injected. Under the
    // old reconcile-on-status behavior this file would gain a PreToolUse hook.
    let after_settings =
        std::fs::read_to_string(home.join(".claude").join("settings.json")).expect("read settings");
    assert_eq!(
        after_settings, original_settings,
        "agents status must not rewrite ~/.claude/settings.json"
    );

    // No PATH shim was installed as a side effect of the read.
    assert!(
        !home.join(".kyris").join("bin").join("claude").exists(),
        "agents status must not install a PATH shim"
    );

    // No env file was prestaged as a side effect of the read.
    assert!(
        !home
            .join(".kyris")
            .join("env")
            .join("claude-code.sh")
            .exists(),
        "agents status must not prestage an env file"
    );

    // The output still reports the detected agent (read path works end-to-end).
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("claude-code"),
        "expected claude-code in status output, got: {stdout}"
    );
}
