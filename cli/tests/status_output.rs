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
    // Keys are not in the yaml (they live in the secret store); `status`
    // doesn't read them, so the config only needs `listen`.
    fs::write(
        config_dir.join("kyrisd.yaml"),
        format!("apiVersion: kyris/v1\nserver:\n  listen: \"{listen}\"\n"),
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
        line.contains("burn:none/proxy"),
        "expected burn:none/proxy, got: {line}"
    );
}

#[test]
fn test_status_claude_code_burn_control_active_via_shim_without_loader() {
    // Regression for the fish/GUI gap: the PATH shim sources the agent's env
    // file on every launch, so burn-control is live even though NO shell RC
    // sources ~/.kyris/env/load.sh. This is the scenario the loader-only probe
    // wrongly reported as off (fish never sources the loader).
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    // The probe is value-aware: the env var must point at THIS kyrisd (from
    // kyrisd.yaml), so the fixture's listen address and env URL must agree.
    write_kyrisd_config(home, "127.0.0.1:4710");

    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".claude").join("settings.json"), "{}").expect("write settings");

    let env_dir = home.join(".kyris").join("env");
    fs::create_dir_all(&env_dir).expect("create env dir");
    fs::write(
        env_dir.join("claude-code.sh"),
        "export ANTHROPIC_BASE_URL='http://127.0.0.1:4710'\n",
    )
    .expect("write claude env");

    // Install a PATH shim that sources the env file — and deliberately NO
    // ~/.zshrc loader, mirroring a fish/GUI launch.
    let bin_dir = home.join(".kyris").join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    fs::write(
        bin_dir.join("claude"),
        "#!/bin/sh\nfor __kyris_env in \"$HOME/.kyris/env/claude-code.sh\" \"$HOME/.kyris/env/claude-code\"-*.sh; do\n  [ -f \"$__kyris_env\" ] && . \"$__kyris_env\"\ndone\nexec claude \"$@\"\n",
    )
    .expect("write claude shim");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("claude-code") && l.contains("burn:"))
        .expect("claude-code line in status output");
    assert!(
        line.contains("burn:proxy"),
        "expected burn:proxy (active via shim, no loader), got: {line}"
    );
}

#[test]
fn test_status_cline_execution_active_via_hook() {
    // cline execution is now a live-hook adapter: the kyris governance file-hook
    // at ~/.cline/hooks/PreToolUse.cjs (auto-discovered, no env/launchd delivery).
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    let hooks_dir = home.join(".cline").join("hooks");
    fs::create_dir_all(&hooks_dir).expect("create cline hooks dir");
    fs::write(
        hooks_dir.join("PreToolUse.cjs"),
        "// kyris hook check --agent cline\n",
    )
    .expect("write cline hook");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("cline") && l.contains("cmd:"))
        .expect("cline line in status output");
    assert!(
        line.contains("cmd:hook"),
        "expected cmd:hook (live-hook adapter active), got: {line}"
    );
}

#[test]
fn test_status_claude_code_burn_control_active_with_loader_sourced() {
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    // Value-aware probe: env URL must equal this kyrisd's base URL. The legacy
    // unquoted export form (pre-quoting installs) must still be recognized.
    write_kyrisd_config(home, "127.0.0.1:4710");

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
    assert!(
        line.contains("burn:proxy"),
        "expected burn:proxy (observed active), got: {line}"
    );
}

#[test]
fn test_status_cline_execution_none_without_hook() {
    // Detected via providers.json (routing configured) but no governance hook
    // installed → execution none.
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    let settings_dir = home.join(".cline").join("data").join("settings");
    fs::create_dir_all(&settings_dir).expect("create cline settings dir");
    fs::write(
        settings_dir.join("providers.json"),
        "{\"version\":1,\"providers\":{}}",
    )
    .expect("write cline providers");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("cline") && l.contains("cmd:"))
        .expect("cline line in status output");
    assert!(
        line.contains("cmd:none/hook"),
        "expected cmd:none/hook, got: {line}"
    );
}

#[test]
fn test_status_codex_burn_control_shows_provider_not_config_skew() {
    // Regression for the observed-vs-plan vocabulary skew: codex burn-control is
    // delivered by rewriting config.toml to route through the kyris model
    // provider. The probe must report that as "provider" (matching the plan
    // label BurnControlMechanism::KyrisdModelProvider), not "config", so a
    // correctly-routed codex shows `burn:provider/provider` rather than the
    // `burn:config/provider` skew that reads as drift.
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir).expect("create .codex");
    fs::write(
        codex_dir.join("config.toml"),
        "model_provider = \"kyris\"\n\n[model_providers.kyris]\nbase_url = \"http://127.0.0.1:4710/v1\"\n",
    )
    .expect("write codex config");

    let output = run_status(home, None);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("codex-cli") && l.contains("burn:"))
        .expect("codex-cli line in status output");
    assert!(
        line.contains("burn:provider/provider"),
        "expected burn:provider/provider (no skew), got: {line}"
    );
}

#[test]
fn test_status_detects_claude_via_binary_without_dot_claude_dir() {
    // Parity fix: claude must be detected when the `claude` binary is on PATH
    // even if ~/.claude doesn't exist yet (the other agents already do this).
    let temp_home = TempDir::new().expect("temp home");
    let fake_bin = TempDir::new().expect("fake bin");
    write_kyrisd_config(temp_home.path(), "127.0.0.1:1");
    write_fake_binary(fake_bin.path(), "claude", "1.0.0");
    // Deliberately do NOT create ~/.claude — detection must come from the binary.

    let output = run_status(temp_home.path(), Some(fake_bin.path()));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("claude-code"),
        "claude should be detected via the `claude` binary on PATH, got: {stdout}"
    );
}

#[test]
fn test_status_warns_about_unwrapped_mcp_servers() {
    // A wrapped tool surface plus MCP servers added after setup (not routed
    // through kyris) must surface a drift warning prompting a reconcile.
    // Servers live in ~/.claude.json — user scope at top level, local scope
    // under projects.<dir> (claude mcp add's default) — NOT settings.json
    // (review Finding 7); both scopes must be seen.
    let temp_home = TempDir::new().expect("temp home");
    let home = temp_home.path();
    write_kyrisd_config(home, "127.0.0.1:1");

    fs::create_dir_all(home.join(".claude")).expect("create .claude");
    fs::write(home.join(".claude").join("settings.json"), "{}").expect("write settings");
    fs::write(
        home.join(".claude.json"),
        r#"{
          "mcpServers": {
            "wrapped": {"command": "kyris-mcp", "args": ["wrap"]},
            "added-later": {"type": "stdio", "command": "npx", "args": ["-y", "srv"]}
          },
          "projects": {
            "/Users/someone/proj": {
              "mcpServers": {"local-scope-srv": {"type": "stdio", "command": "uvx", "args": ["x"]}}
            }
          }
        }"#,
    )
    .expect("write user config");

    let output = run_status(home, None);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("added-later") && stdout.contains("not routed through kyris"),
        "expected unwrapped-server drift warning, got: {stdout}"
    );
    assert!(
        stdout.contains("local-scope-srv"),
        "local-scope (projects.*) servers must be seen too, got: {stdout}"
    );
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

// (Removed test_status_reports_degraded_cline_policy: cline is now a live-hook
// agent with no compiled command policy, so the "compiled policy degraded / ask
// rules dropped" warning no longer applies to it — the hook handles `ask`
// natively. The warning path remains for the agents that still emit a compiled
// policy fallback, codex + gemini.)
