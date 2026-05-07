// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod executable");
}

fn write_fake_brew(bin_dir: &Path) {
    write_executable(
        &bin_dir.join("brew"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "${KYRIS_TEST_BREW_LOG:?}"
if [ "${1-}" = "list" ]; then
  if [ "${2-}" = "kyris" ] && [ "${KYRIS_TEST_BREW_LIST_KYRIS:-0}" = "1" ]; then
    exit 0
  fi
  if [ "${2-}" = "agentpact" ] && [ "${KYRIS_TEST_BREW_LIST_AGENTPACT:-0}" = "1" ]; then
    exit 0
  fi
  exit 1
fi
if [ "${1-}" = "--prefix" ]; then
  printf '%s\n' "${KYRIS_TEST_BREW_PREFIX:-/opt/homebrew}"
  exit 0
fi
if [ "${1-}" = "services" ] && [ "${2-}" = "list" ]; then
  if [ "${KYRIS_TEST_BREW_LIST_KYRIS:-0}" = "1" ]; then
    printf 'kyris %s user ~/Library/LaunchAgents/homebrew.mxcl.kyris.plist\n' "${KYRIS_TEST_BREW_SERVICE_STATUS_KYRIS:-started}"
  fi
  if [ "${KYRIS_TEST_BREW_LIST_AGENTPACT:-0}" = "1" ]; then
    printf 'agentpact %s user ~/Library/LaunchAgents/homebrew.mxcl.agentpact.plist\n' "${KYRIS_TEST_BREW_SERVICE_STATUS_AGENTPACT:-started}"
  fi
  exit 0
fi
if [ "${1-}" = "services" ] && { [ "${2-}" = "start" ] || [ "${2-}" = "stop" ] || [ "${2-}" = "restart" ]; }; then
  exit 0
fi
exit 0
"#,
    );
}

fn write_fake_launchctl(bin_dir: &Path) {
    write_executable(
        &bin_dir.join("launchctl"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "${KYRIS_TEST_LAUNCHCTL_LOG:?}"
if [ "${1-}" = "print" ]; then
  case "${2-}" in
    *is.kyr.kyrisd)
      [ "${KYRIS_TEST_LAUNCHCTL_PRINT_KYRISD:-0}" = "1" ] && exit 0 || exit 1
      ;;
    *is.kyr.agentpactd)
      [ "${KYRIS_TEST_LAUNCHCTL_PRINT_AGENTPACTD:-0}" = "1" ] && exit 0 || exit 1
      ;;
  esac
fi
exit 0
"#,
    );
}

fn write_fake_which(bin_dir: &Path) {
    write_executable(
        &bin_dir.join("which"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "${KYRIS_TEST_WHICH_LOG:?}"
name="${1-}"
if [ -n "${KYRIS_TEST_WHICH_DIR:-}" ] && [ -x "${KYRIS_TEST_WHICH_DIR}/$name" ]; then
  printf '%s/%s\n' "${KYRIS_TEST_WHICH_DIR}" "$name"
  exit 0
fi
exit 1
"#,
    );
}

fn run_kyris(
    home: &Path,
    shim_bin_dir: &Path,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> std::process::Output {
    let path = format!(
        "{}:{}",
        shim_bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_kyris"));
    command
        .current_dir(home)
        .env("HOME", home)
        .env("PATH", path);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.args(args).output().expect("run kyris")
}

#[test]
fn test_install_skips_local_kyrisd_when_homebrew_managed() {
    let temp_home = TempDir::new().expect("temp home");
    let shim_bin = TempDir::new().expect("shim bin");
    let brew_log = temp_home.path().join("brew.log");
    let launchctl_log = temp_home.path().join("launchctl.log");
    let which_log = temp_home.path().join("which.log");
    fs::write(&brew_log, "").expect("write brew log");
    fs::write(&launchctl_log, "").expect("write launchctl log");
    fs::write(&which_log, "").expect("write which log");
    fs::write(temp_home.path().join(".zshrc"), "# zsh\n").expect("write .zshrc");
    fs::write(temp_home.path().join(".bashrc"), "# bash\n").expect("write .bashrc");
    let kyris_bin = temp_home.path().join(".kyris").join("bin");
    fs::create_dir_all(&kyris_bin).expect("create .kyris/bin");
    fs::write(kyris_bin.join("agentpactd"), "").expect("write fake agentpactd");
    write_fake_brew(shim_bin.path());
    write_fake_launchctl(shim_bin.path());
    write_fake_which(shim_bin.path());

    let output = run_kyris(
        temp_home.path(),
        shim_bin.path(),
        &[
            (
                "KYRIS_TEST_BREW_LOG",
                brew_log.to_str().expect("brew log path"),
            ),
            (
                "KYRIS_TEST_LAUNCHCTL_LOG",
                launchctl_log.to_str().expect("launchctl log path"),
            ),
            (
                "KYRIS_TEST_WHICH_LOG",
                which_log.to_str().expect("which log path"),
            ),
            ("KYRIS_TEST_BREW_LIST_KYRIS", "1"),
        ],
        &["install"],
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("detected Homebrew-managed kyris; skipped local kyrisd install"),
        "{stdout}"
    );
    assert!(
        !temp_home
            .path()
            .join(".kyris")
            .join("bin")
            .join("kyrisd")
            .exists()
    );

    let brew_log_contents = fs::read_to_string(&brew_log).expect("read brew log");
    assert!(brew_log_contents.contains("list kyris"));
}

#[test]
fn test_daemon_start_uses_brew_services_for_homebrew_managed_kyrisd() {
    let temp_home = TempDir::new().expect("temp home");
    let shim_bin = TempDir::new().expect("shim bin");
    let brew_log = temp_home.path().join("brew.log");
    let launchctl_log = temp_home.path().join("launchctl.log");
    let which_log = temp_home.path().join("which.log");
    fs::write(&brew_log, "").expect("write brew log");
    fs::write(&launchctl_log, "").expect("write launchctl log");
    fs::write(&which_log, "").expect("write which log");
    write_fake_brew(shim_bin.path());
    write_fake_launchctl(shim_bin.path());
    write_fake_which(shim_bin.path());

    let output = run_kyris(
        temp_home.path(),
        shim_bin.path(),
        &[
            (
                "KYRIS_TEST_BREW_LOG",
                brew_log.to_str().expect("brew log path"),
            ),
            (
                "KYRIS_TEST_LAUNCHCTL_LOG",
                launchctl_log.to_str().expect("launchctl log path"),
            ),
            (
                "KYRIS_TEST_WHICH_LOG",
                which_log.to_str().expect("which log path"),
            ),
            ("KYRIS_TEST_BREW_LIST_KYRIS", "1"),
        ],
        &["daemon", "start"],
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kyrisd started."), "{stdout}");

    let brew_log_contents = fs::read_to_string(&brew_log).expect("read brew log");
    assert!(brew_log_contents.contains("list kyris"));
    assert!(brew_log_contents.contains("--prefix"));
    assert!(brew_log_contents.contains("services start kyris"));
    let launchctl_log_contents = fs::read_to_string(&launchctl_log).expect("read launchctl log");
    assert!(
        launchctl_log_contents.trim().is_empty(),
        "{launchctl_log_contents}"
    );
}

#[test]
fn test_daemon_stop_uses_launchctl_for_launchd_managed_kyrisd() {
    let temp_home = TempDir::new().expect("temp home");
    let shim_bin = TempDir::new().expect("shim bin");
    let brew_log = temp_home.path().join("brew.log");
    let launchctl_log = temp_home.path().join("launchctl.log");
    let which_log = temp_home.path().join("which.log");
    fs::write(&brew_log, "").expect("write brew log");
    fs::write(&launchctl_log, "").expect("write launchctl log");
    fs::write(&which_log, "").expect("write which log");
    write_fake_brew(shim_bin.path());
    write_fake_launchctl(shim_bin.path());
    write_fake_which(shim_bin.path());

    let output = run_kyris(
        temp_home.path(),
        shim_bin.path(),
        &[
            (
                "KYRIS_TEST_BREW_LOG",
                brew_log.to_str().expect("brew log path"),
            ),
            (
                "KYRIS_TEST_LAUNCHCTL_LOG",
                launchctl_log.to_str().expect("launchctl log path"),
            ),
            (
                "KYRIS_TEST_WHICH_LOG",
                which_log.to_str().expect("which log path"),
            ),
        ],
        &["daemon", "stop"],
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kyrisd stopped."), "{stdout}");

    let launchctl_log_contents = fs::read_to_string(&launchctl_log).expect("read launchctl log");
    assert!(
        launchctl_log_contents.contains("bootout gui/"),
        "{launchctl_log_contents}"
    );
    assert!(
        launchctl_log_contents.contains("is.kyr.kyrisd"),
        "{launchctl_log_contents}"
    );
}

#[test]
fn test_update_check_warns_when_homebrew_manages_kyris() {
    let temp_home = TempDir::new().expect("temp home");
    let shim_bin = TempDir::new().expect("shim bin");
    let brew_log = temp_home.path().join("brew.log");
    let launchctl_log = temp_home.path().join("launchctl.log");
    let which_log = temp_home.path().join("which.log");
    fs::write(&brew_log, "").expect("write brew log");
    fs::write(&launchctl_log, "").expect("write launchctl log");
    fs::write(&which_log, "").expect("write which log");
    write_fake_brew(shim_bin.path());
    write_fake_launchctl(shim_bin.path());
    write_fake_which(shim_bin.path());

    let output = run_kyris(
        temp_home.path(),
        shim_bin.path(),
        &[
            (
                "KYRIS_TEST_BREW_LOG",
                brew_log.to_str().expect("brew log path"),
            ),
            (
                "KYRIS_TEST_LAUNCHCTL_LOG",
                launchctl_log.to_str().expect("launchctl log path"),
            ),
            (
                "KYRIS_TEST_WHICH_LOG",
                which_log.to_str().expect("which log path"),
            ),
            ("KYRIS_TEST_BREW_LIST_KYRIS", "1"),
            ("KYRIS_TEST_BREW_LIST_AGENTPACT", "1"),
        ],
        &["update", "--check"],
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kyris: Homebrew-managed install detected, use `brew upgrade kyris`."),
        "{stdout}"
    );
}
