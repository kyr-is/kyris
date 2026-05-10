// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
//! End-to-end tests for `kyris always list` and `kyris always revoke`.
//! These tests do not require a running daemon — `kyris always` operates
//! on `commands.local.yaml` files directly.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const FIXTURE_TWO_OVERRIDES: &str = r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: local-always-overrides
spec:
  commands:
    older-command:
      permission: auto
      created_at: "2024-01-01T00:00:00Z"
    newer-command:
      permission: auto
      created_at: "2025-01-01T00:00:00Z"
"#;

const FIXTURE_MCP_OVERRIDES: &str = r#"apiVersion: agentpact/v1
kind: PolicyOverride
metadata:
  name: local-always-overrides
spec:
  mcp:
    serverA:
      readDoc:
        permission: auto
        created_at: "2025-03-01T12:00:00Z"
      writeDoc:
        permission: auto
        created_at: "2025-04-01T12:00:00Z"
"#;

struct Layout {
    _tmp: TempDir,
    home: PathBuf,
    working_dir: PathBuf,
    policy_dir: PathBuf,
}

fn build_layout(write_fixture: bool) -> Layout {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let working_dir = home.join("project");
    let policy_dir = working_dir.join(".agentpact").join("policy");
    std::fs::create_dir_all(&policy_dir).unwrap();
    if write_fixture {
        std::fs::write(
            policy_dir.join("commands.local.yaml"),
            FIXTURE_TWO_OVERRIDES,
        )
        .unwrap();
    }
    Layout {
        _tmp: tmp,
        home,
        working_dir,
        policy_dir,
    }
}

fn write_mcp_fixture(layout: &Layout) {
    std::fs::write(
        layout.policy_dir.join("mcp.local.yaml"),
        FIXTURE_MCP_OVERRIDES,
    )
    .unwrap();
}

fn run_kyris(layout: &Layout, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(&layout.working_dir)
        .env("HOME", &layout.home)
        .args(args)
        .output()
        .expect("run kyris")
}

fn read_local_yaml(policy_dir: &Path) -> String {
    std::fs::read_to_string(policy_dir.join("commands.local.yaml")).unwrap()
}

#[test]
fn testAlwaysListEmptyWhenNoFile() {
    let layout = build_layout(false);
    let out = run_kyris(&layout, &["always", "list"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("No active overrides."),
        "expected empty marker, got: {stdout}"
    );
}

#[test]
fn testAlwaysListShowsOverrides() {
    let layout = build_layout(true);
    let out = run_kyris(&layout, &["always", "list"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("command\tolder-command\t"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("command\tnewer-command\t"),
        "stdout: {stdout}"
    );
    let yaml_path = layout.policy_dir.join("commands.local.yaml");
    assert!(
        stdout.contains(&yaml_path.display().to_string()),
        "stdout: {stdout}"
    );
}

#[test]
fn testAlwaysRevokeNamedCommentsEntry() {
    let layout = build_layout(true);
    let out = run_kyris(&layout, &["always", "revoke", "older-command"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("Revoked older-command in "),
        "stdout: {stdout}"
    );

    let content = read_local_yaml(&layout.policy_dir);
    assert!(
        content
            .lines()
            .any(|line| line.starts_with("#     older-command:")),
        "older-command entry should be commented; got:\n{content}"
    );
    assert!(
        content
            .lines()
            .any(|line| line.starts_with("    newer-command:")),
        "newer-command should remain active; got:\n{content}"
    );
}

#[test]
fn testAlwaysRevokeLastTargetsNewest() {
    let layout = build_layout(true);
    let out = run_kyris(&layout, &["always", "revoke", "--last"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.starts_with("Revoked --last in "), "stdout: {stdout}");

    let content = read_local_yaml(&layout.policy_dir);
    assert!(
        content
            .lines()
            .any(|line| line.starts_with("#     newer-command:")),
        "newer-command should be commented; got:\n{content}"
    );
    assert!(
        content
            .lines()
            .any(|line| line.starts_with("    older-command:")),
        "older-command should remain active; got:\n{content}"
    );
}

#[test]
fn testAlwaysRevokeMissingArgsFails() {
    let layout = build_layout(true);
    let out = run_kyris(&layout, &["always", "revoke"]);
    assert!(!out.status.success(), "expected clap usage error");
}

#[test]
fn testAlwaysRevokeBothArgsFails() {
    let layout = build_layout(true);
    let out = run_kyris(&layout, &["always", "revoke", "--last", "older-command"]);
    assert!(!out.status.success(), "expected clap conflict error");
}

#[test]
fn testAlwaysRevokeNonexistentSelectorFails() {
    let layout = build_layout(true);
    let out = run_kyris(&layout, &["always", "revoke", "not-a-real-command"]);
    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("override not found"),
        "stderr should mention not-found, got: {stderr}"
    );
}

#[test]
fn testAlwaysListIncludesMcpEntries() {
    let layout = build_layout(false);
    write_mcp_fixture(&layout);

    let out = run_kyris(&layout, &["always", "list"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("mcp\tserverA:readDoc\t"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("mcp\tserverA:writeDoc\t"),
        "stdout: {stdout}"
    );
    let mcp_path = layout.policy_dir.join("mcp.local.yaml");
    assert!(
        stdout.contains(&mcp_path.display().to_string()),
        "stdout: {stdout}"
    );
}

#[test]
fn testAlwaysListMergesCommandAndMcpEntries() {
    let layout = build_layout(true);
    write_mcp_fixture(&layout);

    let out = run_kyris(&layout, &["always", "list"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("command\tnewer-command\t"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("mcp\tserverA:writeDoc\t"),
        "stdout: {stdout}"
    );
    let line_count = stdout.lines().count();
    assert_eq!(
        line_count, 4,
        "expected 4 entries (2 commands + 2 mcp), got {line_count}: {stdout}"
    );
}

#[test]
fn testAlwaysRevokeNamedMcpEntry() {
    let layout = build_layout(false);
    write_mcp_fixture(&layout);

    let out = run_kyris(&layout, &["always", "revoke", "serverA:readDoc"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("Revoked serverA:readDoc in "),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("mcp.local.yaml"), "stdout: {stdout}");

    let content = std::fs::read_to_string(layout.policy_dir.join("mcp.local.yaml")).unwrap();
    assert!(
        content.lines().any(|l| l.starts_with("#       readDoc:")),
        "readDoc should be commented; got:\n{content}"
    );
    assert!(
        content.lines().any(|l| l.starts_with("      writeDoc:")),
        "writeDoc should remain active; got:\n{content}"
    );
}

#[test]
fn testAlwaysRevokeLastChoosesNewestAcrossFiles() {
    let layout = build_layout(true);
    write_mcp_fixture(&layout);

    // mcp writeDoc is dated 2025-04-01, newer than all command entries.
    let out = run_kyris(&layout, &["always", "revoke", "--last"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("mcp.local.yaml"), "stdout: {stdout}");

    let content = std::fs::read_to_string(layout.policy_dir.join("mcp.local.yaml")).unwrap();
    assert!(
        content.lines().any(|l| l.starts_with("#       writeDoc:")),
        "writeDoc should be commented; got:\n{content}"
    );
    assert!(
        content.lines().any(|l| l.starts_with("      readDoc:")),
        "readDoc should remain active; got:\n{content}"
    );
}
