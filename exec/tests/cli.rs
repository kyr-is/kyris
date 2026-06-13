// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Integration tests that drive the built `kyris-exec` binary.
//!
//! Beyond verifying CLI behavior end to end, having a `tests/` integration
//! suite is what makes cargo build the STANDALONE `kyris-exec` binary under
//! `cargo test`/`cargo llvm-cov` (it sets `CARGO_BIN_EXE_kyris-exec`). The
//! bundle smoke test reuses that artifact; without this suite a bin crate with
//! only in-file unit tests yields just a test harness, not a runnable binary.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kyris-exec"))
}

#[test]
fn version_flag_succeeds() {
    let out = Command::new(bin()).arg("--version").output().expect("run");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("kyris-exec "));
}

#[test]
fn usage_error_on_no_command() {
    // No spec source, no command → usage error (64).
    let out = Command::new(bin()).output().expect("run");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn bad_spec_file_exits_65() {
    let out = Command::new(bin())
        .args(["--spec-file", "/no/such/spec.json", "--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(65));
}

#[test]
fn mutually_exclusive_sources_rejected() {
    let out = Command::new(bin())
        .args([
            "--session",
            "--agent",
            "codex-cli",
            "--spec-file",
            "/x.json",
            "--",
            "true",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(64));
}

/// End-to-end on macOS: a session jail must allow a write inside the workspace
/// and block a write into the protected `.git` subtree, at the kernel. Mirrors
/// the standalone proof but through the real binary's `--session` path.
///
/// `.git` (rather than a sibling dir) is the deterministic out-of-bounds
/// target: a tempdir workspace lives under `$TMPDIR`, so the overlap guard
/// drops the `$TMPDIR` writable root, but `.git` under the workspace is always
/// protected regardless of where the workspace sits. Skips if the host refuses
/// to apply a Seatbelt profile (e.g. the test itself runs sandboxed).
#[cfg(target_os = "macos")]
#[test]
fn session_jail_confines_writes_through_the_binary() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let ws = workspace.path();
    std::fs::create_dir_all(ws.join(".git").join("hooks")).expect("seed .git/hooks");

    // cwd == workspace, matching the real shim flow (the shim runs in the
    // agent's launch dir, which kyris-exec uses as the jail root). Without
    // this, the relative writes below would target the test runner's cwd,
    // which is outside the jail.
    let run = |script: &str| {
        Command::new(bin())
            .current_dir(ws)
            .args(["--session", "--workspace"])
            .arg(ws)
            .args(["--agent", "codex-cli", "--", "bash", "-c", script])
            .output()
            .expect("run kyris-exec")
    };

    // Write inside the workspace → allowed.
    let inside = run("echo ok > inside.txt && cat inside.txt");
    let stderr = String::from_utf8_lossy(&inside.stderr);
    if stderr.contains("sandbox-exec: sandbox_apply: Operation not permitted") {
        // Host won't let us apply a profile (already sandboxed) — skip.
        return;
    }
    assert!(
        inside.status.success(),
        "inside-workspace write should succeed; stderr: {stderr}"
    );
    assert!(ws.join("inside.txt").exists());

    // Write into the protected .git subtree → kernel-denied.
    let hook = ws.join(".git").join("hooks").join("pre-commit");
    let blocked = run("echo pwn > .git/hooks/pre-commit");
    assert!(
        !blocked.status.success(),
        "write into protected .git must fail under the jail"
    );
    assert!(!hook.exists(), "git hook must not be created");
}
