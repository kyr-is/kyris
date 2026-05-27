// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use tempfile::TempDir;

struct FakeDaemon {
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeDaemon {
    fn start(socket_path: &Path, responses: Vec<serde_json::Value>) -> Self {
        if socket_path.exists() {
            std::fs::remove_file(socket_path).expect("remove stale socket");
        }
        let listener = UnixListener::bind(socket_path).expect("bind fake daemon socket");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = Arc::clone(&requests);

        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept fake daemon connection");
                let mut buf = Vec::new();
                stream
                    .read_to_end(&mut buf)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_slice(&buf).expect("parse fake daemon request");
                requests_clone
                    .lock()
                    .expect("lock fake daemon requests")
                    .push(request);
                let payload =
                    serde_json::to_vec(&response).expect("serialize fake daemon response");
                stream
                    .write_all(&payload)
                    .expect("write fake daemon response");
            }
        });

        Self {
            requests,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<serde_json::Value> {
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join fake daemon thread");
        }
        self.requests.lock().expect("lock requests").clone()
    }
}

fn hook_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("helper crate lives in hooks/helper")
        .join(name)
}

fn make_helper_path_dir() -> TempDir {
    let bin_dir = TempDir::new().expect("temp bin dir");
    symlink(
        env!("CARGO_BIN_EXE_kyris-hook"),
        bin_dir.path().join("kyris-hook"),
    )
    .expect("symlink kyris-hook");
    bin_dir
}

fn prepend_path(bin_dir: &Path) -> String {
    match std::env::var("PATH") {
        Ok(path) if !path.is_empty() => format!("{}:{path}", bin_dir.display()),
        _ => bin_dir.display().to_string(),
    }
}

fn run_zsh_trapdebug(
    home_dir: &Path,
    working_dir: &Path,
    socket_path: &Path,
    path_env: &str,
    command: &str,
) -> std::process::Output {
    Command::new("/bin/zsh")
        .current_dir(working_dir)
        .env("HOME", home_dir)
        .env("AGENTPACT_SOCK", socket_path)
        .env("PATH", path_env)
        .env("HOOK_PATH", hook_path("zsh_hook.sh"))
        // The hook bails out of its own setup when it detects it is
        // running inside a governed agent (env vars CLAUDECODE /
        // KYRIS_GOVERNED_SUBPROCESS, or `claude`/`codex`/… anywhere
        // in the parent process chain). The test environment can match
        // any of those — clearing the env vars isn't enough because
        // the parent process walk still finds the agent that spawned
        // `cargo test`. `KYRIS_HOOK_FORCE=1` is the dedicated test
        // escape hatch that bypasses the entire guard.
        .env_remove("CLAUDECODE")
        .env_remove("KYRIS_GOVERNED_SUBPROCESS")
        .env("KYRIS_HOOK_FORCE", "1")
        .arg("-fc")
        .arg(format!("source \"$HOOK_PATH\"; {command}"))
        .output()
        .expect("run zsh hook")
}

#[test]
fn test_zsh_hook_blocks_denied_command_via_kyris_hook() {
    if !Path::new("/bin/zsh").exists() {
        return;
    }

    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let bin_dir = make_helper_path_dir();
    let socket_path = temp_home.path().join("agentpact.sock");
    let daemon = FakeDaemon::start(
        &socket_path,
        vec![serde_json::json!({
            "id": "deny-1",
            "code": "PACT_DENIED",
            "reason": "denied by test"
        })],
    );

    let output = run_zsh_trapdebug(
        temp_home.path(),
        temp_home.path(),
        &socket_path,
        &prepend_path(bin_dir.path()),
        "git status",
    );

    assert_eq!(output.status.code(), Some(1));

    let requests = daemon.finish();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request["method"], "permission.request");
    assert_eq!(request["action"], "execute");
    assert_eq!(request["detail"], "git status");
}

#[test]
fn test_kyris_hook_allows_command_via_agentpact_socket() {
    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let socket_path = temp_home.path().join("agentpact.sock");
    let daemon = FakeDaemon::start(
        &socket_path,
        vec![serde_json::json!({
            "id": "allow-1",
            "code": "PACT_OK",
            "decision": "auto"
        })],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kyris-hook"))
        .current_dir(temp_home.path())
        .env("HOME", temp_home.path())
        .env("AGENTPACT_SOCK", &socket_path)
        .arg("check")
        .arg("git status")
        .arg("--cwd")
        .arg(temp_home.path())
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run kyris-hook");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "");

    let requests = daemon.finish();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request["method"], "permission.request");
    assert_eq!(request["action"], "execute");
    assert_eq!(request["detail"], "git status");
    assert_eq!(
        request["context"]["working_dir"],
        temp_home.path().display().to_string()
    );
}

#[test]
fn test_kyris_hook_voids_token_and_exits_2_on_normal_ask() {
    // A normal PACT_ASK is no longer answered with one whole-command token.
    // The helper voids that token (so it does not linger as a pending entry)
    // and exits 2, signaling the shell to hand off to `kyris hook
    // resolve-shell` for per-segment approval. Stdout carries nothing.
    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let socket_path = temp_home.path().join("agentpact.sock");
    let daemon = FakeDaemon::start(
        &socket_path,
        vec![
            serde_json::json!({
                "id": "ask-1",
                "code": "PACT_ASK",
                "approval_id": "apr_1",
                "approval_token": "apt_1"
            }),
            serde_json::json!({ "id": "void-1", "code": "PACT_OK" }),
        ],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kyris-hook"))
        .current_dir(temp_home.path())
        .env("HOME", temp_home.path())
        .env("AGENTPACT_SOCK", &socket_path)
        .arg("check")
        .arg("safe_tool && mystery_tool")
        .arg("--cwd")
        .arg(temp_home.path())
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run kyris-hook");

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "");

    let requests = daemon.finish();
    assert_eq!(requests.len(), 2, "expected request + void: {requests:?}");
    assert_eq!(requests[0]["method"], "permission.request");
    assert_eq!(requests[1]["method"], "permission.respond");
    assert_eq!(requests[1]["response"], "voided");
    assert_eq!(requests[1]["approval_token"], "apt_1");
}

#[test]
fn test_kyris_hook_breaker_ask_still_returns_token_and_exits_3() {
    // The circuit breaker is a session-level gate, not a per-command split,
    // so it keeps its dedicated whole-command prompt: the helper returns the
    // token (+ breaker count) and exits 3 without voiding.
    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let socket_path = temp_home.path().join("agentpact.sock");
    let daemon = FakeDaemon::start(
        &socket_path,
        vec![serde_json::json!({
            "id": "breaker-1",
            "code": "PACT_ASK",
            "approval_id": "apr_b",
            "approval_token": "apt_b",
            "extensions": { "circuit_breaker": { "count": 50 } }
        })],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kyris-hook"))
        .current_dir(temp_home.path())
        .env("HOME", temp_home.path())
        .env("AGENTPACT_SOCK", &socket_path)
        .arg("check")
        .arg("git status")
        .arg("--cwd")
        .arg(temp_home.path())
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run kyris-hook");

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "apr_b\tapt_b\t50"
    );

    let requests = daemon.finish();
    assert_eq!(requests.len(), 1, "breaker ask must not void: {requests:?}");
    assert_eq!(requests[0]["method"], "permission.request");
}

#[test]
fn test_kyris_hook_denies_oversized_command_locally() {
    // A command past the 10240-byte ceiling is denied by the helper itself,
    // before any socket contact — so a monster command can never race the
    // socket limit into a fail-open. No daemon is started here on purpose.
    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let socket_path = temp_home.path().join("agentpact.sock");

    let big = format!("echo {}", "a".repeat(10_241));
    let output = Command::new(env!("CARGO_BIN_EXE_kyris-hook"))
        .current_dir(temp_home.path())
        .env("HOME", temp_home.path())
        .env("AGENTPACT_SOCK", &socket_path)
        .arg("check")
        .arg(&big)
        .arg("--cwd")
        .arg(temp_home.path())
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run kyris-hook");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("governance ceiling"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_kyris_hook_blocks_unknown_daemon_response() {
    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let socket_path = temp_home.path().join("agentpact.sock");
    let daemon = FakeDaemon::start(
        &socket_path,
        vec![serde_json::json!({
            "id": "weird-1",
            "code": "PACT_FUTURE"
        })],
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kyris-hook"))
        .current_dir(temp_home.path())
        .env("HOME", temp_home.path())
        .env("AGENTPACT_SOCK", &socket_path)
        .arg("check")
        .arg("git status")
        .arg("--cwd")
        .arg(temp_home.path())
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run kyris-hook");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unexpected response code from agentpactd"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let requests = daemon.finish();
    assert_eq!(requests.len(), 1);
}

#[test]
fn test_zsh_hook_blocks_unexpected_helper_exit_code() {
    if !Path::new("/bin/zsh").exists() {
        return;
    }

    let temp_home = TempDir::new().expect("temp home");
    std::fs::create_dir_all(temp_home.path().join(".kyris")).expect("create .kyris");
    let bin_dir = TempDir::new().expect("temp bin dir");
    let fake_helper = bin_dir.path().join("kyris-hook");
    std::fs::write(&fake_helper, "#!/bin/sh\nexit 42\n").expect("write fake helper");
    let mut permissions = std::fs::metadata(&fake_helper)
        .expect("stat fake helper")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&fake_helper, permissions).expect("chmod fake helper");

    let socket_path = temp_home.path().join("agentpact.sock");
    let _listener = UnixListener::bind(&socket_path).expect("bind placeholder socket");

    let output = run_zsh_trapdebug(
        temp_home.path(),
        temp_home.path(),
        &socket_path,
        &prepend_path(bin_dir.path()),
        "git status",
    );

    assert_eq!(output.status.code(), Some(1));
}
