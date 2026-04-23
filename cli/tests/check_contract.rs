// SPDX-License-Identifier: Apache-2.0
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use tempfile::TempDir;

struct FakeDaemon {
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    handle: Option<thread::JoinHandle<()>>,
}

fn run_check(
    home_dir: &Path,
    working_dir: &Path,
    socket_path: &Path,
    command: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(working_dir)
        .env("HOME", home_dir)
        .env("AGENTPACT_SOCK", socket_path)
        .arg("check")
        .arg(command)
        .output()
        .expect("run kyris check")
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

#[test]
fn test_check_command_contract_with_agentpact_socket() {
    let temp_home = TempDir::new().expect("temp home");
    let socket_path = temp_home.path().join("agentpact.sock");
    let daemon = FakeDaemon::start(
        &socket_path,
        vec![serde_json::json!({
            "id": "resp-1",
            "code": "PACT_OK",
            "decision": "auto",
            "matched_rule": "git.status",
            "reason": "allowed by test policy"
        })],
    );

    let output = run_check(
        temp_home.path(),
        temp_home.path(),
        &socket_path,
        "git status",
    );

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Decision: auto"), "{stdout}");
    assert!(stdout.contains("Matched rule: git.status"), "{stdout}");
    assert!(
        stdout.contains("Reason: allowed by test policy"),
        "{stdout}"
    );

    let requests = daemon.finish();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request["method"], "permission.request");
    assert_eq!(request["action"], "execute");
    assert_eq!(request["detail"], "git status");
    let expected_working_dir =
        std::fs::canonicalize(temp_home.path()).expect("canonicalize expected working dir");
    let actual_working_dir = Path::new(
        request["context"]["working_dir"]
            .as_str()
            .expect("working_dir string"),
    );
    assert_eq!(actual_working_dir, expected_working_dir.as_path());
}
