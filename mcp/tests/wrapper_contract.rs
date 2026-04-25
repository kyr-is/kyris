// SPDX-License-Identifier: Apache-2.0
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
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

fn run_wrapper_process(
    home_dir: &Path,
    working_dir: &Path,
    socket_path: &Path,
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kyris-mcp"))
        .current_dir(working_dir)
        .env("HOME", home_dir)
        .env("AGENTPACT_SOCK", socket_path)
        .arg("wrap")
        .arg("--server")
        .arg("demo")
        .arg("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kyris-mcp");

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}"#;
    child
        .stdin
        .take()
        .expect("take stdin")
        .write_all(format!("{request}\n").as_bytes())
        .expect("write wrapper input");

    child.wait_with_output().expect("wait for kyris-mcp")
}

fn run_wrapper_with_fake_daemon(
    working_dir: &Path,
    socket_path: &Path,
    daemon_response: serde_json::Value,
) -> (std::process::Output, Vec<serde_json::Value>) {
    let daemon = FakeDaemon::start(socket_path, vec![daemon_response]);
    let output = run_wrapper_process(working_dir, working_dir, socket_path);
    let requests = daemon.finish();
    (output, requests)
}

#[test]
fn test_wrapper_forwards_tools_call_when_daemon_allows() {
    let temp_home = TempDir::new().expect("temp home");
    let socket_path = temp_home.path().join("agentpact.sock");

    let (output, requests) = run_wrapper_with_fake_daemon(
        temp_home.path(),
        &socket_path,
        serde_json::json!({
            "id": "allow-1",
            "code": "PACT_OK"
        }),
    );

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""method":"tools/call""#), "{stdout}");
    assert!(stdout.contains(r#""name":"read_file""#), "{stdout}");

    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request["method"], "permission.request");
    assert_eq!(request["action"], "call");
    assert_eq!(request["detail"], "read_file");
    assert_eq!(request["context"]["mcp_server"], "demo");
    let expected_working_dir =
        std::fs::canonicalize(temp_home.path()).expect("canonicalize expected working dir");
    let actual_working_dir = Path::new(
        request["context"]["working_dir"]
            .as_str()
            .expect("working_dir string"),
    );
    assert_eq!(actual_working_dir, expected_working_dir.as_path());
}

#[test]
fn test_wrapper_blocks_tools_call_when_daemon_denies() {
    let temp_home = TempDir::new().expect("temp home");
    let socket_path = temp_home.path().join("agentpact.sock");

    let (output, requests) = run_wrapper_with_fake_daemon(
        temp_home.path(),
        &socket_path,
        serde_json::json!({
            "id": "deny-1",
            "code": "PACT_DENIED",
            "reason": "blocked by policy"
        }),
    );

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""error""#), "{stdout}");
    assert!(
        stdout.contains("Blocked by policy: blocked by policy"),
        "{stdout}"
    );
    assert!(!stdout.contains(r#""name":"read_file""#), "{stdout}");

    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request["method"], "permission.request");
    assert_eq!(request["action"], "call");
    assert_eq!(request["detail"], "read_file");
    assert_eq!(request["context"]["mcp_server"], "demo");
}
