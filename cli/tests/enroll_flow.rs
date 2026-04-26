// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kyris_core::config::KyrisdConfig;
use kyris_core::sync::EnrollmentResponse;
use serde_json::json;
use tempfile::TempDir;

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

fn write_fake_binary(dir: &Path, name: &str, version: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\necho \"{version}\"\n")).expect("write fake binary");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fake binary");
}

fn run_enroll(home: &Path, fake_bin_dir: &Path, base_url: &str) -> std::process::Output {
    let path = format!(
        "{}:{}",
        fake_bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .env("PATH", path)
        .env("HOSTNAME", "test-host")
        .env("GITHUB_CLIENT_ID", "client-123")
        .env(
            "KYRIS_TEST_GITHUB_DEVICE_CODE_URL",
            format!("{base_url}/login/device/code"),
        )
        .env(
            "KYRIS_TEST_GITHUB_ACCESS_TOKEN_URL",
            format!("{base_url}/login/oauth/access_token"),
        )
        .env("KYRIS_TEST_DISABLE_BROWSER_OPEN", "1")
        .arg("enroll")
        .arg("--force")
        .arg("--relay-url")
        .arg(base_url)
        .output()
        .expect("run kyris enroll")
}

fn spawn_mock_server() -> (
    String,
    Arc<Mutex<Vec<RecordedRequest>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let address = format!("http://{}", listener.local_addr().expect("listener addr"));
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recorded_clone = Arc::clone(&recorded);

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut served = 0;
        while served < 3 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("set stream blocking");
                    served += 1;
                    let request = read_request(&mut stream);
                    let response_body = match request.path.as_str() {
                        "/login/device/code" => json!({
                            "device_code": "device-123",
                            "user_code": "USER-CODE",
                            "verification_uri": "http://127.0.0.1/verify",
                            "expires_in": 600,
                            "interval": 1
                        })
                        .to_string(),
                        "/login/oauth/access_token" => {
                            json!({"access_token": "gh-token"}).to_string()
                        }
                        "/api/v1/enroll" => json!({
                            "machine_token": "new-token",
                            "machine_id": "machine-1"
                        })
                        .to_string(),
                        other => panic!("unexpected request path: {other}"),
                    };

                    recorded_clone.lock().expect("lock requests").push(request);
                    write_response(&mut stream, 200, &response_body);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        panic!("timed out waiting for enrollment requests");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    });

    (address, recorded, handle)
}

fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "request closed before headers");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_subsequence(&buffer, b"\r\n\r\n") {
            break index + 4;
        }
    };

    let header_text = String::from_utf8(buffer[..header_end].to_vec()).expect("headers utf8");
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().expect("request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().expect("method").to_string();
    let path = request_parts.next().expect("path").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let read = stream.read(&mut chunk).expect("read request body");
        assert!(read > 0, "request closed before body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8(buffer[header_end..header_end + content_length].to_vec())
        .expect("body utf8");

    RecordedRequest {
        method,
        path,
        headers,
        body,
    }
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
    let body_bytes = body.as_bytes();
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response headers");
    stream.write_all(body_bytes).expect("write response body");
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn test_enroll_force_uses_stubbed_device_flow_and_persists_credentials() {
    let temp_home = TempDir::new().expect("temp home");
    let fake_bin = TempDir::new().expect("fake bin");
    let home = temp_home.path();

    write_fake_binary(fake_bin.path(), "agentpactd", "9.9.9");
    fs::create_dir_all(home.join(".kyris")).expect("create .kyris");
    fs::write(
        home.join(".kyris").join("credentials.json"),
        serde_json::to_string_pretty(&EnrollmentResponse {
            machine_token: "old-token".to_string(),
            machine_id: "machine-1".to_string(),
        })
        .expect("serialize credentials"),
    )
    .expect("write old credentials");

    let (base_url, recorded, handle) = spawn_mock_server();
    let output = run_enroll(home, fake_bin.path(), &base_url);
    handle.join().expect("join mock server");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Enrollment complete."), "{stdout}");
    assert!(stdout.contains("Machine enrolled as machine-1"), "{stdout}");

    let credentials: EnrollmentResponse = serde_json::from_str(
        &fs::read_to_string(home.join(".kyris").join("credentials.json"))
            .expect("read credentials"),
    )
    .expect("parse credentials");
    assert_eq!(credentials.machine_id, "machine-1");
    assert_eq!(credentials.machine_token, "new-token");

    let config: KyrisdConfig = serde_saphyr::from_str(
        &fs::read_to_string(home.join(".kyris").join("kyrisd.yaml")).expect("read config"),
    )
    .expect("parse config");
    assert!(config.sync.enabled);
    assert_eq!(config.sync.relay_url, base_url);

    let requests = recorded.lock().expect("lock requests");
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/login/device/code");
    assert!(requests[0].body.contains("client_id=client-123"));
    assert_eq!(requests[1].path, "/login/oauth/access_token");
    assert!(requests[1].body.contains("device_code=device-123"));
    assert_eq!(requests[2].path, "/api/v1/enroll");
    assert_eq!(
        requests[2].headers.get("authorization").map(String::as_str),
        Some("Bearer gh-token")
    );

    let enrollment_body: serde_json::Value =
        serde_json::from_str(&requests[2].body).expect("parse enrollment body");
    assert_eq!(enrollment_body["hostname"], "test-host");
    assert_eq!(enrollment_body["os"], std::env::consts::OS);
    assert_eq!(enrollment_body["arch"], std::env::consts::ARCH);
    assert_eq!(enrollment_body["agentpact_version"], "9.9.9");
}
