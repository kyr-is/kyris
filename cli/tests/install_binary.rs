// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

#[derive(Debug, Clone)]
struct RecordedRequest {
    path: String,
}

fn run_kyris(home: &Path, base_url: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kyris"))
        .current_dir(home)
        .env("HOME", home)
        .env("KYRIS_TEST_GITHUB_RELEASES_BASE_URL", base_url)
        .env("KYRIS_TEST_DISABLE_HOMEBREW_DETECTION", "1")
        .env("KYRIS_TEST_DISABLE_SERVICE_MANAGEMENT", "1")
        .args(args)
        .output()
        .expect("run kyris")
}

fn release_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") | ("macos", "arm64") => "darwin-aarch64",
        ("macos", "x86_64") => "darwin-x86_64",
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        (os, arch) => panic!("unsupported test target: {os}/{arch}"),
    }
}

fn create_archive(temp_dir: &Path, asset_name: &str, binary_name: &str, contents: &str) -> PathBuf {
    let payload_dir = temp_dir.join("payload");
    fs::create_dir_all(&payload_dir).expect("create payload dir");
    fs::write(payload_dir.join(binary_name), contents).expect("write payload file");

    let archive_path = temp_dir.join(asset_name);
    let status = Command::new("tar")
        .args([
            "-czf",
            &archive_path.to_string_lossy(),
            "-C",
            &payload_dir.to_string_lossy(),
            binary_name,
        ])
        .status()
        .expect("run tar");
    assert!(status.success(), "tar failed creating archive");
    archive_path
}

fn spawn_release_server(
    asset_name: String,
    asset_bytes: Vec<u8>,
) -> (
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
    let address_for_thread = address.clone();

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut served = 0;
        while served < 2 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    served += 1;
                    let request = read_request(&mut stream);
                    let response = match request.path.as_str() {
                        "/repos/kyr-is/kyris/releases/latest" => Response {
                            content_type: "application/json".to_string(),
                            body: format!(
                                r#"{{"assets":[{{"name":"{asset_name}","browser_download_url":"{address}/assets/{asset_name}"}}]}}"#,
                                address = address_for_thread
                            )
                            .into_bytes(),
                        },
                        path if path == format!("/assets/{asset_name}") => Response {
                            content_type: "application/gzip".to_string(),
                            body: asset_bytes.clone(),
                        },
                        other => panic!("unexpected request path: {other}"),
                    };
                    recorded_clone.lock().expect("lock requests").push(request);
                    write_response(&mut stream, &response);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        panic!("timed out waiting for install requests");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    });

    (address, recorded, handle)
}

#[derive(Debug, Clone)]
struct Response {
    content_type: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "request closed before headers");
        buffer.extend_from_slice(&chunk[..read]);
        if find_subsequence(&buffer, b"\r\n\r\n").is_some() {
            break;
        }
    }

    let header_end = find_subsequence(&buffer, b"\r\n\r\n").expect("header end") + 4;
    let header_text = String::from_utf8(buffer[..header_end].to_vec()).expect("headers utf8");
    let request_line = header_text
        .split("\r\n")
        .find(|line| !line.is_empty())
        .expect("request line");
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().expect("method");
    let path = parts.next().expect("path").to_string();
    RecordedRequest { path }
}

fn write_response(stream: &mut TcpStream, response: &Response) {
    let headers = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.content_type,
        response.body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .expect("write response headers");
    stream
        .write_all(&response.body)
        .expect("write response body");
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn test_install_binary_component_downloads_local_release_and_uninstalls_cleanly() {
    let temp_home = TempDir::new().expect("temp home");
    let release_dir = TempDir::new().expect("release dir");
    let home = temp_home.path();

    let zshrc = "# zsh baseline\n";
    let bashrc = "# bash baseline\n";
    fs::write(home.join(".zshrc"), zshrc).expect("write .zshrc");
    fs::write(home.join(".bashrc"), bashrc).expect("write .bashrc");

    let asset_name = format!("kyris-{}.tar.gz", release_target());
    let expected_binary = "#!/bin/sh\necho \"local kyris-hook\"\n";
    let archive_path = create_archive(
        release_dir.path(),
        &asset_name,
        "kyris-hook",
        expected_binary,
    );
    let asset_bytes = fs::read(&archive_path).expect("read archive");

    let (base_url, recorded, handle) = spawn_release_server(asset_name.clone(), asset_bytes);
    let install_output = run_kyris(home, &base_url, &["install", "--components", "kyris-hook"]);
    handle.join().expect("join release server");

    assert!(install_output.status.success(), "{install_output:?}");
    assert_eq!(
        fs::read_to_string(home.join(".kyris").join("bin").join("kyris-hook"))
            .expect("read installed binary"),
        expected_binary
    );
    assert!(
        fs::read_to_string(home.join(".zshrc"))
            .expect("read updated .zshrc")
            .contains("export PATH=\"$HOME/.kyris/bin:$PATH\"")
    );
    assert!(
        fs::read_to_string(home.join(".bashrc"))
            .expect("read updated .bashrc")
            .contains("export PATH=\"$HOME/.kyris/bin:$PATH\"")
    );

    let requests = recorded.lock().expect("lock requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/repos/kyr-is/kyris/releases/latest");
    assert_eq!(requests[1].path, format!("/assets/{asset_name}"));
    drop(requests);

    let uninstall_output = run_kyris(home, &base_url, &["uninstall"]);
    assert!(uninstall_output.status.success(), "{uninstall_output:?}");
    assert_eq!(
        fs::read_to_string(home.join(".zshrc")).expect("read restored .zshrc"),
        zshrc
    );
    assert_eq!(
        fs::read_to_string(home.join(".bashrc")).expect("read restored .bashrc"),
        bashrc
    );
    assert!(!home.join(".kyris").exists());
}
