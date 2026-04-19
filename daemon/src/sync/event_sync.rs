// SPDX-License-Identifier: Apache-2.0
use std::io::{BufRead, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use kyris_core::event::Event;
use kyris_core::sync::{EventBatch, SyncCursor};

pub struct EventSyncer {
    cursor: SyncCursor,
    scope: Vec<String>,
    log_dir: PathBuf,
}

impl EventSyncer {
    pub fn new(cursor: SyncCursor, scope: Vec<String>, log_dir: PathBuf) -> Self {
        Self {
            cursor,
            scope,
            log_dir,
        }
    }

    pub fn cursor(&self) -> &SyncCursor {
        &self.cursor
    }

    pub fn advance_cursor(&mut self, filename: String, byte_offset: u64) {
        self.cursor.filename = filename;
        self.cursor.byte_offset = byte_offset;
    }

    pub fn is_in_scope(&self, working_dir: Option<&str>) -> bool {
        let Some(dir) = working_dir else {
            return false;
        };
        if self.scope.is_empty() {
            return false;
        }
        self.scope
            .iter()
            .any(|pattern| super::scope::matches_scope(pattern, dir))
    }

    pub fn read_new_events(&mut self) -> Vec<Event> {
        let file_path = self.log_dir.join(&self.cursor.filename);
        let mut events = Vec::new();

        if !file_path.exists() {
            if let Some(oldest) = find_oldest_log_file(&self.log_dir) {
                self.cursor.filename = oldest;
                self.cursor.byte_offset = 0;
            } else {
                return events;
            }
        }

        let file_path = self.log_dir.join(&self.cursor.filename);
        let Ok(file) = std::fs::File::open(&file_path) else {
            return events;
        };

        let mut reader = std::io::BufReader::new(file);
        if reader
            .seek(SeekFrom::Start(self.cursor.byte_offset))
            .is_err()
        {
            return events;
        }

        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(event) = serde_json::from_str::<Event>(trimmed)
                        && self.is_in_scope(event.working_dir.as_deref())
                    {
                        events.push(event);
                    }
                }
            }
        }

        let new_offset = reader.stream_position().unwrap_or(self.cursor.byte_offset);
        self.cursor.byte_offset = new_offset;
        events
    }

    pub fn check_rotation(&mut self) -> bool {
        let active = self.log_dir.join("events.jsonl");

        if self.cursor.filename == "events.jsonl" {
            // Active file was rotated out from under us — it no longer exists but a
            // new active file has been created (or will be shortly). Find the oldest
            // dated file to continue reading from, or stay put if nothing rotated.
            if !active.exists() {
                if let Some(oldest) = find_oldest_log_file(&self.log_dir) {
                    self.cursor.filename = oldest;
                    self.cursor.byte_offset = 0;
                    return true;
                }
            }
            return false;
        }

        // Cursor points to a dated rotated file. Once a new active file appears,
        // switch to it (we've already read through the rotated file).
        if active.exists() {
            self.cursor.filename = "events.jsonl".to_string();
            self.cursor.byte_offset = 0;
            return true;
        }

        false
    }

    pub fn build_batch(
        &self,
        events: Vec<Event>,
        machine_id: &str,
        kyrisd_records: Vec<kyris_core::record::GatewayRecord>,
    ) -> EventBatch {
        EventBatch {
            machine_id: machine_id.to_string(),
            batch_id: uuid::Uuid::now_v7().to_string(),
            events,
            kyrisd_records,
            cursor: self.cursor.clone(),
        }
    }
}

fn is_log_file(name: &str) -> bool {
    name.ends_with(".jsonl") || name.ends_with(".jsonl.gz")
}

fn find_oldest_log_file(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut log_files: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if is_log_file(&name) {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    log_files.sort();
    log_files.into_iter().next()
}

pub fn compute_hmac_signature(key: &[u8], body: &[u8]) -> String {
    use aws_lc_rs::hmac;

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, body);
    const_hex::encode(tag.as_ref())
}

pub async fn send_batch(
    client: &reqwest::Client,
    relay_url: &str,
    machine_id: &str,
    machine_token: &str,
    batch: &EventBatch,
) -> Result<(), String> {
    let body = serde_json::to_vec(batch).map_err(|e| format!("serialize batch: {e}"))?;
    let signature = compute_hmac_signature(machine_token.as_bytes(), &body);

    let response = client
        .post(relay_url)
        .header("content-type", "application/json")
        .header("x-kyris-machine-id", machine_id)
        .header("x-kyris-signature", &signature)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("relay POST failed: {e}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("relay returned {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    fn make_syncer(scope: Vec<String>, log_dir: &Path) -> EventSyncer {
        EventSyncer::new(
            SyncCursor {
                filename: "events.jsonl".to_string(),
                byte_offset: 0,
            },
            scope,
            log_dir.to_path_buf(),
        )
    }

    #[test]
    fn testIsInScopeNoWorkingDir() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        assert!(!syncer.is_in_scope(None));
    }

    #[test]
    fn testIsInScopeEmptyScope() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec![], dir.path());
        assert!(!syncer.is_in_scope(Some("/work/project")));
    }

    #[test]
    fn testAdvanceCursor() {
        let dir = tempfile::tempdir().unwrap();
        let mut syncer = make_syncer(vec![], dir.path());
        syncer.advance_cursor("events-2026-04-12.jsonl".to_string(), 4096);
        assert_eq!(syncer.cursor().filename, "events-2026-04-12.jsonl");
        assert_eq!(syncer.cursor().byte_offset, 4096);
    }

    #[test]
    fn testReadNewEventsFromFile() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let event_json = serde_json::json!({
            "id": "evt-1",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "claude-code",
            "action": "execute",
            "detail": "git status",
            "decision": "auto",
            "working_dir": "/work/project"
        });
        std::fs::write(&log_path, format!("{event_json}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let events = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-1");
        assert!(syncer.cursor().byte_offset > 0);
    }

    #[test]
    fn testReadNewEventsFiltersOutOfScope() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let in_scope = serde_json::json!({
            "id": "evt-1",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test",
            "action": "execute",
            "detail": "cmd",
            "decision": "auto",
            "working_dir": "/work/project"
        });
        let out_of_scope = serde_json::json!({
            "id": "evt-2",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test",
            "action": "execute",
            "detail": "cmd",
            "decision": "auto",
            "working_dir": "/personal/stuff"
        });
        std::fs::write(&log_path, format!("{in_scope}\n{out_of_scope}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let events = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-1");
    }

    #[test]
    fn testReadNewEventsResumesFromCursor() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let evt1 = serde_json::json!({
            "id": "evt-1",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test",
            "action": "execute",
            "detail": "cmd1",
            "decision": "auto",
            "working_dir": "/work/a"
        });
        let evt2 = serde_json::json!({
            "id": "evt-2",
            "timestamp": "2026-04-12T00:00:01Z",
            "agent": "test",
            "action": "execute",
            "detail": "cmd2",
            "decision": "auto",
            "working_dir": "/work/b"
        });
        std::fs::write(&log_path, format!("{evt1}\n{evt2}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let events = syncer.read_new_events();
        assert_eq!(events.len(), 2);

        let evt3 = serde_json::json!({
            "id": "evt-3",
            "timestamp": "2026-04-12T00:00:02Z",
            "agent": "test",
            "action": "execute",
            "detail": "cmd3",
            "decision": "auto",
            "working_dir": "/work/c"
        });
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(f, "{evt3}").unwrap();

        let events = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-3");
    }

    #[test]
    fn testReadNewEventsSkipsInvalidJson() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let valid = serde_json::json!({
            "id": "evt-1",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test",
            "action": "execute",
            "detail": "cmd",
            "decision": "auto",
            "working_dir": "/work/a"
        });
        std::fs::write(&log_path, format!("not json\n{valid}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let events = syncer.read_new_events();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn testReadNewEventsMissingFile() {
        let dir = tempfile::tempdir().unwrap();
        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let events = syncer.read_new_events();
        assert!(events.is_empty());
    }

    #[test]
    fn testCheckRotationFromActiveToRotatedFile() {
        let dir = tempfile::tempdir().unwrap();
        // Cursor on events.jsonl, but it's been renamed (rotated away).
        // A dated file now exists.
        std::fs::write(dir.path().join("events-2026-04-12.jsonl"), "old").unwrap();
        let mut syncer = make_syncer(vec![], dir.path());
        syncer.cursor.byte_offset = 500;
        assert!(syncer.check_rotation());
        assert_eq!(syncer.cursor().filename, "events-2026-04-12.jsonl");
        assert_eq!(syncer.cursor().byte_offset, 0);
    }

    #[test]
    fn testCheckRotationNoRotationWhenActiveExists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events.jsonl"), "data").unwrap();
        let mut syncer = make_syncer(vec![], dir.path());
        assert!(!syncer.check_rotation());
        assert_eq!(syncer.cursor().filename, "events.jsonl");
    }

    #[test]
    fn testCheckRotationFromDatedFileToNewActive() {
        let dir = tempfile::tempdir().unwrap();
        // Cursor on a dated file, new active file has appeared.
        std::fs::write(dir.path().join("events-2026-04-12.jsonl"), "old").unwrap();
        std::fs::write(dir.path().join("events.jsonl"), "new").unwrap();
        let mut syncer = EventSyncer::new(
            SyncCursor {
                filename: "events-2026-04-12.jsonl".to_string(),
                byte_offset: 100,
            },
            vec![],
            dir.path().to_path_buf(),
        );
        assert!(syncer.check_rotation());
        assert_eq!(syncer.cursor().filename, "events.jsonl");
        assert_eq!(syncer.cursor().byte_offset, 0);
    }

    #[test]
    fn testCheckRotationNoRotationDatedFileNoActive() {
        let dir = tempfile::tempdir().unwrap();
        // Cursor on a dated file, no new active file yet.
        std::fs::write(dir.path().join("events-2026-04-12.jsonl"), "old").unwrap();
        let mut syncer = EventSyncer::new(
            SyncCursor {
                filename: "events-2026-04-12.jsonl".to_string(),
                byte_offset: 100,
            },
            vec![],
            dir.path().to_path_buf(),
        );
        assert!(!syncer.check_rotation());
        assert_eq!(syncer.cursor().filename, "events-2026-04-12.jsonl");
        assert_eq!(syncer.cursor().byte_offset, 100);
    }

    #[test]
    fn testBuildBatch() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec![], dir.path());
        let batch = syncer.build_batch(vec![], "machine-1", vec![]);
        assert_eq!(batch.machine_id, "machine-1");
        assert!(!batch.batch_id.is_empty());
        assert!(batch.events.is_empty());
    }

    #[test]
    fn testComputeHmacSignature() {
        let sig = compute_hmac_signature(b"secret", b"hello");
        assert_eq!(sig.len(), 64);

        let sig2 = compute_hmac_signature(b"secret", b"hello");
        assert_eq!(sig, sig2);

        let sig3 = compute_hmac_signature(b"different", b"hello");
        assert_ne!(sig, sig3);
    }

    #[test]
    fn testFindOldestLogFile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events-2026-04-10.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events-2026-04-12.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("not-a-log.txt"), "").unwrap();

        let oldest = find_oldest_log_file(dir.path()).unwrap();
        assert_eq!(oldest, "events-2026-04-10.jsonl");
    }

    #[test]
    fn testFindOldestLogFileIncludesGz() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events-2026-04-08.jsonl.gz"), "").unwrap();
        std::fs::write(dir.path().join("events-2026-04-10.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("not-a-log.txt"), "").unwrap();

        let oldest = find_oldest_log_file(dir.path()).unwrap();
        assert_eq!(oldest, "events-2026-04-08.jsonl.gz");
    }

    #[test]
    fn testFindOldestLogFileEmpty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_oldest_log_file(dir.path()).is_none());
    }

    #[test]
    fn testIsLogFile() {
        assert!(is_log_file("events.jsonl"));
        assert!(is_log_file("events-2026-04-01.jsonl"));
        assert!(is_log_file("events-2026-04-01.jsonl.gz"));
        assert!(!is_log_file("not-a-log.txt"));
        assert!(!is_log_file("events.json"));
    }

    #[tokio::test]
    async fn testSyncerBuildsAndPostsSignedBatchToMockRelay() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let in_scope = serde_json::json!({
            "id": "evt-1",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test",
            "action": "execute",
            "detail": "git status",
            "decision": "auto",
            "working_dir": "/work/project"
        });
        let out_of_scope = serde_json::json!({
            "id": "evt-2",
            "timestamp": "2026-04-12T00:00:01Z",
            "agent": "test",
            "action": "execute",
            "detail": "pwd",
            "decision": "auto",
            "working_dir": "/personal/tmp"
        });
        std::fs::write(&log_path, format!("{in_scope}\n{out_of_scope}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let events = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        let batch = syncer.build_batch(events, "machine-1", vec![]);

        let (relay_url, recorded, handle) = spawn_mock_relay(200);
        let client = reqwest::Client::new();
        send_batch(
            &client,
            &format!("{relay_url}/api/v1/sync"),
            "machine-1",
            "machine-token",
            &batch,
        )
        .await
        .unwrap();
        handle.join().unwrap();

        let request = recorded.lock().unwrap().clone().expect("recorded request");
        assert_eq!(request.path, "/api/v1/sync");
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            request
                .headers
                .get("x-kyris-machine-id")
                .map(String::as_str),
            Some("machine-1")
        );
        let expected_signature = compute_hmac_signature(b"machine-token", &request.body);
        assert_eq!(
            request.headers.get("x-kyris-signature").map(String::as_str),
            Some(expected_signature.as_str())
        );

        let parsed: EventBatch = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(parsed.machine_id, "machine-1");
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].id, "evt-1");
        assert_eq!(parsed.cursor.filename, "events.jsonl");
        assert!(parsed.cursor.byte_offset > 0);
    }

    #[tokio::test]
    async fn testSendBatchReturnsRelayStatusError() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec![], dir.path());
        let batch = syncer.build_batch(vec![], "machine-1", vec![]);

        let (relay_url, _recorded, handle) = spawn_mock_relay(503);
        let client = reqwest::Client::new();
        let error = send_batch(
            &client,
            &format!("{relay_url}/api/v1/sync"),
            "machine-1",
            "machine-token",
            &batch,
        )
        .await
        .expect_err("relay should fail");
        handle.join().unwrap();

        assert!(error.contains("503"), "{error}");
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    fn spawn_mock_relay(
        status_code: u16,
    ) -> (
        String,
        Arc<Mutex<Option<RecordedRequest>>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock relay");
        let address = format!("http://{}", listener.local_addr().expect("relay addr"));
        let recorded = Arc::new(Mutex::new(None));
        let recorded_clone = Arc::clone(&recorded);

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept relay request");
            let request = read_request(&mut stream);
            *recorded_clone.lock().unwrap() = Some(request);
            write_response(&mut stream, status_code, br#"{"ok":true}"#);
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
        let _method = request_parts.next().expect("method");
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

        RecordedRequest {
            path,
            headers,
            body: buffer[header_end..header_end + content_length].to_vec(),
        }
    }

    fn write_response(stream: &mut TcpStream, status_code: u16, body: &[u8]) {
        let status_text = match status_code {
            200 => "OK",
            503 => "Service Unavailable",
            _ => "OK",
        };
        let headers = format!(
            "HTTP/1.1 {status_code} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).expect("write headers");
        stream.write_all(body).expect("write body");
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}
