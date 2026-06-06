// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::io::{BufRead, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use kyris_core::event::Event;
use kyris_core::sync::{SyncCursor, TimelineBatch};
use kyris_core::timeline::TimelineEntry;

use super::scope::SyncScope;

pub struct EventSyncer {
    cursor: SyncCursor,
    scope: SyncScope,
    log_dir: PathBuf,
    /// Inode of `events.jsonl` the last time we opened it (Unix only).
    /// None when cursor is on a dated file, or before first open, or on
    /// non-Unix. Used by `check_rotation` to detect that `events.jsonl`
    /// has been replaced by a new file even though the name still exists.
    active_file_inode: Option<u64>,
}

impl EventSyncer {
    pub fn new(cursor: SyncCursor, scope: Vec<String>, log_dir: PathBuf) -> Self {
        let active_file_inode = if cursor.filename == "events.jsonl" {
            file_inode(&log_dir.join("events.jsonl"))
        } else {
            None
        };
        Self {
            cursor,
            scope: SyncScope::new(scope),
            log_dir,
            active_file_inode,
        }
    }

    pub fn cursor(&self) -> &SyncCursor {
        &self.cursor
    }

    pub fn advance_cursor(&mut self, filename: String, byte_offset: u64) {
        if filename == "events.jsonl" && self.cursor.filename != "events.jsonl" {
            self.active_file_inode = file_inode(&self.log_dir.join("events.jsonl"));
        } else if filename != "events.jsonl" {
            self.active_file_inode = None;
        }
        self.cursor.filename = filename;
        self.cursor.byte_offset = byte_offset;
    }

    pub fn is_in_scope(&self, working_dir: Option<&str>) -> bool {
        self.scope.is_in_scope(working_dir)
    }

    pub fn read_new_events(&mut self) -> (Vec<Box<serde_json::value::RawValue>>, u64) {
        let file_path = self.log_dir.join(&self.cursor.filename);
        let mut raw_events = Vec::new();

        if !file_path.exists() {
            // File is absent. check_rotation() should have handled this on
            // the previous tick; return empty so the caller retries next tick.
            return (raw_events, self.cursor.byte_offset);
        }

        let Ok(file) = std::fs::File::open(&file_path) else {
            return (raw_events, self.cursor.byte_offset);
        };

        let mut reader = std::io::BufReader::new(file);
        if reader
            .seek(SeekFrom::Start(self.cursor.byte_offset))
            .is_err()
        {
            return (raw_events, self.cursor.byte_offset);
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
                    if let Ok(mut event) = serde_json::from_str::<Event>(trimmed)
                        && self.is_in_scope(event.working_dir.as_deref())
                    {
                        kyris_core::coverage::derive_for_event(&mut event);
                        let raw = patch_coverage_state(trimmed, event.coverage_state);
                        raw_events.push(raw);
                    }
                }
            }
        }

        let new_offset = reader.stream_position().unwrap_or(self.cursor.byte_offset);
        (raw_events, new_offset)
    }

    pub fn commit_read(&mut self, byte_offset: u64) {
        self.cursor.byte_offset = byte_offset;
    }

    /// Detect log rotation and advance the cursor accordingly.
    ///
    /// **Normal rotation** (`events.jsonl` renamed, new `events.jsonl` created):
    /// - Detected via inode change: same path, different inode.
    /// - Action: point cursor at the renamed file (same byte offset) so the
    ///   next `read_new_events` drains the tail before switching.
    ///
    /// **Brief absence** (`events.jsonl` temporarily missing):
    /// - Use stored inode to locate the renamed file, then drain it.
    ///
    /// **Daemon-restart fallback** (inode not stored, file smaller than cursor):
    /// - If `events.jsonl` exists but is shorter than our cursor position,
    ///   it is a new file from a rotation that happened while the daemon was
    ///   down. Point at the newest dated file to drain first.
    ///
    /// **Dated file → active**: once the cursor is on a dated file and
    /// `events.jsonl` reappears, switch back to it at offset 0.
    ///
    /// Returns `true` if the cursor was updated.
    pub fn check_rotation(&mut self) -> bool {
        let active_path = self.log_dir.join("events.jsonl");
        let active_exists = active_path.exists();

        if self.cursor.filename == "events.jsonl" {
            if active_exists {
                let current_inode = file_inode(&active_path);

                match (self.active_file_inode, current_inode) {
                    (Some(known), Some(current)) if known != current => {
                        // Inode changed: events.jsonl was atomically replaced.
                        // Find the now-renamed file (it carries the old inode)
                        // and set the cursor there so we drain its tail first.
                        let renamed = find_file_by_inode(&self.log_dir, known)
                            .or_else(|| find_newest_dated_log_file(&self.log_dir));
                        if let Some(rotated) = renamed {
                            // Keep byte_offset: we resume from where we left
                            // off in the old file (now renamed).
                            self.cursor.filename = rotated;
                            self.active_file_inode = None;
                        } else {
                            // Old file already gone (very fast prune after rotate).
                            // Skip its tail and start the new file from 0.
                            self.cursor.byte_offset = 0;
                            self.active_file_inode = current_inode;
                        }
                        return true;
                    }
                    (None, Some(current)) => {
                        // First time we've seen this file (startup or inode
                        // tracking not available).  If the active file is
                        // shorter than our cursor the daemon was down during a
                        // rotation — find the old file by recency.
                        let size = std::fs::metadata(&active_path).map_or(0, |m| m.len());
                        if size < self.cursor.byte_offset {
                            let renamed = find_newest_dated_log_file(&self.log_dir);
                            if let Some(rotated) = renamed {
                                self.cursor.filename = rotated;
                                self.active_file_inode = None;
                                return true;
                            }
                            // No dated file: just reset to the new file's start.
                            self.cursor.byte_offset = 0;
                            self.active_file_inode = Some(current);
                            return true;
                        }
                        // File is at least as large as our cursor: treat as
                        // the same file and record the inode for future checks.
                        self.active_file_inode = Some(current);
                        return false;
                    }
                    _ => {
                        // Inode unchanged or not available on this platform.
                        return false;
                    }
                }
            }
            // events.jsonl is absent (brief gap between rename and creation
            // of new file, or daemon started before agentpactd created it).
            let renamed = self
                .active_file_inode
                .and_then(|inode| find_file_by_inode(&self.log_dir, inode))
                .or_else(|| find_newest_dated_log_file(&self.log_dir));
            if let Some(rotated) = renamed {
                self.cursor.filename = rotated;
                self.active_file_inode = None;
                return true;
            }
            return false;
        }

        // Cursor is on a dated rotated file. Switch back to events.jsonl
        // once it reappears (we've already drained the dated file).
        if active_exists {
            self.cursor.filename = "events.jsonl".to_string();
            self.cursor.byte_offset = 0;
            self.active_file_inode = file_inode(&active_path);
            return true;
        }

        false
    }

    /// Wrap already-joined timeline entries into a sync batch. kyrisd is the
    /// join owner, so the wire carries finished [`TimelineEntry`] rows — the
    /// relay stores them and only coordinates across machines.
    pub fn build_batch(&self, entries: Vec<TimelineEntry>, machine_id: &str) -> TimelineBatch {
        TimelineBatch {
            machine_id: machine_id.to_string(),
            batch_id: uuid::Uuid::now_v7().to_string(),
            entries,
            cursor: self.cursor.clone(),
        }
    }
}

fn patch_coverage_state(
    raw_line: &str,
    coverage_state: kyris_core::event::CoverageState,
) -> Box<serde_json::value::RawValue> {
    let mut map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(raw_line).unwrap_or_default();
    map.insert(
        "coverage_state".to_string(),
        serde_json::Value::String(coverage_state.to_string()),
    );
    serde_json::value::RawValue::from_string(serde_json::to_string(&map).unwrap_or_default())
        .unwrap_or_else(|_| {
            serde_json::value::RawValue::from_string(raw_line.to_string())
                .expect("original line was valid JSON")
        })
}

fn is_log_file(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
        || name.ends_with(".jsonl.gz")
}

/// Inode of a file on Unix; `None` on non-Unix or if the file does not exist.
fn file_inode(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Find a dated log file whose inode matches `target`. Returns the filename
/// (not full path). Used to locate events.jsonl after it has been renamed.
fn find_file_by_inode(dir: &Path, target_inode: u64) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::read_dir(dir)
            .ok()?
            .filter_map(Result::ok)
            .find_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if !is_log_file(&name) || name == "events.jsonl" {
                    return None;
                }
                let meta = e.metadata().ok()?;
                (meta.ino() == target_inode).then_some(name)
            })
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, target_inode);
        None
    }
}

/// The alphabetically last (most recently dated) log file that is NOT
/// `events.jsonl`. Used when we know a rotation just happened but cannot
/// identify the renamed file by inode (e.g. after a daemon restart).
fn find_newest_dated_log_file(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut log_files: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if is_log_file(&name) && name != "events.jsonl" {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    log_files.sort();
    log_files.into_iter().next_back()
}

/// The alphabetically first (oldest) log file in the directory, including
/// `events.jsonl`. Used only for the "cursor file deleted after max age"
/// recovery path — different from rotation recovery.
#[cfg(test)]
fn find_oldest_log_file(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut log_files: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if is_log_file(&name) { Some(name) } else { None }
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

/// Why a sync batch POST failed. The sync loop classifies on this so it can tell
/// an **auth rejection** (credential invalid → enrollment error, pause sync)
/// from a **transient** relay/network problem (relay unavailable → keep
/// accumulating + retry). See [`super::daemon_sync`].
#[derive(Debug)]
pub enum SendError {
    /// Couldn't reach the relay or serialize the batch (network, DNS, timeout,
    /// TLS, serialization). Always transient.
    Transport(String),
    /// The relay responded with a non-2xx status. The code lets the loop
    /// distinguish 401 (enrollment) from 5xx (relay unavailable) from other.
    Status(u16),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "relay request failed: {e}"),
            Self::Status(code) => write!(f, "relay returned HTTP {code}"),
        }
    }
}

pub async fn send_batch(
    client: &reqwest::Client,
    relay_url: &str,
    machine_id: &str,
    machine_token: &str,
    batch: &TimelineBatch,
) -> Result<(), SendError> {
    let body = serde_json::to_vec(batch)
        .map_err(|e| SendError::Transport(format!("serialize batch: {e}")))?;
    let signature = compute_hmac_signature(machine_token.as_bytes(), &body);

    let response = client
        .post(relay_url)
        .header("content-type", "application/json")
        .header("x-kyris-machine-id", machine_id)
        .header("x-kyris-signature", &signature)
        .body(body)
        .send()
        .await
        .map_err(|e| SendError::Transport(format!("relay POST failed: {e}")))?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(SendError::Status(status.as_u16()))
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

    fn parse_event(raw: &serde_json::value::RawValue) -> Event {
        serde_json::from_str(raw.get()).unwrap()
    }

    #[test]
    fn testPatchCoverageStatePreservesFieldsAndOrder() {
        use kyris_core::event::CoverageState;
        let raw =
            r#"{"id":"evt-1","agent":"claude","unknown_field":"kept","coverage_state":"unknown"}"#;
        let patched = patch_coverage_state(raw, CoverageState::Enforced);
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(patched.get()).unwrap();
        assert_eq!(
            map.get("coverage_state").and_then(|v| v.as_str()),
            Some("enforced")
        );
        assert_eq!(
            map.get("unknown_field").and_then(|v| v.as_str()),
            Some("kept")
        );
        let keys: Vec<&String> = map.keys().collect();
        assert_eq!(keys[0], "id");
        assert_eq!(keys[1], "agent");
        assert_eq!(keys[2], "unknown_field");
    }

    #[test]
    fn testReadNewEventsPreservesUnknownFields() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let json = r#"{"id":"evt-1","timestamp":"2026-04-12T00:00:00Z","agent":"test","action":"execute","detail":"cmd","decision":"auto","working_dir":"/work/a","future_field":"hello"}"#;
        std::fs::write(&log_path, format!("{json}\n")).unwrap();
        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let (events, _) = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        let v: serde_json::Value = serde_json::from_str(events[0].get()).unwrap();
        assert_eq!(
            v.get("future_field").and_then(|v| v.as_str()),
            Some("hello")
        );
    }

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
    fn testEmptyScopeSyncsGovernedDir() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec![], dir.path());
        // Default-on: a governed, non-private dir syncs with no explicit scope.
        assert!(syncer.is_in_scope(Some("/work/project")));
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
        let (events, new_offset) = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(parse_event(&events[0]).id, "evt-1");
        assert!(new_offset > 0);
        syncer.commit_read(new_offset);
        assert_eq!(syncer.cursor().byte_offset, new_offset);
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
        let (events, _) = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(parse_event(&events[0]).id, "evt-1");
    }

    #[test]
    fn testReadNewEventsResumesFromCursor() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let evt1 = serde_json::json!({
            "id": "evt-1", "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test", "action": "execute", "detail": "cmd1",
            "decision": "auto", "working_dir": "/work/a"
        });
        let evt2 = serde_json::json!({
            "id": "evt-2", "timestamp": "2026-04-12T00:00:01Z",
            "agent": "test", "action": "execute", "detail": "cmd2",
            "decision": "auto", "working_dir": "/work/b"
        });
        std::fs::write(&log_path, format!("{evt1}\n{evt2}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let (events, offset) = syncer.read_new_events();
        assert_eq!(events.len(), 2);
        syncer.commit_read(offset);

        let evt3 = serde_json::json!({
            "id": "evt-3", "timestamp": "2026-04-12T00:00:02Z",
            "agent": "test", "action": "execute", "detail": "cmd3",
            "decision": "auto", "working_dir": "/work/c"
        });
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(f, "{evt3}").unwrap();

        let (events, _) = syncer.read_new_events();
        assert_eq!(events.len(), 1);
        assert_eq!(parse_event(&events[0]).id, "evt-3");
    }

    #[test]
    fn testReadNewEventsSkipsInvalidJson() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let valid = serde_json::json!({
            "id": "evt-1", "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test", "action": "execute", "detail": "cmd",
            "decision": "auto", "working_dir": "/work/a"
        });
        std::fs::write(&log_path, format!("not json\n{valid}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let (events, _) = syncer.read_new_events();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn testReadNewEventsMissingFile() {
        let dir = tempfile::tempdir().unwrap();
        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let (events, _) = syncer.read_new_events();
        assert!(events.is_empty());
    }

    // ── Rotation tests ────────────────────────────────────────────────────

    /// Normal rotation: events.jsonl is renamed and a new events.jsonl is
    /// created atomically. The inode of the active path changes.
    /// Expected: cursor moves to the renamed file at the SAME byte offset
    /// (to drain the tail), not reset to 0.
    #[cfg(unix)]
    #[test]
    fn testCheckRotationDetectsInodeChangeAndPreservesOffset() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let active_path = dir.path().join("events.jsonl");

        // Write some content to the original events.jsonl.
        std::fs::write(&active_path, "line1\nline2\nline3\n").unwrap();
        let original_inode = std::fs::metadata(&active_path).unwrap().ino();

        let mut syncer = make_syncer(vec![], dir.path());
        // Simulate cursor at offset 6 (after reading "line1\n").
        syncer.cursor.byte_offset = 6;
        // new() records the inode at construction time.
        assert_eq!(syncer.active_file_inode, Some(original_inode));

        // Simulate rotation: rename the original to a dated file, create new.
        let dated = dir.path().join("events-2026-05-15.jsonl");
        std::fs::rename(&active_path, &dated).unwrap();
        std::fs::write(&active_path, "new-line1\n").unwrap();

        // check_rotation should detect the inode change.
        let rotated = syncer.check_rotation();
        assert!(rotated, "should detect rotation via inode change");
        assert_eq!(
            syncer.cursor().filename,
            "events-2026-05-15.jsonl",
            "cursor should point at the renamed file"
        );
        assert_eq!(
            syncer.cursor().byte_offset,
            6,
            "byte offset preserved to drain remaining tail"
        );
        assert!(
            syncer.active_file_inode.is_none(),
            "inode tracking cleared while on dated file"
        );

        // read_new_events drains the tail of the renamed file.
        // The original file had raw non-JSON lines so events.len() == 0 here;
        // we verify instead that the offset advances to EOF.
        let file_len = std::fs::metadata(&dated).unwrap().len();
        let (events, new_offset) = syncer.read_new_events();
        assert_eq!(events.len(), 0); // raw lines, not valid JSON events
        assert_eq!(
            new_offset, file_len,
            "offset should advance to EOF of renamed file"
        );
        syncer.commit_read(new_offset);

        // Next tick: dated file is at EOF, active file reappears.
        let rotated2 = syncer.check_rotation();
        assert!(rotated2, "should switch back to events.jsonl");
        assert_eq!(syncer.cursor().filename, "events.jsonl");
        assert_eq!(syncer.cursor().byte_offset, 0);
        assert!(syncer.active_file_inode.is_some());
    }

    /// Full drain cycle with real JSON events: two events written before
    /// rotation, one event written after. All three must be read in order,
    /// none skipped, none duplicated.
    #[cfg(unix)]
    #[test]
    fn testRotationDrainsCycleFully() {
        let dir = tempfile::tempdir().unwrap();
        let active_path = dir.path().join("events.jsonl");

        let e1 = r#"{"id":"e1","timestamp":"2026-05-15T00:00:00Z","agent":"test","action":"execute","detail":"cmd","decision":"auto","working_dir":"/work/a"}"#;
        let e2 = r#"{"id":"e2","timestamp":"2026-05-15T00:00:01Z","agent":"test","action":"execute","detail":"cmd","decision":"auto","working_dir":"/work/a"}"#;
        let e3 = r#"{"id":"e3","timestamp":"2026-05-15T00:00:02Z","agent":"test","action":"execute","detail":"cmd","decision":"auto","working_dir":"/work/a"}"#;

        std::fs::write(&active_path, format!("{e1}\n{e2}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());

        // Read e1 and e2 from the active file, commit.
        let (events, offset) = syncer.read_new_events();
        assert_eq!(events.len(), 2);
        assert_eq!(parse_event(&events[0]).id, "e1");
        assert_eq!(parse_event(&events[1]).id, "e2");
        syncer.commit_read(offset);

        // Simulate rotation: rename active → dated, create new active with e3.
        let dated = dir.path().join("events-2026-05-15.jsonl");
        std::fs::rename(&active_path, &dated).unwrap();
        std::fs::write(&active_path, format!("{e3}\n")).unwrap();

        // check_rotation detects inode change, cursor moves to dated file.
        let rotated = syncer.check_rotation();
        assert!(rotated);
        assert_eq!(syncer.cursor().filename, "events-2026-05-15.jsonl");

        // Drain dated file from current offset (should be EOF — no more events in tail).
        let (tail_events, tail_offset) = syncer.read_new_events();
        assert!(tail_events.is_empty(), "tail of dated file already drained");
        syncer.commit_read(tail_offset);

        // check_rotation switches back to new events.jsonl.
        let switched = syncer.check_rotation();
        assert!(switched);
        assert_eq!(syncer.cursor().filename, "events.jsonl");
        assert_eq!(syncer.cursor().byte_offset, 0);

        // Read e3 from the new active file.
        let (new_events, new_offset) = syncer.read_new_events();
        assert_eq!(new_events.len(), 1);
        assert_eq!(parse_event(&new_events[0]).id, "e3");
        syncer.commit_read(new_offset);

        // No more events.
        let (more, _) = syncer.read_new_events();
        assert!(more.is_empty());
    }

    /// Absence case: events.jsonl is briefly absent (race between rename and
    /// creation of new active file). Cursor should move to the newest dated
    /// file at the SAME offset, not reset to 0 or jump to oldest file.
    #[cfg(unix)]
    #[test]
    fn testCheckRotationHandlesBriefAbsence() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().unwrap();
        let active_path = dir.path().join("events.jsonl");

        std::fs::write(&active_path, "a\nb\nc\n").unwrap();
        let original_inode = std::fs::metadata(&active_path).unwrap().ino();

        let mut syncer = make_syncer(vec![], dir.path());
        syncer.cursor.byte_offset = 4;
        assert_eq!(syncer.active_file_inode, Some(original_inode));

        // Create an older dated file that should NOT be selected.
        std::fs::write(dir.path().join("events-2026-04-01.jsonl"), "old").unwrap();
        // Rename events.jsonl → newest dated; no new events.jsonl yet.
        let newest = dir.path().join("events-2026-05-15.jsonl");
        std::fs::rename(&active_path, &newest).unwrap();

        let rotated = syncer.check_rotation();
        assert!(rotated, "should detect absent events.jsonl");
        assert_eq!(
            syncer.cursor().filename,
            "events-2026-05-15.jsonl",
            "should pick the newest dated file (the renamed one), not the oldest"
        );
        assert_eq!(
            syncer.cursor().byte_offset,
            4,
            "offset preserved for draining"
        );
    }

    /// Daemon-restart fallback: inode not stored, events.jsonl exists but is
    /// shorter than cursor → rotation happened during downtime.
    #[test]
    fn testCheckRotationRestartFallbackSizeShorterThanCursor() {
        let dir = tempfile::tempdir().unwrap();

        // Simulate post-restart: cursor at 1000 but new events.jsonl is tiny.
        std::fs::write(dir.path().join("events.jsonl"), "new\n").unwrap();
        std::fs::write(dir.path().join("events-2026-05-14.jsonl"), "old").unwrap();

        let mut syncer = EventSyncer::new(
            SyncCursor {
                filename: "events.jsonl".to_string(),
                byte_offset: 1000,
            },
            vec![],
            dir.path().to_path_buf(),
        );
        // Manually clear inode to simulate non-Unix or missing inode at startup.
        syncer.active_file_inode = None;

        let rotated = syncer.check_rotation();
        assert!(rotated, "should detect rotation via size check");
        assert_eq!(syncer.cursor().filename, "events-2026-05-14.jsonl");
        assert_eq!(
            syncer.cursor().byte_offset,
            1000,
            "offset preserved for draining"
        );
    }

    /// When events.jsonl is absent but no dated file exists, do nothing.
    #[test]
    fn testCheckRotationNoActionWhenNoFilesExist() {
        let dir = tempfile::tempdir().unwrap();
        let mut syncer = make_syncer(vec![], dir.path());
        let rotated = syncer.check_rotation();
        assert!(!rotated);
        assert_eq!(syncer.cursor().filename, "events.jsonl");
    }

    /// Cursor on dated file, events.jsonl reappears → switch to it.
    #[test]
    fn testCheckRotationFromDatedFileToNewActive() {
        let dir = tempfile::tempdir().unwrap();
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

    /// Cursor on dated file, no events.jsonl yet → stay put.
    #[test]
    fn testCheckRotationNoRotationDatedFileNoActive() {
        let dir = tempfile::tempdir().unwrap();
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

    /// events.jsonl present, inode unchanged → no rotation.
    #[test]
    fn testCheckRotationNoRotationWhenActiveExists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events.jsonl"), "data").unwrap();
        let mut syncer = make_syncer(vec![], dir.path());
        assert!(!syncer.check_rotation());
        assert_eq!(syncer.cursor().filename, "events.jsonl");
    }

    // ── Existing helper tests ─────────────────────────────────────────────

    fn sample_entry(id: &str) -> TimelineEntry {
        TimelineEntry {
            id: id.to_string(),
            timestamp: "2026-04-12T00:00:00Z".to_string(),
            trace_id: None,
            agent: Some("test".to_string()),
            action: "execute".to_string(),
            detail: Some("git status".to_string()),
            decision: Some("auto".to_string()),
            coverage_state: "observed".to_string(),
            source: "agent".to_string(),
            working_dir: Some("/work/project".to_string()),
            git_remote_origin: None,
            session: None,
            mode: Some("enforce".to_string()),
            rule_kind: None,
            rule_id: None,
            sync_state: None,
            hostname: None,
            provider: None,
            model: None,
            tokens_in: None,
            tokens_out: None,
            tokens_cache_create: None,
            tokens_cache_read: None,
            cost_usd: None,
            latency_ms: None,
            status: None,
            metering: None,
            plan_status: None,
            mcp_server: None,
            mcp_tool: None,
            segments: Vec::new(),
        }
    }

    #[test]
    fn testBuildBatch() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec![], dir.path());
        let batch = syncer.build_batch(vec![], "machine-1");
        assert_eq!(batch.machine_id, "machine-1");
        assert!(!batch.batch_id.is_empty());
        assert!(batch.entries.is_empty());
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
    fn testFindNewestDatedLogFile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events-2026-04-10.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events-2026-04-12.jsonl"), "").unwrap();
        // events.jsonl should be excluded from "newest dated" results.
        std::fs::write(dir.path().join("events.jsonl"), "").unwrap();

        let newest = find_newest_dated_log_file(dir.path()).unwrap();
        assert_eq!(newest, "events-2026-04-12.jsonl");
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

    #[test]
    fn testUncommittedReadRetriesSameEvents() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let evt = serde_json::json!({
            "id": "evt-retry", "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test", "action": "execute", "detail": "cmd",
            "decision": "auto", "working_dir": "/work/a"
        });
        std::fs::write(&log_path, format!("{evt}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let (events, _new_offset) = syncer.read_new_events();
        assert_eq!(events.len(), 1);

        let (events_retry, offset) = syncer.read_new_events();
        assert_eq!(events_retry.len(), 1, "same events returned on retry");
        assert_eq!(parse_event(&events_retry[0]).id, "evt-retry");

        syncer.commit_read(offset);
        let (events_after, _) = syncer.read_new_events();
        assert!(events_after.is_empty());
    }

    #[tokio::test]
    async fn testSyncerBuildsAndPostsSignedBatchToMockRelay() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");

        let in_scope = serde_json::json!({
            "id": "evt-1", "timestamp": "2026-04-12T00:00:00Z",
            "agent": "test", "action": "execute", "detail": "git status",
            "decision": "auto", "working_dir": "/work/project"
        });
        let out_of_scope = serde_json::json!({
            "id": "evt-2", "timestamp": "2026-04-12T00:00:01Z",
            "agent": "test", "action": "execute", "detail": "pwd",
            "decision": "auto", "working_dir": "/personal/tmp"
        });
        std::fs::write(&log_path, format!("{in_scope}\n{out_of_scope}\n")).unwrap();

        let mut syncer = make_syncer(vec!["/work/*".to_string()], dir.path());
        let (events, offset) = syncer.read_new_events();
        syncer.commit_read(offset);
        assert_eq!(events.len(), 1);
        // kyrisd ships joined entries, not raw events; build one from the read.
        let batch = syncer.build_batch(vec![sample_entry("evt-1")], "machine-1");

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
        let expected_signature = compute_hmac_signature(b"machine-token", &request.body);
        assert_eq!(
            request.headers.get("x-kyris-signature").map(String::as_str),
            Some(expected_signature.as_str())
        );
        let parsed: TimelineBatch = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(parsed.machine_id, "machine-1");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].id, "evt-1");
        assert_eq!(parsed.cursor.filename, "events.jsonl");
        assert!(parsed.cursor.byte_offset > 0);
    }

    #[tokio::test]
    async fn testSendBatchReturnsRelayStatusError() {
        let dir = tempfile::tempdir().unwrap();
        let syncer = make_syncer(vec![], dir.path());
        let batch = syncer.build_batch(vec![], "machine-1");

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

        assert!(
            matches!(error, SendError::Status(503)),
            "expected Status(503), got {error}"
        );
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
