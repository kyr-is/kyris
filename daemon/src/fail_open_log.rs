// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

pub use kyris_core::fail_open_log::record;

pub fn read() -> (Vec<Box<serde_json::value::RawValue>>, usize) {
    let path = kyris_core::fail_open_log::log_path();
    if !path.exists() {
        return (Vec::new(), 0);
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read fail-open log");
            return (Vec::new(), 0);
        }
    };

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let count = lines.len();
    let events = lines
        .into_iter()
        .filter_map(|line| serde_json::value::RawValue::from_string(line.to_string()).ok())
        .collect();
    (events, count)
}

pub fn drain(lines_consumed: usize) {
    let path = kyris_core::fail_open_log::log_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read fail-open log for drain");
            return;
        }
    };

    let remaining: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .skip(lines_consumed)
        .collect();

    let tmp = path.with_extension("jsonl.tmp");
    let new_content = if remaining.is_empty() {
        String::new()
    } else {
        let mut s = remaining.join("\n");
        s.push('\n');
        s
    };

    if let Err(e) = std::fs::write(&tmp, &new_content) {
        tracing::warn!(error = %e, "failed to write fail-open tmp");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        tracing::warn!(error = %e, "failed to rename fail-open tmp");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    // fail_open_log::log_path() reads $XDG_STATE_HOME (or $HOME) at call
    // time. These tests set both — XDG_STATE_HOME to point at the tempdir
    // and HOME as a defense-in-depth fallback — and serialize via the
    // mutex so they don't race each other.
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    fn fail_open_log_path_under(base: &std::path::Path) -> std::path::PathBuf {
        base.join("kyris").join("fail-open.jsonl")
    }

    fn write_event(
        path: &std::path::Path,
        action: &str,
        detail: &str,
        mcp_server: &str,
        working_dir: &str,
    ) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let id = uuid::Uuid::now_v7();
        let line = serde_json::json!({
            "id": id.to_string(),
            "timestamp": "2026-04-27T00:00:00Z",
            "agent": "unknown",
            "action": action,
            "detail": detail,
            "decision": "auto",
            "working_dir": working_dir,
            "mcp_server": mcp_server,
            "attribution_method": "unknown",
            "mode": "log",
            "event_kind": "action",
            "coverage_state": "unknown",
            "source": "fail-open",
        });
        writeln!(file, "{line}").unwrap();
    }

    #[test]
    fn testReadReturnsEventsAndCount() {
        let _lock = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log_path = fail_open_log_path_under(dir.path());
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();

        write_event(&log_path, "execute", "ls", "", "/work/a");
        write_event(&log_path, "call", "write_file", "mcp-server", "/work/b");

        unsafe {
            std::env::set_var("HOME", dir.path().to_str().unwrap());
            std::env::set_var("XDG_STATE_HOME", dir.path().to_str().unwrap());
        }

        let (events, count) = read();
        assert_eq!(events.len(), 2);
        assert_eq!(count, 2);

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(!content.trim().is_empty(), "read() should not truncate");
    }

    #[test]
    fn testDrainAllRemovesAllLines() {
        let _lock = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log_path = fail_open_log_path_under(dir.path());
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();

        write_event(&log_path, "execute", "ls", "", "/work/a");

        unsafe {
            std::env::set_var("HOME", dir.path().to_str().unwrap());
            std::env::set_var("XDG_STATE_HOME", dir.path().to_str().unwrap());
        }
        drain(1);

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn testDrainPreservesNewLines() {
        let _lock = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let log_path = fail_open_log_path_under(dir.path());
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();

        write_event(&log_path, "execute", "ls", "", "/work/a");
        write_event(&log_path, "call", "write_file", "mcp", "/work/b");
        write_event(&log_path, "read", "cat", "mcp", "/work/c");

        unsafe {
            std::env::set_var("HOME", dir.path().to_str().unwrap());
            std::env::set_var("XDG_STATE_HOME", dir.path().to_str().unwrap());
        }
        drain(2);

        let (events, count) = read();
        assert_eq!(count, 1);
        assert_eq!(events.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(events[0].get()).unwrap();
        assert_eq!(parsed["detail"], "cat");
    }

    #[test]
    fn testReadEmptyFile() {
        let _lock = HOME_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(fail_open_log_path_under(dir.path()).parent().unwrap()).unwrap();
        unsafe {
            std::env::set_var("HOME", dir.path().to_str().unwrap());
            std::env::set_var("XDG_STATE_HOME", dir.path().to_str().unwrap());
        }

        let (events, count) = read();
        assert!(events.is_empty());
        assert_eq!(count, 0);
    }
}
