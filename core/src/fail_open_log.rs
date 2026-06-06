// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::io::Write;
use std::path::{Path, PathBuf};

#[must_use]
pub fn log_path() -> PathBuf {
    crate::paths::fail_open_path()
}

pub fn record(action: &str, detail: &str, mcp_server: &str, working_dir: Option<&str>) {
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    record_to(&path, action, detail, mcp_server, working_dir);
}

fn record_to(path: &Path, action: &str, detail: &str, mcp_server: &str, working_dir: Option<&str>) {
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        eprintln!("[kyris] failed to open fail-open log at {}", path.display());
        return;
    };

    let id = uuid::Uuid::now_v7();
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let wd = working_dir.unwrap_or("");

    let line = serde_json::json!({
        "id": id.to_string(),
        "timestamp": ts,
        "agent": "unknown",
        "action": action,
        "detail": detail,
        "decision": "auto",
        "working_dir": wd,
        "mcp_server": mcp_server,
        "attribution_method": "unknown",
        "mode": "log",
        "event_kind": "action",
        "coverage_state": "unknown",
        "source": "fail-open",
    });

    if let Err(e) = writeln!(file, "{line}") {
        eprintln!("[kyris] failed to write fail-open event: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRecordWritesJsonlEvent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fail-open.jsonl");

        record_to(
            &path,
            "call",
            "read_file",
            "github-mcp",
            Some("/tmp/project"),
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["action"], "call");
        assert_eq!(parsed["detail"], "read_file");
        assert_eq!(parsed["mcp_server"], "github-mcp");
        assert_eq!(parsed["source"], "fail-open");
        assert_eq!(parsed["coverage_state"], "unknown");
        assert_eq!(parsed["working_dir"], "/tmp/project");
    }

    #[test]
    fn testRecordWithNoWorkingDir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fail-open.jsonl");

        record_to(&path, "call", "write_file", "mcp-server", None);

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["working_dir"], "");
    }
}
