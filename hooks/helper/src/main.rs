// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Minimal shell hook helper (`kyris-hook`). Translates shell hook events
//! (check, respond, send) into `AgentPact` UDS protocol calls. Intentionally
//! tiny — stdlib + serde only, no Tokio, no `DuckDB` — to keep cold start
//! under 5ms and binary under 1MB.
//!
//! Native agent hooks (Claude Code `PreToolUse`, Codex CLI `PreToolUse`,
//! Gemini CLI `BeforeTool`) use `kyris hook check` in the CLI binary — that
//! binary has tokio + reqwest and can run the hold-poll-resolve pattern for
//! `PACT_ASK` approval delegation.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

use std::io::{Read, Write};
use std::process::ExitCode;

#[derive(Debug, PartialEq, Eq)]
enum CheckResponse {
    Allow {
        inform_reason: Option<String>,
    },
    Deny {
        reason: Option<String>,
    },
    Ask {
        approval_id: String,
        approval_token: String,
        breaker_count: Option<String>,
    },
    Invalid(String),
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: kyris-hook <check|respond|send> [args...]");
        return ExitCode::from(1);
    }

    match args[1].as_str() {
        "check" => cmd_check(&args[2..]),
        "respond" => cmd_respond(&args[2..]),
        "send" => cmd_send(&args[2..]),
        other => {
            eprintln!("Unknown command: {other}");
            ExitCode::from(1)
        }
    }
}

/// Hard ceiling (bytes) on a command we will even send to agentpactd. Mirrors
/// `agentpact_types::MAX_COMMAND_LENGTH_CEILING`; kept as a literal because
/// this helper is intentionally stdlib-only and takes no agentpact dependency.
/// A command longer than this cannot fit the daemon's socket message limit, so
/// we deny it locally rather than risk a transport error that fails open.
const MAX_COMMAND_LENGTH_CEILING: usize = 10_240;

fn cmd_check(args: &[String]) -> ExitCode {
    let (command, cwd, socket_path) = parse_check_args(args);

    if command.len() > MAX_COMMAND_LENGTH_CEILING {
        eprintln!(
            "[agentpact] denied: command exceeds the {MAX_COMMAND_LENGTH_CEILING}-byte governance ceiling (length {}); split it into smaller commands",
            command.len()
        );
        return ExitCode::from(1);
    }

    if let Err(msg) = check_protocol_version(&socket_path) {
        eprintln!("[agentpact] {msg}");
        log_error(&msg);
        return ExitCode::from(10);
    }

    let exec_token = std::env::var("AGENTPACT_EXEC_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());

    let mut request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.request",
        "action": "execute",
        "detail": command,
        "context": {
            "working_dir": cwd,
        }
    });
    if let Some(ref token) = exec_token {
        request["exec_token"] = serde_json::Value::String(token.clone());
    }

    let Ok(response) = send_request(&socket_path, &request) else {
        if daemon_state_allows(&socket_path) {
            write_fail_open_event("execute", &command, &cwd);
            return ExitCode::from(11);
        }
        return ExitCode::from(10);
    };

    match parse_check_response(&response) {
        CheckResponse::Allow { inform_reason } => {
            if let Some(reason) = inform_reason {
                eprintln!("[agentpact] {reason}");
            }
            ExitCode::from(0)
        }
        CheckResponse::Deny { reason } => {
            if let Some(reason) = reason {
                eprintln!("[agentpact] denied: {reason}");
            }
            ExitCode::from(1)
        }
        CheckResponse::Ask {
            approval_id,
            approval_token,
            breaker_count,
        } => {
            if let Some(count) = breaker_count {
                // Circuit breaker is a session-level gate ("too many commands
                // without human input"), not a per-command split — so it keeps
                // its dedicated whole-command prompt. The shell reads these
                // fields to drive that prompt.
                print!("{approval_id}\t{approval_token}\t{count}");
                ExitCode::from(3)
            } else {
                // Normal ask. This real request minted a whole-command approval
                // token; the shell hands off to `kyris hook resolve-shell`,
                // which re-derives the compound split and prompts per segment,
                // minting its own per-segment tokens. Void this whole-command
                // token so it does not linger as a stale `kyris pending` entry.
                void_token(&socket_path, &approval_token);
                ExitCode::from(2)
            }
        }
        CheckResponse::Invalid(reason) => {
            eprintln!("[agentpact] {reason}");
            log_error(&reason);
            ExitCode::from(1)
        }
    }
}

fn parse_check_response(response: &serde_json::Value) -> CheckResponse {
    match response.get("code").and_then(|value| value.as_str()) {
        Some("PACT_OK") => CheckResponse::Allow {
            inform_reason: if response.get("decision").and_then(|value| value.as_str())
                == Some("inform")
            {
                response
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            } else {
                None
            },
        },
        Some("PACT_DENIED") => CheckResponse::Deny {
            reason: response
                .get("reason")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        },
        Some("PACT_ASK") => {
            let approval_id = response
                .get("approval_id")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let approval_token = response
                .get("approval_token")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let Some(approval_id) = approval_id else {
                return CheckResponse::Invalid(
                    "invalid PACT_ASK response from agentpactd: missing approval_id".to_string(),
                );
            };
            let Some(approval_token) = approval_token else {
                return CheckResponse::Invalid(
                    "invalid PACT_ASK response from agentpactd: missing approval_token".to_string(),
                );
            };
            let breaker_count = response
                .get("extensions")
                .and_then(|ext| ext.get("circuit_breaker"))
                .and_then(|cb| cb.get("count"))
                .and_then(serde_json::Value::as_u64)
                .map(|c| c.to_string());
            CheckResponse::Ask {
                approval_id,
                approval_token,
                breaker_count,
            }
        }
        Some("PACT_POLICY_ERROR" | "PACT_PROTOCOL_ERROR" | "PACT_CAP_EXCEEDED") => {
            let error = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            let hint = response.get("recovery_hint").and_then(|v| v.as_str());
            let reason = match hint {
                Some(h) => format!("{error} ({h})"),
                None => error.to_string(),
            };
            CheckResponse::Deny {
                reason: Some(reason),
            }
        }
        Some(other) => {
            CheckResponse::Invalid(format!("unexpected response code from agentpactd: {other}"))
        }
        None => {
            CheckResponse::Invalid("invalid response from agentpactd: missing code".to_string())
        }
    }
}

fn cmd_respond(args: &[String]) -> ExitCode {
    let mut socket_path = default_socket();
    let mut req_id = String::new();
    let mut token = String::new();
    let mut response_value = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" if i + 1 < args.len() => {
                socket_path.clone_from(&args[i + 1]);
                i += 2;
            }
            "--req-id" if i + 1 < args.len() => {
                req_id.clone_from(&args[i + 1]);
                i += 2;
            }
            "--token" if i + 1 < args.len() => {
                token.clone_from(&args[i + 1]);
                i += 2;
            }
            "--response" if i + 1 < args.len() => {
                response_value.clone_from(&args[i + 1]);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let request = serde_json::json!({
        "id": req_id,
        "method": "permission.respond",
        "approval_token": token,
        "response": response_value,
    });

    match send_request(&socket_path, &request) {
        Ok(resp) => {
            if resp["code"].as_str() == Some("PACT_OK") {
                ExitCode::from(0)
            } else {
                if let Some(reason) = resp["error"].as_str() {
                    eprintln!("{reason}");
                }
                ExitCode::from(1)
            }
        }
        Err(_) => ExitCode::from(10),
    }
}

/// Release a minted approval token without approving it, so it does not
/// linger as a pending entry. Sent when `check` got a normal `PACT_ASK` for
/// a command the shell will re-resolve per segment via `kyris hook
/// resolve-shell`. Best-effort: a failure here only means the whole-command
/// token expires on its own TTL.
fn void_token(socket_path: &str, approval_token: &str) {
    let request = serde_json::json!({
        "id": generate_id(),
        "method": "permission.respond",
        "approval_token": approval_token,
        "response": "voided",
    });
    let _ = send_request(socket_path, &request);
}

fn cmd_send(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("Usage: kyris-hook send <socket_path> <json_message>");
        return ExitCode::from(1);
    }

    let socket_path = &args[0];
    let message = &args[1];

    let value: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid JSON: {e}");
            return ExitCode::from(1);
        }
    };

    match send_request(socket_path, &value) {
        Ok(resp) => {
            println!("{}", serde_json::to_string(&resp).unwrap_or_default());
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("Send failed: {e}");
            ExitCode::from(10)
        }
    }
}

fn parse_check_args(args: &[String]) -> (String, String, String) {
    let mut command = String::new();
    let mut cwd = String::new();
    let mut socket = default_socket();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cwd" if i + 1 < args.len() => {
                cwd.clone_from(&args[i + 1]);
                i += 2;
            }
            "--socket" if i + 1 < args.len() => {
                socket.clone_from(&args[i + 1]);
                i += 2;
            }
            _ => {
                if command.is_empty() {
                    command.clone_from(&args[i]);
                }
                i += 1;
            }
        }
    }

    (command, cwd, socket)
}

#[cfg(unix)]
fn send_request(
    socket_path: &str,
    request: &serde_json::Value,
) -> Result<serde_json::Value, std::io::Error> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    let mut payload = serde_json::to_vec(request)?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes)?;
    trim_socket_message(&mut response_bytes);
    serde_json::from_slice(&response_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(not(unix))]
fn send_request(
    _socket_path: &str,
    _request: &serde_json::Value,
) -> Result<serde_json::Value, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "UDS not supported on this platform",
    ))
}

fn xdg_state_dir() -> String {
    std::env::var("XDG_STATE_HOME").map_or_else(
        |_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{home}/.local/state/kyris")
        },
        |s| format!("{s}/kyris"),
    )
}

fn log_error(msg: &str) {
    let dir = xdg_state_dir();
    let log_dir = format!("{dir}/log");
    let _ = std::fs::create_dir_all(&log_dir);
    let path = format!("{log_dir}/kyris.log");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = format_utc_timestamp(secs);
    let _ = writeln!(file, "{ts} [kyris-hook] [ERROR] {msg}");
}

fn write_fail_open_event(action: &str, detail: &str, working_dir: &str) {
    let dir = xdg_state_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{dir}/fail-open.jsonl");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = ts.as_secs();
    let line = serde_json::json!({
        "id": format!("kyris-{}", ts.as_nanos()),
        "timestamp": format_utc_timestamp(secs),
        "agent": "unknown",
        "action": action,
        "detail": detail,
        "decision": "auto",
        "working_dir": working_dir,
        "attribution_method": "unknown",
        "mode": "log",
        "event_kind": "action",
        "coverage_state": "unknown",
        "source": "fail-open",
    });
    let _ = writeln!(file, "{line}");
}

fn format_utc_timestamp(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let day_secs = epoch_secs % secs_per_day;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;

    let (year, month, day) = days_to_ymd(days + 719_468);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(day_count: u64) -> (u64, u64, u64) {
    let era = day_count / 146_097;
    let doe = day_count - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

const PROTOCOL_VERSION: u64 = 1;

fn read_daemon_state(socket_path: &str) -> Option<serde_json::Value> {
    let path = std::path::Path::new(socket_path)
        .parent()
        .map(|dir| dir.join("daemon.state"))?;
    let contents = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

fn daemon_state_allows(socket_path: &str) -> bool {
    read_daemon_state(socket_path)
        .as_ref()
        .and_then(|v| v.get("on_daemon_unavailable"))
        .and_then(|val| val.as_str())
        == Some("allow")
}

fn check_protocol_version(socket_path: &str) -> Result<(), String> {
    let Some(state) = read_daemon_state(socket_path) else {
        return Ok(());
    };
    let Some(version) = state
        .get("protocol_version")
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(());
    };
    if version == PROTOCOL_VERSION {
        return Ok(());
    }
    if version > PROTOCOL_VERSION {
        Err(format!(
            "agentpactd protocol version {version} is newer than kyris-hook expects ({PROTOCOL_VERSION}). \
             Upgrade kyris: brew upgrade kyris"
        ))
    } else {
        Err(format!(
            "agentpactd protocol version {version} is older than kyris-hook expects ({PROTOCOL_VERSION}). \
             Upgrade agentpact: brew upgrade agentpact"
        ))
    }
}

fn default_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn trim_socket_message(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

fn generate_id() -> String {
    format!(
        "kyris-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    static ENV_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn lock_env_tests() -> MutexGuard<'static, ()> {
        ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn testParseCheckResponseAllowsInform() {
        let response = serde_json::json!({
            "code": "PACT_OK",
            "decision": "inform",
            "reason": "heads up"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Allow {
                inform_reason: Some("heads up".to_string()),
            }
        );
    }

    #[test]
    fn testParseCheckResponseAskBreakerFromExtensions() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "apr_123",
            "approval_token": "tok_123",
            "extensions": {
                "circuit_breaker": { "count": 50 }
            }
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Ask {
                approval_id: "apr_123".to_string(),
                approval_token: "tok_123".to_string(),
                breaker_count: Some("50".to_string()),
            }
        );
    }

    #[test]
    fn testParseCheckResponseAskNoBreakerWithoutExtensions() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "apr_123",
            "approval_token": "tok_123",
            "reason": "requires approval"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Ask {
                approval_id: "apr_123".to_string(),
                approval_token: "tok_123".to_string(),
                breaker_count: None,
            }
        );
    }

    #[test]
    fn testParseCheckResponseRejectsUnknownCode() {
        let response = serde_json::json!({
            "code": "PACT_FUTURE"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Invalid(
                "unexpected response code from agentpactd: PACT_FUTURE".to_string()
            )
        );
    }

    #[test]
    fn testParseCheckResponseRejectsMalformedAsk() {
        let response = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "apr_123"
        });
        assert_eq!(
            parse_check_response(&response),
            CheckResponse::Invalid(
                "invalid PACT_ASK response from agentpactd: missing approval_token".to_string(),
            )
        );
    }

    #[test]
    fn testGenerateIdNotEmpty() {
        let id = generate_id();
        assert!(id.starts_with("kyris-"));
        assert!(id.len() > 6);
    }

    #[test]
    fn testGenerateIdUnique() {
        let id1 = generate_id();
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let id2 = generate_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn testParseCheckArgsAllFlags() {
        let args: Vec<String> = vec![
            "--cwd",
            "/home/user/project",
            "--socket",
            "/tmp/test.sock",
            "rm -rf /",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (command, cwd, socket) = parse_check_args(&args);
        assert_eq!(command, "rm -rf /");
        assert_eq!(cwd, "/home/user/project");
        assert_eq!(socket, "/tmp/test.sock");
    }

    #[test]
    fn testParseCheckArgsCommandOnly() {
        let args: Vec<String> = vec!["git status"].into_iter().map(String::from).collect();
        let (command, cwd, socket) = parse_check_args(&args);
        assert_eq!(command, "git status");
        assert_eq!(cwd, "");
        assert!(socket.ends_with("agentpact.sock"));
    }

    #[test]
    fn testParseCheckArgsEmpty() {
        let args: Vec<String> = vec![];
        let (command, cwd, _) = parse_check_args(&args);
        assert_eq!(command, "");
        assert_eq!(cwd, "");
    }

    #[test]
    fn testDaemonStateAllowsReturnsTrue() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":1,"on_daemon_unavailable":"allow","on_log_broken":"continue"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testDaemonStateBlockReturnsFalse() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":1,"on_daemon_unavailable":"block","on_log_broken":"continue"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(!daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testDaemonStateMissingFileReturnsFalse() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(!daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testDaemonStateAllowsWithSpaces() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version": 1, "on_daemon_unavailable": "allow", "on_log_broken": "continue"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(daemon_state_allows(socket_path.to_str().unwrap()));
    }

    #[test]
    fn testWriteFailOpenEvent() {
        let dir = tempfile::tempdir().unwrap();
        // fail-open log lives under $XDG_STATE_HOME/kyris/ after the XDG
        // migration. Set both HOME (fallback) and XDG_STATE_HOME to point
        // at the tempdir so the new path resolves there.
        unsafe {
            std::env::set_var("HOME", dir.path().to_str().unwrap());
            std::env::set_var("XDG_STATE_HOME", dir.path().to_str().unwrap());
        }

        write_fail_open_event("execute", "rm -rf /", "/home/user/project");

        let path = dir.path().join("kyris").join("fail-open.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["action"], "execute");
        assert_eq!(parsed["detail"], "rm -rf /");
        assert_eq!(parsed["working_dir"], "/home/user/project");
        assert_eq!(parsed["source"], "fail-open");
        assert_eq!(parsed["coverage_state"], "unknown");
    }

    #[test]
    fn testFormatUtcTimestamp() {
        // 2026-01-01T00:00:00Z
        assert_eq!(format_utc_timestamp(1_767_225_600), "2026-01-01T00:00:00Z");
        // 2026-04-27T12:30:45Z
        assert_eq!(format_utc_timestamp(1_777_293_045), "2026-04-27T12:30:45Z");
    }

    #[test]
    fn testDefaultSocketUsesEnvVar() {
        let _guard = lock_env_tests();
        unsafe { std::env::set_var("AGENTPACT_SOCK", "/custom/path.sock") };
        let sock = default_socket();
        assert_eq!(sock, "/custom/path.sock");
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
    }

    #[test]
    fn testDefaultSocketFallsBackToHome() {
        let _guard = lock_env_tests();
        unsafe { std::env::remove_var("AGENTPACT_SOCK") };
        let sock = default_socket();
        assert!(sock.ends_with(".agentpact/agentpact.sock"));
    }

    #[test]
    fn testCheckProtocolVersionMatchingVersion() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":1,"on_daemon_unavailable":"block"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(check_protocol_version(socket_path.to_str().unwrap()).is_ok());
    }

    #[test]
    fn testCheckProtocolVersionNewerDaemon() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":99,"on_daemon_unavailable":"block"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        let result = check_protocol_version(socket_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Upgrade kyris"));
    }

    #[test]
    fn testCheckProtocolVersionOlderDaemon() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(
            &state_path,
            r#"{"protocol_version":0,"on_daemon_unavailable":"block"}"#,
        )
        .unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        let result = check_protocol_version(socket_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Upgrade agentpact"));
    }

    #[test]
    fn testCheckProtocolVersionMissingState() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(check_protocol_version(socket_path.to_str().unwrap()).is_ok());
    }

    #[test]
    fn testCheckProtocolVersionMissingField() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        std::fs::write(&state_path, r#"{"on_daemon_unavailable":"block"}"#).unwrap();
        let socket_path = dir.path().join("agentpact.sock");
        assert!(check_protocol_version(socket_path.to_str().unwrap()).is_ok());
    }
}
