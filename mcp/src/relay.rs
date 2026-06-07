// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use kyris_core::agentpact::ToolAnnotations;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;

use crate::framing;
use crate::policy::{self, DenyCode, PactDecision};

type AnnotationCache = Arc<RwLock<HashMap<String, ToolAnnotations>>>;

const CHILD_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

type SharedStdout = std::sync::Arc<tokio::sync::Mutex<tokio::io::Stdout>>;

pub async fn run_wrapper(
    server_name: &str,
    cmd: &str,
    args: &[String],
    has_tty: bool,
    socket_timeout: std::time::Duration,
) -> Result<u8, Box<dyn std::error::Error>> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let child_id = child.id();
    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    let stdin = tokio::io::stdin();
    let stdout: SharedStdout = std::sync::Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let annotation_cache: AnnotationCache = Arc::new(RwLock::new(HashMap::new()));

    let server_name_owned = server_name.to_string();

    let agent_to_server = tokio::spawn(relay_agent_to_server(
        stdin,
        child_stdin,
        stdout.clone(),
        server_name_owned.clone(),
        has_tty,
        socket_timeout,
        annotation_cache.clone(),
    ));

    let server_to_agent = tokio::spawn(relay_server_to_agent(
        child_stdout,
        stdout,
        annotation_cache,
    ));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("register SIGTERM");
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("register SIGINT");

    tokio::select! {
        result = agent_to_server => {
            let inner = result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            inner.map_err(|e| -> Box<dyn std::error::Error> { e })?;
        }
        result = server_to_agent => {
            let inner = result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
            inner.map_err(|e| -> Box<dyn std::error::Error> { e })?;
        }
        _ = sigterm.recv() => {
            forward_signal_to_child(child_id, nix::sys::signal::Signal::SIGTERM);
        }
        _ = sigint.recv() => {
            forward_signal_to_child(child_id, nix::sys::signal::Signal::SIGINT);
        }
    }

    match tokio::time::timeout(CHILD_KILL_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let code = status.code().unwrap_or(1) as u8;
            Ok(code)
        }
        Ok(Err(e)) => Err(Box::new(e)),
        Err(_) => {
            child.kill().await.ok();
            Ok(1)
        }
    }
}

fn forward_signal_to_child(child_id: Option<u32>, signal: nix::sys::signal::Signal) {
    if let Some(pid) = child_id {
        let nix_pid = nix::unistd::Pid::from_raw(pid.cast_signed());
        let _ = nix::sys::signal::kill(nix_pid, signal);
    }
}

fn extract_tool_name(bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("params")?.get("name")?.as_str().map(String::from)
}

fn extract_request_id(bytes: &[u8]) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    v.get("id").cloned()
}

/// Formats a JSON-RPC error following the I-05 governance stop contract:
/// `[AgentPact {code}] {reason}. {recovery_hint}`
///
/// `daemon_hint` is the dynamic recovery hint from the daemon (e.g. cap reset
/// time for `PACT_CAP_EXCEEDED`). When `None`, the static I-05 table is used.
fn build_denied_response(
    original_id: &serde_json::Value,
    code: &DenyCode,
    reason: &str,
    daemon_hint: Option<&str>,
) -> String {
    let (code_str, static_hint) = match code {
        DenyCode::PolicyDenied => ("PACT_DENIED", "Change policy or contact admin"),
        DenyCode::CapExceeded => (
            "PACT_CAP_EXCEEDED",
            "Wait until reset_at or adjust caps policy",
        ),
        DenyCode::PolicyError => (
            "PACT_POLICY_ERROR",
            "Fix policy files: run agentpactd schema to validate",
        ),
        DenyCode::DaemonUnreachable => {
            ("DAEMON_UNREACHABLE", "Run agentpactd to restore governance")
        }
    };
    let hint = daemon_hint.unwrap_or(static_hint);
    // Strip trailing period so the ". {hint}" separator is never doubled.
    let reason = reason.trim_end_matches('.');
    let message = format!("[AgentPact {code_str}] {reason}. {hint}");
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": original_id,
        "error": {
            "code": -32001,
            "message": message
        }
    })
    .to_string()
}

enum FrameMode {
    Unknown,
    Newline,
    BraceDepth,
    ContentLength,
}

async fn read_brace_delimited<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut message = Vec::new();
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escape_next = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if message.is_empty() {
                return Ok(None);
            }
            return Ok(Some(message));
        }
        let mut consumed = 0;
        for &byte in available {
            consumed += 1;
            message.push(byte);
            if escape_next {
                escape_next = false;
                continue;
            }
            if in_string {
                match byte {
                    b'\\' => escape_next = true,
                    b'"' => in_string = false,
                    _ => {}
                }
            } else {
                match byte {
                    b'"' => in_string = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            reader.consume(consumed);
                            return Ok(Some(message));
                        }
                    }
                    _ => {}
                }
            }
        }
        reader.consume(consumed);
    }
}

async fn read_content_length<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let n = reader.read_line(&mut header_line).await?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.to_ascii_lowercase().starts_with("content-length:") {
            break;
        }
    }
    let length_str = header_line.trim()["Content-Length:".len()..].trim();
    let length: usize = length_str.parse().map_err(|e| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid Content-Length: {e}"),
        ))
    })?;
    let mut blank = String::new();
    loop {
        blank.clear();
        let n = reader.read_line(&mut blank).await?;
        if n == 0 {
            return Ok(None);
        }
        if blank.trim().is_empty() {
            break;
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn read_message<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    mode: &mut FrameMode,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        match mode {
            FrameMode::Unknown => {
                let buf = reader.fill_buf().await?;
                if buf.is_empty() {
                    return Ok(None);
                }
                let first = buf.iter().find(|b| !b.is_ascii_whitespace());
                match first {
                    Some(b'{') => *mode = FrameMode::BraceDepth,
                    Some(b'C') => *mode = FrameMode::ContentLength,
                    Some(_) => *mode = FrameMode::Newline,
                    None => {
                        let len = buf.len();
                        reader.consume(len);
                    }
                }
            }
            FrameMode::Newline => {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    return Ok(None);
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                return Ok(Some(trimmed.as_bytes().to_vec()));
            }
            FrameMode::BraceDepth => {
                let mut buf = reader.fill_buf().await?;
                if buf.is_empty() {
                    return Ok(None);
                }
                while !buf.is_empty() && buf[0].is_ascii_whitespace() {
                    reader.consume(1);
                    buf = reader.fill_buf().await?;
                }
                if buf.is_empty() {
                    return Ok(None);
                }
                if buf[0] == b'C' {
                    *mode = FrameMode::ContentLength;
                    continue;
                }
                if buf[0] != b'{' {
                    reader.consume(1);
                    continue;
                }
                return read_brace_delimited(reader).await;
            }
            FrameMode::ContentLength => {
                return read_content_length(reader).await;
            }
        }
    }
}

fn normalize(msg: &[u8]) -> Vec<u8> {
    if !msg.contains(&b'\n') {
        return msg.to_vec();
    }
    match serde_json::from_slice::<serde_json::Value>(msg) {
        Ok(v) => serde_json::to_vec(&v).unwrap_or_else(|_| msg.to_vec()),
        Err(_) => msg.to_vec(),
    }
}

/// Agent-to-server relay split into three concurrent tasks so that
/// non-governed traffic (notifications, ping) is never blocked behind a
/// tools/call that is waiting for a `PACT_ASK` approval.
///
/// ```text
///  stdin ──► reader ──► child_tx ──► child_writer ──► child_stdin
///                  └──► tool_tx  ──► policy_task ──────────┘
///                                         └──► stdout (deny)
/// ```
///
/// The reader classifies messages immediately:
///   • non-governed  → `child_tx`  (forwarded without delay)
///   • tools/call    → `tool_tx`   (policy task checks permission)
///
/// The policy task may block on `PACT_ASK` while the reader keeps draining
/// stdin and forwarding notifications/pings in real time.
async fn relay_agent_to_server(
    stdin: tokio::io::Stdin,
    child_stdin: tokio::process::ChildStdin,
    stdout: SharedStdout,
    server_name: String,
    has_tty: bool,
    socket_timeout: std::time::Duration,
    annotation_cache: AnnotationCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Serialises writes from both the reader (non-governed) and the policy
    // task (allowed tools/calls) into child_stdin.
    let (child_tx, child_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    // Bounded at 8: MCP agents typically send one tools/call at a time.
    // A small buffer prevents the reader from blocking if two tool calls
    // arrive while the policy task is processing the first.
    let (tool_tx, tool_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, serde_json::Value)>(8);

    let child_writer = tokio::spawn(child_writer_task(child_rx, child_stdin));
    let policy_task = tokio::spawn(policy_check_task(
        tool_rx,
        child_tx.clone(),
        stdout,
        server_name,
        has_tty,
        socket_timeout,
        annotation_cache,
    ));

    // Reader runs inline: reads stdin, dispatches to the two channels.
    // Non-governed messages go straight to child_tx (no policy delay).
    // tools/call messages go to tool_tx for async policy evaluation.
    let mut reader = BufReader::new(stdin);
    let mut mode = FrameMode::Unknown;
    while let Some(msg) = read_message(&mut reader, &mut mode).await? {
        let compact = normalize(&msg);
        if framing::is_tools_call(&compact) {
            let original_id = extract_request_id(&compact).unwrap_or(serde_json::Value::Null);
            tool_tx
                .send((compact, original_id))
                .await
                .map_err(|_| "policy task closed unexpectedly")?;
        } else {
            child_tx
                .send(compact)
                .await
                .map_err(|_| "child writer closed unexpectedly")?;
        }
    }

    // Drop senders so downstream tasks drain and exit cleanly.
    drop(tool_tx);
    drop(child_tx);

    policy_task.await??;
    child_writer.await??;

    Ok(())
}

/// Receives messages from `child_rx` and writes them to `child_stdin` in order.
/// Both the reader (non-governed) and policy task (allowed tool calls) send
/// here, so all `child_stdin` writes are serialised through this task.
async fn child_writer_task(
    mut child_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut child_stdin: tokio::process::ChildStdin,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while let Some(msg) = child_rx.recv().await {
        child_stdin.write_all(&msg).await?;
        child_stdin.write_all(b"\n").await?;
        child_stdin.flush().await?;
    }
    Ok(())
}

/// Runs concurrently with the reader. For each tools/call: evaluates policy
/// (which may block on `PACT_ASK` / hold-poll-resolve), then either forwards
/// the message to `child_stdin` (via `child_tx`) or sends a JSON-RPC error to
/// stdout. Non-governed traffic flows through `child_tx` unimpeded while this
/// task is blocked on a policy check.
async fn policy_check_task(
    mut tool_rx: tokio::sync::mpsc::Receiver<(Vec<u8>, serde_json::Value)>,
    child_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdout: SharedStdout,
    server_name: String,
    has_tty: bool,
    socket_timeout: std::time::Duration,
    annotation_cache: AnnotationCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while let Some((compact, original_id)) = tool_rx.recv().await {
        let tool_name = extract_tool_name(&compact).unwrap_or_else(|| "unknown".to_string());
        let annotations = annotation_cache
            .read()
            .await
            .get(&tool_name)
            .cloned()
            .unwrap_or_default();

        let decision = policy::check_permission(
            &server_name,
            &tool_name,
            has_tty,
            Some("tools/call"),
            &annotations,
            socket_timeout,
        )
        .await;

        match decision {
            PactDecision::Allow => {
                child_tx
                    .send(compact)
                    .await
                    .map_err(|_| "child writer closed unexpectedly")?;
            }
            PactDecision::Deny { code, reason, hint } => {
                let error_response =
                    build_denied_response(&original_id, &code, &reason, hint.as_deref());
                let mut out = stdout.lock().await;
                out.write_all(error_response.as_bytes()).await?;
                out.write_all(b"\n").await?;
                out.flush().await?;
            }
        }
    }
    Ok(())
}

async fn relay_server_to_agent(
    child_stdout: tokio::process::ChildStdout,
    stdout: SharedStdout,
    annotation_cache: AnnotationCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(child_stdout);
    let mut mode = FrameMode::Unknown;
    while let Some(msg) = read_message(&mut reader, &mut mode).await? {
        let compact = normalize(&msg);
        if framing::is_tools_list_response(&compact) {
            let annotations = framing::extract_tool_annotations(&compact);
            if !annotations.is_empty() {
                let mut cache = annotation_cache.write().await;
                for (name, ann) in annotations {
                    cache.insert(name, ann);
                }
            }
        } else if framing::is_tools_list_changed(&compact) {
            annotation_cache.write().await.clear();
        }
        let mut out = stdout.lock().await;
        out.write_all(&compact).await?;
        out.write_all(b"\n").await?;
        out.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testExtractToolName() {
        let msg = br#"{"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
        assert_eq!(extract_tool_name(msg), Some("read_file".to_string()));

        let no_params = br#"{"method":"tools/call"}"#;
        assert_eq!(extract_tool_name(no_params), None);
    }

    #[test]
    fn testExtractRequestId() {
        let msg = br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{}}"#;
        assert_eq!(extract_request_id(msg), Some(serde_json::json!(42)));

        let str_id = br#"{"jsonrpc":"2.0","id":"abc","method":"tools/call"}"#;
        assert_eq!(extract_request_id(str_id), Some(serde_json::json!("abc")));
    }

    /// Verifies that non-governed messages (notifications, ping) are forwarded
    /// to `child_stdin` while a tools/call is blocked in the policy task.
    ///
    /// Setup: a tools/call arrives first; the policy task delays (simulating
    /// `PACT_ASK`). A notification arrives while the delay is in progress.
    /// The notification must reach `child_stdin` BEFORE or DURING the delay —
    /// not after the policy task unblocks.
    // This integration-style test wires up four async tasks plus assertions;
    // splitting it into helpers would obscure the linear narrative the test is
    // documenting. The length is intentional, not accidental complexity.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn testNotificationsFlowThroughWhileToolCallIsPendingPolicy() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::sync::oneshot;

        // --- channels ---
        // Gate: blocks policy task until test releases it.
        let (policy_gate_tx, policy_gate_rx) = oneshot::channel::<()>();
        // Ready: policy task fires this once it has the tool call and is
        // about to block on the gate — replaces fragile sleep().
        let (policy_ready_tx, policy_ready_rx) = oneshot::channel::<()>();
        // Seen: fires when the notification arrives at child_stdin.
        let (notify_seen_tx, notify_seen_rx) = oneshot::channel::<()>();

        // --- pipe plumbing ---
        let (pipe_reader, mut pipe_writer) = tokio::io::duplex(4096);
        let (child_in_reader, child_in_writer) = tokio::io::duplex(4096);

        let (child_tx, child_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let (tool_tx, mut tool_rx) = tokio::sync::mpsc::channel::<(Vec<u8>, serde_json::Value)>(8);

        // Records every line written to child_stdin. Fires notify_seen_tx
        // when the notification arrives.
        let received: std::sync::Arc<tokio::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let child_reader_task = tokio::spawn({
            let received = received.clone();
            let mut reader = tokio::io::BufReader::new(child_in_reader);
            let mut notify_seen_tx = Some(notify_seen_tx);
            async move {
                use tokio::io::AsyncBufReadExt as _;
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let trimmed = line.trim().to_string();
                            if trimmed.is_empty() {
                                continue;
                            }
                            if trimmed.contains("notification")
                                && let Some(tx) = notify_seen_tx.take()
                            {
                                let _ = tx.send(());
                            }
                            received.lock().await.push(trimmed);
                        }
                    }
                }
            }
        });

        // Drains child_rx → child_in_writer (mirrors child_writer_task).
        let child_in_writer_task = tokio::spawn(async move {
            let mut child_rx = child_rx;
            let mut writer = child_in_writer;
            while let Some(msg) = child_rx.recv().await {
                writer.write_all(&msg).await.unwrap();
                writer.write_all(b"\n").await.unwrap();
                writer.flush().await.unwrap();
            }
        });

        // Stub policy task: signals ready, blocks on gate, then allows.
        let child_tx_policy = child_tx.clone();
        let mut policy_ready_tx = Some(policy_ready_tx);
        let mut policy_gate_rx = Some(policy_gate_rx);
        let policy_task = tokio::spawn(async move {
            while let Some((compact, _id)) = tool_rx.recv().await {
                // Signal before blocking so the test knows we have the call.
                if let Some(tx) = policy_ready_tx.take() {
                    let _ = tx.send(());
                }
                // Block until the test releases the gate.
                if let Some(rx) = policy_gate_rx.take() {
                    let _ = rx.await;
                }
                child_tx_policy.send(compact).await.unwrap();
            }
        });

        // Reader task: reads pipe_reader and dispatches to channels.
        let child_tx_reader = child_tx.clone();
        let reader_task = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(pipe_reader);
            let mut mode = FrameMode::Unknown;
            while let Some(msg) = read_message(&mut reader, &mut mode).await.unwrap() {
                let compact = normalize(&msg);
                if framing::is_tools_call(&compact) {
                    let id = extract_request_id(&compact).unwrap_or(serde_json::Value::Null);
                    tool_tx.send((compact, id)).await.unwrap();
                } else {
                    child_tx_reader.send(compact).await.unwrap();
                }
            }
            drop(tool_tx);
            drop(child_tx_reader);
        });

        // --- test sequence ---

        // 1. Send a tools/call; the policy stub will pick it up and block.
        let tools_call =
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\"}}\n";
        pipe_writer.write_all(tools_call).await.unwrap();

        // 2. Wait until the policy stub signals it has the call and is
        //    blocked on the gate. No sleep() — this is deterministic.
        tokio::time::timeout(std::time::Duration::from_secs(2), policy_ready_rx)
            .await
            .expect("timeout waiting for policy stub to receive tool call")
            .unwrap();

        // 3. Send a notification while the policy task is blocked on the gate.
        let notification =
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/something\",\"params\":{}}\n";
        pipe_writer.write_all(notification).await.unwrap();

        // 4. Notification must reach child_stdin without waiting for the gate.
        tokio::time::timeout(std::time::Duration::from_secs(2), notify_seen_rx)
            .await
            .expect("timeout: notification was blocked behind policy check")
            .unwrap();

        // 5. Release the gate — tools/call is forwarded to child_stdin.
        policy_gate_tx.send(()).ok();

        // 6. EOF.
        drop(pipe_writer);

        // 7. Drain.
        drop(child_tx);
        reader_task.await.unwrap();
        policy_task.await.unwrap();
        child_in_writer_task.await.unwrap();
        child_reader_task.await.unwrap();

        // 8. Assert: both messages arrived; notification came first.
        let msgs = received.lock().await.clone();
        assert_eq!(
            msgs.len(),
            2,
            "expected notification + tool call, got: {msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("notifications/something")),
            "notification missing from output: {msgs:?}"
        );
        assert!(
            msgs.iter().any(|m| m.contains("tools/call")),
            "tool call missing from output: {msgs:?}"
        );
        let notif_idx = msgs
            .iter()
            .position(|m| m.contains("notifications/something"))
            .unwrap();
        let call_idx = msgs.iter().position(|m| m.contains("tools/call")).unwrap();
        assert!(
            notif_idx < call_idx,
            "notification must arrive before tool call; notif={notif_idx}, call={call_idx}: {msgs:?}"
        );
    }

    #[test]
    fn testBuildDeniedResponseI05PolicyDenied() {
        let resp = build_denied_response(
            &serde_json::json!(7),
            &DenyCode::PolicyDenied,
            "blocked by admin",
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], -32001);
        assert_eq!(
            v["error"]["message"],
            "[AgentPact PACT_DENIED] blocked by admin. Change policy or contact admin"
        );
    }

    #[test]
    fn testBuildDeniedResponseI05CapExceededWithDaemonHint() {
        let resp = build_denied_response(
            &serde_json::json!(1),
            &DenyCode::CapExceeded,
            "daily premium cap reached",
            Some("Wait until 2026-01-02T00:00:00Z or adjust caps policy"),
        );
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            v["error"]["message"],
            "[AgentPact PACT_CAP_EXCEEDED] daily premium cap reached. Wait until 2026-01-02T00:00:00Z or adjust caps policy"
        );
    }

    #[test]
    fn testBuildDeniedResponseI05DaemonUnreachable() {
        // Uses the real daemon_unavailable_message() form, including trailing period,
        // to verify the period-stripping logic in build_denied_response.
        let resp = build_denied_response(
            &serde_json::json!(2),
            &DenyCode::DaemonUnreachable,
            "AgentPact daemon is unreachable.",
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            v["error"]["message"],
            "[AgentPact DAEMON_UNREACHABLE] AgentPact daemon is unreachable. Run agentpactd to restore governance"
        );
    }

    #[test]
    fn testBuildDeniedResponseI05PolicyError() {
        let resp = build_denied_response(
            &serde_json::json!("req-99"),
            &DenyCode::PolicyError,
            "malformed pact.yaml",
            Some("Fix policy files: run agentpactd schema to validate"),
        );
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            v["error"]["message"],
            "[AgentPact PACT_POLICY_ERROR] malformed pact.yaml. Fix policy files: run agentpactd schema to validate"
        );
    }

    #[tokio::test]
    async fn testReadMessageNewlineDelimited() {
        let input = b"{\"id\":1}\n{\"id\":2}\n";
        let cursor = std::io::Cursor::new(input.to_vec());
        let mut reader = BufReader::new(cursor);
        let mut mode = FrameMode::Unknown;

        let msg1 = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        assert_eq!(msg1, b"{\"id\":1}");

        let msg2 = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        assert_eq!(msg2, b"{\"id\":2}");

        let eof = read_message(&mut reader, &mut mode).await.unwrap();
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn testReadMessageBraceDepthPrettyPrinted() {
        let input = b"{\n  \"id\": 1,\n  \"method\": \"test\"\n}\n{\n  \"id\": 2\n}\n";
        let cursor = std::io::Cursor::new(input.to_vec());
        let mut reader = BufReader::new(cursor);
        let mut mode = FrameMode::Unknown;

        let msg1 = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        let v1: serde_json::Value = serde_json::from_slice(&msg1).unwrap();
        assert_eq!(v1["id"], 1);

        let msg2 = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&msg2).unwrap();
        assert_eq!(v2["id"], 2);
    }

    #[tokio::test]
    async fn testReadMessageBraceDepthWithStringBraces() {
        let input = b"{\"data\":\"{nested}\"}\n";
        let cursor = std::io::Cursor::new(input.to_vec());
        let mut reader = BufReader::new(cursor);
        let mut mode = FrameMode::Unknown;

        let msg = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&msg).unwrap();
        assert_eq!(v["data"], "{nested}");
    }

    #[tokio::test]
    async fn testReadMessageContentLength() {
        let body = b"{\"id\":1}";
        let input = format!(
            "Content-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let cursor = std::io::Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let mut mode = FrameMode::Unknown;

        let msg = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        assert_eq!(msg, body);
    }

    #[tokio::test]
    async fn testReadMessageContentLengthMultiple() {
        let body1 = b"{\"id\":1}";
        let body2 = b"{\"id\":2}";
        let input = format!(
            "Content-Length: {}\r\n\r\n{}Content-Length: {}\r\n\r\n{}",
            body1.len(),
            std::str::from_utf8(body1).unwrap(),
            body2.len(),
            std::str::from_utf8(body2).unwrap(),
        );
        let cursor = std::io::Cursor::new(input.into_bytes());
        let mut reader = BufReader::new(cursor);
        let mut mode = FrameMode::Unknown;

        let msg1 = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        assert_eq!(msg1, body1);

        let msg2 = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        assert_eq!(msg2, body2);
    }

    #[tokio::test]
    async fn testReadMessageEscapedQuotesInString() {
        let input = b"{\"data\":\"has \\\"quotes\\\" and {braces}\"}\n";
        let cursor = std::io::Cursor::new(input.to_vec());
        let mut reader = BufReader::new(cursor);
        let mut mode = FrameMode::Unknown;

        let msg = read_message(&mut reader, &mut mode).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&msg).unwrap();
        assert_eq!(v["data"], "has \"quotes\" and {braces}");
    }

    #[test]
    fn testNormalizeCompactPassthrough() {
        let input = b"{\"id\":1,\"method\":\"test\"}";
        assert_eq!(normalize(input), input);
    }

    #[test]
    fn testNormalizePrettyPrintedToCompact() {
        let input = b"{\n  \"id\": 1,\n  \"method\": \"test\"\n}";
        let result = normalize(input);
        let expected = b"{\"id\":1,\"method\":\"test\"}";
        assert_eq!(result, expected);
    }

    #[test]
    fn testNormalizeInvalidJsonPassthrough() {
        let input = b"not json\nstuff";
        assert_eq!(normalize(input), input);
    }
}
