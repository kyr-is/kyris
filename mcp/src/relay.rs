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
use crate::policy::{self, PactDecision};

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

fn build_denied_response(original_id: &serde_json::Value, message: &str) -> String {
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

async fn relay_agent_to_server(
    stdin: tokio::io::Stdin,
    mut child_stdin: tokio::process::ChildStdin,
    stdout: SharedStdout,
    server_name: String,
    has_tty: bool,
    socket_timeout: std::time::Duration,
    annotation_cache: AnnotationCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(stdin);
    let mut mode = FrameMode::Unknown;

    while let Some(msg) = read_message(&mut reader, &mut mode).await? {
        let compact = normalize(&msg);
        if framing::is_tools_call(&compact) {
            let tool_name = extract_tool_name(&compact).unwrap_or_else(|| "unknown".to_string());
            let original_id = extract_request_id(&compact).unwrap_or(serde_json::Value::Null);

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
                    child_stdin.write_all(&compact).await?;
                    child_stdin.write_all(b"\n").await?;
                    child_stdin.flush().await?;
                }
                PactDecision::Deny(message) => {
                    let error_response = build_denied_response(&original_id, &message);
                    let mut out = stdout.lock().await;
                    out.write_all(error_response.as_bytes()).await?;
                    out.write_all(b"\n").await?;
                    out.flush().await?;
                }
            }
        } else {
            child_stdin.write_all(&compact).await?;
            child_stdin.write_all(b"\n").await?;
            child_stdin.flush().await?;
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

    #[test]
    fn testBuildDeniedResponse() {
        let resp = build_denied_response(&serde_json::json!(7), "Blocked by policy");
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], -32001);
        assert_eq!(v["error"]["message"], "Blocked by policy");
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
