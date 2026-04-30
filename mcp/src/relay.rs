// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use kyris_core::agentpact::ToolAnnotations;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

async fn relay_agent_to_server(
    stdin: tokio::io::Stdin,
    mut child_stdin: tokio::process::ChildStdin,
    stdout: SharedStdout,
    server_name: String,
    has_tty: bool,
    socket_timeout: std::time::Duration,
    annotation_cache: AnnotationCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let bytes = line.as_bytes();
        if framing::is_tools_call(bytes) {
            let tool_name = extract_tool_name(bytes).unwrap_or_else(|| "unknown".to_string());
            let original_id = extract_request_id(bytes).unwrap_or(serde_json::Value::Null);

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
                    child_stdin.write_all(bytes).await?;
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
            child_stdin.write_all(bytes).await?;
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
    let reader = BufReader::new(child_stdout);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let bytes = line.as_bytes();
        if framing::is_tools_list_response(bytes) {
            let annotations = framing::extract_tool_annotations(bytes);
            if !annotations.is_empty() {
                let mut cache = annotation_cache.write().await;
                for (name, ann) in annotations {
                    cache.insert(name, ann);
                }
            }
        } else if framing::is_tools_list_changed(bytes) {
            annotation_cache.write().await.clear();
        }
        let mut out = stdout.lock().await;
        out.write_all(bytes).await?;
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
}
