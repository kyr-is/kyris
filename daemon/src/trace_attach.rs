// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const ATTACH_TIMEOUT: Duration = Duration::from_millis(100);

fn resolve_socket_path(env_override: Option<&str>, home: &str) -> PathBuf {
    if let Some(path) = env_override {
        return PathBuf::from(path);
    }
    PathBuf::from(format!("{home}/.agentpact/agentpact.sock"))
}

fn socket_path() -> PathBuf {
    resolve_socket_path(
        std::env::var("AGENTPACT_SOCK").ok().as_deref(),
        &std::env::var("HOME").unwrap_or_default(),
    )
}

pub async fn send_trace_attach(trace_id: &str, model: &str) -> Option<String> {
    let sock = socket_path();
    let result = tokio::time::timeout(ATTACH_TIMEOUT, send_to_socket(&sock, trace_id, model)).await;
    match result {
        Ok(Ok(working_dir)) => working_dir,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "trace.attach failed");
            None
        }
        Err(_) => {
            tracing::debug!("trace.attach timed out");
            None
        }
    }
}

async fn send_to_socket(
    sock: &Path,
    trace_id: &str,
    model: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = UnixStream::connect(sock).await?;

    let now = chrono::Utc::now().to_rfc3339();
    let message = serde_json::json!({
        "method": "trace.attach",
        "params": {
            "trace_id": trace_id,
            "model": model,
            "completed_at": now,
        }
    });

    let payload = serde_json::to_vec(&message)?;
    stream.write_all(&payload).await?;
    stream.shutdown().await?;

    let mut buf = Vec::with_capacity(1024);
    stream.read_to_end(&mut buf).await?;

    if buf.is_empty() {
        return Ok(None);
    }

    let response: serde_json::Value = serde_json::from_slice(&buf)?;
    let working_dir = response
        .get("working_dir")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(working_dir)
}

pub fn spawn_trace_attach(trace_id: String, model: String) {
    tokio::spawn(async move {
        send_trace_attach(&trace_id, &model).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testResolveSocketPathDefault() {
        let path = resolve_socket_path(None, "/home/user");
        assert_eq!(path, PathBuf::from("/home/user/.agentpact/agentpact.sock"));
    }

    #[test]
    fn testResolveSocketPathOverride() {
        let path = resolve_socket_path(Some("/tmp/test.sock"), "/home/user");
        assert_eq!(path, PathBuf::from("/tmp/test.sock"));
    }

    #[tokio::test]
    async fn testSendToSocketUnreachable() {
        let sock = PathBuf::from("/tmp/nonexistent_kyris_test.sock");
        let result = send_to_socket(&sock, "trace-123", "claude-4-opus").await;
        assert!(result.is_err());
    }
}
