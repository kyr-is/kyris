// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const RETRY_BACKOFFS: &[u64] = &[50, 100, 250];

#[cfg(test)]
static TEST_AGENTPACT_SOCKET: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[derive(Debug, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
    Ask {
        approval_id: String,
        approval_token: String,
    },
}

fn agentpact_socket() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_AGENTPACT_SOCKET
        .lock()
        .expect("lock test socket")
        .clone()
    {
        return path;
    }

    if let Ok(path) = std::env::var("AGENTPACT_SOCK") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.agentpact/agentpact.sock"))
}

#[cfg(test)]
pub fn set_test_agentpact_socket(path: Option<PathBuf>) {
    *TEST_AGENTPACT_SOCKET.lock().expect("lock test socket") = path;
}

pub async fn check_permission(
    server_name: &str,
    path: &str,
    body: &[u8],
    socket_timeout: Duration,
) -> PolicyDecision {
    let tool_name = extract_tool_name(path, body);

    if tool_name.is_none() {
        return PolicyDecision::Allow;
    }

    let tool = tool_name.as_deref().unwrap_or("unknown");
    tracing::debug!(server = %server_name, tool = %tool, "mcp policy check: tools/call detected");

    let sock = agentpact_socket();
    match send_permission_request(&sock, server_name, tool, socket_timeout).await {
        Ok(decision) => decision,
        Err(e) => {
            if allow_on_daemon_unavailable() {
                tracing::warn!(error = %e, "agentpactd unavailable, allowing due to policy");
                PolicyDecision::Allow
            } else {
                tracing::warn!(error = %e, "agentpactd permission.request failed, blocking");
                PolicyDecision::Deny("agentpact_unavailable".to_string())
            }
        }
    }
}

async fn send_permission_request(
    sock: &Path,
    server_name: &str,
    tool: &str,
    socket_timeout: Duration,
) -> Result<PolicyDecision, Box<dyn std::error::Error + Send + Sync>> {
    let mut attempts = RETRY_BACKOFFS.iter().copied().peekable();
    loop {
        match send_permission_request_once(sock, server_name, tool, socket_timeout).await {
            Ok(decision) => return Ok(decision),
            Err(error) => {
                let Some(backoff_ms) = attempts.next() else {
                    return Err(error);
                };
                let _ = crate::platform::launchd::restart_agentpactd();
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}

async fn send_permission_request_once(
    sock: &Path,
    server_name: &str,
    tool: &str,
    socket_timeout: Duration,
) -> Result<PolicyDecision, Box<dyn std::error::Error + Send + Sync>> {
    let result = tokio::time::timeout(socket_timeout, async {
        let mut stream = UnixStream::connect(sock).await?;

        let request = serde_json::json!({
            "id": format!("kyris-{}", uuid::Uuid::now_v7()),
            "method": "permission.request",
            "action": "call",
            "detail": format!("{server_name}/{tool}"),
        });

        let payload = serde_json::to_vec(&request)?;
        stream.write_all(&payload).await?;
        stream.shutdown().await?;

        let mut buf = Vec::with_capacity(1024);
        stream.read_to_end(&mut buf).await?;

        let response: serde_json::Value = serde_json::from_slice(&buf)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(parse_permission_response(&response))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err("permission.request timed out".into()),
    }
}

fn parse_permission_response(response: &serde_json::Value) -> PolicyDecision {
    let code = response["code"].as_str().unwrap_or("");
    match code {
        "PACT_OK" => PolicyDecision::Allow,
        "PACT_DENIED" => {
            let reason = response["reason"]
                .as_str()
                .unwrap_or("denied by policy")
                .to_string();
            PolicyDecision::Deny(reason)
        }
        "PACT_ASK" => {
            let approval_id = response["approval_id"].as_str().unwrap_or("").to_string();
            let approval_token = response["approval_token"]
                .as_str()
                .unwrap_or("")
                .to_string();
            if approval_id.is_empty() || approval_token.is_empty() {
                PolicyDecision::Deny("invalid approval response from agentpactd".to_string())
            } else {
                PolicyDecision::Ask {
                    approval_id,
                    approval_token,
                }
            }
        }
        _ => PolicyDecision::Deny("invalid response from agentpactd".to_string()),
    }
}

pub fn extract_tool_name(path: &str, body: &[u8]) -> Option<String> {
    let is_tools_call_path = path.contains("tools/call");

    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;

    let is_tools_call_body = parsed
        .get("method")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m == "tools/call");

    if !is_tools_call_path && !is_tools_call_body {
        return None;
    }

    parsed
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
}

fn allow_on_daemon_unavailable() -> bool {
    policy_candidates().iter().any(|path| {
        std::fs::read_to_string(path).is_ok_and(|contents| {
            contents
                .lines()
                .any(|line| line.trim() == "on_daemon_unavailable: allow")
        })
    })
}

fn policy_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("AGENTPACT_POLICY_FILE") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        candidates.push(home.join(".agentpact").join("policy").join("pact.yaml"));
        candidates.push(home.join(".agentpact").join("policy").join("caps.yaml"));
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn testNonToolsCallAllowed() {
        let body = br#"{"method":"ping"}"#;
        let decision =
            check_permission("test-server", "/mcp/test/ping", body, Duration::from_millis(50))
                .await;
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn testExtractToolNameFromPath() {
        let body = br#"{"params":{"name":"write_file"}}"#;
        let name = extract_tool_name("tools/call", body);
        assert_eq!(name, Some("write_file".to_string()));
    }

    #[test]
    fn testExtractToolNameFromBody() {
        let body = br#"{"method":"tools/call","params":{"name":"exec_cmd"}}"#;
        let name = extract_tool_name("/some/path", body);
        assert_eq!(name, Some("exec_cmd".to_string()));
    }

    #[test]
    fn testExtractToolNameNonToolsCall() {
        let body = br#"{"method":"ping"}"#;
        let name = extract_tool_name("/some/path", body);
        assert_eq!(name, None);
    }

    #[test]
    fn testExtractToolNameInvalidJson() {
        let name = extract_tool_name("tools/call", b"not json");
        assert_eq!(name, None);
    }

    #[test]
    fn testParsePermissionResponseOk() {
        let resp = serde_json::json!({"code": "PACT_OK", "decision": "auto"});
        assert_eq!(parse_permission_response(&resp), PolicyDecision::Allow);
    }

    #[test]
    fn testParsePermissionResponseDenied() {
        let resp = serde_json::json!({"code": "PACT_DENIED", "reason": "blocked by policy"});
        assert_eq!(
            parse_permission_response(&resp),
            PolicyDecision::Deny("blocked by policy".to_string())
        );
    }

    #[test]
    fn testParsePermissionResponseAsk() {
        let resp = serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "req-42",
            "approval_token": "tok-abc"
        });
        assert_eq!(
            parse_permission_response(&resp),
            PolicyDecision::Ask {
                approval_id: "req-42".to_string(),
                approval_token: "tok-abc".to_string(),
            }
        );
    }

    #[test]
    fn testParsePermissionResponseUnknownCode() {
        let resp = serde_json::json!({"code": "SOMETHING_NEW"});
        assert_eq!(
            parse_permission_response(&resp),
            PolicyDecision::Deny("invalid response from agentpactd".to_string())
        );
    }

    #[test]
    fn testPolicyDecisionVariants() {
        let deny = PolicyDecision::Deny("test reason".to_string());
        assert_eq!(deny, PolicyDecision::Deny("test reason".to_string()));

        let ask = PolicyDecision::Ask {
            approval_id: "id".to_string(),
            approval_token: "tok".to_string(),
        };
        if let PolicyDecision::Ask { approval_id, .. } = ask {
            assert_eq!(approval_id, "id");
        }
    }
}
