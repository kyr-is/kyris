// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Shared hold-poll-resolve pattern for `PACT_ASK` approval delegation
//! through `kyrisd`'s pending-approval system. Used by both `kyris-mcp`
//! (no-TTY MCP wrapper) and `kyris hook check` (native agent hooks).

use crate::config::KyrisdConnection;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    Approved,
    Denied,
    Failed(String),
}

pub async fn hold_poll_resolve(
    client: &reqwest::Client,
    conn: &KyrisdConnection,
    approval_id: &str,
    approval_token: &str,
    server: &str,
    tool: &str,
) -> Resolution {
    let hold_body = serde_json::json!({
        "id": approval_id,
        "approval_token": approval_token,
        "server": server,
        "tool": tool,
    });

    let hold_result = client
        .post(format!("{}/api/pending/hold", conn.base_url))
        .header("authorization", format!("Bearer {}", conn.operator_key))
        .json(&hold_body)
        .send()
        .await;

    match hold_result {
        Ok(ref r) if r.status().is_success() => {}
        _ => {
            return Resolution::Failed("kyrisd unreachable or rejected hold request".to_string());
        }
    }

    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        if tokio::time::Instant::now() >= deadline {
            cancel(client, conn, approval_id).await;
            return Resolution::Failed("approval timed out".to_string());
        }

        let status_result = client
            .get(format!(
                "{}/api/pending/{}/status",
                conn.base_url, approval_id
            ))
            .header("authorization", format!("Bearer {}", conn.operator_key))
            .send()
            .await;

        let Ok(resp) = status_result else {
            continue;
        };
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };

        match body.get("state").and_then(|s| s.as_str()) {
            Some("held") => {}
            Some("approved") => return Resolution::Approved,
            Some("denied") => return Resolution::Denied,
            _ => {
                cancel(client, conn, approval_id).await;
                return Resolution::Failed("unexpected pending state".to_string());
            }
        }
    }
}

async fn cancel(client: &reqwest::Client, conn: &KyrisdConnection, pending_id: &str) {
    let url = format!("{}/api/pending/{pending_id}/cancel", conn.base_url);
    let _ = client
        .delete(&url)
        .header("authorization", format!("Bearer {}", conn.operator_key))
        .send()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testResolutionEquality() {
        assert_eq!(Resolution::Approved, Resolution::Approved);
        assert_eq!(Resolution::Denied, Resolution::Denied);
        assert_ne!(Resolution::Approved, Resolution::Denied);
    }
}
