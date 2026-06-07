// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Shared hold-poll-resolve pattern for `PACT_ASK` approval delegation
//! through `kyrisd`'s pending-approval system. Used by both `kyris-mcp`
//! (no-TTY MCP wrapper) and `kyris hook check` (native agent hooks).

use crate::config::KyrisdConnection;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const POLL_TIMEOUT: std::time::Duration = NATIVE_HOOK_POLL_TIMEOUT;

/// How long the no-TTY resolver waits for a developer to answer before giving
/// up — kept **as large as possible** so a developer can start a command, walk
/// away, and still approve it on return.
///
/// The hard ceiling is the agent's own hook timeout: Claude Code (and Codex)
/// kill a `PreToolUse` hook at **600s** (10 min — raised from 60s in Claude
/// 2.1.3); if our poll outran that, the agent would kill the hook first and
/// fall back to its own prompt (the double-prompt symptom). So we sit just
/// under it at 590s. (Gemini's default hook timeout is 60s, so its adapter sets
/// an explicit longer hook `timeout`; see the gemini-cli agent config.)
///
/// The rest of the approval chain must clear this window or it would bind
/// first: kyrisd's pending TTL (`mcp.pending_timeout_seconds`) and agentpact's
/// `approval_token.ttl_secs` are both defaulted above 590s.
pub const NATIVE_HOOK_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(590);

#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    Approved,
    Denied,
    /// The hold could not be established — kyrisd was unreachable or rejected
    /// the hold request. The approval dialog was **never rendered**, so the
    /// human was never asked. A down ask-renderer must never block the
    /// developer, so callers fall open / defer to the agent's own prompt.
    Unreachable,
    /// The hold *was* established (the dialog rendered) but resolution failed —
    /// it timed out or the pending entered an unexpected state. The human may
    /// have been mid-decision, so this must **never** fall open: block.
    Failed(String),
}

/// Identity + display payload for a `PACT_ASK` request held in kyrisd.
///
/// Bundles the five name-shaped strings that always travel together so
/// `hold_poll_resolve` and `hold_poll_resolve_with_timeout` keep a tight
/// signature. Borrowed for the lifetime of the call — no allocation; the
/// fields are typically slices of caller-owned `String`s already on the
/// stack.
#[derive(Debug, Clone, Copy)]
pub struct PendingApproval<'a> {
    /// Approval ID from agentpactd's `PACT_ASK` response. kyrisd keys its
    /// pending-store on this.
    pub approval_id: &'a str,
    /// Single-use token from agentpactd that authorises the follow-up
    /// `permission.respond` once the user resolves.
    pub approval_token: &'a str,
    /// Popup title slot ("Kyris: Allow <server>"). For MCP it's the MCP
    /// server name; for native hooks it's a category like "shell".
    pub server: &'a str,
    /// Popup body fallback (typically a tool name like "Bash", "Read").
    pub tool: &'a str,
    /// Optional verbatim payload (shell command, file path, serialized
    /// MCP args) for the popup's syntect-highlighted accessoryView. `None`
    /// lets the daemon fall back to plain-text informativeText.
    pub code: Option<&'a str>,
    /// Whether the popup may offer "Always". `false` (e.g. privilege
    /// escalation, which agentpactd never persists) greys out the button.
    /// Defaults to `true` for callers that don't set it via `..Default`.
    pub allow_always: bool,
}

impl Default for PendingApproval<'_> {
    fn default() -> Self {
        Self {
            approval_id: "",
            approval_token: "",
            server: "",
            tool: "",
            code: None,
            allow_always: true,
        }
    }
}

/// Hold a `PACT_ASK` request in kyrisd and poll until the user resolves it
/// (or the default 60s timeout fires). Used by `kyris-mcp` and other surfaces
/// that do not race against an external hook timeout.
pub async fn hold_poll_resolve(
    client: &reqwest::Client,
    conn: &KyrisdConnection,
    approval: PendingApproval<'_>,
) -> Resolution {
    hold_poll_resolve_with_timeout(client, conn, approval, POLL_TIMEOUT).await
}

/// Variant of `hold_poll_resolve` with a caller-specified deadline. Native
/// agent hooks (Claude Code, Codex CLI, Gemini CLI) must pass
/// `NATIVE_HOOK_POLL_TIMEOUT` so the resolver returns before the agent's
/// own hook timeout fires.
pub async fn hold_poll_resolve_with_timeout(
    client: &reqwest::Client,
    conn: &KyrisdConnection,
    approval: PendingApproval<'_>,
    max_wait: std::time::Duration,
) -> Resolution {
    // `approval.code` is the verbatim payload (shell command, file path,
    // MCP args) — kyrisd uses it as the accessoryView text and runs syntect
    // coloring over it. Shell hooks always have a verbatim payload; if
    // `code` is None the daemon falls back to plain-text informativeText.
    let hold_body = serde_json::json!({
        "id": approval.approval_id,
        "approval_token": approval.approval_token,
        "server": approval.server,
        "tool": approval.tool,
        "code": approval.code,
        "allow_always": approval.allow_always,
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
            // Never got the dialog up — distinct from a rendered-then-lost
            // failure below, so the caller can defer to the agent's own prompt.
            return Resolution::Unreachable;
        }
    }

    let deadline = tokio::time::Instant::now() + max_wait;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        if tokio::time::Instant::now() >= deadline {
            cancel(client, conn, approval.approval_id).await;
            return Resolution::Failed("approval timed out".to_string());
        }

        let status_result = client
            .get(format!(
                "{}/api/pending/{}/status",
                conn.base_url, approval.approval_id
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
                cancel(client, conn, approval.approval_id).await;
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
