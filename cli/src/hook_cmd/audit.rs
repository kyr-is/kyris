// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Best-effort hook audit: the per-invocation id, the kyrisd `/api/hook/log`
//! POST, and the execution-surface live-evidence note.

use super::payload::is_file_action;

/// 32-bit hex identifier attached to the `hook resolved` audit line for
/// a single hook invocation. Derived from nanoseconds since the epoch
/// XOR'd with the process id; collision risk inside one user's session
/// is nil and the resulting log is grep-friendly.
pub(super) fn generate_hook_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos());
    #[allow(clippy::cast_possible_truncation)]
    let id = (nanos as u32) ^ std::process::id();
    format!("{id:08x}")
}

/// Fire-and-forget POST of a single hook log entry to kyrisd's
/// `/api/hook/log` endpoint. Short timeout — kyrisd is local; if it
/// can't respond in 100ms the audit entry is lost but the hook's
/// actual policy decision (via agentpactd, separate socket) is
/// unaffected. Returns nothing; all errors are swallowed.
fn post_hook_log_blocking(conn: &kyris_core::config::KyrisdConnection, body: serde_json::Value) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let base_url = conn.base_url.clone();
    let token = conn.operator_key.clone();
    let _ = rt.block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .ok()?;
        client
            .post(format!("{base_url}/api/hook/log"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .ok()
    });
}

/// Single audit call per hook. Sends one combined payload to kyrisd's
/// `/api/hook/log`, which emits a single `hook resolved` log line. No-op
/// when kyrisd isn't configured/reachable — audit is best-effort, the
/// actual policy decision (via agentpactd, separate socket) is unaffected.
///
/// `segments` is populated only when the daemon split a compound shell
/// command (more than one segment); `approval_id` only when the request
/// went through an Ask path. Both are omitted from the log line when None.
///
/// `agent_prompt` records whether kyris's response to the agent leaves room
/// for the agent to show its own permission prompt: `"none"` means kyris
/// either blocked (exit 2) or returned a definitive allow-shape that
/// suppresses the agent's prompt; `"agent_decides"` means kyris allowed
/// silently (empty stdout) and the agent will apply its own permission
/// rules, which may or may not prompt.
#[allow(clippy::too_many_arguments)]
pub(super) fn audit_log_hook(
    conn: Option<&kyris_core::config::KyrisdConnection>,
    hook_id: &str,
    agent: &str,
    action: &str,
    detail: &str,
    segments: Option<&[String]>,
    decision: &str,
    source: &str,
    approval_id: Option<&str>,
    agent_prompt: &str,
    elapsed: std::time::Duration,
) {
    let Some(conn) = conn else { return };
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = elapsed.as_millis() as u64;
    // Log file paths home-relative (display/privacy only — the decision already
    // ran on the absolute path). Command `detail`/`segments` are left verbatim.
    let detail = if is_file_action(action) {
        kyris_core::path_display::home_relative(detail)
    } else {
        detail.to_string()
    };
    let mut body = serde_json::json!({
        "hook_id": hook_id,
        "agent": agent,
        "action": action,
        "detail": detail,
        "decision": decision,
        "source": source,
        "agent_prompt": agent_prompt,
        "elapsed_ms": elapsed_ms,
    });
    if let Some(segs) = segments {
        body["segments"] = serde_json::json!(segs);
    }
    if let Some(id) = approval_id {
        body["approval_id"] = serde_json::json!(id);
    }
    post_hook_log_blocking(conn, body);
}

/// Record execution-surface live evidence: a real decision round-tripped
/// through this agent's live hook. The shell gate is not an agent surface.
pub(super) fn record_execution_live_evidence(agent: &str) {
    if agent != "shell" {
        kyris_core::live_evidence::record(agent, kyris_core::live_evidence::SURFACE_EXECUTION);
    }
}
