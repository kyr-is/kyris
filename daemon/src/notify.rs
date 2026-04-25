// SPDX-License-Identifier: Apache-2.0

pub fn send_toast(title: &str, body: &str) {
    if let Err(e) = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .appname("Kyris")
        .show()
    {
        tracing::warn!(error = %e, "failed to send toast notification");
    }
}

pub fn circuit_breaker_toast(token_count: i64) {
    send_toast(
        "Kyris: Circuit Breaker",
        &format!("Circuit breaker: {token_count} tokens. Run `kyris continue` to resume."),
    );
}

pub fn mcp_pending_toast(tool: &str) {
    send_toast(
        "Kyris: MCP Approval Required",
        &format!("Agent wants to run {tool}. Run `kyris pending` to review."),
    );
}

pub fn daemon_recovery_toast(duration: &str) {
    send_toast(
        "Kyris Was Offline",
        &format!(
            "kyrisd was unreachable during {duration}. Run `kyris daemon status` to investigate."
        ),
    );
}

pub fn agentpactd_unreachable_toast() {
    send_toast("AgentPact Governance Was Offline", "Daemon unreachable.");
}

pub fn relay_sync_error_toast(reason: &str) {
    send_toast(
        "Kyris: Relay Sync Failed",
        &format!("Relay sync failed: {reason}. Events queued locally."),
    );
}
