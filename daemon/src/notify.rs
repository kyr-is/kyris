// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! User-facing toast notifications.
//!
//! On macOS, every UN center call runs in-process via the
//! `notify_macos` module (objc2 bindings, carved out from the
//! crate-wide `deny(unsafe_code)`). We tried a sibling Swift helper
//! binary and a subprocess approach; both failed because macOS's
//! notification daemon only honors requests from a process
//! `LaunchServices` identifies as a foreground-eligible app, and
//! kyrisd's children don't inherit that identity. See
//! `notify_macos` for the detailed rationale and Apple Forums thread
//! 679326.
//!
//! On non-macOS, delivery falls back to `notify-rust` (freedesktop
//! dbus on Linux); the dep is feature-gated on `tray` because
//! headless server builds don't need toasts.
//!
//! Every call also emits a `tracing::info!` line at
//! `target = "kyris::toast"`, so operators tailing
//! `kyrisd.stderr.log` see the content even when GUI delivery is
//! disabled, denied, or silently dropping.

/// Daemon-startup permission request. Idempotent. Has to run on the
/// daemon side (not in install.sh or a cask postflight) because
/// macOS only honors UN center calls from a `LaunchServices`-
/// registered process — see `notify_macos::request_authorization_if_needed`
/// and Apple Forums thread 679326.
pub fn request_authorization_if_needed() {
    #[cfg(target_os = "macos")]
    crate::notify_macos::request_authorization_if_needed();
}

/// User-facing approval outcomes. `Yes`/`No`/`Always` come from the user
/// clicking a button. `CouldNotShow` is the structural signal that the
/// dialog never became visible to the user (occluded, off-active-space,
/// off-screen, or otherwise undeliverable) and the caller should fall
/// back to another channel (menu-bar attention, TTY prompt, web UI)
/// rather than treating the absence of an answer as a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Yes,
    No,
    Always,
    CouldNotShow,
}

/// Show a modal Yes / No / Always dialog and return the user's choice.
/// On macOS with the tray feature this dispatches to the main thread via
/// the tao event loop; on other platforms it falls back to `Yes`.
///
/// `code`, when `Some`, is rendered in the popup's accessoryView as
/// monospaced text — the right surface for shell commands and file paths
/// (whose readability suffers in the standard `informativeText` font).
/// When `None`, the popup uses `body` alone.
#[cfg(feature = "tray")]
pub async fn ask_approval(title: &str, body: &str, code: Option<&str>) -> ApprovalOutcome {
    #[cfg(target_os = "macos")]
    {
        crate::tray::ask_approval(title, body, code).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, body, code);
        ApprovalOutcome::Yes
    }
}

pub fn send_toast(title: &str, body: &str) {
    tracing::info!(target: "kyris::toast", %title, %body, "toast");

    #[cfg(target_os = "macos")]
    crate::notify_macos::post(title, body);

    // TODO: Desktop toasts for Windows/Linux — not yet implemented.
    // The tracing::info! line above is the authoritative record.
    #[cfg(all(not(target_os = "macos"), feature = "tray"))]
    {}
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
    send_toast(
        "AgentPact Governance Was Offline",
        "agentpactd was unreachable. Run `kyris daemon status` to investigate.",
    );
}

pub fn relay_sync_error_toast(reason: &str) {
    send_toast(
        "Kyris: Relay Sync Failed",
        &format!("Relay sync failed: {reason}. Events queued locally."),
    );
}

pub fn spend_warning_toast(total_usd: f64, threshold_usd: f64, window_hours: u64) {
    send_toast(
        "Kyris: Spend Warning",
        &format!(
            "${total_usd:.2} spent in the last {window_hours}h \
             (threshold: ${threshold_usd:.2}). Run `kyris stats` for details."
        ),
    );
}

pub fn agent_drift_repaired_toast() {
    send_toast(
        "Kyris: Agent Config Repaired",
        "An agent's config was overwritten (e.g., by an update). Kyris detected and re-applied governance.",
    );
}
