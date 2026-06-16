// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//
// AgentPact wire types shared across the kyris workspace. The wire-message
// *builders* and the response parser live in `kyris-agentpact-client` — per
// BOUNDARY.md only that crate may construct or interpret agentpactd wire
// messages. The types below are read-only value types that other kyris
// crates need without ever talking to the daemon directly.
use std::path::PathBuf;

/// Re-export of the canonical [`agentpact_types::Mode`] so kyris-core
/// consumers that already import from this module keep working
/// after the type was extracted to its own crate. The wire value is
/// defined once, in `agentpact-types` — see
/// [`McpPermissionDecision::Allow`] for where the parser surfaces it.
pub use agentpact_types::Mode;

/// Machine-readable cause code for a governance denial (I-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyCode {
    /// `PACT_DENIED` — tool blocked by policy.
    PolicyDenied,
    /// `PACT_CAP_EXCEEDED` — spend / rate cap exceeded.
    CapExceeded,
    /// `PACT_POLICY_ERROR` / `PACT_PROTOCOL_ERROR` — policy or protocol misconfiguration.
    PolicyError,
    /// Daemon unreachable (connection error, not a daemon response code).
    DaemonUnreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpPermissionDecision {
    Allow {
        /// Effective mode the daemon was in for this request. Hook
        /// adapters MUST check this and switch their allow shape to
        /// `EmptyStdout` (defer to agent) when the value is
        /// [`Mode::Log`] — otherwise log mode silently overrides the
        /// agent's permission UX, which is the bug log mode exists to
        /// avoid.
        mode: Mode,
    },
    Deny {
        code: DenyCode,
        reason: String,
        /// Daemon-supplied recovery hint. `None` → caller uses static I-05 table.
        hint: Option<String>,
    },
    Ask {
        approval_id: String,
        approval_token: String,
        /// Authoritative server signal: whether answering "For session" would
        /// actually persist a session-scoped grant. UX surfaces offer the
        /// "For session" choice (field name stays `allow_always` for wire
        /// stability) only when this is `true`. Defaults to `false` when the daemon omits
        /// it (older daemon / malformed response) — conservative: a missing
        /// signal means don't advertise a grant that may not stick.
        allow_always: bool,
        /// Pre-formatted "why this needs approval" body for the approval popup,
        /// rendered by the wire interpreter from the daemon's structured
        /// [`agentpact_types::AskContext`] (see [`format_ask_context`]). `None`
        /// when the daemon sent no ask-context (older daemon / non-popup path).
        detail: Option<String>,
    },
}

/// Render the daemon's structured ask-context into a human popup body — one
/// line per effect (`action resource — note`), then unresolved heads, sandbox
/// bounds, and what "For session" does. Presentation lives here (kyris owns the UX);
/// the daemon emits facts.
#[must_use]
pub fn format_ask_context(ctx: &agentpact_types::AskContext) -> String {
    use agentpact_types::RememberInfo;
    let mut lines: Vec<String> = Vec::new();
    for effect in &ctx.effects {
        // Surface an effect only when it carries a notable classification — a
        // real warning worth weighing before approving (secret material,
        // recursive delete, elevated privileges, external host, a remote
        // change, …). Unremarkable effects (a plain `exec` / `read` / in-
        // workspace write) are log-tier: the command itself is shown in the
        // dialog and the classification is in the event log, so repeating it
        // here is noise.
        let Some(note) = &effect.note else {
            continue;
        };
        let line = match &effect.resource {
            Some(resource) => format!("• {} {resource} — {note}", effect.action),
            None => format!("• {} — {note}", effect.action),
        };
        lines.push(line);
    }
    if !ctx.unresolved.is_empty() {
        lines.push(format!("• unresolved: {}", ctx.unresolved.join(", ")));
    }
    if let Some(sandbox) = &ctx.sandbox {
        lines.push(format_sandbox(sandbox));
    }
    match &ctx.remember {
        Some(RememberInfo::Session { scope }) => {
            lines.push(format!(
                "\u{201c}For session\u{201d} remembers {scope} for the rest of the session."
            ));
        }
        Some(RememberInfo::NotRemembered { reason }) => {
            lines.push(format!("Won\u{2019}t be remembered: {reason}"));
        }
        None => {}
    }
    lines.join("\n")
}

/// One line describing the OS jail: backend + verified status, the writable
/// bounds (when known), and the network scope — so the prompt states *why* a
/// command is physically contained, not just "sandboxed".
fn format_sandbox(sandbox: &agentpact_types::SandboxFact) -> String {
    use agentpact_types::{SandboxBackend, SandboxNetwork};
    let backend = match sandbox.capability.backend {
        SandboxBackend::MacosSeatbelt => "macOS Seatbelt",
        SandboxBackend::None => "OS jail",
    };
    let status = if sandbox.verified {
        "verified"
    } else {
        "unverified — protection not confirmed"
    };
    let mut line = format!("Sandboxed ({backend}, {status})");
    if !sandbox.capability.writable_roots.is_empty() {
        line.push_str(" — writes bounded to ");
        line.push_str(&sandbox.capability.writable_roots.join(", "));
    }
    match &sandbox.capability.network {
        SandboxNetwork::Full => {}
        SandboxNetwork::Off => line.push_str("; network off"),
        SandboxNetwork::Allowlisted(_) => line.push_str("; network allowlisted"),
    }
    line
}

#[cfg(test)]
mod ask_context_tests {
    use super::format_ask_context;
    use agentpact_types::{
        AskContext, EffectFact, RememberInfo, SandboxBackend, SandboxCapability, SandboxFact,
    };

    #[test]
    fn testFormatRendersEffectsSandboxAndRemember() {
        let ctx = AskContext {
            effects: vec![
                // Notable → shown.
                EffectFact {
                    action: "write".to_string(),
                    resource: Some(".git/hooks/pre-commit".to_string()),
                    note: Some("repo control metadata".to_string()),
                },
                // Unremarkable (no note) → suppressed (log-tier, not a warning).
                EffectFact {
                    action: "exec".to_string(),
                    resource: None,
                    note: None,
                },
            ],
            unresolved: vec!["mystery_tool".to_string()],
            sandbox: Some(SandboxFact {
                capability: SandboxCapability {
                    backend: SandboxBackend::MacosSeatbelt,
                    writable_roots: vec!["/repo".to_string(), "/tmp".to_string()],
                    ..Default::default()
                },
                verified: true,
            }),
            remember: Some(RememberInfo::Session {
                scope: "this command".to_string(),
            }),
        };
        let body = format_ask_context(&ctx);
        assert!(
            body.contains("write .git/hooks/pre-commit — repo control metadata"),
            "{body}"
        );
        // The noteless `exec` effect is suppressed — it's not a warning.
        assert!(!body.contains("• exec"), "{body}");
        assert!(body.contains("unresolved: mystery_tool"), "{body}");
        assert!(
            body.contains("Sandboxed (macOS Seatbelt, verified) — writes bounded to /repo, /tmp"),
            "{body}"
        );
        assert!(body.contains("\u{201c}For session\u{201d}"), "{body}");
        assert!(body.contains("rest of the session"), "{body}");
    }

    #[test]
    fn testFormatNotRememberedReason() {
        let ctx = AskContext {
            effects: vec![EffectFact {
                action: "remote_delete".to_string(),
                resource: Some("eks/prod".to_string()),
                note: Some("destroys cloud resources".to_string()),
            }],
            unresolved: Vec::new(),
            sandbox: None,
            remember: Some(RememberInfo::NotRemembered {
                reason: "remote-destroy".to_string(),
            }),
        };
        let body = format_ask_context(&ctx);
        assert!(
            body.contains("remote_delete eks/prod — destroys cloud resources"),
            "{body}"
        );
        assert!(
            body.contains("Won\u{2019}t be remembered: remote-destroy"),
            "{body}"
        );
    }
}

#[derive(Debug, Clone, Default)]
pub struct ToolAnnotations {
    pub read_only_hint: Option<bool>,
    pub destructive_hint: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct McpContext {
    pub working_dir: Option<String>,
    pub mcp_operation: Option<String>,
    pub annotations: ToolAnnotations,
    /// Declared agent identity (canonical `vendor/name`) for the agent whose
    /// tool call is being mediated. Both MCP surfaces hold it with certainty —
    /// kyrisd's HTTP routing from the `x-kyris-agent-id` header its own
    /// rewrite stamped, the stdio wrap from its kyris-written `--agent` flag —
    /// whereas agentpactd's process-tree attribution would resolve the
    /// MEDIATOR (kyrisd / kyris-mcp), not the agent. None for pre-upgrade
    /// wraps and direct use.
    pub declared_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResponse {
    Approved,
    Denied,
    Always,
}

impl ApprovalResponse {
    #[must_use]
    pub fn as_agentpact_response(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Always => "always",
        }
    }

    #[must_use]
    pub fn allows_execution(self) -> bool {
        matches!(self, Self::Approved | Self::Always)
    }
}

#[must_use]
pub fn daemon_unavailable_message() -> String {
    "AgentPact daemon is unreachable.".to_string()
}

#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("AGENTPACT_SOCK") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.agentpact/agentpact.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testApprovalResponseAllowsExecution() {
        assert!(ApprovalResponse::Approved.allows_execution());
        assert!(ApprovalResponse::Always.allows_execution());
        assert!(!ApprovalResponse::Denied.allows_execution());
    }

    // Mode is now re-exported from `agentpact-types`; its
    // from_wire/as_wire/is_log/Display tests live in that crate.
    // Don't duplicate them here — the re-export is statically
    // verified to compile and tests on the canonical home cover
    // the wire-form contract.
}
