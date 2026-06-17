// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Agent-native response shaping: the audit `agent_prompt` value, the
//! mode-correct allow shape, and the stdout/stderr emitters.
//!
//! All agents treat exit 2 + stderr as a hard block, so deny is universal.
//! Allow varies per agent: some expect empty stdout, others expect JSON.

use crate::agents::registry::AllowResponse;

/// Whether the agent will still get to apply its own permission rules after
/// kyris's response. Only meaningful when kyris allows; deny paths always
/// return `"none"` because exit-2 blocks the action universally.
///
/// Derived from the allow shape AND the agent's declared allow EFFECT (G2):
/// emitting a JSON allow does not by itself silence the agent — gemini parses
/// its `{"decision":"allow"}` and prompts anyway, while Claude's
/// `permissionDecision: allow` genuinely suppresses. `EmptyStdout` is "no
/// decision" everywhere, so the agent always decides.
pub(super) fn agent_prompt_for(
    allow_response: &AllowResponse,
    suppresses_agent_prompt: bool,
) -> &'static str {
    match allow_response {
        AllowResponse::Json { .. } if suppresses_agent_prompt => "none",
        AllowResponse::Json { .. } | AllowResponse::EmptyStdout => "agent_decides",
    }
}

/// Resolve the allow shape kyris will actually emit. In `mode: enforce`
/// this is whatever the agent's `HookProtocol` declares (e.g. Claude
/// Code expects a JSON `permissionDecision: allow` to skip its prompt).
/// In `mode: log` we force `EmptyStdout` regardless of the agent's
/// native shape — log mode must not alter agent behavior, so kyris
/// hands the decision back to the agent's own permission system.
///
/// Failing to do this would mean every command in log mode silently
/// bypasses Claude Code's / Gemini CLI's own prompt UX, defeating the
/// "observe only" contract — the user expects log mode to be a
/// no-op as far as the agent is concerned.
pub(super) fn effective_allow_response(native: &AllowResponse, log_mode: bool) -> AllowResponse {
    if log_mode {
        AllowResponse::EmptyStdout
    } else {
        native.clone()
    }
}

/// The allow shape for a tool that never reaches agentpactd.
///
/// - `pass_through` (a blessed coordination primitive): emit the agent's
///   native allow shape so its own prompt is suppressed and the primitive runs
///   frictionlessly — except in log mode, where we still defer.
/// - **unmapped** (a tool kyris does not recognize): emit the `EmptyStdout`
///   "no decision" shape so the agent's own permission system decides. kyris
///   neither prompts nor suppresses — it behaves as if it were not installed.
///   Emitting the native allow shape here would silently approve an unknown,
///   possibly side-effecting tool (fail-open), which is exactly what must not
///   happen for an ungoverned tool.
pub(super) fn non_governed_response(
    pass_through: bool,
    native: &AllowResponse,
    log_mode: bool,
) -> AllowResponse {
    if pass_through {
        effective_allow_response(native, log_mode)
    } else {
        AllowResponse::EmptyStdout
    }
}

pub(super) fn emit_allow(allow_response: &AllowResponse) {
    match allow_response {
        AllowResponse::EmptyStdout => {}
        AllowResponse::Json { body } => {
            println!("{}", serde_json::to_string(body).unwrap_or_default());
        }
    }
}

pub(super) fn emit_deny(reason: &str) {
    eprintln!("[agentpact] {reason}");
}
