// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Per-segment governance: real (token-bearing) classification, the popup
//! drive loop, the patch-envelope batch driver, and the native-ask emitter.

use kyris_agentpact_client::{self as pact_client, ApprovalResponse, McpPermissionDecision};

use crate::agents::registry::{AllowResponse, ApprovalMode, AskResponse};

use super::audit::{audit_log_hook, record_execution_live_evidence};
use super::hold::declared_canonical_agent;
use super::payload::{is_file_action, parse_apply_patch_paths, resolve_relative_path};
use super::request::{PermissionCtx, deny_for_missing_backstop};
use super::response::{agent_prompt_for, effective_allow_response, emit_allow, emit_deny};

/// Margin added to a caller's poll window when sizing the approval-token TTL
/// (`approval_ttl_secs`): the user can answer at the very end of the window
/// and the `permission.respond` round-trip must still find a live token.
const APPROVAL_TTL_MARGIN_SECS: u64 = 120;

/// A single segment's classification from a real (token-bearing) request.
pub(super) enum SegClass {
    /// Catalog/default/already-"always"-allowed — runs with no popup.
    Auto,
    /// Needs approval; carries the token that drives its popup and the
    /// daemon's authoritative `allow_always` (whether "Always" would persist).
    Ask {
        approval_id: String,
        approval_token: String,
        allow_always: bool,
        /// Pre-formatted "why this needs approval" popup body from the daemon's
        /// structured ask-context (`None` → terse default).
        detail: Option<String>,
    },
    /// Policy denied this segment.
    Deny { reason: String },
    /// agentpactd was unreachable while classifying this segment.
    Unavailable { reason: String },
}

/// The outcome of driving one segment's approval popup (no agent response
/// is emitted here — the caller emits exactly once after the loop).
pub(super) enum PopupResult {
    Approved {
        source: &'static str,
    },
    Blocked {
        exit_code: i32,
        source: &'static str,
        reason: String,
    },
}

/// Why the whole command was blocked, with the exit code and audit source.
#[derive(Debug)]
pub(super) struct SegBlock {
    pub(super) exit_code: i32,
    pub(super) source: &'static str,
    pub(super) reason: String,
}

/// Pure aggregation over a command's segments. Auto segments pass; the first
/// `Deny`, an `Unavailable` (the decider is down), or a blocked popup stops the
/// walk and returns a [`SegBlock`] for the whole command (the agent runs it as a
/// unit, so a partial approval is useless). Returns the audit `source` for the
/// allow path, or a [`SegBlock`] otherwise.
///
/// `Unavailable` returns a block tagged `agentpact_unreachable`; it is the
/// *caller* that decides what unavailability means — the agent hook defers to
/// the agent's own prompt, the shell gate fails open — so this function does not
/// itself fail open or closed.
///
/// I/O lives entirely in the injected closures, so this is unit-tested
/// directly with canned classifications and popup results.
pub(super) fn run_segments<C, P>(
    segments: &[String],
    mut classify: C,
    mut prompt: P,
) -> Result<&'static str, SegBlock>
where
    C: FnMut(&str) -> SegClass,
    P: FnMut(&str, &str, &str, bool, Option<&str>) -> PopupResult,
{
    let mut source: &'static str = "agentpact_auto";
    for seg in segments {
        match classify(seg) {
            SegClass::Auto => {}
            SegClass::Deny { reason } => {
                return Err(SegBlock {
                    exit_code: 2,
                    source: "agentpact_deny",
                    reason,
                });
            }
            SegClass::Unavailable { reason } => {
                return Err(SegBlock {
                    exit_code: 2,
                    source: "agentpact_unreachable",
                    reason,
                });
            }
            SegClass::Ask {
                approval_id,
                approval_token,
                allow_always,
                detail,
            } => match prompt(
                &approval_id,
                &approval_token,
                seg,
                allow_always,
                detail.as_deref(),
            ) {
                PopupResult::Approved { source: s } => source = s,
                PopupResult::Blocked {
                    exit_code,
                    source: s,
                    reason,
                } => {
                    return Err(SegBlock {
                        exit_code,
                        source: s,
                        reason,
                    });
                }
            },
        }
    }
    Ok(source)
}

/// Drive per-segment approval, emit one agent response, and exit. `segments`
/// is the daemon's parsed split; when it did not split (single command,
/// non-execute action) we treat the whole `detail` as the one segment. Each
/// segment is classified with a real, token-bearing request, so this is what
/// audits the command, counts the circuit breaker, issues exec tokens, and
/// updates session cwd — for every command, not just asks.
///
/// `log_mode` selects the success allow shape: in log mode the agent must keep
/// its own permission UX, so we emit `EmptyStdout` (defer); in enforce mode we
/// emit the agent's native allow shape (suppressing its prompt for a command
/// `AgentPact` already cleared).
pub(super) fn drive_per_segment(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    segments: Option<Vec<String>>,
    log_mode: bool,
) -> ! {
    let segs = segments.unwrap_or_else(|| vec![ctx.detail.to_string()]);
    // Compound line (>=2 segments) → drive per-segment but audit as one event.
    let command_group_id = (segs.len() >= 2).then(pact_client::new_command_group);
    let batch = ActionBatch {
        action: ctx.action.to_string(),
        segments: segs,
    };
    drive_batches(ctx, seed_pid, vec![batch], log_mode, command_group_id)
}

/// One governed action applied to a list of details: the daemon's compound
/// split for `execute`, or one file-path batch of a patch envelope.
pub(super) struct ActionBatch {
    action: String,
    segments: Vec<String>,
}

/// Per-file governance for a patch envelope (`apply_patch`): kyris parses the
/// touched paths itself (the grammar is fixed; the daemon's splitter is for
/// shell text) and drives a `write` batch and a `delete` batch through the
/// same real-request machinery — each file is decided against the actual
/// workspace boundary instead of the old single-request shape, whose "path"
/// was the entire patch text lexically joined to the cwd (always inside the
/// workspace, so out-of-tree targets were mis-anchored).
pub(super) fn drive_apply_patch(ctx: &PermissionCtx<'_>, seed_pid: Option<u32>) -> ! {
    let parsed = parse_apply_patch_paths(ctx.detail);
    if parsed.writes.is_empty() && parsed.deletes.is_empty() {
        // Not a parseable envelope — never guess paths. Backstopped agents
        // defer (the agent's own approval still gates the patch); without a
        // backstop, enforce mode denies (a defer would be a silent allow).
        if !ctx.native_backstop && !ctx.log_mode_fallback {
            deny_for_missing_backstop(ctx, None, "unparseable_patch");
        }
        eprintln!(
            "[agentpact] warning: apply_patch payload has no recognizable file \
             markers; deferring to {}'s own approval",
            ctx.agent
        );
        audit_log_hook(
            ctx.audit_conn,
            ctx.hook_id,
            ctx.agent,
            ctx.action,
            ctx.detail,
            None,
            "defer",
            "unparseable_patch",
            None,
            agent_prompt_for(&AllowResponse::EmptyStdout, false),
            ctx.started_at.elapsed(),
        );
        emit_allow(&AllowResponse::EmptyStdout);
        std::process::exit(0);
    }

    let resolve = |paths: Vec<String>| -> Vec<String> {
        paths
            .iter()
            // "write" engages the relative-path join; patch paths resolve
            // against the same cwd codex resolves them against.
            .map(|p| resolve_relative_path("write", p, ctx.cwd))
            .collect()
    };
    let mut batches = Vec::new();
    if !parsed.writes.is_empty() {
        batches.push(ActionBatch {
            action: "write".to_string(),
            segments: resolve(parsed.writes),
        });
    }
    if !parsed.deletes.is_empty() {
        batches.push(ActionBatch {
            action: "delete".to_string(),
            segments: resolve(parsed.deletes),
        });
    }

    // Scout the per-request mode from a side-effect-free preview of the first
    // path so a repo-local log-mode override is honored (the generic flow gets
    // this from its whole-command preview).
    let log_mode = match pact_client::request_hook_permission_preview(
        ctx.sock_path,
        "kyris-hook",
        &batches[0].action,
        &batches[0].segments[0],
        ctx.cwd,
        seed_pid,
        declared_canonical_agent(ctx.agent).as_deref(),
        ctx.socket_timeout,
    ) {
        Ok((McpPermissionDecision::Allow { mode }, _)) => mode.is_log(),
        Ok(_) => false,
        Err(_) => ctx.log_mode_fallback,
    };

    drive_batches(ctx, seed_pid, batches, log_mode, None)
}

#[allow(clippy::too_many_lines)]
fn drive_batches(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    batches: Vec<ActionBatch>,
    log_mode: bool,
    command_group_id: Option<String>,
) -> ! {
    let command_group = command_group_id.as_deref().map(|group| (group, ctx.detail));
    let all_segs: Vec<String> = batches
        .iter()
        .flat_map(|b| b.segments.iter().cloned())
        .collect();

    // Native mode delegates an `ask` to the agent's own prompt instead of
    // holding kyris's popup. We still classify every segment (audit, breaker,
    // exec token); a single `ask` anywhere makes the whole tool call a native
    // ask, while a deny still wins.
    let native_mode = ctx.approval_mode == ApprovalMode::Native && ctx.native_ask.is_some();
    let mut native_ask_requested = false;
    let mut source: &'static str = "agentpact_auto";
    let mut blocked: Option<SegBlock> = None;
    for batch in &batches {
        let result = run_segments(
            &batch.segments,
            |seg| classify_segment(ctx, seed_pid, &batch.action, seg, command_group),
            |approval_id, approval_token, seg, allow_always, detail| {
                if native_mode {
                    // Do NOT hold: the agent will prompt its own user. Leave the
                    // agentpactd ASK token to expire — recording a deny here
                    // would be an audit lie, since the agent may approve.
                    native_ask_requested = true;
                    return PopupResult::Approved {
                        source: "native_ask",
                    };
                }
                // The poll deadline is a budget for the WHOLE hook invocation,
                // not per popup: N sequential asks (a compound line, a
                // multi-file patch) must still resolve before the agent's
                // fail-open hook timeout, or the entire request would run
                // ungoverned with stale popups left pending. An exhausted
                // budget makes the remaining asks time out immediately —
                // a clean deny instead of the agent's timer firing.
                let remaining = ctx.poll_deadline.saturating_sub(ctx.started_at.elapsed());
                poll_segment(
                    ctx.agent,
                    &batch.action,
                    ctx.sock_path,
                    ctx.socket_timeout,
                    approval_id,
                    approval_token,
                    seg,
                    allow_always,
                    detail,
                    remaining,
                )
            },
        );
        match result {
            // A human approval anywhere in the walk is the significant source.
            Ok(s) if s != "agentpact_auto" => source = s,
            Ok(_) => {}
            Err(block) => {
                blocked = Some(block);
                break;
            }
        }
    }

    // Finalize the buffered aggregate into one event (best-effort; expiry sweep
    // backstops a dropped commit).
    if let Some(group) = &command_group_id {
        pact_client::send_command_commit(ctx.sock_path, group, ctx.socket_timeout);
    }

    let segs = all_segs;
    match blocked.map_or(Ok(source), Err) {
        Ok(source) => {
            if native_ask_requested {
                // An `ask` routed to the agent's native prompt: emit the native
                // ask shape (or abstain for codex's PermissionRequest) and never
                // reach the allow path below. Deny would have won above.
                emit_native_ask(ctx, segs.as_slice(), log_mode);
            }
            // The adapted execution surface just worked end-to-end (real
            // agentpactd decision behind a live agent hook) — record it.
            record_execution_live_evidence(ctx.agent);
            // A popup-approved request leaves a short-lived note so the
            // agent's native-approval hook (codex PermissionRequest) does not
            // prompt the human a SECOND time for the same request. Only
            // recorded for agents with a consumer — anything else is dead
            // state churn.
            if matches!(source, "user_approved" | "user_always") && ctx.has_permission_request {
                crate::recent_approvals::record(ctx.agent, ctx.action, ctx.cwd, ctx.detail);
            }
            let response = effective_allow_response(ctx.native_allow_response, log_mode);
            audit_log_hook(
                ctx.audit_conn,
                ctx.hook_id,
                ctx.agent,
                ctx.action,
                ctx.detail,
                Some(segs.as_slice()),
                "allow",
                source,
                None,
                agent_prompt_for(&response, ctx.allow_suppresses_agent_prompt),
                ctx.started_at.elapsed(),
            );
            emit_allow(&response);
            std::process::exit(0);
        }
        Err(block) if block_from_daemon_unavailable(block.source) => {
            // A daemon was unavailable: either agentpactd (the decider) is down,
            // or it returned a real "ask" but kyrisd (the no-TTY ask renderer)
            // couldn't show the dialog. With a native backstop, never block the
            // developer — defer to the AGENT's own permission UX by emitting the
            // EmptyStdout shape, so the human still decides via the agent's
            // prompt, and spool it so the audit trail shows kyris punted this
            // command. Without one (G1), a defer is a silent allow — deny,
            // except in log mode (observe-only must never alter agent behavior;
            // `log_mode` here is the preview's authoritative per-request mode).
            // A real deny / user denial / rendered-then-timed-out ask always
            // blocks below.
            if !ctx.native_backstop && !log_mode {
                deny_for_missing_backstop(ctx, Some(segs.as_slice()), block.source);
            }
            kyris_core::fail_open_log::record(ctx.agent, ctx.action, ctx.detail, "shell", ctx.cwd);
            audit_log_hook(
                ctx.audit_conn,
                ctx.hook_id,
                ctx.agent,
                ctx.action,
                ctx.detail,
                Some(segs.as_slice()),
                "defer",
                block.source,
                None,
                agent_prompt_for(&AllowResponse::EmptyStdout, false),
                ctx.started_at.elapsed(),
            );
            emit_allow(&AllowResponse::EmptyStdout);
            std::process::exit(0);
        }
        Err(block) => {
            record_execution_live_evidence(ctx.agent);
            audit_log_hook(
                ctx.audit_conn,
                ctx.hook_id,
                ctx.agent,
                ctx.action,
                ctx.detail,
                Some(segs.as_slice()),
                "deny",
                block.source,
                None,
                "none",
                ctx.started_at.elapsed(),
            );
            emit_deny(&block.reason);
            std::process::exit(block.exit_code);
        }
    }
}

/// Route an `ask` to the agent's OWN native approval prompt (native mode),
/// instead of holding kyris's popup. For an [`AskResponse::NativePrompt`] agent
/// (claude/gemini) this emits the agent's ask JSON; for
/// [`AskResponse::DeferToNativeApproval`] (codex) it abstains (empty stdout) so
/// the agent's separate native-approval hook drives the prompt. Audits and exits
/// 0; never returns. In log mode it defers — observe-only must not force a
/// prompt.
fn emit_native_ask(ctx: &PermissionCtx<'_>, segs: &[String], log_mode: bool) -> ! {
    // The adapted execution surface round-tripped a real decision (the
    // per-segment classify), so it is live regardless of who renders the ask.
    record_execution_live_evidence(ctx.agent);

    if log_mode {
        audit_log_hook(
            ctx.audit_conn,
            ctx.hook_id,
            ctx.agent,
            ctx.action,
            ctx.detail,
            Some(segs),
            "defer",
            "log_mode",
            None,
            agent_prompt_for(&AllowResponse::EmptyStdout, false),
            ctx.started_at.elapsed(),
        );
        emit_allow(&AllowResponse::EmptyStdout);
        std::process::exit(0);
    }

    audit_log_hook(
        ctx.audit_conn,
        ctx.hook_id,
        ctx.agent,
        ctx.action,
        ctx.detail,
        Some(segs),
        "ask",
        "native_prompt",
        None,
        // The agent's own prompt decides — kyris hands the decision back.
        agent_prompt_for(&AllowResponse::EmptyStdout, false),
        ctx.started_at.elapsed(),
    );

    match ctx.native_ask {
        Some(AskResponse::NativePrompt { body }) => {
            println!("{}", serde_json::to_string(body).unwrap_or_default());
        }
        // codex (DeferToNativeApproval) or absent: abstain — empty stdout lets
        // the agent's approval ladder + PermissionRequest hook drive the prompt.
        Some(AskResponse::DeferToNativeApproval) | None => {
            emit_allow(&AllowResponse::EmptyStdout);
        }
    }
    std::process::exit(0);
}

/// Whether a [`SegBlock`] was caused by a daemon being *unavailable* rather than
/// by a genuine decision. Unavailability must never block the developer's
/// machine — the agent hook responds by deferring to the agent's own permission
/// prompt, the shell gate by failing open — so both callers branch on this.
/// - `agentpact_unreachable` — the decider (agentpactd) is down, so there is no
///   verdict to enforce.
/// - `kyrisd_unreachable` — agentpactd returned a real "ask" but the no-TTY ask
///   renderer (kyrisd) couldn't show the dialog.
///
/// Every other source is a genuine decision and always blocks: a policy deny
/// (`agentpact_deny`), the developer's own denial (`user_denied`), or a rendered
/// ask that the human never resolved (`user_timeout` / `resolution_failed`).
pub(super) fn block_from_daemon_unavailable(source: &str) -> bool {
    matches!(source, "kyrisd_unreachable" | "agentpact_unreachable")
}

/// Classify one segment with a real (token-bearing) request to agentpactd.
///
/// The `anchor_pid` we pass is `parent_id()` — i.e. the agent's PID, since
/// this CLI runs as a hook child of the agent (Claude Code, Codex CLI, …).
/// That tag makes the `exec_token` the daemon mints anchored to the agent,
/// so when the agent later spawns `bash -c '…'` the shell trap's
/// `ppid_chain` will match and the daemon auto-allows the segments
/// instead of re-asking. This is the kyris-side half of the
/// `AGENTPACT_EXEC_TOKEN` chain-anchoring contract (the other half is
/// `consume_by_chain` in `agentpact::permission::request`).
pub(super) fn classify_segment(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    action: &str,
    seg: &str,
    command_group: Option<(&str, &str)>,
) -> SegClass {
    // The agent process is our parent (this CLI runs as a hook child of
    // Claude Code / Codex / Gemini). `std::os::unix::process::parent_id`
    // is stable since 1.69 and returns `u32`; kyris targets only Unix.
    #[cfg(unix)]
    let anchor_pid = Some(std::os::unix::process::parent_id());
    #[cfg(not(unix))]
    let anchor_pid: Option<u32> = None;
    // Size the approval-token TTL to this caller's hold window: the token
    // that resolves an Ask must outlive the popup hold (codex's window is
    // days), plus margin for the respond round-trip after the user answers
    // at the last moment.
    let approval_ttl_secs = ctx
        .poll_deadline
        .as_secs()
        .saturating_add(APPROVAL_TTL_MARGIN_SECS);
    match pact_client::request_hook_permission(
        ctx.sock_path,
        "kyris-hook",
        action,
        seg,
        ctx.cwd,
        seed_pid,
        declared_canonical_agent(ctx.agent).as_deref(),
        anchor_pid,
        None,
        command_group,
        Some(approval_ttl_secs),
        ctx.socket_timeout,
    ) {
        Ok((McpPermissionDecision::Allow { .. }, _)) => SegClass::Auto,
        Ok((
            McpPermissionDecision::Ask {
                approval_id,
                approval_token,
                allow_always,
                detail,
            },
            _,
        )) => SegClass::Ask {
            approval_id,
            approval_token,
            allow_always,
            detail,
        },
        Ok((McpPermissionDecision::Deny { reason, .. }, _)) => SegClass::Deny { reason },
        Err(reason) => {
            kyris_core::fail_open_log::record(ctx.agent, action, seg, "shell", ctx.cwd);
            SegClass::Unavailable { reason }
        }
    }
}

/// Drive one segment's approval popup via kyrisd and return the outcome
/// **without** emitting an agent response — the per-segment caller emits
/// exactly once after the whole command resolves.
///
/// `max_wait` is the caller's approval window: the agent hook passes its
/// per-agent `HookRuntime::poll_deadline` (always inside the agent's own
/// hook-kill deadline — G3), the shell paths the global ceiling.
#[allow(clippy::too_many_arguments)]
pub(super) fn poll_segment(
    agent: &str,
    server: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
    approval_id: &str,
    approval_token: &str,
    seg: &str,
    allow_always: bool,
    detail: Option<&str>,
    max_wait: std::time::Duration,
) -> PopupResult {
    // For a file action `seg` is a path — render it home-relative for the popup
    // and the fail-open spool (display/privacy only; the decision already ran on
    // the absolute path, and approval identity rides in approval_id/token, not
    // `seg`). Command segments (execute/shell) are shown verbatim.
    let seg_display = if is_file_action(server) {
        kyris_core::path_display::home_relative(seg)
    } else {
        seg.to_string()
    };
    let seg = seg_display.as_str();
    let Some(conn) = kyris_core::config::load_kyrisd_connection() else {
        // No kyrisd to render the ask. Report it as a daemon-unavailability
        // block; the caller (agent hook → defer, shell → fail open) decides what
        // that means. We do NOT deny the agentpactd ask here — the command may
        // still run via the deferred/fail-open path, and recording a deny for a
        // command that runs would be an audit lie. Let the pending ask expire.
        return PopupResult::Blocked {
            exit_code: 2,
            source: "kyrisd_unreachable",
            reason: "kyrisd unreachable — could not render approval dialog".to_string(),
        };
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let resolution = rt.block_on(async {
        let client = reqwest::Client::new();
        eprintln!(
            "[kyris] {server}/{seg} held for approval — resolve via the Kyris desktop prompt, tray, or app"
        );
        kyris_core::pending::hold_poll_resolve_with_timeout(
            &client,
            &conn,
            kyris_core::pending::PendingApproval {
                approval_id,
                approval_token,
                server,
                tool: seg,
                code: Some(seg),
                agent,
                // Authoritative server signal from the per-segment PACT_ASK:
                // the popup greys out "For session" when the daemon would not
                // persist the grant (privilege/control/remote-destroy,
                // breaker, or no working_dir) — superseding the old
                // leading-word `sudo` heuristic, which missed wrapper-hidden
                // privilege like `env sudo …`.
                allow_always,
                // Structured "why" body the daemon attached to this ask.
                detail,
            },
            max_wait,
        )
        .await
    });

    match resolution {
        kyris_core::pending::Resolution::Approved => PopupResult::Approved {
            source: "user_approved",
        },
        kyris_core::pending::Resolution::Denied => PopupResult::Blocked {
            exit_code: 2,
            source: "user_denied",
            reason: "denied by the developer at the approval prompt".to_string(),
        },
        kyris_core::pending::Resolution::Unreachable => {
            // The dialog never rendered (kyrisd is down). Report it as a
            // daemon-unavailability block; the caller defers (agent hook) or
            // fails open (shell), so the command may still run. Do NOT deny the
            // agentpactd ask here — recording a deny for a command that
            // subsequently runs would be an audit lie. Let the pending expire.
            PopupResult::Blocked {
                exit_code: 2,
                source: "kyrisd_unreachable",
                reason: "kyrisd unreachable — could not render approval dialog".to_string(),
            }
        }
        kyris_core::pending::Resolution::Failed(reason) => {
            // The dialog WAS rendered but resolution failed (timed out or an
            // unexpected pending state). The human may have been mid-decision,
            // so this never defers — always deny + block.
            deny_ask_immediately(approval_token, sock_path, socket_timeout);
            let source = if reason.contains("timeout") || reason.contains("timed out") {
                "user_timeout"
            } else {
                "resolution_failed"
            };
            PopupResult::Blocked {
                exit_code: 2,
                source,
                reason,
            }
        }
    }
}

pub(super) fn deny_ask_immediately(
    approval_token: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) {
    let _ = pact_client::send_permission_response(
        sock_path,
        "kyris-hook-deny",
        approval_token,
        ApprovalResponse::Denied,
        Some(socket_timeout),
    );
}
