// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The `kyris hook check` governance gate: payload ingest, the non-governed
//! fast path, the shared [`PermissionCtx`], preview-outcome dispatch, the
//! missing-backstop deny, and codex's native-approval consultation.

use kyris_agentpact_client::{self as pact_client, McpPermissionDecision};
use std::io::Read as _;

use crate::agents::registry::{self, AllowResponse, ApprovalMode, AskResponse, HookProtocol};

use super::HookCheckArgs;
use super::audit::{audit_log_hook, generate_hook_id};
use super::hold::{declared_canonical_agent, discover_agent_pid};
use super::payload::{
    derive_session_cwd, map_payload, parse_apply_patch_paths, resolve_relative_path,
};
use super::response::{agent_prompt_for, emit_allow, emit_deny, non_governed_response};
use super::segments::{drive_apply_patch, drive_per_segment};

#[allow(clippy::too_many_lines)]
pub(super) fn run_check(args: HookCheckArgs) {
    let agent = &args.agent;
    let hook_id = generate_hook_id();
    let started_at = std::time::Instant::now();

    // Pre-load the kyrisd audit connection once. Used for the single
    // best-effort `hook resolved` log line that this function emits at
    // every exit. None when kyrisd is unreachable / not configured —
    // audit silently no-ops then, the actual policy decision still
    // works via agentpactd directly.
    let audit_conn = kyris_core::config::load_kyrisd_connection();

    // Detect user-level log mode as a fail-open FALLBACK only.
    // The primary signal is the per-request `mode` field agentpactd
    // returns on every PACT_OK — that reflects the walk-up at the
    // request's cwd, so a repo override is honored. We only consult
    // this user-level snapshot when agentpactd is unreachable (no
    // response to read), and we use `cwd=None` because the
    // pass-through fast-path and fail-open arm don't have a working
    // dir to evaluate against.
    // `agentpact` is the upstream agentpact library (policy/protocol);
    // `pact_client` (above) is kyris's UDS client to agentpactd.
    let log_mode = std::env::current_dir()
        .ok()
        .as_deref()
        .and_then(agentpact::policy::resolution::resolve_mode_at)
        .is_some_and(|r| r.mode == kyris_core::agentpact::Mode::Log);

    if let Err(msg) = pact_client::check_protocol_compatibility() {
        // No action/detail known yet — protocol mismatch happens
        // before payload-mapping. Audit anyway so the log shows the
        // hook tried to fire and was rejected at the protocol layer.
        audit_log_hook(
            audit_conn.as_ref(),
            &hook_id,
            agent,
            "unknown",
            "",
            None,
            "deny",
            "protocol_mismatch",
            None,
            "none",
            started_at.elapsed(),
        );
        emit_deny(&msg);
        std::process::exit(2);
    }

    let mut payload = String::new();
    std::io::stdin().read_to_string(&mut payload).unwrap_or(0);

    let hook_input: serde_json::Value =
        serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null);

    let protocol = registry::agent_by_id(agent).and_then(|a| a.hook_protocol());
    let tool_name = protocol
        .as_ref()
        .and_then(|p| hook_input[&p.tool_name_field].as_str())
        .map(str::to_string);

    // One script serves both of codex's hook events; the payload's
    // hook_event_name distinguishes a native-approval consultation
    // (PermissionRequest — answer allow / abstain) from the governance
    // gate (PreToolUse — the rest of this function). Gated on the agent
    // DECLARING the integration: run_permission_request abstains with empty
    // stdout, which a no-backstop bridge would read as allow — an agent
    // without the declaration must take the normal governance path no matter
    // what its payload claims.
    if protocol
        .as_ref()
        .is_some_and(|p| p.permission_request_allow.is_some())
        && hook_input.get("hook_event_name").and_then(|v| v.as_str()) == Some("PermissionRequest")
    {
        run_permission_request(
            agent,
            protocol.as_ref(),
            &hook_input,
            log_mode,
            audit_conn.as_ref(),
            &hook_id,
            started_at,
        );
    }

    let (action, detail) = map_payload(protocol.as_ref(), &hook_input);

    // Fast-path: tools that do not reach agentpactd. Returns here only when the
    // tool IS governable; otherwise it audits, emits, and exits the process.
    if let (Some(proto), Some(tool)) = (protocol.as_ref(), tool_name.as_deref()) {
        handle_non_governed(
            proto,
            tool,
            agent,
            &action,
            &detail,
            log_mode,
            audit_conn.as_ref(),
            &hook_id,
            started_at,
        );
    }

    // The permitted-domain anchor: the agent's FIXED launch dir from its
    // launch_dir_env var (inherited by this hook subprocess), resolved here so
    // derive_session_cwd stays pure/testable.
    let launch_dir = registry::agent_by_id(agent)
        .and_then(|a| a.launch_dir_env())
        .and_then(|var| std::env::var(var).ok());
    let cwd = derive_session_cwd(launch_dir.as_deref(), &hook_input);
    // For file actions, if the agent gave a relative path, resolve it
    // against the cwd we just picked so agentpactd's lexical fallback
    // (boundaries::is_path_inside) can match it correctly.
    let detail = resolve_relative_path(&action, &detail, cwd.as_deref());

    let seed_pid = discover_agent_pid();

    let sock_path = pact_client::default_socket_path().display().to_string();
    let socket_timeout = std::time::Duration::from_secs(5);

    let native_allow_response = protocol
        .as_ref()
        .map_or(AllowResponse::EmptyStdout, |p| p.allow_response.clone());
    // No declared protocol → conservative defaults: assume a native backstop
    // exists (defer behaves as before), no prompt suppression, global ceiling.
    let native_backstop = protocol.as_ref().is_none_or(|p| p.runtime.native_backstop);
    let allow_suppresses_agent_prompt = protocol
        .as_ref()
        .is_some_and(|p| p.runtime.allow_suppresses_agent_prompt);
    let poll_deadline = protocol
        .as_ref()
        .map_or(kyris_core::pending::NATIVE_HOOK_POLL_TIMEOUT, |p| {
            p.runtime.poll_deadline()
        });

    // Native-prompt routing: how an `ask` reaches the human for this agent.
    let native_ask = protocol.as_ref().and_then(|p| p.native_ask.as_ref());
    let approval_mode = registry::resolve_approval_mode(agent, native_ask.is_some());

    let ctx = PermissionCtx {
        audit_conn: audit_conn.as_ref(),
        hook_id: &hook_id,
        agent,
        action: &action,
        detail: &detail,
        cwd: cwd.as_deref(),
        native_allow_response: &native_allow_response,
        sock_path: &sock_path,
        socket_timeout,
        started_at,
        native_backstop,
        allow_suppresses_agent_prompt,
        poll_deadline,
        log_mode_fallback: log_mode,
        has_permission_request: protocol
            .as_ref()
            .is_some_and(|p| p.permission_request_allow.is_some()),
        approval_mode,
        native_ask,
    };

    // A patch envelope is governed PER FILE: kyris parses the paths itself
    // (the daemon's splitter is for shell compounds) and drives a write batch
    // and a delete batch through the same per-segment machinery.
    if action == "apply_patch" {
        drive_apply_patch(&ctx, seed_pid);
    }

    // Classify the whole command with a side-effect-free PREVIEW first:
    // the daemon returns the decision plus the compound `segments` it
    // parsed, without issuing a token. We then drive per-segment popups
    // off that split (the hook never parses shell itself). See
    // `dispatch_preview_outcome`.
    let outcome = pact_client::request_hook_permission_preview(
        &sock_path,
        "kyris-hook",
        &action,
        &detail,
        cwd.as_deref(),
        seed_pid,
        declared_canonical_agent(ctx.agent).as_deref(),
        socket_timeout,
    );
    dispatch_preview_outcome(&ctx, seed_pid, outcome);
}

/// Handle a tool that does not go through agentpactd. Returns normally only
/// when `tool` IS governable (a `tool_mappings` entry) — the caller then
/// proceeds to the daemon round-trip. Otherwise it audits, emits, and exits
/// the process; it never returns in that case. The non-governable outcomes:
///
/// - **pass-through** (a blessed coordination primitive): allow, with the
///   agent's native allow shape (see [`super::response::non_governed_response`]).
/// - **agent-owned** (known, deliberately left to the agent): `EmptyStdout`
///   with no warning — the agent's own permission controls (e.g. Claude's
///   `WebFetch` domain rules) apply untouched. Only meaningful with a native
///   backstop (locked by a registry invariant).
/// - **kyris-routed MCP tool** (recognized via the agent's `mcp_tool_naming`
///   against servers the kyris MCP rewrite routed): allow with `EmptyStdout` —
///   the actual `tools/call` is governed at the TOOL surface (`kyris-mcp wrap`
///   / kyrisd `/mcp/` routing), so the hook must not double-gate it. Only
///   consulted for no-backstop agents; backstopped agents take the unmapped
///   defer below, preserving their own prompt.
/// - **unmapped, agent has a native backstop**: warn + defer (`EmptyStdout`) —
///   the agent's own permission system decides, as if kyris were not installed.
/// - **unmapped, NO native backstop** (G1): there is nothing behind kyris to
///   defer to — cline's CLI auto-approves and opencode's native permissions
///   were set permissive BY kyris — so a defer would silently run an unknown,
///   possibly side-effecting tool. Deny with an actionable reason instead.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_non_governed(
    proto: &HookProtocol,
    tool: &str,
    agent: &str,
    action: &str,
    detail: &str,
    log_mode: bool,
    audit_conn: Option<&kyris_core::config::KyrisdConnection>,
    hook_id: &str,
    started_at: std::time::Instant,
) {
    let governable = proto.tool_mappings.iter().any(|m| m.tool_name == tool);
    if governable {
        return;
    }

    if proto.agent_owned_tools.iter().any(|t| t == tool) {
        audit_log_hook(
            audit_conn,
            hook_id,
            agent,
            action,
            detail,
            None,
            "allow",
            "agent_owned",
            None,
            agent_prompt_for(&AllowResponse::EmptyStdout, false),
            started_at.elapsed(),
        );
        emit_allow(&AllowResponse::EmptyStdout);
        std::process::exit(0);
    }

    let pass_through = proto.pass_through_tools.iter().any(|t| t == tool);

    // The no-backstop deny (G1) is an ENFORCE-mode posture. Log mode is
    // observe-only by contract — kyris must not alter agent behavior there,
    // even when that behavior is "auto-approve everything".
    if !pass_through && !proto.runtime.native_backstop && !log_mode {
        if is_kyris_routed_mcp_tool(proto, agent, tool) {
            audit_log_hook(
                audit_conn,
                hook_id,
                agent,
                action,
                detail,
                None,
                "allow",
                "mcp_tool_surface",
                None,
                // Not "agent_decides" — this agent has no prompt behind the
                // hook; the actual gate is the kyris-mcp wrap / kyrisd /mcp/
                // routing the call is about to hit.
                "tool_surface",
                started_at.elapsed(),
            );
            emit_allow(&AllowResponse::EmptyStdout);
            std::process::exit(0);
        }
        let reason = format!(
            "tool '{tool}' is not governed by kyris, and {agent} has no native \
             permission backstop behind the kyris hook — allowing it would run \
             ungoverned. Denied. Update kyris's {agent} tool mappings (then \
             `kyris agent setup {agent}`), or `kyris agent disconnect {agent}` to \
             restore {agent}'s own permission prompts."
        );
        audit_log_hook(
            audit_conn,
            hook_id,
            agent,
            action,
            detail,
            None,
            "deny",
            "unmapped_no_backstop",
            None,
            "none",
            started_at.elapsed(),
        );
        emit_deny(&reason);
        std::process::exit(2);
    }

    if !pass_through {
        // Reaches here for backstopped agents (their own permission system
        // decides) and for no-backstop agents in log mode (observe-only).
        eprintln!(
            "[agentpact] warning: '{tool}' is not in the {agent} mapping table; \
             handing the decision back to {agent} (kyris is not governing it). \
             Add it to tool_mappings to govern it, or pass_through_tools to bless it."
        );
    }
    let source = if pass_through {
        "passthrough"
    } else {
        "unmapped"
    };
    let response = non_governed_response(pass_through, &proto.allow_response, log_mode);
    audit_log_hook(
        audit_conn,
        hook_id,
        agent,
        action,
        detail,
        None,
        "allow",
        source,
        None,
        agent_prompt_for(&response, proto.runtime.allow_suppresses_agent_prompt),
        started_at.elapsed(),
    );
    emit_allow(&response);
    std::process::exit(0);
}

/// Whether `tool` is named like an MCP tool of a server the kyris MCP rewrite
/// routed (wrapped stdio / kyrisd-routed HTTP) — i.e. it is governed at the
/// tool surface and must not be denied at the hook. Reads the agent's MCP
/// config; only called on the cold unmapped path of no-backstop agents.
///
/// Matched against ALL configured servers by LONGEST sanitized prefix, and
/// exempted only when that winner is routed: with a single-`_` separator, a
/// routed server `data` must not bless `data_prod_query` when the longer match
/// `data_prod` is an UNROUTED server — that tool's calls bypass the tool
/// surface, so the deny must stand.
fn is_kyris_routed_mcp_tool(proto: &HookProtocol, agent: &str, tool: &str) -> bool {
    let Some(naming) = proto.mcp_tool_naming.as_ref() else {
        return false;
    };
    let Some(descriptor) = registry::agent_by_id(agent) else {
        return false;
    };
    let routed = crate::agents::configure::kyris_routed_mcp_server_names(descriptor.as_ref());
    let all = crate::agents::configure::mcp_server_names_from_agent(descriptor.as_ref());
    all.iter()
        .filter(|server| naming.tool_belongs_to_server(tool, server))
        .max_by_key(|server| naming.sanitized_len(server))
        .is_some_and(|winner| routed.contains(winner))
}

/// References needed to route a permission outcome through audit, agent
/// response emission, and process exit. Bundled because the dispatch
/// function takes 10 parameters otherwise.
///
/// The allow-shape decision is made INSIDE the dispatcher per outcome
/// rather than baked in here: a successful daemon response carries the
/// effective mode in [`McpPermissionDecision::Allow`] and the dispatcher
/// branches on it. The daemon-unavailable arm has no decision to scout, so
/// it defers to the agent's own prompt (`EmptyStdout`) regardless of mode —
/// never suppressing a prompt for a command the daemon never actually cleared.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct PermissionCtx<'a> {
    pub(super) audit_conn: Option<&'a kyris_core::config::KyrisdConnection>,
    pub(super) hook_id: &'a str,
    pub(super) agent: &'a str,
    pub(super) action: &'a str,
    pub(super) detail: &'a str,
    pub(super) cwd: Option<&'a str>,
    pub(super) native_allow_response: &'a AllowResponse,
    pub(super) sock_path: &'a str,
    pub(super) socket_timeout: std::time::Duration,
    pub(super) started_at: std::time::Instant,
    /// From the agent's `HookRuntime`: whether the agent's own permission
    /// system still gates a tool kyris defers on. When false, every defer path
    /// (daemon unavailable, unrenderable ask) becomes a DENY — a defer would be
    /// a silent allow (G1). True for the shell gate: the human at the terminal
    /// is the backstop.
    pub(super) native_backstop: bool,
    /// From the agent's `HookRuntime`: whether the native allow shape actually
    /// suppresses the agent's own prompt — drives the `agent_prompt` audit
    /// field (G2).
    pub(super) allow_suppresses_agent_prompt: bool,
    /// Per-agent no-TTY approval window (`HookRuntime::poll_deadline`): always
    /// inside the agent's own hook-kill deadline (G3).
    pub(super) poll_deadline: std::time::Duration,
    /// User-level log-mode snapshot, used ONLY where no per-request mode is
    /// available (agentpactd unreachable): in log mode the no-backstop deny is
    /// suppressed — observe-only must never alter agent behavior.
    pub(super) log_mode_fallback: bool,
    /// Whether this agent declares a native-approval hook integration
    /// (`permission_request_allow`) — the only consumer of recent-approval
    /// notes, so recording is gated on it.
    pub(super) has_permission_request: bool,
    /// Which approval UX to use for an `ask` verdict — the agent's own native
    /// prompt ([`ApprovalMode::Native`]) or kyris's pending-approval popup
    /// ([`ApprovalMode::KyrisPopup`]). Resolved from the `approval_prompt`
    /// setting, defaulting to native where the agent declares a `native_ask`.
    pub(super) approval_mode: ApprovalMode,
    /// How to render a native ask for this agent ([`AskResponse`]); `None` when
    /// the agent has no native ask channel (kyris popup is then the only path).
    pub(super) native_ask: Option<&'a AskResponse>,
}

/// Route the side-effect-free PREVIEW outcome from agentpactd.
///
/// The preview has no side effects: it neither audits, nor counts the circuit
/// breaker, nor issues exec tokens, nor updates session state. So its decision
/// is used **only** as a scout — for the compound split it carries and for the
/// effective mode — and every command is then re-driven through real,
/// token-bearing per-segment requests ([`super::segments::drive_per_segment`]).
/// That is what produces the `AgentPact` action events, breaker accounting,
/// exec tokens, and session-cwd update, and it is uniform across what the
/// preview classified as `Auto`, `Ask`, or `Deny`: the per-segment real
/// requests determine the true outcome (auto segments run silently, ask
/// segments each get their own popup and per-segment "Always", a denied segment
/// blocks the line).
///
/// The success allow shape is mode-correct: `EmptyStdout` in log mode (defer to
/// the agent's own prompt), the agent's native allow shape in enforce mode.
/// Only the daemon-unreachable arms (no decision to scout) emit directly.
///
/// Compound splitting is the daemon's job (`agentpact::policy::splitter`); the
/// hook never parses shell itself.
pub(super) fn dispatch_preview_outcome(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    outcome: Result<(McpPermissionDecision, Option<Vec<String>>), String>,
) -> ! {
    match outcome {
        // A line the preview would DENY is doomed: the agent gets a failure
        // response and runs none of it, so we present nothing per-segment.
        // Issue ONE real whole-command request (segments = None) purely so the
        // deny is written to agentpact's append-only event log, then fail. (A
        // strictest-wins Ask aggregate, below, can never hide a denied segment,
        // so the per-segment walk never prompts for a doomed line.)
        Ok((McpPermissionDecision::Deny { .. }, _segments)) => {
            drive_per_segment(ctx, seed_pid, None, false);
        }
        // Auto / Ask re-drive real per-segment requests: auto and already-
        // "always" segments run silently, only ask segments are prompted (each
        // with its own per-segment "Always"), and the agent gets one aggregate
        // proceed response once every segment is approved. The preview only
        // supplies the split and (for Allow) the effective mode — log mode
        // surfaces every decision as `Allow { mode: Log }` (see process_preview),
        // so deriving log-mode from an Allow is sufficient; an Ask is
        // enforce-only and emits the native allow shape on success.
        Ok((decision, segments)) => {
            let log_mode =
                matches!(&decision, McpPermissionDecision::Allow { mode } if mode.is_log());
            drive_per_segment(ctx, seed_pid, segments, log_mode);
        }
        Err(_reason) => {
            // agentpactd (the decider) is unreachable. With a native backstop,
            // defer to the AGENT's own permission UX by emitting the EmptyStdout
            // shape (NOT the native allow shape, which would suppress the
            // agent's own prompt for a command the daemon never actually
            // cleared) and spool for the audit trail. Without one (G1), a defer
            // is a silent allow — deny with an actionable reason instead.
            // Except in log mode: observe-only must never alter agent behavior
            // (the daemon is down, so only the user-level mode snapshot exists).
            if !ctx.native_backstop && !ctx.log_mode_fallback {
                deny_for_missing_backstop(ctx, None, "agentpact_unreachable");
            }
            kyris_core::fail_open_log::record(ctx.agent, ctx.action, ctx.detail, "shell", ctx.cwd);
            audit_log_hook(
                ctx.audit_conn,
                ctx.hook_id,
                ctx.agent,
                ctx.action,
                ctx.detail,
                None,
                "defer",
                "agentpact_unreachable",
                None,
                agent_prompt_for(&AllowResponse::EmptyStdout, false),
                ctx.started_at.elapsed(),
            );
            emit_allow(&AllowResponse::EmptyStdout);
            std::process::exit(0);
        }
    }
}

/// G1 deny path: a defer-class outcome (daemon unavailable, unrenderable ask)
/// on an agent with NO native permission backstop. Nothing behind kyris would
/// gate the command, so "defer" would silently run it — deny instead, with a
/// reason that names the fix. Audits and exits; never returns.
pub(super) fn deny_for_missing_backstop(
    ctx: &PermissionCtx<'_>,
    segments: Option<&[String]>,
    source: &'static str,
) -> ! {
    let agent = ctx.agent;
    let daemon = if source == "kyrisd_unreachable" {
        "kyrisd (the approval renderer)"
    } else {
        "agentpactd (the policy daemon)"
    };
    let reason = format!(
        "{daemon} is unreachable and {agent} has no native permission backstop \
         behind the kyris hook — running this command would be ungoverned. \
         Denied. Start the daemon (`kyris status` shows what's down), or \
         `kyris agent disconnect {agent}` to restore {agent}'s own permission prompts."
    );
    audit_log_hook(
        ctx.audit_conn,
        ctx.hook_id,
        ctx.agent,
        ctx.action,
        ctx.detail,
        segments,
        "deny",
        source,
        None,
        "none",
        ctx.started_at.elapsed(),
    );
    emit_deny(&reason);
    std::process::exit(2);
}

/// Answer an agent's NATIVE-approval consultation (codex `PermissionRequest`):
/// the agent is about to prompt its user for a tool it already cleared through
/// `PreToolUse`. kyris answers **allow** (suppressing the redundant native
/// prompt) only when it can vouch for the request:
///   - agentpactd's side-effect-free preview says Allow (catalog/always — the
///     command would never have produced a kyris popup), or
///   - the human JUST approved this exact request through kyris's popup (a
///     fresh single-use `recent_approvals` note).
///
/// Everything else ABSTAINS (empty stdout — codex's documented "no decision"),
/// letting the native prompt appear: log mode (observe-only), unmapped /
/// pass-through / agent-owned tools, a Deny or Ask preview without a note, a
/// down daemon, an unparseable patch. Never deny from here — `PreToolUse`
/// already blocks what policy forbids; this hook only completes the allow path
/// (review Finding 9, the kyris-approves-then-codex-prompts-again double
/// prompt).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn run_permission_request(
    agent: &str,
    protocol: Option<&HookProtocol>,
    hook_input: &serde_json::Value,
    log_mode: bool,
    audit_conn: Option<&kyris_core::config::KyrisdConnection>,
    hook_id: &str,
    started_at: std::time::Instant,
) -> ! {
    let abstain = |action: &str, detail: &str, source: &str| -> ! {
        audit_log_hook(
            audit_conn,
            hook_id,
            agent,
            action,
            detail,
            None,
            "defer",
            source,
            None,
            "agent_decides",
            started_at.elapsed(),
        );
        // Empty stdout, exit 0 — codex's "no decision": the native prompt
        // appears as if kyris were not installed.
        std::process::exit(0);
    };

    let Some(proto) = protocol else {
        abstain("unknown", "", "no_protocol");
    };
    let Some(allow_body) = proto.permission_request_allow.clone() else {
        abstain("unknown", "", "no_integration");
    };

    let (action, detail) = map_payload(Some(proto), hook_input);
    let governable = hook_input[&proto.tool_name_field]
        .as_str()
        .is_some_and(|tool| proto.tool_mappings.iter().any(|m| m.tool_name == tool));
    if !governable {
        abstain(&action, &detail, "ungoverned_tool");
    }
    if log_mode {
        abstain(&action, &detail, "log_mode");
    }

    let launch_dir = registry::agent_by_id(agent)
        .and_then(|a| a.launch_dir_env())
        .and_then(|var| std::env::var(var).ok());
    let cwd = derive_session_cwd(launch_dir.as_deref(), hook_input);
    let detail = resolve_relative_path(&action, &detail, cwd.as_deref());

    // The previews this consultation runs on: per file for a patch envelope,
    // the whole command otherwise.
    let requests: Vec<(String, String)> = if action == "apply_patch" {
        let parsed = parse_apply_patch_paths(&detail);
        if parsed.writes.is_empty() && parsed.deletes.is_empty() {
            abstain(&action, &detail, "unparseable_patch");
        }
        let resolve = |p: &String| resolve_relative_path("write", p, cwd.as_deref());
        parsed
            .writes
            .iter()
            .map(|p| ("write".to_string(), resolve(p)))
            .chain(
                parsed
                    .deletes
                    .iter()
                    .map(|p| ("delete".to_string(), resolve(p))),
            )
            .collect()
    } else {
        vec![(action.clone(), detail.clone())]
    };

    let sock_path = pact_client::default_socket_path().display().to_string();
    let socket_timeout = std::time::Duration::from_secs(5);
    let seed_pid = discover_agent_pid();

    let mut all_allow = true;
    for (req_action, req_detail) in &requests {
        match pact_client::request_hook_permission_preview(
            &sock_path,
            "kyris-hook",
            req_action,
            req_detail,
            cwd.as_deref(),
            seed_pid,
            declared_canonical_agent(agent).as_deref(),
            socket_timeout,
        ) {
            Ok((McpPermissionDecision::Allow { mode }, _)) if mode.is_log() => {
                abstain(&action, &detail, "log_mode");
            }
            Ok((McpPermissionDecision::Allow { .. }, _)) => {}
            Ok(_) => {
                all_allow = false;
                break;
            }
            // The decider is down: nothing to vouch with — codex's native
            // prompt is exactly the backstop this situation needs.
            Err(_) => abstain(&action, &detail, "agentpact_unreachable"),
        }
    }

    let source = if all_allow {
        "agentpact_auto"
    } else if crate::recent_approvals::consume(agent, &action, cwd.as_deref(), &detail) {
        "recent_approval"
    } else {
        abstain(&action, &detail, "native_prompt");
    };

    audit_log_hook(
        audit_conn,
        hook_id,
        agent,
        &action,
        &detail,
        None,
        "allow",
        source,
        None,
        // This allow genuinely suppresses the native prompt — that is its job.
        "none",
        started_at.elapsed(),
    );
    println!("{}", serde_json::to_string(&allow_body).unwrap_or_default());
    std::process::exit(0);
}
