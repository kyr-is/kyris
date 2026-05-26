// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris hook check` — native agent hook adapter. Reads an agent's hook
//! payload from stdin, maps it through the agent's `HookProtocol`, round-trips
//! to `agentpactd`, and handles `PACT_ASK` via `kyrisd`'s pending-approval
//! system. Writes the agent-native response (JSON or text) to stdout.
//!
//! This replaces `kyris-hook check-hook` for native agent hooks (Claude Code
//! `PreToolUse`, Codex CLI `PreToolUse`, Gemini CLI `BeforeTool`). Shell hooks
//! continue to use `kyris-hook check` for the fast synchronous path.

use clap::Args;
use std::io::Read as _;

use kyris_agentpact_client::{self as agentpact, ApprovalResponse, McpPermissionDecision};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, UpdateKind};

use crate::agents::registry::{self, AllowResponse, HookProtocol, ToolMapping};

#[derive(Args)]
pub struct HookArgs {
    #[command(subcommand)]
    pub command: HookCommand,
}

#[derive(clap::Subcommand)]
pub enum HookCommand {
    Check(HookCheckArgs),
    /// Delegate a `PACT_ASK` or circuit-breaker approval to kyrisd's
    /// pending-approval system. Used by shell hooks in non-interactive
    /// (no-TTY) shells where prompting is impossible. Blocks until the
    /// developer resolves the request via `kyris pending`, then sends
    /// `permission.respond` to agentpactd and exits 0 (approved) or
    /// non-zero (denied/failed).
    Hold(HookHoldArgs),
}

#[derive(Args)]
pub struct HookHoldArgs {
    /// Approval ID from agentpactd (`req_id` field in kyris-hook output).
    #[arg(long)]
    pub req_id: String,
    /// Approval token from agentpactd.
    #[arg(long)]
    pub token: String,
    /// Human-readable description shown in `kyris pending` (the command text).
    #[arg(long)]
    pub display: String,
    /// Path to the agentpactd UDS socket (defaults to the standard location).
    #[arg(long)]
    pub socket: Option<String>,
}

#[derive(Args)]
pub struct HookCheckArgs {
    #[arg(long)]
    pub agent: String,
}

pub fn run(args: HookArgs) {
    match args.command {
        HookCommand::Check(check_args) => run_check(check_args),
        HookCommand::Hold(hold_args) => run_hold(hold_args),
    }
}

fn run_hold(args: HookHoldArgs) {
    let sock_path = args
        .socket
        .unwrap_or_else(|| agentpact::default_socket_path().display().to_string());
    let socket_timeout = std::time::Duration::from_secs(5);

    // Reuse poll_segment: it holds the request in kyrisd's pending system,
    // polls for developer resolution (kyrisd sends permission.respond to
    // agentpactd), and returns the outcome. The shell hook only cares about
    // the exit code, so an approval emits nothing and exits 0.
    //
    // `server` is "shell" (the popup title slot — "Kyris: Allow shell");
    // `args.display` (the verbatim command) is the segment text, which
    // becomes the popup body and the syntect-highlighted accessoryView.
    match poll_segment(
        "shell",
        &sock_path,
        socket_timeout,
        &args.req_id,
        &args.token,
        &args.display,
    ) {
        PopupResult::Approved { .. } => std::process::exit(0),
        PopupResult::Blocked {
            exit_code, reason, ..
        } => {
            emit_deny(&reason);
            std::process::exit(exit_code);
        }
    }
}

fn discover_agent_pid() -> Option<u32> {
    let sig_table = ::agentpact::attribution::signatures::SignatureTable::default_phase1();
    let refresh_kind = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    let mut sys = sysinfo::System::new();

    let my_pid = std::process::id();
    let mut current = my_pid;

    for _ in 0..64 {
        if current <= 1 {
            return None;
        }
        let sysinfo_pid = Pid::from_u32(current);
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[sysinfo_pid]),
            false,
            refresh_kind,
        );
        let proc = sys.process(sysinfo_pid)?;

        let exe_str = proc
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cmd: Vec<String> = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();

        if sig_table.match_process(&exe_str, &cmd).is_some() {
            return Some(current);
        }

        current = match proc.parent() {
            Some(ppid) if ppid.as_u32() > 1 => ppid.as_u32(),
            _ => return None,
        };
    }
    None
}

fn run_check(args: HookCheckArgs) {
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
    // `agentpact` is locally aliased to `kyris_agentpact_client`
    // (the wire-types crate); reach the real agentpact server lib
    // via the fully-qualified `::agentpact` path.
    let log_mode = std::env::current_dir()
        .ok()
        .as_deref()
        .and_then(::agentpact::policy::resolution::resolve_mode_at)
        .is_some_and(|r| r.mode == ::agentpact::protocol::types::Mode::Log);

    if let Err(msg) = agentpact::check_protocol_compatibility() {
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

    let (action, detail) = map_payload(protocol.as_ref(), &hook_input);

    // Fast-path: pass-through tools (LLM coordination primitives with no
    // governable side effect) skip the daemon entirely. Unmapped tools also
    // skip the daemon but emit a stderr warning so we notice and update the
    // per-agent mapping table. Both rely on the agent's `allow_response`
    // shape to suppress the agent's own permission prompt — except in log
    // mode, where we must hand the decision back to the agent.
    if let (Some(proto), Some(tool)) = (protocol.as_ref(), tool_name.as_deref()) {
        let governable = proto.tool_mappings.iter().any(|m| m.tool_name == tool);
        let pass_through = proto.pass_through_tools.iter().any(|t| t == tool);
        if !governable {
            let source = if pass_through {
                "passthrough"
            } else {
                "unmapped"
            };
            if !pass_through {
                eprintln!(
                    "[agentpact] warning: '{tool}' is not in the {agent} mapping table; allowing without governance. Add it to tool_mappings or pass_through_tools."
                );
            }
            let response = effective_allow_response(&proto.allow_response, log_mode);
            audit_log_hook(
                audit_conn.as_ref(),
                &hook_id,
                agent,
                &action,
                &detail,
                None,
                "allow",
                source,
                None,
                agent_prompt_for(&response),
                started_at.elapsed(),
            );
            emit_allow(&response);
            std::process::exit(0);
        }
    }

    let cwd = derive_session_cwd(&hook_input);
    // For file actions, if the agent gave a relative path, resolve it
    // against the cwd we just picked so agentpactd's lexical fallback
    // (boundaries::is_path_inside) can match it correctly.
    let detail = resolve_relative_path(&action, &detail, cwd.as_deref());

    let seed_pid = discover_agent_pid();

    let sock_path = agentpact::default_socket_path().display().to_string();
    let socket_timeout = std::time::Duration::from_secs(5);

    // Classify the whole command with a side-effect-free PREVIEW first:
    // the daemon returns the decision plus the compound `segments` it
    // parsed, without issuing a token. We then drive per-segment popups
    // off that split (the hook never parses shell itself). See
    // `dispatch_preview_outcome`.
    let outcome = agentpact::request_hook_permission_preview(
        &sock_path,
        "kyris-hook",
        &action,
        &detail,
        cwd.as_deref(),
        seed_pid,
        socket_timeout,
    );

    let native_allow_response = protocol
        .as_ref()
        .map_or(AllowResponse::EmptyStdout, |p| p.allow_response.clone());

    let ctx = PermissionCtx {
        audit_conn: audit_conn.as_ref(),
        hook_id: &hook_id,
        agent,
        action: &action,
        detail: &detail,
        cwd: cwd.as_deref(),
        native_allow_response: &native_allow_response,
        log_mode_fallback: log_mode,
        sock_path: &sock_path,
        socket_timeout,
        started_at,
    };
    dispatch_preview_outcome(&ctx, seed_pid, outcome);
}

/// References needed to route a permission outcome through audit, agent
/// response emission, and process exit. Bundled because the dispatch
/// function takes 10 parameters otherwise.
///
/// The allow-shape decision is made INSIDE the dispatcher per outcome
/// rather than baked in here: a successful daemon response carries the
/// effective mode in [`McpPermissionDecision::Allow`] and the
/// dispatcher branches on it; only the fail-open arm (no daemon
/// response to consult) falls back to `log_mode_fallback`, which the
/// caller computes once via `agentpact::policy::resolution` against
/// the current working directory so a repo override still wins on
/// the fail-open path.
struct PermissionCtx<'a> {
    audit_conn: Option<&'a kyris_core::config::KyrisdConnection>,
    hook_id: &'a str,
    agent: &'a str,
    action: &'a str,
    detail: &'a str,
    cwd: Option<&'a str>,
    native_allow_response: &'a AllowResponse,
    log_mode_fallback: bool,
    sock_path: &'a str,
    socket_timeout: std::time::Duration,
    started_at: std::time::Instant,
}

/// Route the side-effect-free PREVIEW outcome from agentpactd.
///
/// The preview classifies the whole command without issuing a token:
/// - `Auto`/`Inform` → fast path: emit the agent allow shape, no popups
///   (in log mode this defers to the agent via `effective_allow_response`);
/// - `Deny` → block;
/// - daemon unreachable → fail open or closed per `on_daemon_unavailable`;
/// - `Ask` → drive per-segment approval ([`drive_per_segment`]).
///
/// Compound splitting is the daemon's job (`agentpact::policy::splitter`);
/// the preview response carries the segments it parsed. For an `Ask` we
/// issue one real, token-bearing request per segment, so each segment is
/// classified on its own — auto segments run silently, and each segment
/// that needs approval gets its own popup and its own per-segment
/// "Always". The hook never parses shell itself.
fn dispatch_preview_outcome(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    outcome: Result<(McpPermissionDecision, Option<Vec<String>>), String>,
) -> ! {
    match outcome {
        Ok((McpPermissionDecision::Allow { mode }, segments)) => {
            let response = effective_allow_response(ctx.native_allow_response, mode.is_log());
            audit_log_hook(
                ctx.audit_conn,
                ctx.hook_id,
                ctx.agent,
                ctx.action,
                ctx.detail,
                segments.as_deref(),
                "allow",
                "agentpact_auto",
                None,
                agent_prompt_for(&response),
                ctx.started_at.elapsed(),
            );
            emit_allow(&response);
            std::process::exit(0);
        }
        Ok((McpPermissionDecision::Deny { reason, .. }, segments)) => {
            audit_and_exit_deny(ctx, segments.as_deref(), "agentpact_deny", &reason);
        }
        Ok((McpPermissionDecision::Ask { .. }, segments)) => {
            drive_per_segment(ctx, seed_pid, segments);
        }
        Err(_) if agentpact::allow_on_daemon_unavailable() => {
            let response =
                effective_allow_response(ctx.native_allow_response, ctx.log_mode_fallback);
            kyris_core::fail_open_log::record(ctx.action, ctx.detail, ctx.agent, ctx.cwd);
            audit_log_hook(
                ctx.audit_conn,
                ctx.hook_id,
                ctx.agent,
                ctx.action,
                ctx.detail,
                None,
                "allow",
                "agentpact_unreachable",
                None,
                agent_prompt_for(&response),
                ctx.started_at.elapsed(),
            );
            emit_allow(&response);
            std::process::exit(0);
        }
        Err(reason) => {
            audit_and_exit_deny(ctx, None, "agentpact_unreachable", &reason);
        }
    }
}

/// A single segment's classification from a real (token-bearing) request.
enum SegClass {
    /// Catalog/default/already-"always"-allowed — runs with no popup.
    Auto,
    /// Needs approval; carries the token that drives its popup.
    Ask {
        approval_id: String,
        approval_token: String,
    },
    /// Policy denied this segment.
    Deny { reason: String },
    /// agentpactd was unreachable while classifying this segment.
    Unavailable { reason: String },
}

/// The outcome of driving one segment's approval popup (no agent response
/// is emitted here — the caller emits exactly once after the loop).
enum PopupResult {
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
struct SegBlock {
    exit_code: i32,
    source: &'static str,
    reason: String,
}

/// Pure aggregation over a command's segments. Auto segments pass; the
/// first `Deny`, a fail-closed `Unavailable`, or a blocked popup stops
/// the walk and blocks the whole command (the agent runs it as a unit,
/// so a partial approval is useless). Returns the audit `source` for the
/// allow path, or a [`SegBlock`] for the deny path.
///
/// I/O lives entirely in the injected closures, so this is unit-tested
/// directly with canned classifications and popup results.
fn run_segments<C, P>(
    segments: &[String],
    allow_on_unavailable: bool,
    mut classify: C,
    mut prompt: P,
) -> Result<&'static str, SegBlock>
where
    C: FnMut(&str) -> SegClass,
    P: FnMut(&str, &str, &str) -> PopupResult,
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
                if allow_on_unavailable {
                    source = "agentpact_unreachable";
                } else {
                    return Err(SegBlock {
                        exit_code: 2,
                        source: "agentpact_unreachable",
                        reason,
                    });
                }
            }
            SegClass::Ask {
                approval_id,
                approval_token,
            } => match prompt(&approval_id, &approval_token, seg) {
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

/// Drive per-segment approval for an `Ask`'d command, emit one agent
/// response, and exit. `segments` is the daemon's parsed split; when it
/// did not split (single command, non-execute action) we treat the whole
/// `detail` as the one segment.
fn drive_per_segment(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    segments: Option<Vec<String>>,
) -> ! {
    let segs = segments.unwrap_or_else(|| vec![ctx.detail.to_string()]);

    let result = run_segments(
        &segs,
        agentpact::allow_on_daemon_unavailable(),
        |seg| classify_segment(ctx, seed_pid, seg),
        |approval_id, approval_token, seg| {
            poll_segment(
                ctx.action,
                ctx.sock_path,
                ctx.socket_timeout,
                approval_id,
                approval_token,
                seg,
            )
        },
    );

    match result {
        Ok(source) => {
            // Ask only fires in enforce mode, so the agent's native allow
            // shape is correct here (no log-mode override needed).
            let response = ctx.native_allow_response.clone();
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
                agent_prompt_for(&response),
                ctx.started_at.elapsed(),
            );
            emit_allow(&response);
            std::process::exit(0);
        }
        Err(block) => {
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

/// Classify one segment with a real (token-bearing) request to agentpactd.
fn classify_segment(ctx: &PermissionCtx<'_>, seed_pid: Option<u32>, seg: &str) -> SegClass {
    match agentpact::request_hook_permission(
        ctx.sock_path,
        "kyris-hook",
        ctx.action,
        seg,
        ctx.cwd,
        seed_pid,
        ctx.socket_timeout,
    ) {
        Ok((McpPermissionDecision::Allow { .. }, _)) => SegClass::Auto,
        Ok((
            McpPermissionDecision::Ask {
                approval_id,
                approval_token,
            },
            _,
        )) => SegClass::Ask {
            approval_id,
            approval_token,
        },
        Ok((McpPermissionDecision::Deny { reason, .. }, _)) => SegClass::Deny { reason },
        Err(reason) => {
            kyris_core::fail_open_log::record(ctx.action, seg, ctx.agent, ctx.cwd);
            SegClass::Unavailable { reason }
        }
    }
}

/// Drive one segment's approval popup via kyrisd and return the outcome
/// **without** emitting an agent response — the per-segment caller emits
/// exactly once after the whole command resolves.
fn poll_segment(
    server: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
    approval_id: &str,
    approval_token: &str,
    seg: &str,
) -> PopupResult {
    let Some(conn) = kyris_core::config::load_kyrisd_connection() else {
        if agentpact::allow_on_daemon_unavailable() {
            kyris_core::fail_open_log::record(server, seg, "kyris-hook", None);
            return PopupResult::Approved {
                source: "kyrisd_unreachable",
            };
        }
        deny_ask_immediately(approval_token, sock_path, socket_timeout);
        return PopupResult::Blocked {
            exit_code: 2,
            source: "kyrisd_unreachable",
            reason: "kyrisd unreachable — cannot delegate approval".to_string(),
        };
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let resolution = rt.block_on(async {
        let client = reqwest::Client::new();
        eprintln!("[kyris] {server}/{seg} held for approval — resolve with 'kyris pending'");
        kyris_core::pending::hold_poll_resolve_with_timeout(
            &client,
            &conn,
            kyris_core::pending::PendingApproval {
                approval_id,
                approval_token,
                server,
                tool: seg,
                code: Some(seg),
                // Privilege escalation is never persistable (agentpactd
                // refuses it server-side), so grey out "Always" in the popup.
                allow_always: !::agentpact::policy::compound::is_privilege_command(seg),
            },
            kyris_core::pending::NATIVE_HOOK_POLL_TIMEOUT,
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
            reason: "denied by developer via kyris pending".to_string(),
        },
        kyris_core::pending::Resolution::Failed(reason) => {
            deny_ask_immediately(approval_token, sock_path, socket_timeout);
            let source = if reason.contains("timeout") || reason.contains("timed out") {
                "user_timeout"
            } else {
                "kyrisd_unreachable"
            };
            PopupResult::Blocked {
                exit_code: 2,
                source,
                reason,
            }
        }
    }
}

/// Audit a deny outcome and exit with code 2. Always reports
/// `agent_prompt=none` because exit-2 blocks the tool regardless of the
/// agent's own permission logic.
fn audit_and_exit_deny(
    ctx: &PermissionCtx<'_>,
    segments: Option<&[String]>,
    source: &str,
    reason: &str,
) -> ! {
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
    emit_deny(reason);
    std::process::exit(2);
}

fn deny_ask_immediately(
    approval_token: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
) {
    let _ = agentpact::send_permission_response(
        sock_path,
        "kyris-hook-deny",
        approval_token,
        ApprovalResponse::Denied,
        Some(socket_timeout),
    );
}

/// Pick the session cwd to send to agentpactd. Prefer the cwd the agent
/// reports in its hook payload (Claude Code, Codex CLI and Gemini CLI all
/// include this) — it's the authoritative session cwd, and the hook
/// process's own cwd may diverge. Without this, inside-CWD reads can be
/// misclassified as outside-CWD — see
/// `agentpact/src/policy/boundaries.rs:43`.
fn derive_session_cwd(hook_input: &serde_json::Value) -> Option<String> {
    hook_input
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
        })
}

/// Resolve a relative file path against the session cwd for `read`/`write`
/// actions. Absolute paths, non-file actions, and missing cwd pass through
/// unchanged. Done lexically — we do not touch the filesystem; canonicalization
/// happens inside agentpactd's boundary check.
fn resolve_relative_path(action: &str, detail: &str, cwd: Option<&str>) -> String {
    if action != "read" && action != "write" {
        return detail.to_string();
    }
    if detail.is_empty() {
        return detail.to_string();
    }
    let path = std::path::Path::new(detail);
    if path.is_absolute() {
        return detail.to_string();
    }
    let Some(base) = cwd else {
        return detail.to_string();
    };
    std::path::Path::new(base)
        .join(detail)
        .to_string_lossy()
        .into_owned()
}

/// 32-bit hex identifier attached to the `hook resolved` audit line for
/// a single hook invocation. Derived from nanoseconds since the epoch
/// XOR'd with the process id; collision risk inside one user's session
/// is nil and the resulting log is grep-friendly.
fn generate_hook_id() -> String {
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
fn audit_log_hook(
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

/// Whether the agent will still get to apply its own permission rules
/// after kyris's response. Derived from the `AllowResponse` shape kyris
/// is about to emit. Only meaningful when kyris allows; deny paths
/// always return `"none"` because exit-2 blocks the action universally.
fn agent_prompt_for(allow_response: &AllowResponse) -> &'static str {
    match allow_response {
        AllowResponse::Json { .. } => "none",
        AllowResponse::EmptyStdout => "agent_decides",
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
fn effective_allow_response(native: &AllowResponse, log_mode: bool) -> AllowResponse {
    if log_mode {
        AllowResponse::EmptyStdout
    } else {
        native.clone()
    }
}

fn map_payload(protocol: Option<&HookProtocol>, input: &serde_json::Value) -> (String, String) {
    let Some(protocol) = protocol else {
        let method = input["method"].as_str().unwrap_or("call");
        let detail = input["detail"].as_str().unwrap_or("");
        return (method.to_string(), detail.to_string());
    };

    let tool = if let Some(t) = input[&protocol.tool_name_field].as_str() {
        t
    } else {
        eprintln!(
            "[agentpact] warning: payload missing '{}' field, defaulting to unknown",
            protocol.tool_name_field
        );
        "unknown"
    };

    let mapping = protocol.tool_mappings.iter().find(|m| m.tool_name == tool);

    let action = mapping.map_or(protocol.default_action.as_str(), |m| m.action.as_str());

    let detail = extract_detail(protocol, mapping, input, tool);

    (action.to_string(), detail)
}

fn extract_detail(
    protocol: &HookProtocol,
    mapping: Option<&ToolMapping>,
    input: &serde_json::Value,
    tool: &str,
) -> String {
    for field in &protocol.detail_fields {
        let value = &input[field];
        if let Some(s) = value.as_str() {
            return s.to_string();
        }
        if value.is_object() {
            if let Some(key) = mapping.and_then(|m| m.detail_key.as_deref())
                && let Some(s) = value[key].as_str()
            {
                return s.to_string();
            }
            return value.to_string();
        }
    }
    tool.to_string()
}

// --- Response formatting ---
// All agents treat exit 2 + stderr as a hard block, so deny is universal.
// Allow varies per agent: some expect empty stdout, others expect JSON.

fn emit_allow(allow_response: &AllowResponse) {
    match allow_response {
        AllowResponse::EmptyStdout => {}
        AllowResponse::Json { body } => {
            println!("{}", serde_json::to_string(body).unwrap_or_default());
        }
    }
}

fn emit_deny(reason: &str) {
    eprintln!("[agentpact] {reason}");
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- per-segment aggregation driver (`run_segments`) ---
    //
    // Pure logic, exercised with canned classifications/popup results so
    // the all-allow / any-deny / short-circuit behavior is covered without
    // a live daemon or popup.

    fn seg_vec(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn testRunSegmentsAllAutoAllows() {
        // Every segment auto-allows → no popup invoked, allow.
        let segs = seg_vec(&["cat hello.txt", "grep hi"]);
        let mut prompted = 0;
        let result = run_segments(
            &segs,
            false,
            |_seg| SegClass::Auto,
            |_id, _tok, _seg| {
                prompted += 1;
                PopupResult::Approved {
                    source: "user_approved",
                }
            },
        );
        assert_eq!(result.unwrap(), "agentpact_auto");
        assert_eq!(prompted, 0, "auto segments must not prompt");
    }

    #[test]
    fn testRunSegmentsPromptsOnlyAskSegments() {
        // Mixed: only the unclassified segment is prompted; approval allows.
        let segs = seg_vec(&["cat hello.txt", "mystery-bin"]);
        let mut prompted = Vec::new();
        let result = run_segments(
            &segs,
            false,
            |seg| {
                if seg == "mystery-bin" {
                    SegClass::Ask {
                        approval_id: "apr_1".to_string(),
                        approval_token: "tok_1".to_string(),
                    }
                } else {
                    SegClass::Auto
                }
            },
            |_id, _tok, seg| {
                prompted.push(seg.to_string());
                PopupResult::Approved {
                    source: "user_approved",
                }
            },
        );
        assert_eq!(result.unwrap(), "user_approved");
        assert_eq!(prompted, vec!["mystery-bin".to_string()]);
    }

    #[test]
    fn testRunSegmentsDeniedSegmentBlocksAndShortCircuits() {
        // First segment's popup is denied → block, and the later segment is
        // never classified (short-circuit: the agent runs it as a unit).
        let segs = seg_vec(&["mystery-bin", "later-seg"]);
        let mut classified = Vec::new();
        let result = run_segments(
            &segs,
            false,
            |seg| {
                classified.push(seg.to_string());
                SegClass::Ask {
                    approval_id: "a".to_string(),
                    approval_token: "t".to_string(),
                }
            },
            |_id, _tok, _seg| PopupResult::Blocked {
                exit_code: 2,
                source: "user_denied",
                reason: "nope".to_string(),
            },
        );
        let block = result.unwrap_err();
        assert_eq!(block.exit_code, 2);
        assert_eq!(block.source, "user_denied");
        assert_eq!(
            classified,
            vec!["mystery-bin".to_string()],
            "must stop at the first denied segment"
        );
    }

    #[test]
    fn testRunSegmentsPolicyDenyBlocks() {
        let segs = seg_vec(&["rm -rf /"]);
        let result = run_segments(
            &segs,
            false,
            |_seg| SegClass::Deny {
                reason: "blocked by policy".to_string(),
            },
            |_id, _tok, _seg| unreachable!("deny must not prompt"),
        );
        let block = result.unwrap_err();
        assert_eq!(block.source, "agentpact_deny");
        assert_eq!(block.reason, "blocked by policy");
    }

    #[test]
    fn testRunSegmentsUnavailableFailsClosedByDefault() {
        let segs = seg_vec(&["cmd"]);
        let result = run_segments(
            &segs,
            false, // fail closed
            |_seg| SegClass::Unavailable {
                reason: "daemon down".to_string(),
            },
            |_id, _tok, _seg| unreachable!(),
        );
        assert_eq!(result.unwrap_err().source, "agentpact_unreachable");
    }

    #[test]
    fn testRunSegmentsUnavailableFailsOpenWhenAllowed() {
        let segs = seg_vec(&["cmd"]);
        let result = run_segments(
            &segs,
            true, // fail open
            |_seg| SegClass::Unavailable {
                reason: "daemon down".to_string(),
            },
            |_id, _tok, _seg| unreachable!(),
        );
        assert_eq!(result.unwrap(), "agentpact_unreachable");
    }

    #[test]
    fn testAgentPromptForJsonShapeIsNone() {
        // Agents whose hook protocol returns a JSON allow shape (Claude
        // Code, Gemini CLI today) get a definitive allow, suppressing
        // any prompt the agent would otherwise show.
        let json = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        assert_eq!(agent_prompt_for(&json), "none");
    }

    #[test]
    fn testAgentPromptForEmptyStdoutDefersToAgent() {
        // Agents whose hook protocol returns empty stdout (Codex CLI
        // today) leave the decision to the agent's own permission
        // rules, which may or may not prompt.
        assert_eq!(
            agent_prompt_for(&AllowResponse::EmptyStdout),
            "agent_decides"
        );
    }

    #[test]
    fn testEffectiveAllowResponseEnforceModePreservesNativeJsonShape() {
        // When kyris is enforcing, Claude Code / Gemini CLI must get
        // their native JSON allow shape so kyris's "approved by
        // AgentPact policy" decision skips the agent's own prompt.
        let native = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        match effective_allow_response(&native, false) {
            AllowResponse::Json { body } => {
                assert_eq!(
                    body["hookSpecificOutput"]["permissionDecision"],
                    serde_json::json!("allow")
                );
            }
            AllowResponse::EmptyStdout => {
                panic!("enforce mode must preserve the agent's native Json shape");
            }
        }
    }

    #[test]
    fn testEffectiveAllowResponseLogModeForcesEmptyStdout() {
        // The whole point of this helper: in log mode the agent must
        // get to apply its own permission rules. Emitting the Json
        // "allow" shape would suppress Claude Code's prompt and
        // silently approve every command — the bug we're guarding
        // against.
        let native = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        assert!(matches!(
            effective_allow_response(&native, true),
            AllowResponse::EmptyStdout
        ));
    }

    #[test]
    fn testEffectiveAllowResponseLogModeKeepsEmptyStdoutAsEmptyStdout() {
        // Agents whose native shape is already EmptyStdout (Codex
        // CLI) shouldn't change behavior in log mode — it's the same
        // shape either way. Test guards against a future refactor
        // accidentally producing a different value.
        let native = AllowResponse::EmptyStdout;
        assert!(matches!(
            effective_allow_response(&native, true),
            AllowResponse::EmptyStdout
        ));
        assert!(matches!(
            effective_allow_response(&native, false),
            AllowResponse::EmptyStdout
        ));
    }

    #[test]
    fn testAuditAgentPromptReflectsEffectiveResponseInLogMode() {
        // Audit log honesty: when kyris hands the decision back to
        // the agent (log mode), the audit field must say
        // "agent_decides" — not "none" (which would imply kyris
        // suppressed the prompt).
        let native = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        let effective = effective_allow_response(&native, true);
        assert_eq!(agent_prompt_for(&effective), "agent_decides");
    }

    #[test]
    fn testMapPayloadWithoutProtocol() {
        let input = serde_json::json!({"method": "execute", "detail": "git status"});
        let (action, detail) = map_payload(None, &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "git status");
    }

    #[test]
    fn testMapPayloadStringDetail() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![ToolMapping {
                tool_name: "Bash".to_string(),
                action: "execute".to_string(),
                detail_key: Some("command".to_string()),
            }],
            pass_through_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input = serde_json::json!({"tool_name": "Bash", "tool_input": "ls -la"});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "ls -la");
    }

    #[test]
    fn testMapPayloadStructuredDetailWithKey() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![ToolMapping {
                tool_name: "Bash".to_string(),
                action: "execute".to_string(),
                detail_key: Some("command".to_string()),
            }],
            pass_through_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp"}});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "rm -rf /tmp");
    }

    #[test]
    fn testMapPayloadStructuredDetailFallbackJson() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![ToolMapping {
                tool_name: "CustomTool".to_string(),
                action: "call".to_string(),
                detail_key: None,
            }],
            pass_through_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input = serde_json::json!({"tool_name": "CustomTool", "tool_input": {"foo": "bar"}});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"foo":"bar"}"#);
    }

    #[test]
    fn testMapPayloadDefaultAction() {
        let protocol = HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![],
            pass_through_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
        };
        let input = serde_json::json!({"tool_name": "Read", "tool_input": "/tmp/file"});
        let (action, detail) = map_payload(Some(&protocol), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "/tmp/file");
    }

    #[test]
    fn testMapPayloadMissingFields() {
        let input = serde_json::json!({});
        let (action, detail) = map_payload(None, &input);
        assert_eq!(action, "call");
        assert_eq!(detail, "");
    }

    fn agent_protocol(id: &str) -> HookProtocol {
        registry::agent_by_id(id)
            .expect("agent exists")
            .hook_protocol()
            .expect("agent has hook protocol")
    }

    // --- Claude Code real payload fixtures ---

    #[test]
    fn testClaudeCodeBashStringPayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "git diff --stat"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "git diff --stat");
    }

    #[test]
    fn testClaudeCodeReadFilePayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Read",
            "tool_input": {"file_path": "/home/user/project/src/main.rs"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "read");
        assert_eq!(detail, "/home/user/project/src/main.rs");
    }

    #[test]
    fn testClaudeCodeWriteFilePayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/output.txt", "content": "hello"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/tmp/output.txt");
    }

    #[test]
    fn testClaudeCodeEditFilePayload() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {"file_path": "/home/user/lib.rs", "old_string": "foo", "new_string": "bar"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/home/user/lib.rs");
    }

    #[test]
    fn testClaudeCodeLowercaseBashVariant() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "bash",
            "tool_input": {"command": "npm test"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "npm test");
    }

    #[test]
    fn testClaudeCodeUnknownToolDefaultsToCall() {
        let proto = agent_protocol("claude-code");
        let input = serde_json::json!({
            "tool_name": "WebSearch",
            "tool_input": {"query": "rust async"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"query":"rust async"}"#);
    }

    // --- Codex CLI real payload fixtures ---

    #[test]
    fn testCodexCliBashPayload() {
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "cargo build --release"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "cargo build --release");
    }

    #[test]
    fn testCodexCliApplyPatchPayload() {
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": {"command": "--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-old\n+new"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(
            detail,
            "--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-old\n+new"
        );
    }

    #[test]
    fn testCodexCliUnknownToolDefaultsToCall() {
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "browser",
            "tool_input": {"url": "https://example.com"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"url":"https://example.com"}"#);
    }

    // --- Gemini CLI real payload fixtures ---

    #[test]
    fn testGeminiCliShellPayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "run_shell_command",
            "tool_input": {"command": "python3 -m pytest"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "python3 -m pytest");
    }

    #[test]
    fn testGeminiCliReadFilePayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "read_file",
            "tool_input": {"file_path": "/home/user/package.json"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "read");
        assert_eq!(detail, "/home/user/package.json");
    }

    #[test]
    fn testGeminiCliWriteFilePayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "write_file",
            "tool_input": {"file_path": "/home/user/output.ts", "content": "new code"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/home/user/output.ts");
    }

    #[test]
    fn testGeminiCliReplacePayload() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "replace",
            "tool_input": {"file_path": "/home/user/index.ts", "old_text": "foo", "new_text": "bar"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "write");
        assert_eq!(detail, "/home/user/index.ts");
    }

    // --- cwd / relative-path resolution (P4) ---

    #[test]
    fn testResolveRelativePathAbsoluteUnchanged() {
        let out = resolve_relative_path("read", "/abs/foo.txt", Some("/proj"));
        assert_eq!(out, "/abs/foo.txt");
    }

    #[test]
    fn testResolveRelativePathReadJoinsCwd() {
        let out = resolve_relative_path("read", "src/main.rs", Some("/proj"));
        assert_eq!(out, "/proj/src/main.rs");
    }

    #[test]
    fn testResolveRelativePathWriteJoinsCwd() {
        let out = resolve_relative_path("write", "out.txt", Some("/proj"));
        assert_eq!(out, "/proj/out.txt");
    }

    #[test]
    fn testResolveRelativePathExecutePassesThrough() {
        // Execute details are commands, not paths — never rewrite them.
        let out = resolve_relative_path("execute", "ls -la", Some("/proj"));
        assert_eq!(out, "ls -la");
    }

    #[test]
    fn testResolveRelativePathNoCwdPassesThrough() {
        let out = resolve_relative_path("read", "src/main.rs", None);
        assert_eq!(out, "src/main.rs");
    }

    #[test]
    fn testHookPayloadCwdParsedPreferredOverEnv() {
        // Sanity: the payload's cwd field must be a string and non-empty.
        // The actual env-vs-payload selection logic lives in run_check;
        // here we just confirm the JSON path used to extract it.
        let input = serde_json::json!({
            "cwd": "/Users/alex/proj",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/main.rs"}
        });
        assert_eq!(
            input.get("cwd").and_then(|v| v.as_str()),
            Some("/Users/alex/proj")
        );
    }

    #[test]
    fn testGeminiCliUnknownToolDefaultsToCall() {
        let proto = agent_protocol("gemini-cli");
        let input = serde_json::json!({
            "tool_name": "google_search",
            "tool_input": {"query": "rust async runtime"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "call");
        assert_eq!(detail, r#"{"query":"rust async runtime"}"#);
    }
}
