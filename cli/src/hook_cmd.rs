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

use kyris_agentpact_client::{self as pact_client, ApprovalResponse, McpPermissionDecision};
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
    /// Resolve an interactive shell-hook approval **per compound segment**.
    /// Invoked by the zsh/bash preexec hooks when `kyris-hook check` returns
    /// a normal ask (exit 2). Re-derives the compound split with a
    /// side-effect-free preview, then issues one real token-bearing request
    /// per segment: auto segments run silently, and each segment that needs
    /// approval gets its own prompt and its own "always" — on the TTY when
    /// one is available, else via kyrisd's pending-approval system. Exits 0
    /// (every segment allowed) or non-zero (a segment was denied/blocked).
    ResolveShell(HookResolveShellArgs),
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

#[derive(Args)]
pub struct HookResolveShellArgs {
    /// The full shell command line the preexec hook intercepted.
    #[arg(long)]
    pub cmd: String,
    /// The shell's working directory (the request's `working_dir`).
    #[arg(long)]
    pub cwd: Option<String>,
    /// Path to the agentpactd UDS socket (defaults to the standard location).
    #[arg(long)]
    pub socket: Option<String>,
}

pub fn run(args: HookArgs) {
    match args.command {
        HookCommand::Check(check_args) => run_check(check_args),
        HookCommand::Hold(hold_args) => run_hold(hold_args),
        HookCommand::ResolveShell(resolve_args) => run_resolve_shell(resolve_args),
    }
}

/// Drive per-segment approval for a shell command the fast `kyris-hook check`
/// path flagged as a normal ask. Mirrors the native hook's per-segment flow
/// ([`dispatch_preview_outcome`]/[`drive_per_segment`]) but prompts on the
/// TTY when one is available, falling back to kyrisd's pending-approval
/// popup otherwise.
fn run_resolve_shell(args: HookResolveShellArgs) -> ! {
    let sock_path = args
        .socket
        .unwrap_or_else(|| pact_client::default_socket_path().display().to_string());
    let socket_timeout = std::time::Duration::from_secs(5);
    let cwd = args.cwd.as_deref();
    let action = "execute";

    // Side-effect-free preview to learn the compound split. The hook never
    // parses shell itself — the daemon owns splitting (`policy::splitter`).
    // No token is minted here.
    // The preview is a side-effect-free scout used ONLY for the compound split;
    // its decision is discarded. Every line — including one the preview would
    // deny — is re-driven through real per-segment requests below, so it is
    // presented one component at a time and audited/accounted segment by
    // segment in agentpactd (`classify_segment`), never short-circuited here
    // on a side-effect-free preview.
    let (_decision, segments) = match pact_client::request_hook_permission_preview(
        &sock_path,
        "kyris-hook",
        action,
        &args.cmd,
        cwd,
        None,
        socket_timeout,
    ) {
        Ok(pair) => pair,
        Err(reason) => {
            if pact_client::allow_on_daemon_unavailable() {
                kyris_core::fail_open_log::record(action, &args.cmd, "shell", cwd);
                std::process::exit(0);
            }
            emit_deny(&reason);
            std::process::exit(2);
        }
    };

    let segs = segments.unwrap_or_else(|| vec![args.cmd.clone()]);

    // A genuinely compound command (>=2 segments) is driven per-segment but
    // audited as ONE event: mint a command-group id and tag every segment's
    // request with it + the original line. Single commands carry no group and
    // audit one event as before.
    let command_group_id = (segs.len() >= 2).then(pact_client::new_command_group);
    let command_group = command_group_id
        .as_deref()
        .map(|group| (group, args.cmd.as_str()));

    let allow_response = AllowResponse::EmptyStdout;
    let ctx = PermissionCtx {
        audit_conn: None,
        hook_id: "",
        agent: "shell",
        action,
        detail: &args.cmd,
        cwd,
        native_allow_response: &allow_response,
        log_mode_fallback: false,
        sock_path: &sock_path,
        socket_timeout,
        started_at: std::time::Instant::now(),
    };

    // Open the controlling terminal once. Present → prompt inline; absent
    // (agent-spawned non-interactive shell) → delegate to kyrisd's pending
    // popup, exactly as the no-TTY `kyris hook hold` path does today.
    let tty = open_tty();

    let result = run_segments(
        &segs,
        pact_client::allow_on_daemon_unavailable(),
        |seg| classify_segment(&ctx, None, seg, command_group),
        |approval_id, approval_token, seg, allow_always| match tty.as_ref() {
            Some(tty) => tty_prompt_segment(
                tty,
                &sock_path,
                socket_timeout,
                approval_token,
                seg,
                allow_always,
            ),
            None => poll_segment(
                "shell",
                &sock_path,
                socket_timeout,
                approval_id,
                approval_token,
                seg,
                allow_always,
            ),
        },
    );

    // Every segment of the line has been driven (allowed or denied): finalize
    // the buffered aggregate into one event. Best-effort — the daemon's expiry
    // sweep flushes the buffer if this commit is dropped.
    if let Some(group) = &command_group_id {
        pact_client::send_command_commit(&sock_path, group, socket_timeout);
    }

    match result {
        Ok(_) => std::process::exit(0),
        // Gate 2 of the two-gate flow: an ask that couldn't be rendered because
        // kyrisd is unreachable, under a fail-open policy → allow + spool. This
        // is what lets a command the agent-hook already deferred-and-approved
        // actually run (the agent hook only defers under the same `allow`).
        // Under `deny` this arm is skipped and we hard-deny below.
        Err(block)
            if block.source == "kyrisd_unreachable"
                && pact_client::allow_on_daemon_unavailable() =>
        {
            kyris_core::fail_open_log::record(action, &args.cmd, "shell", cwd);
            std::process::exit(0);
        }
        Err(block) => {
            emit_deny(&block.reason);
            std::process::exit(block.exit_code);
        }
    }
}

/// Open the controlling terminal for interactive prompting. Returns `None`
/// when there is no TTY (an agent-spawned non-interactive shell), in which
/// case the caller falls back to kyrisd's pending-approval popup.
fn open_tty() -> Option<std::fs::File> {
    // A TUI agent (Claude Code et al.) owns the controlling terminal in raw
    // mode with focus/mouse reporting enabled. Opening and blocking-reading
    // /dev/tty here would steal the agent's input bytes (focus `\e[I`/`\e[O`
    // events, keystrokes) and desync its TUI, freezing its input line. When we
    // detect a TUI-agent context, report "no TTY" so the caller falls back to
    // kyrisd's out-of-band pending-approval flow and never touches the agent's
    // terminal.
    if std::env::var_os("CLAUDECODE").is_some()
        || std::env::var_os("KYRIS_GOVERNED_SUBPROCESS").is_some()
    {
        return None;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

/// Read one line from the TTY one byte at a time. Deliberately unbuffered:
/// the same `/dev/tty` handle is reused across every per-segment prompt, so
/// a `BufReader` could read past the newline and swallow the next prompt's
/// answer. Returns `None` on EOF-before-any-input or a read error (treated
/// as "no decision" → deny). The trailing newline is included; the caller
/// trims.
fn read_tty_line(tty: &std::fs::File) -> Option<String> {
    use std::io::Read as _;
    let mut reader = tty;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break, // EOF
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    if line.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&line).into_owned())
}

/// Prompt for one segment on the TTY (`[y/n/always]`) and deliver the
/// decision to agentpactd. Returns the [`PopupResult`] without emitting any
/// shell output beyond the prompt — the caller maps the aggregate result to
/// an exit code. A read failure denies safe.
fn tty_prompt_segment(
    tty: &std::fs::File,
    sock_path: &str,
    socket_timeout: std::time::Duration,
    approval_token: &str,
    seg: &str,
    allow_always: bool,
) -> PopupResult {
    use std::io::Write as _;

    // Offer "always" only when the daemon says a grant would persist.
    let choices = if allow_always {
        "[y/n/always]"
    } else {
        "[y/n]"
    };
    eprint!("\x1b[33m[kyris] allow?\x1b[0m {seg} {choices} ");
    let _ = std::io::stderr().flush();

    let Some(answer) = read_tty_line(tty) else {
        deny_ask_immediately(approval_token, sock_path, socket_timeout);
        return PopupResult::Blocked {
            exit_code: 2,
            source: "tty_error",
            reason: "could not read approval from /dev/tty".to_string(),
        };
    };

    let (response, source) = match answer.trim() {
        "y" | "Y" | "yes" => (ApprovalResponse::Approved, "user_approved"),
        // "always" sticks only when persistable; otherwise the daemon would
        // refuse to persist anyway, so honor it as a one-time approval.
        "a" | "A" | "always" => {
            if allow_always {
                (ApprovalResponse::Always, "user_always")
            } else {
                (ApprovalResponse::Approved, "user_approved")
            }
        }
        _ => (ApprovalResponse::Denied, "user_denied"),
    };

    match pact_client::send_permission_response(
        sock_path,
        "kyris-hook-tty",
        approval_token,
        response,
        Some(socket_timeout),
    ) {
        Ok(_) if response == ApprovalResponse::Denied => PopupResult::Blocked {
            exit_code: 2,
            source,
            reason: "denied by developer".to_string(),
        },
        Ok(warning) => {
            // The daemon applied the decision but may warn that a side effect
            // (e.g. persisting an "always" grant) could not be completed — show
            // it on the TTY where the developer just answered.
            if let Some(warning) = warning {
                eprintln!("\x1b[33m[kyris]\x1b[0m {warning}");
            }
            PopupResult::Approved { source }
        }
        Err(reason) => PopupResult::Blocked {
            exit_code: 2,
            source: "respond_failed",
            reason,
        },
    }
}

fn run_hold(args: HookHoldArgs) {
    let sock_path = args
        .socket
        .unwrap_or_else(|| pact_client::default_socket_path().display().to_string());
    let socket_timeout = std::time::Duration::from_secs(5);

    // Reuse poll_segment: it holds the request in kyrisd's pending system,
    // polls for developer resolution (kyrisd sends permission.respond to
    // agentpactd), and returns the outcome. The shell hook only cares about
    // the exit code, so an approval emits nothing and exits 0.
    //
    // `server` is "shell" (the popup title slot — "Kyris: Allow shell");
    // `args.display` (the verbatim command) is the segment text, which
    // becomes the popup body and the syntect-highlighted accessoryView.
    //
    // `hold` now serves only the circuit-breaker path (normal asks go through
    // `resolve-shell`), and a breaker ask never persists an override — so
    // "Always" is never offered here.
    match poll_segment(
        "shell",
        &sock_path,
        socket_timeout,
        &args.req_id,
        &args.token,
        &args.display,
        false,
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
    let sig_table = agentpact::attribution::signatures::SignatureTable::default_phase1();
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
    // `agentpact` is the upstream agentpact library (policy/protocol);
    // `pact_client` (above) is kyris's UDS client to agentpactd.
    let log_mode = std::env::current_dir()
        .ok()
        .as_deref()
        .and_then(agentpact::policy::resolution::resolve_mode_at)
        .is_some_and(|r| r.mode == agentpact::protocol::types::Mode::Log);

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

/// Handle a tool that does not go through agentpactd. Returns normally only
/// when `tool` IS governable (a `tool_mappings` entry) — the caller then
/// proceeds to the daemon round-trip. For a pass-through or unmapped tool it
/// audits, emits the appropriate allow shape (see [`non_governed_response`]),
/// and exits the process; it never returns in that case.
#[allow(clippy::too_many_arguments)]
fn handle_non_governed(
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
    let pass_through = proto.pass_through_tools.iter().any(|t| t == tool);
    if !pass_through {
        eprintln!(
            "[agentpact] warning: '{tool}' is not in the {agent} mapping table; \
             deferring to {agent}'s own permission prompt (kyris is not governing it). \
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
        agent_prompt_for(&response),
        started_at.elapsed(),
    );
    emit_allow(&response);
    std::process::exit(0);
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
/// The preview has no side effects: it neither audits, nor counts the circuit
/// breaker, nor issues exec tokens, nor updates session state. So its decision
/// is used **only** as a scout — for the compound split it carries and for the
/// effective mode — and every command is then re-driven through real,
/// token-bearing per-segment requests ([`drive_per_segment`]). That is what
/// produces the `AgentPact` action events, breaker accounting, exec tokens, and
/// session-cwd update, and it is uniform across what the preview classified as
/// `Auto`, `Ask`, or `Deny`: the per-segment real requests determine the true
/// outcome (auto segments run silently, ask segments each get their own popup
/// and per-segment "Always", a denied segment blocks the line).
///
/// The success allow shape is mode-correct: `EmptyStdout` in log mode (defer to
/// the agent's own prompt), the agent's native allow shape in enforce mode.
/// Only the daemon-unreachable arms (no decision to scout) emit directly.
///
/// Compound splitting is the daemon's job (`agentpact::policy::splitter`); the
/// hook never parses shell itself.
fn dispatch_preview_outcome(
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
        Err(_) if pact_client::allow_on_daemon_unavailable() => {
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
    /// Needs approval; carries the token that drives its popup and the
    /// daemon's authoritative `allow_always` (whether "Always" would persist).
    Ask {
        approval_id: String,
        approval_token: String,
        allow_always: bool,
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
    P: FnMut(&str, &str, &str, bool) -> PopupResult,
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
                allow_always,
            } => match prompt(&approval_id, &approval_token, seg, allow_always) {
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
fn drive_per_segment(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
    segments: Option<Vec<String>>,
    log_mode: bool,
) -> ! {
    let segs = segments.unwrap_or_else(|| vec![ctx.detail.to_string()]);

    // Compound line (>=2 segments) → drive per-segment but audit as one event.
    let command_group_id = (segs.len() >= 2).then(pact_client::new_command_group);
    let command_group = command_group_id.as_deref().map(|group| (group, ctx.detail));

    let result = run_segments(
        &segs,
        pact_client::allow_on_daemon_unavailable(),
        |seg| classify_segment(ctx, seed_pid, seg, command_group),
        |approval_id, approval_token, seg, allow_always| {
            poll_segment(
                ctx.action,
                ctx.sock_path,
                ctx.socket_timeout,
                approval_id,
                approval_token,
                seg,
                allow_always,
            )
        },
    );

    // Finalize the buffered aggregate into one event (best-effort; expiry sweep
    // backstops a dropped commit).
    if let Some(group) = &command_group_id {
        pact_client::send_command_commit(ctx.sock_path, group, ctx.socket_timeout);
    }

    match result {
        Ok(source) => {
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
                agent_prompt_for(&response),
                ctx.started_at.elapsed(),
            );
            emit_allow(&response);
            std::process::exit(0);
        }
        Err(block)
            if block_defers_to_agent(block.source, pact_client::allow_on_daemon_unavailable()) =>
        {
            // agentpactd returned a real "ask", but the no-TTY resolution
            // channel (kyrisd) couldn't render the dialog, AND the policy is
            // fail-open (`on_daemon_unavailable: allow`). Defer to the AGENT's
            // own permission UX by emitting the EmptyStdout shape, so the human
            // still decides via the agent's prompt; the shell-preexec gate also
            // fails-open under `allow`, so an approved command actually runs.
            // Spool it so the audit trail shows kyris punted this command.
            // (Under `deny`, this arm is skipped and we hard-deny below — no
            // false-hope "approve then shell-deny". A real deny / user denial /
            // timeout always blocks.)
            kyris_core::fail_open_log::record(ctx.action, ctx.detail, ctx.agent, ctx.cwd);
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
                agent_prompt_for(&AllowResponse::EmptyStdout),
                ctx.started_at.elapsed(),
            );
            emit_allow(&AllowResponse::EmptyStdout);
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

/// On the agent-hook path, decide whether a blocked segment should *defer to
/// the agent's own permission UX* instead of hard-denying.
///
/// Deferring is correct ONLY when (a) the block is `kyrisd_unreachable` —
/// agentpactd returned a real "ask" but the no-TTY resolution channel (kyrisd)
/// couldn't render the dialog — AND (b) the operator's `on_daemon_unavailable`
/// is `allow`. The `allow` gate matters because the agent's command is governed
/// a SECOND time by the shell preexec hook: there, `on_daemon_unavailable:allow`
/// makes that gate fail-open, so a command the agent prompts-and-approves
/// actually runs. Under `deny`, the shell gate would re-deny it — so deferring
/// there only yields a confusing "agent prompts → you approve → shell denies."
/// Hence under `deny` we hard-deny here too, cleanly and consistently.
///
/// Every other source always blocks: a policy deny (`agentpact_deny`), the
/// developer's own denial (`user_denied`), an unreachable decider
/// (`agentpact_unreachable`), or a timeout (`user_timeout`).
fn block_defers_to_agent(source: &str, allow_on_unavailable: bool) -> bool {
    source == "kyrisd_unreachable" && allow_on_unavailable
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
fn classify_segment(
    ctx: &PermissionCtx<'_>,
    seed_pid: Option<u32>,
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
    match pact_client::request_hook_permission(
        ctx.sock_path,
        "kyris-hook",
        ctx.action,
        seg,
        ctx.cwd,
        seed_pid,
        anchor_pid,
        None,
        command_group,
        ctx.socket_timeout,
    ) {
        Ok((McpPermissionDecision::Allow { .. }, _)) => SegClass::Auto,
        Ok((
            McpPermissionDecision::Ask {
                approval_id,
                approval_token,
                allow_always,
            },
            _,
        )) => SegClass::Ask {
            approval_id,
            approval_token,
            allow_always,
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
    allow_always: bool,
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
        if pact_client::allow_on_daemon_unavailable() {
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
                // Authoritative server signal from the per-segment PACT_ASK:
                // the popup greys out "Always" when the daemon would not
                // persist the grant (privilege/control/remote-destroy,
                // breaker, or no working_dir) — superseding the old
                // leading-word `sudo` heuristic, which missed wrapper-hidden
                // privilege like `env sudo …`.
                allow_always,
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
        kyris_core::pending::Resolution::Unreachable => {
            // The dialog never rendered. If the policy is `allow`,
            // drive_per_segment will DEFER this to the agent's own prompt
            // (source "kyrisd_unreachable") and the command may then run — so do
            // NOT deny the agentpactd ask here: recording a deny for a command
            // that subsequently runs would be an audit lie. Let the pending
            // expire. Under `deny` we hard-deny, where the deny IS accurate.
            if !pact_client::allow_on_daemon_unavailable() {
                deny_ask_immediately(approval_token, sock_path, socket_timeout);
            }
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
    let _ = pact_client::send_permission_response(
        sock_path,
        "kyris-hook-deny",
        approval_token,
        ApprovalResponse::Denied,
        Some(socket_timeout),
    );
}

/// Pick the workspace anchor to send to agentpactd as `working_dir`. This is
/// the permitted-domain root — the directory tree the agent may touch — so it
/// must be the agent's FIXED launch/project dir, never a value that moves when
/// the agent runs `cd`.
///
/// Resolution order:
///   1. `launch_dir` — the agent's fixed launch/project dir, already resolved
///      by the caller from the agent's `launch_dir_env` var (e.g.
///      `CLAUDE_PROJECT_DIR`). Stable across the agent's own `cd` — unlike
///      Claude Code's payload `cwd`, which is the LIVE working directory.
///   2. The hook payload's `cwd` (already fixed at session start for Codex and
///      Gemini; for Claude a fallback only if the env var is absent).
///   3. `None`. We deliberately do NOT fall back to the hook process's own
///      `current_dir()` — that is the kyris-hook process, not the agent, and
///      would anchor the permitted domain to the wrong tree. agentpactd fails
///      safe (asks) when the workspace is unknown.
fn derive_session_cwd(launch_dir: Option<&str>, hook_input: &serde_json::Value) -> Option<String> {
    if let Some(dir) = launch_dir.filter(|s| !s.trim().is_empty()) {
        return Some(dir.to_string());
    }
    hook_input
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
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

/// Actions whose `detail` is a single filesystem path (not a command string).
/// These are rendered home-relative for display/logging; `execute` details are
/// command text and are left verbatim.
fn is_file_action(action: &str) -> bool {
    matches!(action, "read" | "write" | "delete")
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
fn non_governed_response(
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

    // --- workspace anchor resolution (`derive_session_cwd`) ---

    #[test]
    fn testDeriveSessionCwdPrefersLaunchDirOverPayloadCwd() {
        // The fixed launch dir (from launch_dir_env) wins over the payload cwd,
        // which for Claude Code is the mutable live cwd that must NOT anchor the
        // permitted domain.
        let input = serde_json::json!({ "cwd": "/live/cwd/after/cd" });
        assert_eq!(
            derive_session_cwd(Some("/project/root"), &input),
            Some("/project/root".to_string())
        );
    }

    #[test]
    fn testDeriveSessionCwdFallsBackToPayloadCwd() {
        // No launch dir (agents whose payload cwd is already fixed, e.g. Codex).
        let input = serde_json::json!({ "cwd": "/session/launch/dir" });
        assert_eq!(
            derive_session_cwd(None, &input),
            Some("/session/launch/dir".to_string())
        );
    }

    #[test]
    fn testDeriveSessionCwdBlankLaunchDirFallsThrough() {
        let input = serde_json::json!({ "cwd": "/payload/cwd" });
        assert_eq!(
            derive_session_cwd(Some("   "), &input),
            Some("/payload/cwd".to_string())
        );
    }

    #[test]
    fn testDeriveSessionCwdUnknownIsNoneNotProcessCwd() {
        // No launch dir and no payload cwd → None. Critically, we do NOT fall
        // back to the hook process's current_dir(), which would anchor the
        // domain to the wrong tree; agentpactd fails safe on a None workspace.
        let input = serde_json::json!({ "tool_name": "Bash" });
        assert_eq!(derive_session_cwd(None, &input), None);
    }

    #[test]
    fn testLaunchDirEnvWiredForLiveHookAgents() {
        use crate::agents::registry;
        // Claude Code's payload cwd is mutable → must use CLAUDE_PROJECT_DIR.
        assert_eq!(
            registry::agent_by_id("claude-code").and_then(|a| a.launch_dir_env()),
            Some("CLAUDE_PROJECT_DIR")
        );
        assert_eq!(
            registry::agent_by_id("gemini-cli").and_then(|a| a.launch_dir_env()),
            Some("GEMINI_PROJECT_DIR")
        );
        // Codex's payload cwd is already the fixed session dir → no env needed.
        assert_eq!(
            registry::agent_by_id("codex-cli").and_then(|a| a.launch_dir_env()),
            None
        );
    }

    // --- per-segment aggregation driver (`run_segments`) ---
    //
    // Pure logic, exercised with canned classifications/popup results so
    // the all-allow / any-deny / short-circuit behavior is covered without
    // a live daemon or popup.

    fn seg_vec(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    // --- read_tty_line: unbuffered, no cross-prompt over-read ---

    #[test]
    fn testReadTtyLineReturnsSingleLineWithNewline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tty");
        std::fs::write(&path, "always\n").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        assert_eq!(read_tty_line(&f).as_deref(), Some("always\n"));
    }

    #[test]
    fn testReadTtyLineDoesNotOverReadAcrossCalls() {
        // Two answers queued on one handle: the first read must stop at the
        // first newline and leave the second answer for the next prompt.
        // A BufReader would swallow the second line — this guards that.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tty");
        std::fs::write(&path, "y\nn\n").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        assert_eq!(read_tty_line(&f).as_deref(), Some("y\n"));
        assert_eq!(read_tty_line(&f).as_deref(), Some("n\n"));
    }

    #[test]
    fn testReadTtyLineEmptyIsNone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tty");
        std::fs::write(&path, "").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        assert_eq!(read_tty_line(&f), None);
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
            |_id, _tok, _seg, _allow| {
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
        // Also asserts the per-segment `allow_always` propagates to the prompt.
        let segs = seg_vec(&["cat hello.txt", "mystery-bin"]);
        let mut prompted = Vec::new();
        let mut prompted_allow_always = None;
        let result = run_segments(
            &segs,
            false,
            |seg| {
                if seg == "mystery-bin" {
                    SegClass::Ask {
                        approval_id: "apr_1".to_string(),
                        approval_token: "tok_1".to_string(),
                        allow_always: true,
                    }
                } else {
                    SegClass::Auto
                }
            },
            |_id, _tok, seg, allow_always| {
                prompted.push(seg.to_string());
                prompted_allow_always = Some(allow_always);
                PopupResult::Approved {
                    source: "user_approved",
                }
            },
        );
        assert_eq!(result.unwrap(), "user_approved");
        assert_eq!(prompted, vec!["mystery-bin".to_string()]);
        assert_eq!(prompted_allow_always, Some(true));
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
                    allow_always: false,
                }
            },
            |_id, _tok, _seg, _allow| PopupResult::Blocked {
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
            |_id, _tok, _seg, _allow| unreachable!("deny must not prompt"),
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
            |_id, _tok, _seg, _allow| unreachable!(),
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
            |_id, _tok, _seg, _allow| unreachable!(),
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
    fn testNonGovernedUnmappedDefersToAgentEvenInEnforce() {
        // The P0 fix: an unmapped tool must NEVER get the agent's native allow
        // shape (which suppresses the agent's own prompt and silently approves
        // an unknown tool). It gets EmptyStdout — "no decision" — so the
        // agent's own permission system decides, as if kyris weren't installed.
        let native = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        assert!(matches!(
            non_governed_response(false, &native, false),
            AllowResponse::EmptyStdout
        ));
        // Same in log mode — unmapped is always defer.
        assert!(matches!(
            non_governed_response(false, &native, true),
            AllowResponse::EmptyStdout
        ));
        // Even when the agent's native shape is already EmptyStdout (Codex).
        assert!(matches!(
            non_governed_response(false, &AllowResponse::EmptyStdout, false),
            AllowResponse::EmptyStdout
        ));
    }

    #[test]
    fn testNonGovernedPassThroughSuppressesAgentPromptInEnforce() {
        // Blessed primitives keep the frictionless behavior: in enforce mode
        // they get the agent's native allow shape (suppressing its prompt),
        // and in log mode they defer like everything else.
        let native = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        match non_governed_response(true, &native, false) {
            AllowResponse::Json { body } => assert_eq!(
                body["hookSpecificOutput"]["permissionDecision"],
                serde_json::json!("allow")
            ),
            AllowResponse::EmptyStdout => {
                panic!("pass-through in enforce must keep the native allow shape")
            }
        }
        assert!(matches!(
            non_governed_response(true, &native, true),
            AllowResponse::EmptyStdout
        ));
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

    #[test]
    fn testDeferGatedOnKyrisdUnreachableAndFailOpenPolicy() {
        // The agent-hook defers ONLY when (a) the dialog couldn't be rendered
        // (kyrisd down → `kyrisd_unreachable`) AND (b) the policy is fail-open.
        // Under `allow`, the shell-preexec gate also fails-open so an approved
        // command runs; under `deny`, deferring would only yield a confusing
        // "approve → shell denies", so we hard-deny here too.
        assert!(
            block_defers_to_agent("kyrisd_unreachable", true),
            "kyrisd_unreachable under fail-open → defer"
        );
        assert!(
            !block_defers_to_agent("kyrisd_unreachable", false),
            "kyrisd_unreachable under fail-closed → hard-deny, not defer"
        );
        // No other source ever defers, regardless of policy.
        for source in [
            "agentpact_deny",
            "user_denied",
            "user_timeout",
            "agentpact_unreachable",
            "agentpact_auto",
        ] {
            assert!(
                !block_defers_to_agent(source, true),
                "`{source}` must NOT defer"
            );
            assert!(
                !block_defers_to_agent(source, false),
                "`{source}` must NOT defer"
            );
        }
    }
}
