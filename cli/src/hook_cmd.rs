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

use crate::agents::registry::{
    self, AllowResponse, ApprovalMode, AskResponse, HookProtocol, ToolMapping,
};

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
        // The shell gate carries no installed identity — never declare one.
        None,
        socket_timeout,
    ) {
        Ok(pair) => pair,
        Err(_reason) => {
            // agentpactd (the decider) is unreachable — never freeze the
            // developer's shell. Fail open (spool for the audit trail) and let
            // the command run; the human at the terminal is the operator.
            kyris_core::fail_open_log::record("shell", action, &args.cmd, "shell", cwd);
            std::process::exit(0);
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
        sock_path: &sock_path,
        socket_timeout,
        started_at: std::time::Instant::now(),
        // The human at the terminal is the backstop, and no agent hook
        // deadline races the shell gate.
        native_backstop: true,
        allow_suppresses_agent_prompt: false,
        poll_deadline: kyris_core::pending::NATIVE_HOOK_POLL_TIMEOUT,
        log_mode_fallback: false,
        has_permission_request: false,
        // The shell gate is not an agent: it prompts inline on the TTY or via
        // kyris's popup — there is no agent native prompt to defer to.
        approval_mode: ApprovalMode::KyrisPopup,
        native_ask: None,
    };

    // Open the controlling terminal once. Present → prompt inline; absent
    // (agent-spawned non-interactive shell) → delegate to kyrisd's pending
    // popup, exactly as the no-TTY `kyris hook hold` path does today.
    let tty = open_tty();

    // When this gate runs INSIDE a governed agent (codex/claude/gemini each set
    // a per-agent marker on the commands they spawn), that agent's OWN hook
    // already gated this command on its single approval surface — its TUI in
    // native mode, its popup otherwise. Defer an ask to it rather than opening a
    // SECOND surface for the same command. A deny still blocks below; auto runs
    // silently. Only the bare terminal (no agent) prompts here.
    let host_agent = inside_governed_agent();

    let result = run_segments(
        &segs,
        |seg| classify_segment(&ctx, None, ctx.action, seg, command_group),
        |approval_id, approval_token, seg, allow_always| {
            if host_agent {
                return PopupResult::Approved {
                    source: "host_agent",
                };
            }
            match tty.as_ref() {
                Some(tty) => tty_prompt_segment(
                    tty,
                    &sock_path,
                    socket_timeout,
                    approval_id,
                    approval_token,
                    seg,
                    allow_always,
                ),
                None => poll_segment(
                    "shell",
                    "shell",
                    &sock_path,
                    socket_timeout,
                    approval_id,
                    approval_token,
                    seg,
                    allow_always,
                    kyris_core::pending::NATIVE_HOOK_POLL_TIMEOUT,
                ),
            }
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
        // A daemon was unavailable — agentpactd (the decider) is down, or an ask
        // couldn't be rendered because kyrisd is down. Never freeze the
        // developer's shell: fail open and spool for the audit trail. This also
        // keeps the two gates consistent — a command the agent hook deferred and
        // the human approved actually runs here. A real deny / denial / timeout
        // still blocks below.
        Err(block) if block_from_daemon_unavailable(block.source) => {
            kyris_core::fail_open_log::record("shell", action, &args.cmd, "shell", cwd);
            std::process::exit(0);
        }
        Err(block) => {
            emit_deny(&block.reason);
            std::process::exit(block.exit_code);
        }
    }
}

/// Whether the shell gate is running INSIDE a governed agent's subprocess, by
/// the per-agent marker each one sets on the commands it spawns: codex's
/// `KYRIS_GOVERNED_SUBPROCESS` (also exported by the hook wrappers), Claude
/// Code's `CLAUDECODE`, and Gemini CLI's `GEMINI_CLI` — plus
/// `__KYRIS_GUARD_RESULT=1`, the cached verdict of the SHELL hook's own
/// detector (`bash_hook.sh` / `zsh_hook.sh`), whose ppid-walk slow path
/// recognizes agents launched WITHOUT the shim. The shell hook arms its trap
/// based on that detector, so this function must agree with it: when the
/// shell side decided "governed agent" but this check said "bare terminal",
/// an ask landed on the interactive TTY prompt inside an agent's hook
/// subprocess — an invisible blocking read of /dev/tty that stole the
/// agent's terminal input (the codex `[I]11;rgb:…` composer-garbage bug).
/// When true, the agent's OWN hook is the single approval surface for the
/// command, so the shell gate defers an ask to it instead of opening a
/// second one. False means a bare terminal (no agent), where the shell gate
/// prompts itself.
fn inside_governed_agent() -> bool {
    std::env::var_os("KYRIS_GOVERNED_SUBPROCESS").is_some()
        || std::env::var_os("CLAUDECODE").is_some()
        || std::env::var_os("GEMINI_CLI").is_some()
        || std::env::var_os("__KYRIS_GUARD_RESULT").is_some_and(|v| v == "1")
}

/// Open the controlling terminal for interactive prompting. Returns `None`
/// when there is no usable TTY (an agent-spawned non-interactive shell), in
/// which case the caller falls back to kyrisd's pending-approval popup.
fn open_tty() -> Option<std::fs::File> {
    // A TUI agent (Claude Code et al.) owns the controlling terminal in raw
    // mode with focus/mouse reporting enabled. Opening and blocking-reading
    // /dev/tty here would steal the agent's input bytes (focus `\e[I`/`\e[O`
    // events, keystrokes) and desync its TUI, freezing its input line. When we
    // detect a governed-agent context, report "no TTY" so the caller falls
    // back to kyrisd's out-of-band pending-approval flow and never touches
    // the agent's terminal.
    if inside_governed_agent() {
        return None;
    }
    // Safety net for contexts no marker covers (an agent launched around the
    // shim with its hook ancestry invisible to every detector): the prompt is
    // printed to stderr, so if stderr is NOT a terminal the human cannot see
    // it — a blocking /dev/tty read would silently eat whatever terminal owns
    // this process group. Only prompt when the prompt is actually visible;
    // otherwise fall back to the kyrisd popup.
    {
        use std::io::IsTerminal as _;
        if !std::io::stderr().is_terminal() {
            return None;
        }
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
    approval_id: &str,
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
    kyris_core::prompt_log::record_now(
        approval_id,
        "tty",
        "displayed",
        "shell",
        Some(seg),
        Some(seg),
        "shell",
        allow_always,
        None,
    );
    eprint!("\x1b[33m[kyris] allow?\x1b[0m {seg} {choices} ");
    let _ = std::io::stderr().flush();

    let Some(answer) = read_tty_line(tty) else {
        kyris_core::prompt_log::record_now(
            approval_id,
            "tty",
            "read_failed",
            "shell",
            Some(seg),
            Some(seg),
            "shell",
            allow_always,
            Some("tty_error"),
        );
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
    let outcome = match response {
        ApprovalResponse::Approved => "approved",
        ApprovalResponse::Always => "always",
        ApprovalResponse::Denied => "denied",
    };
    kyris_core::prompt_log::record_now(
        approval_id,
        "tty",
        "decision_submitted",
        "shell",
        Some(seg),
        Some(seg),
        "shell",
        allow_always,
        Some(outcome),
    );

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
        "shell",
        &sock_path,
        socket_timeout,
        &args.req_id,
        &args.token,
        &args.display,
        false,
        kyris_core::pending::NATIVE_HOOK_POLL_TIMEOUT,
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

/// Canonical `vendor/name` identity for a kyris-integrated agent id, used as
/// the DECLARED attribution identity on agentpactd requests. The hook's
/// `--agent` value was written into the agent's hook config by `kyris agents
/// setup` (install-time-owned, not chosen by the agent at runtime), so the
/// daemon can attribute exactly with zero signature-catalog knowledge of the
/// agent's install layout. Returns None for ids with no registered
/// integration — notably the shell gate's `"shell"` — which keep attributing
/// via lineage.
fn declared_canonical_agent(agent: &str) -> Option<String> {
    registry::agent_by_id(agent).map(|a| a.canonical_id().to_string())
}

fn discover_agent_pid() -> Option<u32> {
    // Same catalog agentpactd loads (single source): resolved via the daemon
    // config's defaults-dir logic. Discovery failing here is non-fatal — the
    // request still carries the declared `--agent` identity plus `anchor_pid`,
    // which the daemon can seed a boundary from with ancestry validation.
    let sig_table = agentpact::config::DaemonConfig::load()
        .ok()
        .map(|c| c.defaults_dir.join("agents.yaml"))
        .and_then(|p| {
            agentpact::attribution::signatures::SignatureTable::load_from_yaml(&p).ok()
        })?;
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

#[allow(clippy::too_many_lines)]
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
///   agent's native allow shape (see [`non_governed_response`]).
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
             `kyris agents setup {agent}`), or `kyris agents undo {agent}` to \
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
struct PermissionCtx<'a> {
    audit_conn: Option<&'a kyris_core::config::KyrisdConnection>,
    hook_id: &'a str,
    agent: &'a str,
    action: &'a str,
    detail: &'a str,
    cwd: Option<&'a str>,
    native_allow_response: &'a AllowResponse,
    sock_path: &'a str,
    socket_timeout: std::time::Duration,
    started_at: std::time::Instant,
    /// From the agent's `HookRuntime`: whether the agent's own permission
    /// system still gates a tool kyris defers on. When false, every defer path
    /// (daemon unavailable, unrenderable ask) becomes a DENY — a defer would be
    /// a silent allow (G1). True for the shell gate: the human at the terminal
    /// is the backstop.
    native_backstop: bool,
    /// From the agent's `HookRuntime`: whether the native allow shape actually
    /// suppresses the agent's own prompt — drives the `agent_prompt` audit
    /// field (G2).
    allow_suppresses_agent_prompt: bool,
    /// Per-agent no-TTY approval window (`HookRuntime::poll_deadline`): always
    /// inside the agent's own hook-kill deadline (G3).
    poll_deadline: std::time::Duration,
    /// User-level log-mode snapshot, used ONLY where no per-request mode is
    /// available (agentpactd unreachable): in log mode the no-backstop deny is
    /// suppressed — observe-only must never alter agent behavior.
    log_mode_fallback: bool,
    /// Whether this agent declares a native-approval hook integration
    /// (`permission_request_allow`) — the only consumer of recent-approval
    /// notes, so recording is gated on it.
    has_permission_request: bool,
    /// Which approval UX to use for an `ask` verdict — the agent's own native
    /// prompt ([`ApprovalMode::Native`]) or kyris's pending-approval popup
    /// ([`ApprovalMode::KyrisPopup`]). Resolved from the `approval_prompt`
    /// setting, defaulting to native where the agent declares a `native_ask`.
    approval_mode: ApprovalMode,
    /// How to render a native ask for this agent ([`AskResponse`]); `None` when
    /// the agent has no native ask channel (kyris popup is then the only path).
    native_ask: Option<&'a AskResponse>,
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
fn deny_for_missing_backstop(
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
         `kyris agents undo {agent}` to restore {agent}'s own permission prompts."
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

/// Margin added to a caller's poll window when sizing the approval-token TTL
/// (`approval_ttl_secs`): the user can answer at the very end of the window
/// and the `permission.respond` round-trip must still find a live token.
const APPROVAL_TTL_MARGIN_SECS: u64 = 120;

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
fn run_segments<C, P>(
    segments: &[String],
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
    let batch = ActionBatch {
        action: ctx.action.to_string(),
        segments: segs,
    };
    drive_batches(ctx, seed_pid, vec![batch], log_mode, command_group_id)
}

/// One governed action applied to a list of details: the daemon's compound
/// split for `execute`, or one file-path batch of a patch envelope.
struct ActionBatch {
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
fn drive_apply_patch(ctx: &PermissionCtx<'_>, seed_pid: Option<u32>) -> ! {
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
            |approval_id, approval_token, seg, allow_always| {
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
fn block_from_daemon_unavailable(source: &str) -> bool {
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
fn classify_segment(
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
            },
            _,
        )) => SegClass::Ask {
            approval_id,
            approval_token,
            allow_always,
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
fn poll_segment(
    agent: &str,
    server: &str,
    sock_path: &str,
    socket_timeout: std::time::Duration,
    approval_id: &str,
    approval_token: &str,
    seg: &str,
    allow_always: bool,
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
                agent,
                // Authoritative server signal from the per-segment PACT_ASK:
                // the popup greys out "Always" when the daemon would not
                // persist the grant (privilege/control/remote-destroy,
                // breaker, or no working_dir) — superseding the old
                // leading-word `sudo` heuristic, which missed wrapper-hidden
                // privilege like `env sudo …`.
                allow_always,
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
            reason: "denied by developer via kyris pending".to_string(),
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

/// Whether the agent will still get to apply its own permission rules after
/// kyris's response. Only meaningful when kyris allows; deny paths always
/// return `"none"` because exit-2 blocks the action universally.
///
/// Derived from the allow shape AND the agent's declared allow EFFECT (G2):
/// emitting a JSON allow does not by itself silence the agent — gemini parses
/// its `{"decision":"allow"}` and prompts anyway, while Claude's
/// `permissionDecision: allow` genuinely suppresses. `EmptyStdout` is "no
/// decision" everywhere, so the agent always decides.
fn agent_prompt_for(allow_response: &AllowResponse, suppresses_agent_prompt: bool) -> &'static str {
    match allow_response {
        AllowResponse::Json { .. } if suppresses_agent_prompt => "none",
        AllowResponse::Json { .. } | AllowResponse::EmptyStdout => "agent_decides",
    }
}

/// Record execution-surface live evidence: a real decision round-tripped
/// through this agent's live hook. The shell gate is not an agent surface.
fn record_execution_live_evidence(agent: &str) {
    if agent != "shell" {
        kyris_core::live_evidence::record(agent, kyris_core::live_evidence::SURFACE_EXECUTION);
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

/// File paths a patch envelope touches, split by governed action.
struct PatchPaths {
    /// `Add File` / `Update File` / `Move to` destinations — content lands at
    /// these paths. A move's SOURCE also stays here: it is being modified;
    /// its simultaneous disappearance is governed as part of that write
    /// (renames are not escalated to delete policy).
    writes: Vec<String>,
    /// `Delete File` — the file is removed outright.
    deletes: Vec<String>,
}

/// Parse codex's `apply_patch` envelope markers (apply-patch crate grammar:
/// `*** Begin Patch`, `*** Add File: `, `*** Update File: `, `*** Move to: `,
/// `*** Delete File: `; lenient about surrounding whitespace, paths may be
/// relative to the session cwd). Returns empty lists for text with no
/// recognizable markers — the caller treats that as unparseable and never
/// guesses.
fn parse_apply_patch_paths(patch: &str) -> PatchPaths {
    let mut paths = PatchPaths {
        writes: Vec::new(),
        deletes: Vec::new(),
    };
    for line in patch.lines() {
        // Markers live at COLUMN 0 in the grammar; update-hunk context lines
        // are space-prefixed, so trimming the start would turn file CONTENT
        // that mentions a marker into a phantom path. Trim the end only
        // (\r\n / trailing whitespace).
        let line = line.trim_end();
        if let Some(path) = line.strip_prefix("*** Add File:") {
            paths.writes.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Update File:") {
            paths.writes.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Move to:") {
            paths.writes.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Delete File:") {
            paths.deletes.push(path.trim().to_string());
        }
    }
    paths
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
fn run_permission_request(
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
    fn testRunSegmentsUnavailableBlocksAsDaemonUnreachable() {
        // The decider being down is reported as an `agentpact_unreachable`
        // block; run_segments itself never fails open or closed — the caller
        // (agent hook → defer, shell → fail open) decides what unavailability
        // means. `block_from_daemon_unavailable` recognizes this source.
        let segs = seg_vec(&["cmd"]);
        let result = run_segments(
            &segs,
            |_seg| SegClass::Unavailable {
                reason: "daemon down".to_string(),
            },
            |_id, _tok, _seg, _allow| unreachable!(),
        );
        let block = result.unwrap_err();
        assert_eq!(block.source, "agentpact_unreachable");
        assert!(block_from_daemon_unavailable(block.source));
    }

    #[test]
    fn testAgentPromptForJsonShapeUsesDeclaredEffectNotShape() {
        // G2: emitting a JSON allow does not by itself silence the agent.
        // Claude's permissionDecision:allow genuinely suppresses its prompt
        // (suppresses=true → "none"); Gemini parses its {"decision":"allow"}
        // but prompts anyway (suppresses=false → "agent_decides"). The audit
        // must reflect the EFFECT, not the shape.
        let json = AllowResponse::Json {
            body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
        };
        assert_eq!(agent_prompt_for(&json, true), "none");
        assert_eq!(agent_prompt_for(&json, false), "agent_decides");
    }

    #[test]
    fn testAgentPromptForEmptyStdoutDefersToAgent() {
        // EmptyStdout is "no decision" everywhere — the agent's own permission
        // rules apply regardless of any declared suppression flag.
        assert_eq!(
            agent_prompt_for(&AllowResponse::EmptyStdout, false),
            "agent_decides"
        );
        assert_eq!(
            agent_prompt_for(&AllowResponse::EmptyStdout, true),
            "agent_decides"
        );
    }

    #[test]
    fn testAgentPromptMatchesEachAgentsVerifiedAllowEffect() {
        // Lock the per-agent audit value to the upstream-verified effects:
        // only Claude Code's allow shape actually suppresses its prompt.
        for (id, expected) in [
            ("claude-code", "none"),
            ("gemini-cli", "agent_decides"),
            ("codex-cli", "agent_decides"),
            ("cline", "agent_decides"),
            ("opencode", "agent_decides"),
        ] {
            let proto = registry::agent_by_id(id)
                .expect("known agent")
                .hook_protocol()
                .expect("hook protocol");
            assert_eq!(
                agent_prompt_for(
                    &proto.allow_response,
                    proto.runtime.allow_suppresses_agent_prompt
                ),
                expected,
                "agent_prompt audit value for {id}"
            );
        }
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
        // Suppression is declared true here, but the effective shape in log
        // mode is EmptyStdout — the agent still decides.
        assert_eq!(agent_prompt_for(&effective, true), "agent_decides");
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

    /// Neutral runtime contract for synthetic test protocols (backstopped,
    /// 600s window) — the per-agent declared values are exercised via
    /// `agent_protocol` below and locked in registry tests.
    fn test_runtime() -> crate::agents::registry::HookRuntime {
        crate::agents::registry::HookRuntime {
            agent_hook_timeout_secs: 600,
            on_timeout: crate::agents::registry::HookTimeoutPosture::FailOpen,
            native_backstop: true,
            allow_suppresses_agent_prompt: false,
        }
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
            agent_owned_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
            runtime: test_runtime(),
            permission_request_allow: None,
            mcp_tool_naming: None,
            native_ask: None,
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
            agent_owned_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
            runtime: test_runtime(),
            permission_request_allow: None,
            mcp_tool_naming: None,
            native_ask: None,
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
            agent_owned_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
            runtime: test_runtime(),
            permission_request_allow: None,
            mcp_tool_naming: None,
            native_ask: None,
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
            agent_owned_tools: Vec::new(),
            default_action: "call".to_string(),
            allow_response: AllowResponse::EmptyStdout,
            runtime: test_runtime(),
            permission_request_allow: None,
            mcp_tool_naming: None,
            native_ask: None,
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
    fn testCodexCliShellSnapshotIsNoLongerExempt() {
        // Current codex spawns snapshot capture directly (no hook fires), so
        // the old `.codex/shell_snapshots/` substring exemption — and the
        // whole DetailPassThrough mechanism it justified — is gone. A command
        // merely MENTIONING the snapshot dir maps to a plain governed execute.
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf ~ # .codex/shell_snapshots/"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "execute");
        assert_eq!(detail, "rm -rf ~ # .codex/shell_snapshots/");
    }

    #[test]
    fn testCodexCliApplyPatchPayloadMapsToPatchAction() {
        // Review Finding 10: the patch envelope is parsed into per-file
        // decisions (drive_apply_patch), not treated as one write whose "path"
        // is the whole patch text.
        let proto = agent_protocol("codex-cli");
        let input = serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": {"command": "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch"}
        });
        let (action, detail) = map_payload(Some(&proto), &input);
        assert_eq!(action, "apply_patch");
        assert!(detail.contains("*** Update File: src/lib.rs"));
    }

    #[test]
    fn testParseApplyPatchPathsSplitsWritesAndDeletes() {
        let patch = "*** Begin Patch\n\
                     *** Add File: new/thing.rs\n\
                     +content\n\
                     *** Update File: src/lib.rs\n\
                     *** Move to: src/renamed.rs\n\
                     @@\n\
                     -a\n\
                     +b\n\
                     *** Delete File: old/junk.rs\n\
                     *** End Patch";
        let parsed = parse_apply_patch_paths(patch);
        assert_eq!(
            parsed.writes,
            vec!["new/thing.rs", "src/lib.rs", "src/renamed.rs"]
        );
        assert_eq!(parsed.deletes, vec!["old/junk.rs"]);
    }

    #[test]
    fn testParseApplyPatchPathsEmptyForNonPatchText() {
        // No markers → unparseable; the caller defers/denies, never guesses.
        let parsed = parse_apply_patch_paths("--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-o\n+n");
        assert!(parsed.writes.is_empty() && parsed.deletes.is_empty());
        // Diff body lines mentioning markers must not count: added lines
        // (+-prefixed) and space-prefixed CONTEXT lines — a patch updating a
        // file whose content cites the grammar must not grow phantom paths.
        let parsed = parse_apply_patch_paths("+ say '*** Delete File: x' loudly");
        assert!(parsed.deletes.is_empty());
        let parsed = parse_apply_patch_paths(
            "*** Update File: docs/grammar.md\n @@\n *** Delete File: example.rs\n",
        );
        assert_eq!(parsed.writes, vec!["docs/grammar.md"]);
        assert!(parsed.deletes.is_empty());
    }

    #[test]
    fn testCodexPermissionRequestAllowBodyMatchesUpstreamContract() {
        // Verified upstream shape (hooks/src/schema.rs): camelCase,
        // hookSpecificOutput.decision.behavior, deny_unknown_fields.
        let proto = agent_protocol("codex-cli");
        let body = proto
            .permission_request_allow
            .expect("codex declares the PermissionRequest integration");
        assert_eq!(
            body["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(body["hookSpecificOutput"]["decision"]["behavior"], "allow");
        // Exactly these fields — upstream rejects unknown ones.
        assert_eq!(body.as_object().unwrap().len(), 1);
        assert_eq!(body["hookSpecificOutput"].as_object().unwrap().len(), 2);
        assert_eq!(
            body["hookSpecificOutput"]["decision"]
                .as_object()
                .unwrap()
                .len(),
            1
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
    fn testDaemonUnavailableSourcesNeverBlockTheDeveloper() {
        // A daemon being unavailable — the decider (agentpactd) down, or kyrisd
        // unable to render an ask — never blocks: the agent hook defers, the
        // shell gate fails open. No operator flag gates this anymore.
        assert!(
            block_from_daemon_unavailable("kyrisd_unreachable"),
            "kyrisd down (can't render ask) must hand back to the agent"
        );
        assert!(
            block_from_daemon_unavailable("agentpact_unreachable"),
            "agentpactd down (no decider) must hand back to the agent"
        );
        // Genuine decisions always block — they are not unavailability.
        for source in [
            "agentpact_deny",
            "user_denied",
            "user_timeout",
            "resolution_failed",
            "agentpact_auto",
        ] {
            assert!(
                !block_from_daemon_unavailable(source),
                "`{source}` is a real decision and must NOT be treated as daemon-unavailable"
            );
        }
    }
}
