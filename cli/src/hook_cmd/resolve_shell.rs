// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Shell-gate per-segment approval (`kyris hook resolve-shell`) and the
//! controlling-terminal prompting helpers it uses.

use kyris_agentpact_client::{self as pact_client, ApprovalResponse};

use crate::agents::registry::{AllowResponse, ApprovalMode};

use super::HookResolveShellArgs;
use super::request::PermissionCtx;
use super::response::emit_deny;
use super::segments::{
    PopupResult, block_from_daemon_unavailable, classify_segment, deny_ask_immediately,
    poll_segment, run_segments,
};

/// Drive per-segment approval for a shell command the fast `kyris-hook check`
/// path flagged as a normal ask. Mirrors the native hook's per-segment flow
/// ([`super::request::dispatch_preview_outcome`]/[`super::segments::drive_per_segment`])
/// but prompts on the TTY when one is available, falling back to kyrisd's
/// pending-approval popup otherwise.
pub(super) fn run_resolve_shell(args: HookResolveShellArgs) -> ! {
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
        |approval_id, approval_token, seg, allow_always, detail| {
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
                    detail,
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
                    detail,
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
pub(super) fn read_tty_line(tty: &std::fs::File) -> Option<String> {
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
#[allow(clippy::too_many_arguments)]
fn tty_prompt_segment(
    tty: &std::fs::File,
    sock_path: &str,
    socket_timeout: std::time::Duration,
    approval_id: &str,
    approval_token: &str,
    seg: &str,
    allow_always: bool,
    // The structured "why" body is a popup affordance; the TTY prompt shows the
    // command itself, so it is accepted for signature parity and ignored here.
    _detail: Option<&str>,
) -> PopupResult {
    use std::io::Write as _;

    // Offer "session" only when the daemon says a grant would persist.
    let choices = if allow_always {
        "[y/n/session]"
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
        // "session" grants for the rest of the session, but only when the
        // daemon says it would persist; otherwise honor it as a one-time
        // approval. The variant/source labels stay `*_always` (wire/code stable).
        "session" => {
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
