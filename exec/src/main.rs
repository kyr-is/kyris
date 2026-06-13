// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris-exec` — the kyris-owned parent at the spawn site.
//!
//! Compiles a [`agentpact_sandbox::SandboxSpec`] and `exec`s the given
//! command under the OS sandbox **in place** (no fork): stdio, TTY, cwd, and
//! environment are inherited from whoever invoked us, so wrapping a command —
//! or a whole agent launch via the PATH shim — is transparent.
//!
//! Two ways to supply the spec:
//! ```text
//! kyris-exec --session [--workspace <dir>] --agent <id> [--print-policy] -- <command> [args…]
//! kyris-exec --spec-file <path>                          [--print-policy] -- <command> [args…]
//! ```
//! `--session` builds the profile from the launch dir (cwd, or `--workspace`)
//! and agent id — the path the shim uses. `--spec-file` reads a pre-resolved
//! spec as JSON — used for escalations and tests.
//!
//! Exit codes (kyris-exec's OWN failures only — after a successful exec the
//! exit status is the sandboxed command's):
//! - 64 usage error
//! - 65 spec file unreadable or invalid
//! - 69 sandbox unavailable on this host (non-macOS, or
//!   /usr/bin/sandbox-exec missing) — the caller decides whether to fall
//!   back to advisory-only, LOUDLY; kyris-exec never runs the command
//!   unconfined
//! - 71 exec of the sandbox launcher failed
//!
//! Fail-closed by design: every failure path exits without running the
//! command. There is no "run anyway" flag.

#![forbid(unsafe_code)]

mod profile;

use std::path::Path;
use std::path::PathBuf;
use std::process::exit;

use agentpact_sandbox::SandboxSpec;
use agentpact_sandbox::create_seatbelt_command_args;

const EXIT_USAGE: i32 = 64;
const EXIT_BAD_SPEC: i32 = 65;
const EXIT_SANDBOX_UNAVAILABLE: i32 = 69;
const EXIT_EXEC_FAILED: i32 = 71;

const USAGE: &str = concat!(
    "usage: kyris-exec --session [--workspace <dir>] --agent <id> [--print-policy] -- <command> [args...]\n",
    "       kyris-exec --spec-file <path> [--print-policy] -- <command> [args...]"
);

fn fail(code: i32, message: &str) -> ! {
    eprintln!("[kyris-exec] {message}");
    exit(code);
}

/// Where the [`SandboxSpec`] comes from. Exactly one form per invocation.
enum SpecSource {
    File(String),
    Session {
        workspace: Option<PathBuf>,
        agent: String,
    },
}

struct Invocation {
    source: SpecSource,
    print_policy: bool,
    command: Vec<String>,
}

fn parse_args(args: Vec<String>) -> Result<Invocation, String> {
    let mut spec_file: Option<String> = None;
    let mut session = false;
    let mut workspace: Option<PathBuf> = None;
    let mut agent: Option<String> = None;
    let mut print_policy = false;
    let mut iter = args.into_iter();
    let command: Vec<String>;

    loop {
        match iter.next() {
            Some(arg) if arg == "--spec-file" => {
                spec_file = Some(iter.next().ok_or("--spec-file requires a path")?);
            }
            Some(arg) if arg == "--session" => session = true,
            Some(arg) if arg == "--workspace" => {
                workspace = Some(PathBuf::from(
                    iter.next().ok_or("--workspace requires a path")?,
                ));
            }
            Some(arg) if arg == "--agent" => {
                agent = Some(iter.next().ok_or("--agent requires an id")?);
            }
            Some(arg) if arg == "--print-policy" => print_policy = true,
            Some(arg) if arg == "--" => {
                command = iter.collect();
                break;
            }
            Some(arg) => return Err(format!("unknown argument: {arg}")),
            None => return Err("missing -- separator before command".to_string()),
        }
    }

    if command.is_empty() {
        return Err("missing command after --".to_string());
    }

    let source = match (spec_file, session) {
        (Some(_), true) => return Err("--spec-file and --session are mutually exclusive".into()),
        (Some(path), false) => {
            if workspace.is_some() || agent.is_some() {
                return Err("--workspace/--agent only apply with --session".into());
            }
            SpecSource::File(path)
        }
        (None, true) => {
            let agent = agent.ok_or("--session requires --agent <id>")?;
            SpecSource::Session { workspace, agent }
        }
        (None, false) => return Err("missing --session or --spec-file".into()),
    };

    Ok(Invocation {
        source,
        print_policy,
        command,
    })
}

/// Returns the compiled spec plus the writable roots to register with
/// agentpactd for the out-of-jail-write block (both literal + canonical forms;
/// see [`profile::registration_roots`]).
fn resolve_spec(source: SpecSource) -> Result<(SandboxSpec, Vec<String>), String> {
    match source {
        SpecSource::File(path) => {
            let contents = std::fs::read_to_string(&path)
                .map_err(|err| format!("cannot read spec file {path}: {err}"))?;
            let spec: SandboxSpec = serde_json::from_str(&contents)
                .map_err(|err| format!("invalid spec in {path}: {err}"))?;
            // Spec-file callers (tests/escalations) own their roots; register
            // the spec's writable roots verbatim.
            let roots = spec
                .writable_roots
                .iter()
                .map(|r| r.root.to_string_lossy().into_owned())
                .collect();
            Ok((spec, roots))
        }
        SpecSource::Session { workspace, agent } => {
            let workspace = match workspace {
                Some(dir) => dir,
                None => std::env::current_dir()
                    .map_err(|err| format!("cannot resolve launch dir: {err}"))?,
            };
            let spec = profile::build_session_spec(&workspace, &agent);
            let roots = profile::registration_roots(&workspace, &agent);
            Ok((spec, roots))
        }
    }
}

#[cfg(target_os = "macos")]
fn exec_sandboxed(
    spec: &SandboxSpec,
    registration_roots: &[String],
    command: Vec<String>,
    print_policy: bool,
) -> ! {
    use agentpact_sandbox::MACOS_PATH_TO_SEATBELT_EXECUTABLE;
    use std::os::unix::process::CommandExt;

    if !Path::new(MACOS_PATH_TO_SEATBELT_EXECUTABLE).exists() {
        fail(
            EXIT_SANDBOX_UNAVAILABLE,
            &format!("{MACOS_PATH_TO_SEATBELT_EXECUTABLE} not found; cannot establish sandbox"),
        );
    }

    let args = create_seatbelt_command_args(spec, command);
    if print_policy {
        // args[1] is the compiled policy (args[0] is "-p").
        eprintln!("{}", args[1]);
    }

    // Register this jailed session with agentpactd BEFORE exec, while we still
    // have our own PID (the in-place exec keeps it, so our PID is the jail
    // root the daemon will see as the ancestor of every governed request).
    // Best-effort: a failure means governed commands fall back to advisory
    // behavior (no workspace-write Auto flip); it must NEVER block the launch.
    register_session(spec, registration_roots);

    // Loader env scrub + core-dump limit; inherited by the exec'd child.
    agentpact_hardening::exec_wrapper_hardening();

    // exec in place: only returns on failure.
    let err = std::process::Command::new(MACOS_PATH_TO_SEATBELT_EXECUTABLE)
        .args(&args)
        .exec();
    fail(
        EXIT_EXEC_FAILED,
        &format!("exec {MACOS_PATH_TO_SEATBELT_EXECUTABLE} failed: {err}"),
    );
}

#[cfg(not(target_os = "macos"))]
fn exec_sandboxed(
    _spec: &SandboxSpec,
    _registration_roots: &[String],
    _command: Vec<String>,
    _print_policy: bool,
) -> ! {
    fail(
        EXIT_SANDBOX_UNAVAILABLE,
        "no sandbox backend for this platform (macOS Seatbelt only today)",
    );
}

/// Announce this jailed session to agentpactd over its UDS (best-effort).
/// Short timeout so a slow/absent daemon never delays the agent launch.
fn register_session(spec: &SandboxSpec, registration_roots: &[String]) {
    let socket = kyris_agentpact_client::default_socket_path();
    let summary = profile::summary(spec);
    let ok = kyris_agentpact_client::register_jailed_session(
        &socket.to_string_lossy(),
        &summary,
        registration_roots,
        Some(std::time::Duration::from_millis(250)),
    );
    if !ok {
        eprintln!(
            "[kyris-exec] could not register sandbox session with agentpactd; \
             the jail is active but governed commands will prompt as usual"
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("kyris-exec {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let invocation = match parse_args(args) {
        Ok(invocation) => invocation,
        Err(message) => fail(EXIT_USAGE, &format!("{message}\n{USAGE}")),
    };

    let (spec, registration_roots) = match resolve_spec(invocation.source) {
        Ok(resolved) => resolved,
        Err(message) => fail(EXIT_BAD_SPEC, &message),
    };

    exec_sandboxed(
        &spec,
        &registration_roots,
        invocation.command,
        invocation.print_policy,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn parse_requires_a_spec_source_and_command() {
        // No command.
        assert!(parse_args(args(&["--spec-file", "/s.json"])).is_err());
        assert!(parse_args(args(&["--spec-file", "/s.json", "--"])).is_err());
        // No spec source.
        assert!(parse_args(args(&["--", "true"])).is_err());
        // --session without --agent.
        assert!(parse_args(args(&["--session", "--", "true"])).is_err());

        let invocation =
            parse_args(args(&["--spec-file", "/s.json", "--", "bash", "-c", "x"])).expect("parse");
        assert!(matches!(&invocation.source, SpecSource::File(p) if p == "/s.json"));
        assert!(!invocation.print_policy);
        assert_eq!(invocation.command, args(&["bash", "-c", "x"]));
    }

    #[test]
    fn parse_session_form_with_workspace_and_agent() {
        let invocation = parse_args(args(&[
            "--session",
            "--workspace",
            "/work",
            "--agent",
            "codex-cli",
            "--",
            "codex",
        ]))
        .expect("parse");
        match &invocation.source {
            SpecSource::Session { workspace, agent } => {
                assert_eq!(workspace.as_deref(), Some(Path::new("/work")));
                assert_eq!(agent, "codex-cli");
            }
            SpecSource::File(_) => panic!("expected session source"),
        }
        assert_eq!(invocation.command, args(&["codex"]));
    }

    #[test]
    fn parse_rejects_mixed_and_misplaced_flags() {
        // Mutually exclusive sources.
        assert!(
            parse_args(args(&[
                "--session",
                "--agent",
                "codex-cli",
                "--spec-file",
                "/s.json",
                "--",
                "x"
            ]))
            .is_err()
        );
        // Session-only flags with a file source.
        assert!(parse_args(args(&["--spec-file", "/s.json", "--agent", "x", "--", "y"])).is_err());
        assert!(parse_args(args(&["--bogus", "--", "true"])).is_err());
    }

    #[test]
    fn parse_keeps_command_flags_verbatim_after_separator() {
        // Flags after -- belong to the command, not to kyris-exec.
        let invocation = parse_args(args(&[
            "--spec-file",
            "/s.json",
            "--print-policy",
            "--",
            "tool",
            "--session",
            "--agent",
        ]))
        .expect("parse");
        assert!(invocation.print_policy);
        assert_eq!(invocation.command, args(&["tool", "--session", "--agent"]));
    }
}
