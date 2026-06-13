// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Per-agent PATH shim.
//!
//! Each installed agent gets a tiny shell script at `~/.kyris/bin/<binary>`
//! (where `<binary>` is what the user types — `claude`, `codex`, `gemini`,
//! `cline`, `opencode`). `~/.kyris/bin` is already PATH-prepended by
//! `kyris install`, so the shim shadows the real binary on PATH lookup.
//!
//! The shim's only jobs are:
//!   1. Export `KYRIS_GOVERNED_SUBPROCESS=<agent-id>`. This is the marker
//!      our shell hooks (`zsh_hook.sh`, `bash_hook.sh`) check to decide
//!      whether to arm the preexec trap. With the marker set, every
//!      subshell the agent spawns — interactive, non-interactive, bash
//!      or zsh — installs the trap and contacts agentpactd. Without it
//!      (i.e. the user's own terminal), the hook sourcing in `~/.zshrc`
//!      / `~/.bashrc` short-circuits to a no-op.
//!   2. Strip its own `~/.kyris/bin` directory from PATH and `exec` the
//!      real agent binary, found by re-walking PATH. No hardcoded path,
//!      no agent-update breakage — same pattern rbenv / pyenv / nvm
//!      shims use.
//!
//! ## Session sandbox (gated OFF by default)
//!
//! When the marker file `~/.kyris/sandbox.on` exists AND a `kyris-exec`
//! binary is resolvable, the shim's final step becomes
//! `exec kyris-exec --session --agent <id> -- <real> "$@"` instead of
//! `exec <real> "$@"`, jailing the entire agent process tree at launch
//! (the codex-equivalent "be the parent" move — see `codex-agentpact.md`).
//! The marker does not exist after a normal install, so this changes
//! nothing for existing users until a future `kyris sandbox enable`
//! (or the Phase-3 mechanism) creates it. If the marker is present but
//! `kyris-exec` cannot be found, the shim launches UNJAILED with a loud
//! stderr line rather than failing the launch — degraded, indicated, never
//! silently "sandboxed".

use crate::config_writer::NoopValidator;
use crate::state::{bin_dir, write_managed_file};

/// Map an agent registry id to the executable name the user actually types.
/// (`claude-code` → `claude`, `codex-cli` → `codex`, …)
fn binary_name(agent_id: &str) -> Option<&'static str> {
    match agent_id {
        "claude-code" => Some("claude"),
        "codex-cli" => Some("codex"),
        "gemini-cli" => Some("gemini"),
        "cline" => Some("cline"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

fn shim_source(agent_id: &str, binary: &str) -> String {
    // Pure POSIX sh — no bashisms, runs under /bin/sh on macOS and Linux.
    // The IFS loop rebuilds PATH without our own dir; `${var//}` would
    // be simpler but is a bash extension.
    format!(
        r#"#!/bin/sh
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
# Kyris PATH shim for {binary} (agent id: {agent_id}).
# Marks the spawned agent's process tree so kyris's shell hooks know
# they are inside a governed agent and arm the preexec trap.
export KYRIS_GOVERNED_SUBPROCESS="{agent_id}"

# Source this agent's Kyris env file(s) — base-URL redirect + inbound-key
# header — so burn-control / gateway routing reaches the agent on EVERY launch.
# This is the sole env-delivery path (there is no shell-RC env loader): the shim
# is the one wrapper that always runs when the agent binary is invoked. Guarded
# with -f so agents that ship no env file are unaffected. The "-"*.sh glob also
# picks up split files (e.g. cline's cline-policy.sh).
for __kyris_env in "$HOME/.kyris/env/{agent_id}.sh" "$HOME/.kyris/env/{agent_id}"-*.sh; do
    [ -f "$__kyris_env" ] && . "$__kyris_env"
done
unset __kyris_env

# Strip our own directory from PATH so `command -v {binary}` resolves to
# the real binary (the next match on PATH). Without this we would loop
# onto ourselves.
__kyris_shim_dir="$HOME/.kyris/bin"
__kyris_new_path=""
__kyris_old_ifs="$IFS"
IFS=":"
for __kyris_d in $PATH; do
    [ "$__kyris_d" = "$__kyris_shim_dir" ] && continue
    if [ -z "$__kyris_new_path" ]; then
        __kyris_new_path="$__kyris_d"
    else
        __kyris_new_path="$__kyris_new_path:$__kyris_d"
    fi
done
IFS="$__kyris_old_ifs"
PATH="$__kyris_new_path"
export PATH
unset __kyris_shim_dir __kyris_new_path __kyris_old_ifs __kyris_d

real=$(command -v {binary} 2>/dev/null) || {{
    printf '[kyris] %s not found on PATH after stripping shim dir\n' "{binary}" >&2
    exit 127
}}

# Session sandbox (opt-in via the marker file; absent by default → no-op).
# When enabled, jail the whole agent process tree at launch via kyris-exec.
# kyris-exec is found on the (post-strip) PATH like the real binary; if the
# marker is set but the launcher is missing, fall through to an UNJAILED
# launch with a loud warning — never silently claim confinement, never block
# the launch.
if [ -f "$HOME/.kyris/sandbox.on" ]; then
    __kyris_exec=$(command -v kyris-exec 2>/dev/null)
    if [ -n "$__kyris_exec" ]; then
        exec "$__kyris_exec" --session --agent "{agent_id}" -- "$real" "$@"
    fi
    printf '[kyris] sandbox.on set but kyris-exec not found; launching %s UNJAILED\n' "{binary}" >&2
fi

exec "$real" "$@"
"#
    )
}

/// Create or refresh the PATH shim for `agent_id`. Returns the human-readable
/// change line(s) suitable for the install transcript, or an empty vec if the
/// agent isn't shimmable (e.g. unknown id) or the shim is already current.
pub fn install_shim(agent_id: &str) -> Result<Vec<String>, String> {
    let Some(binary) = binary_name(agent_id) else {
        return Ok(Vec::new());
    };
    let path = bin_dir()?.join(binary);
    let contents = shim_source(agent_id, binary);
    if write_managed_file(&path, &contents, "agents", Some(0o755), &NoopValidator)? {
        Ok(vec![format!("wrote shim {}", path.display())])
    } else {
        Ok(Vec::new())
    }
}

/// True iff the on-disk shim for `agent_id` sources that agent's Kyris env
/// file. The burn-control / execution probes use this to recognize
/// shim-delivered env vars as a live delivery path independent of shell-RC
/// sourcing. A pre-env shim (older kyris) lacks the line → returns false, so
/// the surface is reported honestly until a reinstall refreshes the shim.
pub(super) fn shim_delivers_env(agent_id: &str) -> bool {
    let Some(binary) = binary_name(agent_id) else {
        return false;
    };
    let Ok(dir) = bin_dir() else {
        return false;
    };
    std::fs::read_to_string(dir.join(binary))
        .is_ok_and(|contents| shim_content_delivers_env(&contents, agent_id))
}

/// Pure predicate: does shim `contents` source `agent_id`'s Kyris env file?
/// Split out so it can be tested without a filesystem or HOME dependency.
fn shim_content_delivers_env(contents: &str, agent_id: &str) -> bool {
    contents.contains(&format!(".kyris/env/{agent_id}.sh"))
}

/// Remove an agent's PATH shim. Manifest-tracked, so the normal uninstall
/// path (`restore_manifest_entry`) will also clean it up; this helper is for
/// `kyris agents uninstall <agent>`, which removes just one agent's surfaces.
pub fn uninstall_shim(agent_id: &str) -> Result<bool, String> {
    let Some(binary) = binary_name(agent_id) else {
        return Ok(false);
    };
    let path = bin_dir()?.join(binary);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&path).map_err(|e| format!("Cannot remove {}: {e}", path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testBinaryNameMapsKnownAgents() {
        assert_eq!(binary_name("claude-code"), Some("claude"));
        assert_eq!(binary_name("codex-cli"), Some("codex"));
        assert_eq!(binary_name("gemini-cli"), Some("gemini"));
        assert_eq!(binary_name("cline"), Some("cline"));
        assert_eq!(binary_name("opencode"), Some("opencode"));
        assert_eq!(binary_name("unknown-agent"), None);
    }

    #[test]
    fn testShimSourceSetsMarkerAndExecsRealBinary() {
        let s = shim_source("claude-code", "claude");
        assert!(s.contains(r#"export KYRIS_GOVERNED_SUBPROCESS="claude-code""#));
        assert!(s.contains(r#"__kyris_shim_dir="$HOME/.kyris/bin""#));
        assert!(s.contains("real=$(command -v claude"));
        assert!(s.contains("exec \"$real\" \"$@\""));
    }

    #[test]
    fn testShimSourcesAgentEnvFile() {
        // The shim must deliver the agent's env file on every launch so
        // burn-control reaches it independent of shell-RC sourcing (fish, GUI).
        let s = shim_source("claude-code", "claude");
        assert!(s.contains(r#""$HOME/.kyris/env/claude-code.sh""#));
        // Split env files (e.g. cline-policy.sh) are picked up via the glob.
        assert!(s.contains(r#""$HOME/.kyris/env/claude-code"-*.sh"#));
        assert!(shim_content_delivers_env(&s, "claude-code"));
    }

    #[test]
    fn testShimContentDeliversEnvDetectsAbsence() {
        // A pre-env shim (no env-source line) must be reported as NOT delivering,
        // so the probe stays honest until a reinstall refreshes the shim.
        let pre_env =
            "#!/bin/sh\nexport KYRIS_GOVERNED_SUBPROCESS=\"claude-code\"\nexec claude \"$@\"\n";
        assert!(!shim_content_delivers_env(pre_env, "claude-code"));
        assert!(shim_content_delivers_env(
            &shim_source("cline", "cline"),
            "cline"
        ));
    }

    #[test]
    fn testShimGatesSandboxBehindMarkerFile() {
        // The sandbox path must be guarded by the marker file (absent by
        // default) so a normal install changes no launch behavior, and must
        // wrap via kyris-exec --session when enabled.
        let s = shim_source("codex-cli", "codex");
        assert!(s.contains(r#"if [ -f "$HOME/.kyris/sandbox.on" ]; then"#));
        assert!(
            s.contains(r#"exec "$__kyris_exec" --session --agent "codex-cli" -- "$real" "$@""#)
        );
        // Degraded path: marker on but launcher missing → loud, unjailed,
        // still launches (no exit before the final unconditional exec).
        assert!(s.contains("launching %s UNJAILED"));
        // The unconditional direct exec remains the default (marker absent).
        assert!(s.contains(r#"exec "$real" "$@""#));
    }

    /// The shim must be runnable by /bin/sh — no bashisms. macOS' /bin/sh is
    /// bash in POSIX mode, which rejects `${var//pat/rep}` and similar.
    #[test]
    fn testShimSourceParsesUnderPosixSh() {
        let s = shim_source("claude-code", "claude");
        let out = std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&s)
            .output()
            .expect("run /bin/sh -n");
        assert!(
            out.status.success(),
            "shim failed POSIX sh syntax check:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
