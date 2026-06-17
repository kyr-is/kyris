// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Session profile builder — resolves a launch into a [`SandboxSpec`].
//!
//! This is the kyris-owned half of the sandbox: it decides *which roots a
//! jailed agent session gets*, while `agentpact-sandbox` is the pure
//! spec→argv compiler. The v1 model (filesystem jail, network on):
//!
//! - **workspace** (the launch dir): writable, with `.git`/`.kyris`/… kept
//!   read-only inside it (privilege-escalation guard).
//! - **temp dirs** (`$TMPDIR`, `/tmp`): writable, unprotected.
//! - **the agent's own dirs** (`~/.claude`, `~/.codex`, caches, …):
//!   writable, unprotected — the agent must be able to manage its own
//!   config/state/caches or it breaks. This is the carveout list, and it is
//!   the v1 tuning surface (see the per-agent map below). It lives here, not
//!   in the agentpact server or the kyris CLI registry, because it is the
//!   jail's single source of truth for what a session may write outside the
//!   workspace.
//! - **reads**: whole disk (reads are not the boundary; writes are).
//! - **network**: full (the agent needs its provider; loopback/UDS to the
//!   daemons works under blanket outbound — see the `allow_unix_sockets`
//!   note where network tightening will land).
//!
//! KNOWN-INCOMPLETE (intentional, v1): the per-agent carveout list is
//! best-effort and not exhaustively verified against every live agent. The
//! sandbox is on by default wherever a backend exists (macOS Seatbelt today;
//! see `cli/src/agents/shim.rs`), so a missing carveout surfaces as an
//! over-tight jail to tune here — not a silent gate. `kyris status` reports
//! the jail as active.

use std::path::Path;
use std::path::PathBuf;

use agentpact_sandbox::NetworkPolicy;
use agentpact_sandbox::ReadAccess;
use agentpact_sandbox::SandboxSpec;
use agentpact_sandbox::WritableRoot;

/// Build the session sandbox spec for an agent launched in `workspace`.
///
/// `workspace` is the launch directory (canonicalized here — the single
/// source edge, per the working-dir canonicalization rule). `agent_id` is
/// the kyris registry id (`claude-code`, `codex-cli`, …); an unknown id
/// yields a spec with no agent carveouts (workspace + temp only), which is
/// safe but may break that agent — callers should only pass known ids.
pub fn build_session_spec(workspace: &Path, agent_id: &str) -> SandboxSpec {
    let workspace = canonicalize_or_keep(workspace);
    let mut writable_roots = vec![WritableRoot::with_default_protections(workspace.clone())];

    // Add temp + agent carveouts as unprotected roots, but NEVER one that
    // is an ancestor of the workspace: a broad unprotected root containing
    // the workspace would re-expose its protected `.git`/`.kyris`/…
    // (seatbelt allow rules are additive). This keeps "the workspace's
    // protections always hold" true even when an agent is launched with cwd
    // inside `/tmp` or a cache dir.
    let extra = temp_roots()
        .into_iter()
        .chain(agent_carveout_dirs(agent_id))
        .map(|dir| canonicalize_or_keep(&dir))
        .filter(|dir| !workspace.starts_with(dir));
    for dir in extra {
        writable_roots.push(WritableRoot::unprotected(dir));
    }

    SandboxSpec {
        writable_roots,
        read_access: ReadAccess::FullDisk,
        network: NetworkPolicy::Full,
        // v1: blanket outbound (network = Full) covers AF_UNIX, so the
        // agent's governed subshells still reach agentpactd's socket. When
        // network tightening lands (network = Off / localhost-only), the
        // daemon sockets must be listed here explicitly.
        allow_unix_sockets: Vec::new(),
    }
}

fn canonicalize_or_keep(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// The writable roots to register with agentpactd for the out-of-jail-write
/// block. Each root is emitted in BOTH its literal (lexically-absolute) and
/// canonicalized (symlinks resolved) form, deduped — because agentpactd
/// compares a command's write target by lexical normalization, but resolves a
/// *workspace-relative* write against the working_dir it canonicalized at
/// ingest. On macOS `/tmp`→`/private/tmp` and `$TMPDIR`→`/private/var/…`, so
/// sending only one form would wrongly deny legitimate writes to the other.
///
/// Mirrors [`build_session_spec`]'s root selection (workspace + temp + agent
/// carveouts, minus ancestors of the workspace) so the registered roots match
/// the jail the agent actually runs under.
pub fn registration_roots(workspace: &Path, agent_id: &str) -> Vec<String> {
    let workspace_canon = canonicalize_or_keep(workspace);
    let mut candidates: Vec<PathBuf> = vec![workspace.to_path_buf(), workspace_canon.clone()];
    for dir in temp_roots()
        .into_iter()
        .chain(agent_carveout_dirs(agent_id))
    {
        // Same ancestor-overlap guard as the spec: a root that contains the
        // workspace is not part of the jail (it was dropped there too).
        if workspace_canon.starts_with(canonicalize_or_keep(&dir)) {
            continue;
        }
        candidates.push(dir.clone());
        candidates.push(canonicalize_or_keep(&dir));
    }
    let mut roots: Vec<String> = candidates
        .into_iter()
        .filter(|p| p.is_absolute())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// A short, human-readable one-line summary of a spec for the agentpactd audit
/// trail (the `profile_summary` carried on `session.register`). Not parsed.
pub fn summary(spec: &SandboxSpec) -> String {
    let workspace = spec
        .writable_roots
        .first()
        .map(|r| r.root.display().to_string())
        .unwrap_or_else(|| "-".to_string());
    let net = match spec.network {
        NetworkPolicy::Off => "off",
        NetworkPolicy::Full => "full",
    };
    format!(
        "workspace-write {workspace}; {} writable roots; net={net}",
        spec.writable_roots.len()
    )
}

/// Existing temp roots a jailed process may write. `$TMPDIR` first (macOS
/// per-user), then `/tmp`. Only included if present so the spec does not
/// carry phantom roots.
fn temp_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
        let path = PathBuf::from(tmpdir);
        if path.is_dir() {
            roots.push(path);
        }
    }
    let slash_tmp = PathBuf::from("/tmp");
    if slash_tmp.is_dir() {
        roots.push(slash_tmp);
    }
    roots
}

/// Directories an agent must be able to write for its own operation
/// (config, state, caches), independent of the workspace. Resolved against
/// `$HOME`; non-existent entries are kept (the agent may create them on
/// first run, and seatbelt allows writes under a declared root regardless of
/// whether it exists yet).
///
/// This is the v1 carveout list. It is deliberately small and explicit;
/// when the shim gate is flipped on, missing entries surface as kernel
/// write failures inside the agent and get added here.
fn agent_carveout_dirs(agent_id: &str) -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = match agent_id {
        "claude-code" => vec![home.join(".claude"), home.join(".claude.json")],
        "codex-cli" => vec![home.join(".codex")],
        "gemini-cli" => vec![home.join(".gemini")],
        "cline" => vec![home.join(".cline")],
        "opencode" => vec![
            home.join(".config").join("opencode"),
            home.join(".local").join("share").join("opencode"),
            home.join(".local").join("state").join("opencode"),
        ],
        _ => Vec::new(),
    };

    // Shared, agent-agnostic write targets these CLIs commonly touch:
    // per-user caches (npm/node/uv/pip) and the agentpact policy dir the
    // governed subshells may update via "always" overrides. Whole-cache
    // writability is acceptable (caches are not user data) and avoids a
    // long tail of tool-specific cache paths.
    #[cfg(target_os = "macos")]
    dirs.push(home.join("Library").join("Caches"));
    #[cfg(not(target_os = "macos"))]
    dirs.push(home.join(".cache"));

    dirs.push(home.join(".agentpact"));

    dirs
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_is_writable_with_default_protections() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let spec = build_session_spec(tmp.path(), "codex-cli");
        let workspace_canonical = tmp.path().canonicalize().expect("canonicalize");
        let workspace_root = spec
            .writable_roots
            .iter()
            .find(|r| r.root == workspace_canonical)
            .expect("workspace must be a writable root");
        assert!(
            workspace_root
                .protected_metadata_names
                .iter()
                .any(|n| n == ".git"),
            "workspace root must keep .git protected"
        );
    }

    #[test]
    fn agent_dirs_are_unprotected_writable_roots() {
        let home = std::env::var("HOME").expect("HOME");
        let spec = build_session_spec(Path::new("/tmp"), "claude-code");
        let claude = PathBuf::from(&home).join(".claude");
        let root = spec
            .writable_roots
            .iter()
            .find(|r| r.root == claude)
            .expect("~/.claude must be a writable root for claude-code");
        assert!(
            root.protected_metadata_names.is_empty(),
            "agent's own dir should be unprotected (it writes its own config)"
        );
    }

    #[test]
    fn unknown_agent_yields_no_agent_carveouts_but_still_workspace() {
        let spec = build_session_spec(Path::new("/tmp"), "not-an-agent");
        let home = std::env::var("HOME").expect("HOME");
        // No agent-specific dir, but the shared agentpact dir + cache + temp
        // + workspace are still present.
        assert!(
            !spec.writable_roots.is_empty(),
            "workspace must always be writable"
        );
        assert!(
            spec.writable_roots
                .iter()
                .all(|r| r.root != PathBuf::from(&home).join(".claude")),
            "unknown agent must not get another agent's carveout"
        );
    }

    #[test]
    fn v1_is_full_read_and_full_network() {
        let spec = build_session_spec(Path::new("/tmp"), "codex-cli");
        assert_eq!(spec.read_access, ReadAccess::FullDisk);
        assert_eq!(spec.network, NetworkPolicy::Full);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn registration_roots_emit_both_literal_and_canonical_for_symlinked_temp() {
        // On macOS /tmp is a symlink to /private/tmp. The registration must
        // carry BOTH so agentpactd matches a write to either form — the fix
        // for the canonicalization mismatch. Workspace is under $TMPDIR (so
        // /tmp is not its ancestor and is kept as a root).
        let workspace = tempfile::tempdir().expect("tempdir");
        let roots = registration_roots(workspace.path(), "codex-cli");
        assert!(
            roots.iter().any(|r| r == "/tmp"),
            "literal /tmp must be registered: {roots:?}"
        );
        assert!(
            roots.iter().any(|r| r == "/private/tmp"),
            "canonical /private/tmp must be registered: {roots:?}"
        );
        // The workspace itself, canonicalized, is present.
        let ws_canon = workspace
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            roots.contains(&ws_canon),
            "workspace root must be registered"
        );
    }

    #[test]
    fn root_ancestor_of_workspace_is_not_added_unprotected() {
        // tempdir() lives under the ambient temp root ($TMPDIR on macOS,
        // /tmp on Linux), so a workspace inside it exercises the
        // ancestor-overlap guard without mutating the environment. The
        // broad temp root must NOT be added, or it would re-expose the
        // workspace's protected .git.
        let workspace_dir = tempfile::tempdir().expect("tempdir");
        let spec = build_session_spec(workspace_dir.path(), "codex-cli");
        let workspace_canonical = workspace_dir.path().canonicalize().expect("canonicalize");

        assert!(
            spec.writable_roots
                .iter()
                .any(|r| r.root == workspace_canonical
                    && r.protected_metadata_names.iter().any(|n| n == ".git")),
            "workspace must be a protected writable root"
        );
        assert!(
            spec.writable_roots
                .iter()
                .all(|r| r.root == workspace_canonical || !workspace_canonical.starts_with(&r.root)),
            "no unprotected ancestor root may cover the workspace"
        );
    }
}
