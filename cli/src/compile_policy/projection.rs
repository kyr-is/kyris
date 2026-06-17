// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::Permission;

/// Filesystem access mode for a single path glob, modeled after Codex CLI's
/// `FileSystemAccessMode` (`codex-rs/protocol/src/permissions.rs`). Lives in
/// kyris — not in `AgentPact` — because the value set, wire form, and the
/// fail-closed projection from `AgentPact`'s `Permission` are kyris-side
/// implementation choices, not part of the `AgentPact` standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccessMode {
    /// No access (deny both read and write).
    None,
    /// Read allowed, write denied.
    #[allow(dead_code)] // reserved for future read-only path permission
    Read,
    /// Read and write allowed.
    Write,
}

impl FileAccessMode {
    /// Canonical wire token used in Codex's `[permissions.<profile>.filesystem]`
    /// table. Matches `FileSystemAccessMode`'s `serde(rename_all = "lowercase")`.
    #[must_use]
    pub fn as_codex_token(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Network-access primitive for a single domain or URL pattern, modeled after
/// Codex CLI's `NetworkDomainPermission`. As with [`FileAccessMode`], the
/// projection lives in kyris because network egress is non-interactive at
/// the sandbox layer — `Ask` collapses to `Deny` (fail-closed). A different
/// `AgentPact` implementation might choose a different mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccess {
    Allow,
    Deny,
}

impl NetworkAccess {
    /// Canonical wire token used in Codex's `[permissions.<profile>.network.domains]`
    /// table.
    #[must_use]
    pub fn as_codex_token(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Project an `AgentPact` `Permission` onto a Codex-style filesystem access mode
/// for compiled (non-interactive) enforcement.
///
/// `Ask` fails closed at the sandbox layer because there is no prompt path
/// at file-permission decision time. When a live `PreToolUse` hook is present,
/// the hook is what interprets `Ask` interactively; the compiled config is
/// defense-in-depth for the hook-down case.
#[must_use]
pub fn permission_to_file_mode(perm: Permission) -> FileAccessMode {
    match perm {
        Permission::Auto => FileAccessMode::Write,
        Permission::Ask | Permission::Deny => FileAccessMode::None,
    }
}

/// Project an `AgentPact` `Permission` onto a Codex-style network decision.
/// See [`permission_to_file_mode`] for the fail-closed rationale.
#[must_use]
pub fn permission_to_network_access(perm: Permission) -> NetworkAccess {
    match perm {
        Permission::Auto => NetworkAccess::Allow,
        Permission::Ask | Permission::Deny => NetworkAccess::Deny,
    }
}
