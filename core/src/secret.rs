// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Portable on-disk store for the local hook<->daemon auth secrets
//! (`inbound_key`, `operator_key`).
//!
//! These keys are NOT user data — they're a localhost-only shared secret that
//! gates kyrisd's HTTP API (`auth.rs`). They live as `0600` files in a `0700`
//! directory ([`crate::paths::secret_dir`], default
//! `~/.local/share/kyris/secret/`), so there is a single source of truth that
//! `kyrisd`, the `kyris` CLI, and the hook all read. They are minted once on
//! first use and preserved across uninstall and `--reset-data`, so they never
//! regenerate and the daemon and hook never drift — key drift is what 401'd
//! every approval before.
//!
//! Why a plain file rather than a native OS store: the macOS Keychain, Linux
//! Secret Service, and Windows Credential Manager all require an interactive
//! login session, so they're absent or fail in Docker / CI / SSH / headless
//! contexts that kyris must also run in. A file works identically everywhere.
//! Its posture (readable by the same user) matches the threat model — we guard
//! against agent *mistakes*, not a same-user attacker — and is exactly what the
//! plaintext `kyrisd.yaml` it replaces already had.
//!
//! Permissions are enforced on Unix (`0700` dir, `0600` files). Windows
//! hardening (owner-only ACL / DPAPI-encrypted contents) is a TODO; until then
//! the file relies on the per-user profile directory's ACLs.

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::Path;

/// Account (file name) for the inbound (agent -> proxy) bearer key.
pub const ACCOUNT_INBOUND: &str = "inbound_key";
/// Account (file name) for the operator (hook/CLI -> daemon API) bearer key.
pub const ACCOUNT_OPERATOR: &str = "operator_key";

/// Read `account`'s secret, minting and persisting one (prefixed with `prefix`,
/// e.g. `sk-kyris`) on first use. Idempotent and race-safe: if a concurrent
/// process writes the file between our read and our create, we adopt its value
/// so both processes converge on a single secret.
///
/// # Errors
/// Returns `Err` if the secret directory or file cannot be created or read.
pub fn get_or_create(account: &str, prefix: &str) -> Result<String, String> {
    get_or_create_in(&crate::paths::secret_dir(), account, prefix)
}

/// Remove `account`'s secret (explicit key rotation). A missing file is treated
/// as success, so it is safe to call blindly.
///
/// # Errors
/// Returns `Err` only if the file exists but cannot be removed.
pub fn delete(account: &str) -> Result<(), String> {
    delete_in(&crate::paths::secret_dir(), account)
}

/// Mint a fresh secret: `{prefix}-{64 hex chars}` from 32 CSPRNG bytes.
fn generate_secret(prefix: &str) -> String {
    let mut buf = [0u8; 32];
    aws_lc_rs::rand::fill(&mut buf).expect("generate random bytes");
    let hex = buf.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    });
    format!("{prefix}-{hex}")
}

// --- file store (directory injected so tests run against a tempdir) ---------

fn get_or_create_in(dir: &Path, account: &str, prefix: &str) -> Result<String, String> {
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    restrict_dir(dir);
    let path = dir.join(account);
    if let Ok(existing) = fs::read_to_string(&path) {
        return Ok(existing.trim_end_matches('\n').to_string());
    }
    let candidate = generate_secret(prefix);
    match create_secret_file(&path) {
        Ok(mut file) => {
            file.write_all(candidate.as_bytes())
                .map_err(|e| format!("write {}: {e}", path.display()))?;
            Ok(candidate)
        }
        // Lost the race: another process created it first — adopt its value so
        // both sides converge instead of clobbering.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => fs::read_to_string(&path)
            .map(|s| s.trim_end_matches('\n').to_string())
            .map_err(|e| format!("read {}: {e}", path.display())),
        Err(e) => Err(format!("create {}: {e}", path.display())),
    }
}

fn delete_in(dir: &Path, account: &str) -> Result<(), String> {
    let path = dir.join(account);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

/// Create the secret file for exclusive write. `create_new` fails with
/// `AlreadyExists` if a racing writer won (the caller then adopts theirs). On
/// Unix the file is `0600` from creation, so there is no world-readable window.
#[cfg(unix)]
fn create_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_secret_file(path: &Path) -> std::io::Result<fs::File> {
    // TODO(windows): set an owner-only ACL and/or DPAPI-encrypt the contents.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Best-effort tighten of the secret directory to `0700` on Unix.
#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) {
    // TODO(windows): restrict the directory ACL to the current user.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testGenerateSecretShape() {
        let key = generate_secret("sk-kyris");
        assert!(key.starts_with("sk-kyris-"));
        // prefix + '-' + 64 hex chars
        assert_eq!(key.len(), "sk-kyris-".len() + 64);
        assert!(
            key["sk-kyris-".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
        // Two draws differ (CSPRNG, not a constant).
        assert_ne!(generate_secret("sk-kyris"), generate_secret("sk-kyris"));
    }

    #[test]
    fn testGetOrCreatePersistsAndReuses() {
        let dir = tempfile::tempdir().unwrap();
        let first = get_or_create_in(dir.path(), ACCOUNT_INBOUND, "sk-kyris").unwrap();
        assert!(first.starts_with("sk-kyris-"));
        // Second call returns the persisted value — does not re-mint.
        assert_eq!(
            get_or_create_in(dir.path(), ACCOUNT_INBOUND, "sk-kyris").unwrap(),
            first
        );
    }

    #[test]
    fn testDeleteThenRecreateMintsFresh() {
        let dir = tempfile::tempdir().unwrap();
        let a = get_or_create_in(dir.path(), ACCOUNT_OPERATOR, "sk-kyris-ops").unwrap();
        delete_in(dir.path(), ACCOUNT_OPERATOR).unwrap();
        let b = get_or_create_in(dir.path(), ACCOUNT_OPERATOR, "sk-kyris-ops").unwrap();
        assert_ne!(a, b);
        // Deleting a missing item is Ok (idempotent).
        delete_in(dir.path(), "absent").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn testFilePermissionsAre0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        get_or_create_in(dir.path(), ACCOUNT_INBOUND, "sk-kyris").unwrap();
        let mode = fs::metadata(dir.path().join(ACCOUNT_INBOUND))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret file must be 0600, got {mode:o}");
    }
}
