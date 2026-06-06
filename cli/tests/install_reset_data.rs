// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for `install.sh`'s `--reset-data` uninstall verification.
//!
//! `--reset-data` wipes the XDG dirs but PRESERVES the auth-key store
//! (`$DATA_DIR/secret/`) by design, so keys never regenerate. The post-uninstall
//! verification must therefore treat `secret/` as preserved, not as residue — a
//! 2026-05-31 bug failed verification because it required `$DATA_DIR` to be gone
//! entirely. We exercise the extracted `data_dir_reset_residue` helper by
//! sourcing install.sh (its `main` is guarded so sourcing is side-effect-free).

#![allow(non_snake_case)]
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn install_sh() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("install.sh")
}

/// Source install.sh and run `data_dir_reset_residue <data_dir> secret`,
/// returning its stdout (the offending paths; empty = clean).
fn residue(home: &Path, data_dir: &Path) -> String {
    let script = format!(
        "source '{}' >/dev/null 2>&1; set +e; data_dir_reset_residue '{}' secret",
        install_sh().display(),
        data_dir.display(),
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .env("HOME", home) // real dir; install.sh top-level only string-interpolates it
        .output()
        .expect("run bash");
    assert!(
        out.status.success(),
        "bash exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn testResetDataResidueIgnoresPreservedSecretStore() {
    // DATA_DIR holding ONLY the preserved secret/ store → no residue. (The bug:
    // verification used to fail here because DATA_DIR still existed.)
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("share/kyris");
    std::fs::create_dir_all(data.join("secret")).unwrap();
    std::fs::write(data.join("secret/inbound_key"), b"k").unwrap();
    assert_eq!(
        residue(dir.path(), &data),
        "",
        "DATA_DIR containing only secret/ must be residue-free"
    );
}

#[test]
fn testResetDataResidueFlagsRealLeftovers() {
    // A genuine leftover (event DB, credentials) under DATA_DIR IS residue.
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("share/kyris");
    std::fs::create_dir_all(data.join("secret")).unwrap();
    std::fs::write(data.join("kyrisd.duckdb"), b"x").unwrap();
    std::fs::write(data.join("credentials.json"), b"{}").unwrap();
    let r = residue(dir.path(), &data);
    assert!(
        r.contains("kyrisd.duckdb"),
        "duckdb leftover must be flagged: {r:?}"
    );
    assert!(
        r.contains("credentials.json"),
        "credentials leftover must be flagged: {r:?}"
    );
}

#[test]
fn testResetDataResidueCleanWhenDataDirAbsent() {
    // Full wipe (no DATA_DIR at all) → clean.
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("share/kyris"); // intentionally not created
    assert_eq!(
        residue(dir.path(), &data),
        "",
        "absent DATA_DIR must be residue-free"
    );
}
