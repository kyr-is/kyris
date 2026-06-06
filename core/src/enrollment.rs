// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Enrollment credentials — the single source of truth for "am I enrolled?".
//!
//! `credentials.json` on disk holds *only* the machine identity the relay
//! issued: `{machine_id, machine_token}` — the same shape as the wire enroll
//! response ([`crate::sync::EnrollmentResponse`]). The relay URL is NOT stored
//! here: it's a config setting (`relay.url` in `kyrisd.yaml`), available
//! without enrollment so pricing works standalone. That keeps one home for the
//! relay URL and makes `credentials.json` pure proof-of-enrollment. Enrolled ⟺
//! a valid `credentials.json` is present (parses + has both fields). Standalone
//! ⟺ it's absent (or unparseable).

use serde::{Deserialize, Serialize};

/// On-disk enrollment artifact at [`crate::paths::credentials_path`] — the
/// machine identity issued by the relay. Where the machine enrolled (the relay
/// URL) lives in config, not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub machine_id: String,
    pub machine_token: String,
}

/// The canonical "am I enrolled?" predicate.
///
/// Reads [`crate::paths::credentials_path`] (honoring
/// `KYRIS_CREDENTIALS_PATH`), parses it, and returns the [`Credentials`] iff
/// the file is present, valid JSON, and carries both fields. Returns `None`
/// for standalone (file missing or invalid) — standalone is a normal state,
/// not an error.
#[must_use]
pub fn load() -> Option<Credentials> {
    let path = if let Ok(p) = std::env::var("KYRIS_CREDENTIALS_PATH") {
        std::path::PathBuf::from(p)
    } else {
        crate::paths::credentials_path()
    };
    load_from(&path)
}

/// Parse a credentials file at an explicit path. This path-injection seam lets
/// the unit tests exercise the predicate without mutating the process-global
/// `KYRIS_CREDENTIALS_PATH` (which would race with the parallel test runner and
/// with `paths`' own `HOME`/`XDG` mutations in the same test binary). Returns
/// `None` if the file is absent, unreadable, or not valid `Credentials` JSON.
#[must_use]
fn load_from(path: &std::path::Path) -> Option<Credentials> {
    let contents = std::fs::read_to_string(path).ok()?;
    let creds = serde_json::from_str::<Credentials>(&contents).ok()?;
    // Enrolled ⟺ both identity fields are present AND non-empty. A blank-field
    // file (e.g. a half-written or hand-cleared credentials.json) reads as
    // standalone, not as a bogus "enrolled with an empty machine identity."
    if creds.machine_id.trim().is_empty() || creds.machine_token.trim().is_empty() {
        return None;
    }
    Some(creds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_creds(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("credentials.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn testLoadValidCredentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_creds(dir.path(), r#"{"machine_id":"m-1","machine_token":"tok"}"#);
        let creds = load_from(&path).unwrap();
        assert_eq!(creds.machine_id, "m-1");
        assert_eq!(creds.machine_token, "tok");
    }

    #[test]
    fn testLoadMissingFile() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_from(&dir.path().join("absent.json")).is_none());
    }

    #[test]
    fn testLoadMissingField() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_creds(dir.path(), r#"{"machine_id":"m-1"}"#);
        assert!(load_from(&path).is_none());
    }

    #[test]
    fn testLoadInvalidJson() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_creds(dir.path(), "not json {{{");
        assert!(load_from(&path).is_none());
    }

    #[test]
    fn testLoadEmptyFieldsIsStandalone() {
        // A well-formed file with blank identity is NOT enrolled.
        let dir = tempfile::tempdir().unwrap();
        let path = write_creds(dir.path(), r#"{"machine_id":"","machine_token":""}"#);
        assert!(load_from(&path).is_none());
        let path2 = write_creds(dir.path(), r#"{"machine_id":"m-1","machine_token":"  "}"#);
        assert!(load_from(&path2).is_none());
    }
}
