// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Compile-time provenance: version, build date, commit, and the list
//! of Cargo features that shaped this binary. Used by `--version`, the
//! `/healthz` endpoint, and the startup log line.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_DATE: &str = env!("KYRIS_BUILD_DATE");
pub const COMMIT: &str = env!("KYRIS_COMMIT");

pub const FEATURES: &[&str] = &[
    #[cfg(feature = "tray")]
    "tray",
    #[cfg(feature = "oslog")]
    "oslog",
    #[cfg(feature = "journald")]
    "journald",
];

/// Human-readable feature label for one-line displays. Falls back to
/// "headless" when no opt-in features are compiled in.
pub fn features_label() -> String {
    if FEATURES.is_empty() {
        "headless".to_string()
    } else {
        FEATURES.join(",")
    }
}

/// Format the standard `--version` line.
pub fn version_line() -> String {
    format!(
        "kyrisd {} ({} {}) [{}]",
        VERSION,
        BUILD_DATE,
        COMMIT,
        features_label(),
    )
}
