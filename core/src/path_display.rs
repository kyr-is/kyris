// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Home-relative path rendering for kyris's HUMAN DISPLAY and LOGS only.
//!
//! Never use this for policy decisions or path matching — those run on the real
//! absolute/canonical path. This is purely cosmetic + privacy: paths inside the
//! user's `$HOME` are shown with a `~` prefix (`/Users/me/proj/x` → `~/proj/x`),
//! which is shorter and keeps the username out of approval dialogs and audit
//! logs. Paths outside `$HOME`, non-absolute inputs, and the `$HOME`-unset case
//! are returned unchanged.

/// Render `path` home-relative for display/logging, using the process `$HOME`.
#[must_use]
pub fn home_relative(path: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) => home_relative_to(&home, path),
        Err(_) => path.to_string(),
    }
}

/// Pure core of [`home_relative`] — `home` is injected so it is testable
/// without mutating the process environment.
#[must_use]
pub fn home_relative_to(home: &str, path: &str) -> String {
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return path.to_string();
    }
    if path == home {
        return "~".to_string();
    }
    // Only collapse on a real path-component boundary: `/home/me` must match
    // `/home/me/x` but NOT `/home/meXYZ/x`.
    if let Some(rest) = path.strip_prefix(home)
        && rest.starts_with('/')
    {
        return format!("~{rest}");
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testHomeRelativeRendering() {
        assert_eq!(
            home_relative_to("/Users/me", "/Users/me/proj/x.rs"),
            "~/proj/x.rs"
        );
        assert_eq!(home_relative_to("/Users/me", "/Users/me"), "~");
        assert_eq!(home_relative_to("/Users/me/", "/Users/me/proj"), "~/proj");
        assert_eq!(home_relative_to("/Users/me", "/etc/passwd"), "/etc/passwd");
        assert_eq!(
            home_relative_to("/Users/me", "/Users/meXYZ/x"),
            "/Users/meXYZ/x"
        );
        assert_eq!(home_relative_to("/Users/me", "relative/x"), "relative/x");
        assert_eq!(home_relative_to("", "/Users/me/x"), "/Users/me/x");
    }
}
