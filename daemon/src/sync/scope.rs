// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

use std::path::{Component, Path};

/// macOS TCC-protected / standard home folders that never sync by default.
/// Grounded in convention (Apple's TCC-protected locations + the standard home
/// layout), not an ad-hoc blocklist.
const PERSONAL_DIRS: &[&str] = &[
    "Documents",
    "Downloads",
    "Desktop",
    "Pictures",
    "Music",
    "Movies",
    "Public",
    "Library",
    "Applications",
];

pub struct SyncScope {
    /// Explicit include patterns. Empty = sync every governed directory that is
    /// not conventionally private; non-empty = additionally narrow to
    /// directories matching one of these patterns.
    patterns: Vec<String>,
    /// `$HOME`, captured once at construction. Anchors the personal-folder and
    /// owner-only checks (and `~` expansion in include patterns).
    home: Option<String>,
}

impl SyncScope {
    pub fn new(patterns: Vec<String>) -> Self {
        Self {
            patterns,
            home: std::env::var("HOME").ok().filter(|home| !home.is_empty()),
        }
    }

    #[cfg(test)]
    fn with_home(patterns: Vec<String>, home: Option<&str>) -> Self {
        Self {
            patterns,
            home: home.map(String::from),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether a record/event from `working_dir` should sync to the relay.
    ///
    /// Sync is **default-on for governed directories**: every call routed
    /// through kyris carries the governed session's launch dir as `working_dir`
    /// (see `forest/design/kyris.md` §5.8). We sync it unless:
    /// - there is no `working_dir` — no governed context, and "Kyris does not
    ///   guess"; or
    /// - the directory is conventionally **private** ([`Self::is_private`]) —
    ///   this is absolute and wins even over an explicit `scope` entry; or
    /// - an explicit include `scope` is configured and the directory is not
    ///   under it (the list only *narrows* the default-on set).
    pub fn is_in_scope(&self, working_dir: Option<&str>) -> bool {
        let Some(dir) = working_dir else {
            return false;
        };
        // Pure literal matcher: paths are already canonical by the time they get
        // here. `working_dir` is canonicalized at its source edge (agentpactd at
        // request ingest; kyrisd's peer-cwd via getcwd), and the configured scope
        // is canonicalized once at config-load (see `canonicalize_scope_config`
        // in `daemon_sync`). Keeping this comparison literal makes `SyncScope` a
        // single-responsibility matcher with no filesystem I/O.
        if self.is_private(dir) {
            return false;
        }
        if self.patterns.is_empty() {
            return true;
        }
        self.patterns
            .iter()
            .any(|pattern| self.matches_scope(pattern, dir))
    }

    /// A directory is *private* — never synced by default — if it matches any of
    /// three OS conventions for "not shareable content":
    ///
    /// 1. **Hidden** — a dot-prefixed path component (`~/.ssh`, `~/.aws`,
    ///    `~/.config`, the XDG `~/.local` tree, …): the universal Unix
    ///    hidden-file convention, where credentials and config live.
    /// 2. **Owner-only** — the directory, or an ancestor up to (but not
    ///    including) `$HOME`, has no group/other permission bits (mode
    ///    `0o700`/`0o600`): the truest Unix "this is private" signal. `$HOME`
    ///    itself is skipped because it is routinely `0700` on macOS, which is
    ///    not a per-directory privacy choice.
    /// 3. **Personal** — a macOS TCC-protected / standard home folder
    ///    ([`PERSONAL_DIRS`]: `~/Documents`, `~/Downloads`, `~/Desktop`, …).
    fn is_private(&self, dir: &str) -> bool {
        // 1. Hidden (any dot-prefixed path component).
        if Path::new(dir).components().any(|component| {
            matches!(component, Component::Normal(name)
                if name.to_str().is_some_and(|s| s.starts_with('.')))
        }) {
            return true;
        }

        let Some(home) = self.home.as_deref() else {
            // No $HOME to anchor #2/#3 — fall back to the dir's own mode (#2).
            return is_owner_only(Path::new(dir));
        };

        // 3. Personal home folder (the dir itself or anything beneath it).
        for name in PERSONAL_DIRS {
            let personal = format!("{home}/{name}");
            if dir == personal || dir.starts_with(&format!("{personal}/")) {
                return true;
            }
        }

        // 2. Owner-only at the directory or any ancestor strictly below $HOME.
        owner_only_below_home(Path::new(dir), Path::new(home))
    }

    fn matches_scope(&self, pattern: &str, path: &str) -> bool {
        let expanded = match (pattern.strip_prefix('~'), self.home.as_deref()) {
            (Some(rest), Some(home)) => format!("{home}{rest}"),
            _ => pattern.to_string(),
        };

        if let Some(prefix) = expanded.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == expanded || path.starts_with(&format!("{expanded}/"))
        }
    }
}

/// Resolve symlinks in the longest existing leading portion of `path`, keeping
/// any non-existent tail — and a trailing `*` wildcard — verbatim. This yields
/// one canonical spelling whether or not the full path exists and whether or not
/// it ends in `*`. Returns the input unchanged when nothing along it resolves.
///
/// Used to canonicalize the user-configured `sync.scope` at config-load (the one
/// kyrisd-side path edge), so a scope entry typed through a symlinked root
/// (`/tmp/...`, `~/work` → `/mnt/...`) matches the already-canonical
/// `working_dir` produced upstream. It is deliberately NOT applied inside
/// [`SyncScope`] itself, which stays a pure literal matcher.
pub fn canonicalize_scope_path(path: &str) -> String {
    // Common case: a concrete, existing directory resolves whole.
    if let Ok(resolved) = std::fs::canonicalize(path)
        && let Some(s) = resolved.to_str()
    {
        return s.to_string();
    }
    // Otherwise resolve the longest existing ancestor and re-attach the tail
    // (covers wildcard patterns like `/work/*` and not-yet-created dirs).
    let p = Path::new(path);
    for ancestor in p.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Ok(canon) = std::fs::canonicalize(ancestor)
            && let Ok(tail) = p.strip_prefix(ancestor)
            && let Some(s) = canon.join(tail).to_str()
        {
            return s.to_string();
        }
    }
    path.to_string()
}

/// True if `path` or any ancestor *strictly below* `home` is owner-only. `home`
/// and anything above it are not checked (`$HOME` is commonly `0700` on macOS,
/// which is not a signal that a project under it is private). If `path` is not
/// under `home`, only `path` itself is checked.
fn owner_only_below_home(path: &Path, home: &Path) -> bool {
    let mut current = path;
    loop {
        if current == home {
            return false;
        }
        if is_owner_only(current) {
            return true;
        }
        if !current.starts_with(home) {
            // Outside the home tree — we checked `current` itself; stop.
            return false;
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return false,
        }
    }
}

#[cfg(unix)]
fn is_owner_only(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // No group/other permission bits set = owner-only. The bit-mask form is the
    // idiomatic permission check; clippy's `trailing_zeros` rewrite is less
    // legible here.
    #[allow(clippy::verbose_bit_mask)]
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o077 == 0)
}

#[cfg(not(unix))]
fn is_owner_only(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testIsInScopeNoWorkingDir() {
        // No governed context → never syncs ("Kyris does not guess").
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        assert!(!scope.is_in_scope(None));
    }

    #[test]
    fn testEmptyScopeSyncsGovernedDir() {
        // Default-on: an ordinary governed dir syncs with no explicit scope.
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        assert!(scope.is_in_scope(Some("/home/dev/work/project")));
    }

    #[test]
    fn testHiddenDirExcluded() {
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        assert!(!scope.is_in_scope(Some("/home/dev/.ssh")));
        assert!(!scope.is_in_scope(Some("/home/dev/.config/app")));
        assert!(!scope.is_in_scope(Some("/home/dev/.local/share/x")));
    }

    #[test]
    fn testPersonalDirsExcluded() {
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        for name in [
            "Documents",
            "Downloads",
            "Desktop",
            "Pictures",
            "Music",
            "Movies",
        ] {
            let dir = format!("/home/dev/{name}/sub");
            assert!(!scope.is_in_scope(Some(&dir)), "{dir} should be private");
        }
        // The folder itself, not just children.
        assert!(!scope.is_in_scope(Some("/home/dev/Documents")));
        // A look-alike prefix is NOT excluded.
        assert!(scope.is_in_scope(Some("/home/dev/Documents-archive/x")));
    }

    #[test]
    fn testOwnerOnlyDirExcluded() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("kyris-scope-{}", std::process::id()));
        let home = tmp.join("home");
        let private = home.join("private");
        let open = home.join("open");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let scope = SyncScope::with_home(vec![], home.to_str());
        // Owner-only dir (and anything under it) is private.
        assert!(!scope.is_in_scope(Some(private.to_str().unwrap())));
        let under = private.join("proj");
        std::fs::create_dir_all(&under).unwrap();
        std::fs::set_permissions(&under, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!scope.is_in_scope(Some(under.to_str().unwrap())));
        // A world-readable dir under $HOME syncs.
        assert!(scope.is_in_scope(Some(open.to_str().unwrap())));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn testExplicitScopeNarrows() {
        let scope = SyncScope::with_home(vec!["/work/*".to_string()], Some("/home/dev"));
        assert!(scope.is_in_scope(Some("/work/project")));
        // Non-private but outside the explicit include → not synced.
        assert!(!scope.is_in_scope(Some("/home/dev/elsewhere")));
    }

    #[test]
    fn testPrivateWinsOverExplicitScope() {
        let scope = SyncScope::with_home(vec!["~/Documents/*".to_string()], Some("/home/dev"));
        // Even explicitly listed, a personal dir stays private.
        assert!(!scope.is_in_scope(Some("/home/dev/Documents/proj")));
    }

    #[test]
    fn testMatchesScopeWildcard() {
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        assert!(scope.matches_scope("/work/*", "/work/project1"));
        assert!(scope.matches_scope("/work/*", "/work/project1/src"));
        assert!(!scope.matches_scope("/work/*", "/home/user"));
    }

    #[test]
    fn testMatchesScopeExact() {
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        assert!(scope.matches_scope("/work/project1", "/work/project1"));
        assert!(scope.matches_scope("/work/project1", "/work/project1/src"));
        assert!(!scope.matches_scope("/work/project1", "/work/project2"));
    }

    #[test]
    fn testMatchesScopeTildeExpansion() {
        let scope = SyncScope::with_home(vec![], Some("/home/dev"));
        assert!(scope.matches_scope("~/work/*", "/home/dev/work/project"));
        assert!(!scope.matches_scope("~/work/*", "/other/work/project"));
    }

    #[test]
    fn testScopeIsEmpty() {
        assert!(SyncScope::with_home(vec![], Some("/home/dev")).is_empty());
        assert!(!SyncScope::with_home(vec!["/work/*".to_string()], Some("/home/dev")).is_empty());
    }
}
