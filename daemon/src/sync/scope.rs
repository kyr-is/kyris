// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

pub struct SyncScope {
    patterns: Vec<String>,
}

impl SyncScope {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn is_in_scope(&self, working_dir: Option<&str>) -> bool {
        let Some(dir) = working_dir else {
            return false;
        };
        if self.patterns.is_empty() {
            return false;
        }
        self.patterns
            .iter()
            .any(|pattern| matches_scope(pattern, dir))
    }
}

fn matches_scope(pattern: &str, path: &str) -> bool {
    let expanded = if let Some(rest) = pattern.strip_prefix('~') {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}{rest}")
    } else {
        pattern.to_string()
    };

    if let Some(prefix) = expanded.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == expanded || path.starts_with(&format!("{expanded}/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testIsInScopeNoWorkingDir() {
        let scope = SyncScope::new(vec!["/work/*".to_string()]);
        assert!(!scope.is_in_scope(None));
    }

    #[test]
    fn testIsInScopeEmptyScope() {
        let scope = SyncScope::new(vec![]);
        assert!(!scope.is_in_scope(Some("/work/project")));
    }

    #[test]
    fn testIsInScopeMatch() {
        let scope = SyncScope::new(vec!["/work/*".to_string()]);
        assert!(scope.is_in_scope(Some("/work/project")));
    }

    #[test]
    fn testIsInScopeNoMatch() {
        let scope = SyncScope::new(vec!["/work/*".to_string()]);
        assert!(!scope.is_in_scope(Some("/personal/stuff")));
    }

    #[test]
    fn testMatchesScopeWildcard() {
        assert!(matches_scope("/work/*", "/work/project1"));
        assert!(matches_scope("/work/*", "/work/project1/src"));
        assert!(!matches_scope("/work/*", "/home/user"));
    }

    #[test]
    fn testMatchesScopeExact() {
        assert!(matches_scope("/work/project1", "/work/project1"));
        assert!(matches_scope("/work/project1", "/work/project1/src"));
        assert!(!matches_scope("/work/project1", "/work/project2"));
    }

    #[test]
    fn testMatchesScopeNoMatch() {
        assert!(!matches_scope("/corp/*", "/work/project"));
    }

    #[test]
    fn testMatchesScopeEmptyPath() {
        assert!(!matches_scope("/work/*", ""));
    }

    #[test]
    fn testMatchesScopeTildeExpansion() {
        unsafe { std::env::set_var("HOME", "/home/dev") };
        assert!(matches_scope("~/work/*", "/home/dev/work/project"));
        assert!(!matches_scope("~/work/*", "/other/work/project"));
    }

    #[test]
    fn testScopeIsEmpty() {
        assert!(SyncScope::new(vec![]).is_empty());
        assert!(!SyncScope::new(vec!["/work/*".to_string()]).is_empty());
    }
}
