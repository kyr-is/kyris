// SPDX-License-Identifier: Apache-2.0

pub fn matches_scope(pattern: &str, path: &str) -> bool {
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
    fn testMatchesWildcard() {
        assert!(matches_scope("/work/*", "/work/project1"));
        assert!(matches_scope("/work/*", "/work/project1/src"));
        assert!(!matches_scope("/work/*", "/home/user"));
    }

    #[test]
    fn testMatchesExact() {
        assert!(matches_scope("/work/project1", "/work/project1"));
        assert!(matches_scope("/work/project1", "/work/project1/src"));
        assert!(!matches_scope("/work/project1", "/work/project2"));
    }

    #[test]
    fn testMatchesNoMatch() {
        assert!(!matches_scope("/corp/*", "/work/project"));
    }

    #[test]
    fn testEmptyPath() {
        assert!(!matches_scope("/work/*", ""));
    }
}
