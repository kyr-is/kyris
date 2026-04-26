// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use regex::Regex;
use std::path::Path;

use super::scanner::{Finding, FindingCategory, FindingLocation, Severity};

struct KeyPattern {
    name: &'static str,
    regex: Regex,
}

fn key_patterns() -> Vec<KeyPattern> {
    vec![
        KeyPattern {
            name: "OpenAI",
            regex: Regex::new(r"sk-[a-zA-Z0-9]{20,}").expect("compile openai regex"),
        },
        KeyPattern {
            name: "Anthropic",
            regex: Regex::new(r"sk-ant-[a-zA-Z0-9\-]{20,}").expect("compile anthropic regex"),
        },
        KeyPattern {
            name: "Google",
            regex: Regex::new(r"AIza[a-zA-Z0-9_\-]{35}").expect("compile google regex"),
        },
        KeyPattern {
            name: "AWS",
            regex: Regex::new(r"AKIA[A-Z0-9]{16}").expect("compile aws regex"),
        },
        KeyPattern {
            name: "GitHub",
            regex: Regex::new(r"ghp_[a-zA-Z0-9]{36}").expect("compile github regex"),
        },
    ]
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "vendor",
];

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "bmp", "svg", "woff", "woff2", "ttf", "eot", "zip", "tar",
    "gz", "bz2", "xz", "7z", "rar", "exe", "dll", "so", "dylib", "o", "a", "pdf", "doc", "docx",
    "xls", "xlsx", "class", "jar", "war", "pyc", "pyo", "db", "sqlite", "duckdb",
];

pub fn scan(dir: &Path) -> Vec<Finding> {
    let patterns = key_patterns();
    let mut findings = Vec::new();
    scan_dir(dir, &patterns, &mut findings);
    findings
}

fn scan_dir(dir: &Path, patterns: &[KeyPattern], findings: &mut Vec<Finding>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            scan_dir(&path, patterns, findings);
        } else if path.is_file() {
            if is_binary_file(&path) {
                continue;
            }
            scan_file(&path, patterns, findings);
        }
    }
}

fn is_binary_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
}

fn scan_file(path: &Path, patterns: &[KeyPattern], findings: &mut Vec<Finding>) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };

    for (line_num, line) in contents.lines().enumerate() {
        for pattern in patterns {
            if let Some(m) = pattern.regex.find(line) {
                let redacted = redact_key(m.as_str());
                findings.push(Finding {
                    category: FindingCategory::ApiKey,
                    severity: Severity::Critical,
                    title: format!("{} API key found", pattern.name),
                    description: format!("Detected a {} API key in source file.", pattern.name),
                    location: FindingLocation {
                        path: path.display().to_string(),
                        line: Some(line_num + 1),
                    },
                    evidence: Some(redacted),
                    remediation: "Move the key to an environment variable or secrets manager. \
                                  Add the file to .gitignore if appropriate."
                        .to_string(),
                });
            }
        }
    }
}

pub fn redact_key(key: &str) -> String {
    if key.len() > 8 {
        format!("{}...", &key[..8])
    } else {
        format!("{key}...")
    }
}

pub fn pattern_names() -> Vec<&'static str> {
    vec![
        "OpenAI (sk-...)",
        "Anthropic (sk-ant-...)",
        "Google (AIza...)",
        "AWS (AKIA...)",
        "GitHub (ghp_...)",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testDetectsOpenAIKey() {
        let patterns = key_patterns();
        let openai = &patterns[0];
        assert!(openai.regex.is_match("sk-abcdefghijklmnopqrst1234"));
        assert!(!openai.regex.is_match("sk-short"));
    }

    #[test]
    fn testDetectsAnthropicKey() {
        let patterns = key_patterns();
        let anthropic = &patterns[1];
        assert!(
            anthropic
                .regex
                .is_match("sk-ant-api03-abcdefghijklmnopqrst")
        );
        assert!(!anthropic.regex.is_match("sk-ant-short"));
    }

    #[test]
    fn testRedactsKeyValue() {
        let key = "sk-abcdefghijklmnopqrst1234";
        let redacted = redact_key(key);
        assert_eq!(redacted, "sk-abcde...");
        assert!(!redacted.contains("mnopqrst"));
    }

    #[test]
    fn testDetectsAwsKey() {
        let patterns = key_patterns();
        let aws = &patterns[3];
        assert!(aws.regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!aws.regex.is_match("AKIAshort"));
    }

    #[test]
    fn testDetectsGithubKey() {
        let patterns = key_patterns();
        let github = &patterns[4];
        assert!(
            github
                .regex
                .is_match("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        );
        assert!(!github.regex.is_match("ghp_short"));
    }

    #[test]
    fn testBinaryExtensionSkipped() {
        assert!(is_binary_file(Path::new("image.png")));
        assert!(is_binary_file(Path::new("archive.zip")));
        assert!(!is_binary_file(Path::new("code.rs")));
        assert!(!is_binary_file(Path::new("config.toml")));
    }

    #[test]
    fn testBinaryExtensionCaseInsensitive() {
        assert!(is_binary_file(Path::new("image.PNG")));
        assert!(is_binary_file(Path::new("archive.ZIP")));
    }

    #[test]
    fn testBinaryExtensionNoExtension() {
        assert!(!is_binary_file(Path::new("Makefile")));
    }

    #[test]
    fn testRedactShortKey() {
        assert_eq!(redact_key("sk-short"), "sk-short...");
    }

    #[test]
    fn testRedactExactly8Chars() {
        assert_eq!(redact_key("12345678"), "12345678...");
    }

    #[test]
    fn testPatternNames() {
        let names = pattern_names();
        assert_eq!(names.len(), 5);
        assert!(names[0].contains("OpenAI"));
        assert!(names[1].contains("Anthropic"));
    }

    #[test]
    fn testDetectsGoogleKey() {
        let patterns = key_patterns();
        let google = &patterns[2];
        assert!(
            google
                .regex
                .is_match("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456")
        );
        assert!(!google.regex.is_match("AIzaShort"));
    }

    #[test]
    fn testSkipDirsIncluded() {
        assert!(SKIP_DIRS.contains(&".git"));
        assert!(SKIP_DIRS.contains(&"node_modules"));
        assert!(SKIP_DIRS.contains(&"target"));
    }

    #[test]
    fn testScanFileWithKeyInDir() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.rs");
        std::fs::write(&file, "let key = \"sk-abcdefghijklmnopqrst1234\";\n").unwrap();

        let patterns = key_patterns();
        let mut findings = Vec::new();
        scan_file(&file, &patterns, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::ApiKey);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].location.line == Some(1));
    }

    #[test]
    fn testScanFileClean() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clean.rs");
        std::fs::write(&file, "fn main() { println!(\"hello\"); }\n").unwrap();

        let patterns = key_patterns();
        let mut findings = Vec::new();
        scan_file(&file, &patterns, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanDirSkipsGitDir() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(git_dir.join("config"), "sk-abcdefghijklmnopqrst1234\n").unwrap();

        let findings = scan(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanDirSkipsBinaryFiles() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("image.png"),
            "sk-abcdefghijklmnopqrst1234\n",
        )
        .unwrap();

        let findings = scan(dir.path());
        assert!(findings.is_empty());
    }
}
