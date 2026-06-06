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

const PROJECT_REMEDIATION: &str = "Move the key to an environment variable or secrets manager. \
     Add the file to .gitignore if appropriate.";

const ENV_VAR_REMEDIATION: &str = "Remove the API key from environment variables. \
     Use kyrisd's credential store or a secrets manager instead.";

const CLOUD_SDK_REMEDIATION: &str = "Rotate this credential immediately. Use IAM roles or short-lived tokens \
     instead of long-lived credentials.";

pub fn scan(dir: &Path) -> Vec<Finding> {
    let patterns = key_patterns();
    let mut findings = Vec::new();
    scan_dir(dir, &patterns, &mut findings);
    scan_vars(std::env::vars(), &patterns, &mut findings);
    scan_cloud_sdk_at_paths(&cloud_sdk_paths(), &patterns, &mut findings);
    findings
}

/// Fixed paths where cloud SDK tools store long-lived credentials.
fn cloud_sdk_paths() -> Vec<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![
        std::path::PathBuf::from(format!("{home}/.aws/credentials")),
        std::path::PathBuf::from(format!(
            "{home}/.config/gcloud/application_default_credentials.json"
        )),
    ]
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
            scan_file(&path, patterns, findings, PROJECT_REMEDIATION);
        }
    }
}

fn is_binary_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
}

fn scan_file(path: &Path, patterns: &[KeyPattern], findings: &mut Vec<Finding>, remediation: &str) {
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
                    remediation: remediation.to_string(),
                });
            }
        }
    }
}

/// Scans an iterable of `(name, value)` pairs for API key patterns.
/// Kept separate from `std::env::vars()` for deterministic unit testing.
fn scan_vars<I>(vars: I, patterns: &[KeyPattern], findings: &mut Vec<Finding>)
where
    I: IntoIterator<Item = (String, String)>,
{
    for (name, value) in vars {
        for pattern in patterns {
            if let Some(m) = pattern.regex.find(&value) {
                let redacted = redact_key(m.as_str());
                findings.push(Finding {
                    category: FindingCategory::ApiKey,
                    severity: Severity::Critical,
                    title: format!("{} API key in environment variable", pattern.name),
                    description: format!(
                        "Detected a {} API key in the ${name} environment variable.",
                        pattern.name
                    ),
                    location: FindingLocation {
                        path: format!("${name}"),
                        line: None,
                    },
                    evidence: Some(redacted),
                    remediation: ENV_VAR_REMEDIATION.to_string(),
                });
            }
        }
    }
}

/// Scans the given paths (cloud SDK credential files). Missing paths are silently skipped.
fn scan_cloud_sdk_at_paths(
    paths: &[std::path::PathBuf],
    patterns: &[KeyPattern],
    findings: &mut Vec<Finding>,
) {
    for path in paths {
        if path.is_file() {
            scan_file(path, patterns, findings, CLOUD_SDK_REMEDIATION);
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
        scan_file(&file, &patterns, &mut findings, PROJECT_REMEDIATION);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::ApiKey);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].location.line == Some(1));
        assert_eq!(findings[0].remediation, PROJECT_REMEDIATION);
    }

    #[test]
    fn testScanFileClean() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clean.rs");
        std::fs::write(&file, "fn main() { println!(\"hello\"); }\n").unwrap();

        let patterns = key_patterns();
        let mut findings = Vec::new();
        scan_file(&file, &patterns, &mut findings, PROJECT_REMEDIATION);
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanDirSkipsGitDir() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(git_dir.join("config"), "sk-abcdefghijklmnopqrst1234\n").unwrap();

        let findings = scan(dir.path());
        // Only check that the .git dir key was not found (env vars/cloud sdk may add others).
        assert!(
            !findings
                .iter()
                .any(|f| f.location.path.contains(".git/config"))
        );
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
        assert!(!findings.iter().any(|f| {
            std::path::Path::new(&f.location.path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
        }));
    }

    // --- env var scanner ---

    #[test]
    fn testScanVarsDetectsAnthropicKey() {
        let patterns = key_patterns();
        let mut findings = Vec::new();
        let vars = vec![
            (
                "ANTHROPIC_API_KEY".to_string(),
                "sk-ant-api03-abcdefghijklmnopqrst".to_string(),
            ),
            ("PATH".to_string(), "/usr/local/bin:/usr/bin".to_string()),
        ];
        scan_vars(vars, &patterns, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.path, "$ANTHROPIC_API_KEY");
        assert!(findings[0].location.line.is_none());
        assert_eq!(findings[0].category, FindingCategory::ApiKey);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn testScanVarsClean() {
        let patterns = key_patterns();
        let mut findings = Vec::new();
        let vars = vec![
            ("PATH".to_string(), "/usr/local/bin:/usr/bin".to_string()),
            ("HOME".to_string(), "/Users/test".to_string()),
            ("TERM".to_string(), "xterm-256color".to_string()),
        ];
        scan_vars(vars, &patterns, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanVarsMultipleKeysInDifferentVars() {
        let patterns = key_patterns();
        let mut findings = Vec::new();
        let vars = vec![
            (
                "OPENAI_KEY".to_string(),
                "sk-abcdefghijklmnopqrst1234".to_string(),
            ),
            (
                "AWS_ACCESS_KEY_ID".to_string(),
                "AKIAIOSFODNN7EXAMPLE".to_string(),
            ),
        ];
        scan_vars(vars, &patterns, &mut findings);
        assert_eq!(findings.len(), 2);
        let paths: Vec<&str> = findings.iter().map(|f| f.location.path.as_str()).collect();
        assert!(paths.contains(&"$OPENAI_KEY"));
        assert!(paths.contains(&"$AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn testScanVarsUsesEnvVarRemediation() {
        let patterns = key_patterns();
        let mut findings = Vec::new();
        let vars = vec![(
            "MY_KEY".to_string(),
            "sk-abcdefghijklmnopqrst1234".to_string(),
        )];
        scan_vars(vars, &patterns, &mut findings);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].remediation, ENV_VAR_REMEDIATION);
        // Must not suggest adding to .gitignore — env vars aren't in files.
        assert!(!findings[0].remediation.contains(".gitignore"));
    }

    #[test]
    fn testScanVarsTitleMentionsEnvVar() {
        let patterns = key_patterns();
        let mut findings = Vec::new();
        let vars = vec![(
            "GITHUB_TOKEN".to_string(),
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij".to_string(),
        )];
        scan_vars(vars, &patterns, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("environment variable"));
        assert!(findings[0].description.contains("$GITHUB_TOKEN"));
    }

    // --- cloud SDK scanner ---

    #[test]
    fn testScanCloudSdkDetectsAwsKey() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::write(
            &creds,
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret\n",
        )
        .unwrap();

        let patterns = key_patterns();
        let mut findings = Vec::new();
        scan_cloud_sdk_at_paths(std::slice::from_ref(&creds), &patterns, &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].location.path.contains("credentials"));
        assert_eq!(findings[0].location.line, Some(2));
        assert_eq!(findings[0].remediation, CLOUD_SDK_REMEDIATION);
    }

    #[test]
    fn testScanCloudSdkMissingFileSkipped() {
        let patterns = key_patterns();
        let mut findings = Vec::new();
        let nonexistent = std::path::PathBuf::from("/nonexistent/path/credentials");
        scan_cloud_sdk_at_paths(&[nonexistent], &patterns, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn testScanCloudSdkUsesCloudSdkRemediation() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("credentials");
        std::fs::write(&creds, "AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let patterns = key_patterns();
        let mut findings = Vec::new();
        scan_cloud_sdk_at_paths(&[creds], &patterns, &mut findings);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].remediation, CLOUD_SDK_REMEDIATION);
        // Must not suggest adding to .gitignore — ~/.aws/credentials isn't a git repo.
        assert!(!findings[0].remediation.contains(".gitignore"));
    }

    #[test]
    fn testCloudSdkPathsIncludeAwsAndGcloud() {
        let paths = cloud_sdk_paths();
        assert_eq!(paths.len(), 2);
        assert!(
            paths
                .iter()
                .any(|p| p.to_string_lossy().contains(".aws/credentials"))
        );
        assert!(paths.iter().any(|p| {
            p.to_string_lossy()
                .contains("gcloud/application_default_credentials.json")
        }));
    }

    #[test]
    fn testCloudSdkPathsAreUnderHome() {
        let home = std::env::var("HOME").unwrap_or_default();
        let paths = cloud_sdk_paths();
        for path in &paths {
            assert!(
                path.starts_with(&home),
                "expected path under $HOME, got {path:?}"
            );
        }
    }
}
