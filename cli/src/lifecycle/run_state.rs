// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris disable` and `kyris enable` — toggle the user policy's
//! enforcement mode.
//!
//! Both commands edit the `mode:` value in
//! `$XDG_CONFIG_HOME/agentpact/policy/pact.yaml` (the user-level policy
//! that the daemon walk-up merge picks up). `agentpactd`'s policy
//! watcher reloads the file in place, so the change takes effect
//! without restarting any daemons. kyrisd's `policy_mode_poller`
//! refreshes the tray icon within 5s.
//!
//!   disable  →  spec.mode: log     (record-only; commands run unmediated)
//!   enable   →  spec.mode: enforce (catalog auto-allows, unclassified asks)
//!
//! Both commands probe `agentpactd`'s socket first and fail loudly if
//! it isn't reachable. Rationale: writing the YAML when the daemon
//! can't read it produces a silent "I told kyris something but nothing
//! happened" UX. Users who want kyris fully removed should run
//! `kyris uninstall` (preserves data) or `kyris uninstall --reset-data`
//! (full wipe) — not a runtime toggle.

use clap::Args;
use std::fmt::Write as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const MODE_LOG: &str = "log";
const MODE_ENFORCE: &str = "enforce";

/// Switch governance into log-only mode.
///
/// Edits `pact.yaml` so the user policy's `spec.mode` is `log`.
/// agentpactd continues to evaluate every request but returns Allow
/// without prompting; everything is still recorded in the audit log
/// and the tray icon shows a red horizontal bar across the kyris
/// glyph to make the non-enforcing state visible at a glance.
#[derive(Args)]
pub struct DisableArgs {}

/// Switch governance into enforce mode.
///
/// Edits `pact.yaml` so the user policy's `spec.mode` is `enforce`.
/// Catalog-classified commands auto-allow; unclassified commands
/// route to the menu-bar approval popup (the tray or app resolve it
/// when no desktop dialog is available). Tray icon clears the log-mode overlay.
#[derive(Args)]
pub struct EnableArgs {}

pub fn run_disable(_args: DisableArgs) {
    run_toggle(MODE_LOG);
}

pub fn run_enable(_args: EnableArgs) {
    run_toggle(MODE_ENFORCE);
}

fn run_toggle(target_mode: &str) {
    if !agentpactd_reachable() {
        let sock = agentpact_socket();
        eprintln!(
            "[kyris] agentpactd is not reachable at {sock}. \
             Mode changes only take effect when the policy daemon is running. \
             Fix that first (try `kyris doctor` or reinstall agentpact), then re-run."
        );
        std::process::exit(1);
    }

    let path = pact_yaml_path();
    let outcome = match write_mode_in_place(&path, target_mode) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[kyris] could not update {}: {e}", path.display());
            std::process::exit(1);
        }
    };

    match (target_mode, outcome) {
        (MODE_LOG, WriteOutcome::Updated) => {
            println!("Kyris disabled — mode is now `log`.");
            println!("  - agentpactd will record commands but not enforce. The tray icon");
            println!("    shows a red bar across the kyris glyph until you run `kyris enable`.");
        }
        (MODE_ENFORCE, WriteOutcome::Updated) => {
            println!("Kyris enabled — mode is now `enforce`.");
            println!("  - agentpactd will prompt for unclassified commands. Tray overlay cleared.");
        }
        (MODE_LOG, WriteOutcome::Unchanged) => {
            println!("Kyris is already in `log` mode. No change.");
        }
        (MODE_ENFORCE, WriteOutcome::Unchanged) => {
            println!("Kyris is already in `enforce` mode. No change.");
        }
        (MODE_LOG, WriteOutcome::Created) => {
            println!(
                "Kyris disabled — created {} with mode `log`.",
                path.display()
            );
        }
        (MODE_ENFORCE, WriteOutcome::Created) => {
            println!(
                "Kyris enabled — created {} with mode `enforce`.",
                path.display()
            );
        }
        _ => unreachable!("target_mode is always log or enforce"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum WriteOutcome {
    Created,
    Updated,
    Unchanged,
}

/// Edit the `mode:` line in `pact.yaml` to `target_mode`, preserving
/// every other line (including comments, blank lines, the
/// `apiVersion`/`kind`/`metadata` block, and any user-added `commands:`
/// rules). If the file doesn't exist, write a fresh minimal pact.yaml
/// with the requested mode. If the file exists but has no uncommented
/// `mode:` line, return an error rather than guessing where to inject it.
fn write_mode_in_place(path: &Path, target_mode: &str) -> Result<WriteOutcome, String> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
        std::fs::write(path, fresh_pact_yaml(target_mode)).map_err(|e| format!("write: {e}"))?;
        return Ok(WriteOutcome::Created);
    }

    let contents = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let (new_contents, changed) = rewrite_mode_line(&contents, target_mode)?;
    if !changed {
        return Ok(WriteOutcome::Unchanged);
    }
    std::fs::write(path, new_contents).map_err(|e| format!("write: {e}"))?;
    Ok(WriteOutcome::Updated)
}

/// Pure helper — produces the rewritten file body and whether the
/// content actually changed. Split out so unit tests can drive every
/// edge case without disk I/O.
fn rewrite_mode_line(contents: &str, target_mode: &str) -> Result<(String, bool), String> {
    let mut output = String::with_capacity(contents.len() + 16);
    let mut found = false;
    let mut changed = false;

    for raw_line in contents.lines() {
        if found {
            output.push_str(raw_line);
            output.push('\n');
            continue;
        }
        let trimmed = raw_line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            output.push_str(raw_line);
            output.push('\n');
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("mode:") {
            // Split off any inline `# comment` so we can preserve it.
            let (value_part, comment_part) = match rest.find('#') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            let current_value = value_part.trim();
            let indent_len = raw_line.len() - trimmed.len();
            let indent = &raw_line[..indent_len];

            let comment_suffix = if comment_part.is_empty() {
                String::new()
            } else {
                format!("  {comment_part}")
            };
            writeln!(output, "{indent}mode: {target_mode}{comment_suffix}")
                .expect("writing to String never fails");

            found = true;
            if current_value != target_mode {
                changed = true;
            }
        } else {
            output.push_str(raw_line);
            output.push('\n');
        }
    }

    if !found {
        return Err(format!(
            "no uncommented `mode:` key found. Add `  mode: {target_mode}` under `spec:` \
             or delete the file to have `kyris install` re-seed it."
        ));
    }

    // Preserve trailing-newline-or-not semantics of the input.
    if !contents.ends_with('\n') && output.ends_with('\n') {
        output.pop();
    }

    Ok((output, changed))
}

fn fresh_pact_yaml(target_mode: &str) -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         # User policy. Toggle enforcement with `kyris disable` (log)\n\
         # or `kyris enable` (enforce). Add `commands:` rules under\n\
         # `spec:` for per-pattern decisions.\n\
         apiVersion: agentpact/v1\n\
         kind: Pact\n\
         metadata:\n  name: user-default\n\
         spec:\n  mode: {target_mode}\n",
    )
}

fn pact_yaml_path() -> PathBuf {
    let xdg = std::env::var("XDG_CONFIG_HOME").ok().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.config")
    });
    PathBuf::from(xdg).join("agentpact/policy/pact.yaml")
}

fn agentpact_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn agentpactd_reachable() -> bool {
    UnixStream::connect(agentpact_socket()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRewriteFlipsLogToEnforce() {
        let body = "spec:\n  mode: log\n";
        let (out, changed) = rewrite_mode_line(body, MODE_ENFORCE).unwrap();
        assert!(changed);
        assert!(out.contains("mode: enforce"));
        assert!(!out.contains("mode: log"));
    }

    #[test]
    fn testRewriteIsIdempotentWhenAlreadyTarget() {
        let body = "spec:\n  mode: enforce\n";
        let (out, changed) = rewrite_mode_line(body, MODE_ENFORCE).unwrap();
        assert!(!changed);
        // Output still contains the line (we preserve formatting), just
        // didn't flag it as changed.
        assert!(out.contains("mode: enforce"));
    }

    #[test]
    fn testRewritePreservesSurroundingContent() {
        let body = "# comment 1\n\
                    apiVersion: agentpact/v1\n\
                    kind: Pact\n\
                    metadata:\n  name: user-default\n\
                    spec:\n  mode: log\n  commands:\n    \"git·status\": auto\n";
        let (out, changed) = rewrite_mode_line(body, MODE_ENFORCE).unwrap();
        assert!(changed);
        assert!(out.contains("# comment 1"));
        assert!(out.contains("apiVersion: agentpact/v1"));
        assert!(out.contains("kind: Pact"));
        assert!(out.contains("name: user-default"));
        assert!(out.contains("mode: enforce"));
        assert!(out.contains("\"git·status\": auto"));
    }

    #[test]
    fn testRewritePreservesInlineComment() {
        let body = "spec:\n  mode: log   # observe-only for the demo\n";
        let (out, _changed) = rewrite_mode_line(body, MODE_ENFORCE).unwrap();
        assert!(out.contains("mode: enforce"));
        assert!(
            out.contains("# observe-only for the demo"),
            "inline comment must survive: {out}"
        );
    }

    #[test]
    fn testRewriteIgnoresCommentedOutModeLine() {
        // A `mode: log` inside a comment must not be the line we edit.
        let body = "# spec:\n#   mode: log\nspec:\n  mode: enforce\n";
        let (out, changed) = rewrite_mode_line(body, MODE_LOG).unwrap();
        assert!(changed);
        // The commented line is untouched; only the real `mode:` line flips.
        assert!(out.contains("#   mode: log"));
        assert!(out.contains("  mode: log\n"));
        assert!(!out.contains("mode: enforce"));
    }

    #[test]
    fn testRewriteErrorsWhenNoModeKeyPresent() {
        let body = "spec:\n  commands:\n    foo: auto\n";
        let result = rewrite_mode_line(body, MODE_LOG);
        assert!(result.is_err(), "expected error, got {result:?}");
    }

    #[test]
    fn testFreshPactYamlIncludesMode() {
        let body = fresh_pact_yaml(MODE_ENFORCE);
        assert!(body.contains("mode: enforce"));
        assert!(body.contains("kind: Pact"));
    }

    #[test]
    fn testWriteModeInPlaceCreatesMissingFile() {
        let tmp = std::env::temp_dir().join(format!("kyris-test-pact-{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let outcome = write_mode_in_place(&tmp, MODE_LOG).expect("create");
        assert_eq!(outcome, WriteOutcome::Created);
        let body = std::fs::read_to_string(&tmp).unwrap();
        assert!(body.contains("mode: log"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn testWriteModeInPlaceReportsUnchanged() {
        let tmp = std::env::temp_dir().join(format!(
            "kyris-test-pact-unchanged-{}.yaml",
            std::process::id()
        ));
        std::fs::write(&tmp, "spec:\n  mode: enforce\n").unwrap();
        let outcome = write_mode_in_place(&tmp, MODE_ENFORCE).expect("unchanged");
        assert_eq!(outcome, WriteOutcome::Unchanged);
        let _ = std::fs::remove_file(&tmp);
    }
}
