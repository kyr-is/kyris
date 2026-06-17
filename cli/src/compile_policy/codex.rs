// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{
    Path, Permission, id_to_shell, load_merged_policy, permission_to_file_mode,
    permission_to_network_access,
};

pub fn compile_codex_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    let mut rules = Vec::new();

    for (command_id, perm) in &level.commands {
        let shell_cmd = id_to_shell(command_id);
        let permission = match perm {
            Permission::Auto | Permission::Inform => "Allow",
            Permission::Deny => "Forbidden",
            Permission::Ask => "Prompt",
        };
        rules.push(serde_json::json!({
            "prefix": shell_cmd,
            "permission": permission,
        }));
    }

    rules.sort_by(|a, b| {
        a["prefix"]
            .as_str()
            .unwrap_or("")
            .cmp(b["prefix"].as_str().unwrap_or(""))
    });

    Ok((serde_json::Value::Array(rules), 0))
}

pub fn serialize_codex_rules_file(rules: &serde_json::Value) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let Some(arr) = rules.as_array() else {
        return out;
    };
    for rule in arr {
        let prefix = rule["prefix"].as_str().unwrap_or("");
        let permission = rule["permission"].as_str().unwrap_or("Prompt");
        let tokens: Vec<&str> = prefix.split_whitespace().collect();
        let pattern = tokens
            .iter()
            .map(|t| {
                // Escape for a Starlark double-quoted string literal: backslash
                // first, then the quote. A raw `"` token (e.g. from `tr -d '"'`)
                // otherwise produces `"""` — an unfinished string literal that
                // makes codex fail to load the whole rules file.
                let escaped = t.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{escaped}\"")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let decision = permission.to_ascii_lowercase();
        let _ = writeln!(
            out,
            "prefix_rule(pattern=[{pattern}], decision=\"{decision}\")"
        );
    }
    out
}

/// Output of [`compile_codex_permissions_table`]: the two permission tables
/// Codex CLI supports plus any precision-loss warnings.
pub struct CodexPermissionsTable {
    /// Entries for `[permissions.kyris.filesystem]`: path-glob → access mode.
    pub filesystem: std::collections::BTreeMap<String, String>,
    /// Entries for `[permissions.kyris.network.domains]`: hostname → "allow"|"deny".
    /// URL path components are stripped; host is extracted.
    pub network_domains: std::collections::BTreeMap<String, String>,
    /// Warnings about policy dimensions that lost precision during compilation.
    pub gaps: Vec<String>,
}

/// Compile `AgentPact` `paths` and `urls` policy into the two permission
/// tables that Codex CLI supports natively.
///
/// **Filesystem** (`paths`): direct mapping — each path glob gets a Codex
/// access mode via [`permission_to_file_mode`]. `Ask` fails closed to `none`.
///
/// **Network** (`urls`): host-only mapping — Codex matches by hostname, not
/// URL path. If a url key includes a path component (`"api.example.com/v2/*"`)
/// the host is extracted (`"api.example.com"`) and the path is dropped with a
/// gap warning. `Ask` fails closed to `deny`.
///
/// Empty tables are omitted; callers should skip writing `[permissions.kyris]`
/// when both maps are empty.
///
/// Resolve a policy filesystem glob into a Codex-accepted path. Absolute, `~/`,
/// `~`, and `:special` paths pass through unchanged; a relative glob (`./x` or
/// `x`) is resolved against `workspace_root` (Codex rejects relative paths). The
/// trailing glob (`*`) survives as a literal path component.
pub(super) fn to_codex_fs_path(glob: &str, workspace_root: &Path) -> String {
    if glob == "~" || glob.starts_with('/') || glob.starts_with("~/") || glob.starts_with(':') {
        return glob.to_string();
    }
    let rel = glob.strip_prefix("./").unwrap_or(glob);
    workspace_root.join(rel).to_string_lossy().into_owned()
}

pub fn compile_codex_permissions_table(
    policy_path: Option<&Path>,
) -> Result<CodexPermissionsTable, String> {
    let level = load_merged_policy(policy_path)?;

    let mut filesystem = std::collections::BTreeMap::new();
    let mut network_domains = std::collections::BTreeMap::new();
    let mut url_paths_dropped: Vec<String> = Vec::new();
    let mut ask_collapsed: Vec<String> = Vec::new();

    // Codex requires absolute / `~/` / `:special` filesystem paths and REJECTS
    // the whole config on a relative one. Policy globs may be project-relative
    // (`./src/*`), so resolve them against the workspace (the cwd at setup time)
    // into absolute paths Codex accepts. The glob tail (`*`) is preserved.
    let workspace_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    for (path_glob, perm) in &level.paths {
        if *perm == Permission::Ask {
            ask_collapsed.push(path_glob.clone());
        }
        let mode = permission_to_file_mode(*perm);
        filesystem.insert(
            to_codex_fs_path(path_glob, &workspace_root),
            mode.as_codex_token().to_string(),
        );
    }

    for (domain_key, perm) in &level.urls {
        let host = extract_host(domain_key);
        if host != domain_key.as_str() {
            url_paths_dropped.push(domain_key.clone());
        }
        if *perm == Permission::Ask {
            ask_collapsed.push(domain_key.clone());
        }
        let access = permission_to_network_access(*perm);
        network_domains.insert(host, access.as_codex_token().to_string());
    }

    let mut gaps = Vec::new();
    if !url_paths_dropped.is_empty() {
        gaps.push(format!(
            "{} domain rule(s) had URL path components stripped — Codex matches host only: {}",
            url_paths_dropped.len(),
            url_paths_dropped.join(", ")
        ));
    }
    if !ask_collapsed.is_empty() {
        gaps.push(format!(
            "{} ask rule(s) compiled as deny/none in [permissions.kyris] — no prompt path at Codex sandbox layer: {}",
            ask_collapsed.len(),
            ask_collapsed.join(", ")
        ));
    }

    Ok(CodexPermissionsTable {
        filesystem,
        network_domains,
        gaps,
    })
}

/// Extract the hostname from a domain key, stripping any scheme prefix
/// and URL path component.
///
/// - `"api.example.com"`        → `"api.example.com"`
/// - `"api.example.com/v2/*"`   → `"api.example.com"`
/// - `"https://api.example.com/v2"` → `"api.example.com"`
pub(super) fn extract_host(domain_key: &str) -> String {
    let without_scheme = if let Some(pos) = domain_key.find("://") {
        &domain_key[pos + 3..]
    } else {
        domain_key
    };
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

/// Returns precision-loss warnings from compiling the current policy into
/// Codex CLI's native permission tables.
///
/// Paths and urls are now compiled into `[permissions.kyris]` in
/// `config.toml`. This function surfaces only what was lost in translation:
/// URL path components stripped from url keys (Codex is host-only) and
/// ask rules that collapsed to deny/none (no prompt path at the sandbox layer).
/// Returns an empty Vec when all rules compile without loss.
///
/// Test-only since the user-facing surface that consumed it (`kyris scan
/// agents`) was removed in the CLI reshape; the underlying
/// `compile_codex_permissions_table().gaps` it wraps is production code, and
/// these tests keep the codex gap-detection covered.
#[cfg(test)]
pub fn detect_codex_gaps(policy_path: Option<&Path>) -> Vec<String> {
    compile_codex_permissions_table(policy_path)
        .map(|table| table.gaps)
        .unwrap_or_default()
}
