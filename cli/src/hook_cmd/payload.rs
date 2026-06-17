// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Hook-payload mapping: workspace-anchor resolution, relative-path joining,
//! `apply_patch` envelope parsing, and the protocol-driven action/detail map.

use crate::agents::registry::{HookProtocol, ToolMapping};

/// Pick the workspace anchor to send to agentpactd as `working_dir`. This is
/// the permitted-domain root — the directory tree the agent may touch — so it
/// must be the agent's FIXED launch/project dir, never a value that moves when
/// the agent runs `cd`.
///
/// Resolution order:
///   1. `launch_dir` — the agent's fixed launch/project dir, already resolved
///      by the caller from the agent's `launch_dir_env` var (e.g.
///      `CLAUDE_PROJECT_DIR`). Stable across the agent's own `cd` — unlike
///      Claude Code's payload `cwd`, which is the LIVE working directory.
///   2. The hook payload's `cwd` (already fixed at session start for Codex and
///      Gemini; for Claude a fallback only if the env var is absent).
///   3. `None`. We deliberately do NOT fall back to the hook process's own
///      `current_dir()` — that is the kyris-hook process, not the agent, and
///      would anchor the permitted domain to the wrong tree. agentpactd fails
///      safe (asks) when the workspace is unknown.
pub(super) fn derive_session_cwd(
    launch_dir: Option<&str>,
    hook_input: &serde_json::Value,
) -> Option<String> {
    if let Some(dir) = launch_dir.filter(|s| !s.trim().is_empty()) {
        return Some(dir.to_string());
    }
    hook_input
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Resolve a relative file path against the session cwd for `read`/`write`
/// actions. Absolute paths, non-file actions, and missing cwd pass through
/// unchanged. Done lexically — we do not touch the filesystem; canonicalization
/// happens inside agentpactd's boundary check.
pub(super) fn resolve_relative_path(action: &str, detail: &str, cwd: Option<&str>) -> String {
    if action != "read" && action != "write" {
        return detail.to_string();
    }
    if detail.is_empty() {
        return detail.to_string();
    }
    let path = std::path::Path::new(detail);
    if path.is_absolute() {
        return detail.to_string();
    }
    let Some(base) = cwd else {
        return detail.to_string();
    };
    std::path::Path::new(base)
        .join(detail)
        .to_string_lossy()
        .into_owned()
}

/// Actions whose `detail` is a single filesystem path (not a command string).
/// These are rendered home-relative for display/logging; `execute` details are
/// command text and are left verbatim.
pub(super) fn is_file_action(action: &str) -> bool {
    matches!(action, "read" | "write" | "delete")
}

/// File paths a patch envelope touches, split by governed action.
pub(super) struct PatchPaths {
    /// `Add File` / `Update File` / `Move to` destinations — content lands at
    /// these paths. A move's SOURCE also stays here: it is being modified;
    /// its simultaneous disappearance is governed as part of that write
    /// (renames are not escalated to delete policy).
    pub(super) writes: Vec<String>,
    /// `Delete File` — the file is removed outright.
    pub(super) deletes: Vec<String>,
}

/// Parse codex's `apply_patch` envelope markers (apply-patch crate grammar:
/// `*** Begin Patch`, `*** Add File: `, `*** Update File: `, `*** Move to: `,
/// `*** Delete File: `; lenient about surrounding whitespace, paths may be
/// relative to the session cwd). Returns empty lists for text with no
/// recognizable markers — the caller treats that as unparseable and never
/// guesses.
pub(super) fn parse_apply_patch_paths(patch: &str) -> PatchPaths {
    let mut paths = PatchPaths {
        writes: Vec::new(),
        deletes: Vec::new(),
    };
    for line in patch.lines() {
        // Markers live at COLUMN 0 in the grammar; update-hunk context lines
        // are space-prefixed, so trimming the start would turn file CONTENT
        // that mentions a marker into a phantom path. Trim the end only
        // (\r\n / trailing whitespace).
        let line = line.trim_end();
        if let Some(path) = line.strip_prefix("*** Add File:") {
            paths.writes.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Update File:") {
            paths.writes.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Move to:") {
            paths.writes.push(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("*** Delete File:") {
            paths.deletes.push(path.trim().to_string());
        }
    }
    paths
}

pub(super) fn map_payload(
    protocol: Option<&HookProtocol>,
    input: &serde_json::Value,
) -> (String, String) {
    let Some(protocol) = protocol else {
        let method = input["method"].as_str().unwrap_or("call");
        let detail = input["detail"].as_str().unwrap_or("");
        return (method.to_string(), detail.to_string());
    };

    let tool = if let Some(t) = input[&protocol.tool_name_field].as_str() {
        t
    } else {
        eprintln!(
            "[agentpact] warning: payload missing '{}' field, defaulting to unknown",
            protocol.tool_name_field
        );
        "unknown"
    };

    let mapping = protocol.tool_mappings.iter().find(|m| m.tool_name == tool);

    let action = mapping.map_or(protocol.default_action.as_str(), |m| m.action.as_str());

    let detail = extract_detail(protocol, mapping, input, tool);

    (action.to_string(), detail)
}

fn extract_detail(
    protocol: &HookProtocol,
    mapping: Option<&ToolMapping>,
    input: &serde_json::Value,
    tool: &str,
) -> String {
    for field in &protocol.detail_fields {
        let value = &input[field];
        if let Some(s) = value.as_str() {
            return s.to_string();
        }
        if value.is_object() {
            if let Some(key) = mapping.and_then(|m| m.detail_key.as_deref())
                && let Some(s) = value[key].as_str()
            {
                return s.to_string();
            }
            return value.to_string();
        }
    }
    tool.to_string()
}
