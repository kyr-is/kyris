// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
// ── MCP tool-deny filters ────────────────────────────────────────────────
//
// These apply the policy's per-(server, tool) DENY entries to an agent's config
// so the model is steered away from denied MCP tools *upfront*. This is
// SUPPLEMENTARY, not the enforcement boundary: every MCP `tools/call` is already
// mediated at runtime — stdio servers through the `kyris-mcp wrap` (which checks
// agentpactd) and HTTP servers through kyrisd's `/mcp/{name}/` routing
// (`daemon::mcp_routing::policy::check_permission`). So tool denial is enforced
// for ALL agents regardless of these filters; the filters only spare the agent a
// wasted round-trip on a tool it will be denied anyway.
//
// They are applied per agent according to what its config can natively express:
//   - codex   → `disabled_tools` per `[mcp_servers.<name>]`  (apply_toml_tool_filters)
//   - gemini  → `excludeTools` per `mcpServers.<name>`        (apply_json_tool_filters)
//   - claude  → global `permissions.deny` via `mcp__<server>__<tool>` matchers
//               (apply_claude_mcp_tool_denies) — claude has no per-server field
//   - cline / opencode → no native per-server tool-denylist field; they rely on
//               the runtime wrap/routing backstop above (documented at their
//               `configure_tool_surface`).

pub fn apply_toml_tool_filters(config: &mut toml::Value) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    if filters.is_empty() {
        return false;
    }

    let Some(servers) = config
        .as_table_mut()
        .and_then(|t| t.get_mut("mcp_servers"))
        .and_then(toml::Value::as_table_mut)
    else {
        return false;
    };

    let mut changed = false;
    for (server_name, denied_tools) in &filters {
        let Some(server) = servers
            .get_mut(server_name)
            .and_then(toml::Value::as_table_mut)
        else {
            continue;
        };
        let new_val = toml::Value::Array(
            denied_tools
                .iter()
                .map(|t| toml::Value::String(t.clone()))
                .collect(),
        );
        if server.get("disabled_tools") != Some(&new_val) {
            server.insert("disabled_tools".to_string(), new_val);
            changed = true;
        }
    }
    changed
}

pub fn apply_json_tool_filters(config: &mut serde_json::Value, servers_path: &[&str]) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    if filters.is_empty() {
        return false;
    }

    let mut cursor = config.as_object_mut();
    for key in servers_path {
        cursor = cursor
            .and_then(|obj| obj.get_mut(*key))
            .and_then(|v| v.as_object_mut());
    }
    let Some(servers) = cursor else {
        return false;
    };

    let mut changed = false;
    for (server_name, denied_tools) in &filters {
        let Some(server) = servers.get_mut(server_name).and_then(|v| v.as_object_mut()) else {
            continue;
        };
        let new_val: serde_json::Value = denied_tools.clone().into();
        if server.get("excludeTools") != Some(&new_val) {
            server.insert("excludeTools".to_string(), new_val);
            changed = true;
        }
    }
    changed
}

/// Claude has no per-MCP-server tool-denylist field, but it CAN deny individual
/// MCP tools via the documented global `permissions.deny` matcher
/// `mcp__<server>__<tool>`. Add a deny entry for every policy-denied tool on a
/// PRESENT server (matching the gemini/codex behavior of only touching servers
/// that exist). The deny entries live in `settings.json` while the servers live
/// in `~/.claude.json`/`.mcp.json`, so the caller supplies the present-server
/// names (from `mcp_server_names_from_agent`) rather than this function reading
/// them out of `settings`. Idempotent: existing entries are preserved and
/// duplicates are not added. ADD-ONLY by design, unlike the codex/gemini
/// filters which replace their dedicated per-server fields: `permissions.deny`
/// is shared with user-authored rules, so kyris never removes entries (a
/// policy-dropped deny lingers until `kyris agent disconnect` restores the file —
/// supplementary steering only; runtime enforcement is the wrap/routing).
/// Returns whether `settings` changed.
pub fn apply_claude_mcp_tool_denies(
    settings: &mut serde_json::Value,
    present_servers: &[String],
) -> bool {
    let Ok(filters) = crate::compile_policy::compile_mcp_tool_filters(None) else {
        return false;
    };
    add_mcp_tool_denies(settings, &filters, present_servers)
}

/// Pure core of [`apply_claude_mcp_tool_denies`], split out so it can be tested
/// with synthetic filters (the public entry reads the policy from disk).
pub(super) fn add_mcp_tool_denies(
    settings: &mut serde_json::Value,
    filters: &std::collections::HashMap<String, Vec<String>>,
    present_servers: &[String],
) -> bool {
    if filters.is_empty() {
        return false;
    }

    let present: std::collections::BTreeSet<&str> =
        present_servers.iter().map(String::as_str).collect();

    let mut wanted: Vec<String> = Vec::new();
    for (server, tools) in filters {
        if present.contains(server.as_str()) {
            for tool in tools {
                wanted.push(format!("mcp__{server}__{tool}"));
            }
        }
    }
    if wanted.is_empty() {
        return false;
    }

    let Some(root) = settings.as_object_mut() else {
        return false;
    };
    let permissions = root
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}));
    // Don't clobber a non-object `permissions` the user may have set.
    let Some(permissions) = permissions.as_object_mut() else {
        return false;
    };
    let deny = permissions
        .entry("deny")
        .or_insert_with(|| serde_json::json!([]));
    let Some(deny_arr) = deny.as_array_mut() else {
        return false;
    };

    let existing: std::collections::BTreeSet<String> = deny_arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let mut changed = false;
    for entry in wanted {
        if !existing.contains(&entry) {
            deny_arr.push(serde_json::Value::String(entry));
            changed = true;
        }
    }
    changed
}
