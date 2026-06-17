// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! MCP server config rewriting (route stdio servers through `kyris-mcp wrap`
//! and HTTP servers through kyrisd's `/mcp/` routing), the upstream registry in
//! `kyrisd.yaml`, and the server-name discovery/drift detectors that read an
//! agent's MCP config locations.
use super::registry;
use crate::config_writer::WellFormedJsonValidator;
use crate::integration::{read_json_value, write_json_value};

#[derive(Debug, Clone, Default)]
pub struct McpRewriteResult {
    pub changed: bool,
    pub http_rewrites: Vec<(String, String)>,
}

impl McpRewriteResult {
    fn unchanged() -> Self {
        Self::default()
    }
}

/// Walk one MCP config location and collect the names of servers matching the
/// per-format predicates. Missing file / missing path → empty (clean no-op).
fn mcp_server_names_at(
    location: &registry::McpConfigLocation,
    json_keep: &dyn Fn(&serde_json::Value) -> bool,
    toml_keep: &dyn Fn(&toml::Value) -> bool,
) -> Vec<String> {
    match &location.format {
        registry::McpConfigFormat::Json { servers_path } => {
            let Ok(val) = crate::integration::read_json_value(&location.path) else {
                return Vec::new();
            };
            let mut cur = &val;
            for key in servers_path {
                match cur.get(key) {
                    Some(v) => cur = v,
                    None => return Vec::new(),
                }
            }
            cur.as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(_, server)| json_keep(server))
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
        registry::McpConfigFormat::Toml { servers_key } => {
            let Ok(val) = crate::integration::read_toml_value(&location.path) else {
                return Vec::new();
            };
            val.get(servers_key)
                .and_then(toml::Value::as_table)
                .map(|t| {
                    t.iter()
                        .filter(|(_, server)| toml_keep(server))
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
    }
}

/// Union of matching server names across ALL of the agent's MCP config
/// locations, sorted and deduped (the same name can appear in several scopes).
fn mcp_server_names_matching(
    agent: &dyn registry::AgentDescriptor,
    json_keep: &dyn Fn(&serde_json::Value) -> bool,
    toml_keep: &dyn Fn(&toml::Value) -> bool,
) -> Vec<String> {
    let mut names: Vec<String> = agent
        .mcp_configs()
        .iter()
        .flat_map(|location| mcp_server_names_at(location, json_keep, toml_keep))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Collect the MCP server names currently registered in any of the agent's
/// config locations.
///
/// Called at the start of tool-surface undo, before `restore_manifest_entry`
/// restores the file(s) to their pre-kyris state, so we can identify which
/// upstream entries to remove from `kyrisd.yaml`.
pub fn mcp_server_names_from_agent(agent: &dyn registry::AgentDescriptor) -> Vec<String> {
    mcp_server_names_matching(agent, &|_| true, &|_| true)
}

/// Names of MCP servers in the agent's config that ARE routed through kyris —
/// a stdio server wrapped by `kyris-mcp`, or an HTTP server whose `url` points
/// at kyrisd's `/mcp/` routing. The hook engine uses this to recognize an
/// unmapped hook tool name as an MCP tool that is already governed at the TOOL
/// surface, so the no-backstop deny posture (G1) does not break wrapped MCP
/// servers. Servers NOT in this list get no such blessing — an unwrapped
/// server's tools are ungoverned everywhere and deny is the honest outcome.
pub fn kyris_routed_mcp_server_names(agent: &dyn registry::AgentDescriptor) -> Vec<String> {
    let kyrisd_mcp_prefix = crate::state::load_config()
        .ok()
        .map(|c| format!("{}/mcp/", c.base_url()));
    let url_is_routed = move |url: Option<&str>| {
        url.zip(kyrisd_mcp_prefix.as_deref())
            .is_some_and(|(u, prefix)| u.starts_with(prefix))
    };
    mcp_server_names_matching(
        agent,
        &|server| {
            let fields = json_mcp_fields(server);
            !json_mcp_server_unwrapped(server)
                && (fields.get("command").is_some()
                    || url_is_routed(fields.get("url").and_then(serde_json::Value::as_str)))
        },
        &|server| {
            !toml_mcp_server_unwrapped(server)
                && (server.get("command").is_some()
                    || url_is_routed(server.get("url").and_then(toml::Value::as_str)))
        },
    )
}

/// Names of MCP servers in the agent's config that are NOT yet routed through
/// kyris — a stdio server whose `command` isn't `kyris-mcp`. Surfaces config
/// drift (e.g. an MCP server added *after* `kyris agent setup`, which the
/// configure-time rewrite never saw) so `kyris status` can prompt a reconcile.
/// URL/HTTP servers are out of scope here.
pub fn unwrapped_mcp_server_names(agent: &dyn registry::AgentDescriptor) -> Vec<String> {
    mcp_server_names_matching(
        agent,
        &json_mcp_server_unwrapped,
        &toml_mcp_server_unwrapped,
    )
}

/// A stdio MCP server is "unwrapped" when it has a `command` that isn't
/// `kyris-mcp` (string form or array-first form). Servers with no `command`
/// (URL/HTTP) are not flagged. Reads through `json_mcp_fields` so cline's
/// nested `transport.command` is detected, not just the flat form.
pub(super) fn json_mcp_server_unwrapped(server: &serde_json::Value) -> bool {
    match json_mcp_fields(server).get("command") {
        Some(serde_json::Value::String(cmd)) => cmd != "kyris-mcp",
        Some(serde_json::Value::Array(cmd)) => {
            cmd.first().and_then(serde_json::Value::as_str) != Some("kyris-mcp")
        }
        _ => false,
    }
}

pub(super) fn toml_mcp_server_unwrapped(server: &toml::Value) -> bool {
    match server.get("command").and_then(toml::Value::as_str) {
        Some(cmd) => cmd != "kyris-mcp",
        None => false,
    }
}

/// Remove named MCP upstream entries from `kyrisd.yaml`.
///
/// Called during agent tool-surface undo to reverse the
/// `upsert_mcp_upstreams` call that happened during tool-surface setup. Server
/// names not present in `kyrisd.yaml` are silently skipped (idempotent).
pub fn remove_mcp_upstreams(names: &[String]) -> Result<(), String> {
    if names.is_empty() {
        return Ok(());
    }
    let Ok(mut config) = crate::state::load_config() else {
        return Ok(()); // config absent — nothing to clean
    };
    let before = config.mcp.servers.len();
    config.mcp.servers.retain(|s| !names.contains(&s.name));
    if config.mcp.servers.len() == before {
        return Ok(()); // no matching entries found
    }
    if config.mcp.servers.is_empty() {
        config.mcp.enabled = false;
    }
    crate::state::save_config(&config)
}

/// Shared configure flow for agents whose MCP servers live in JSON config(s)
/// (claude, gemini, cline, opencode): route every MCP server through kyris
/// (`rewrite_json_mcp_servers`) at EVERY declared location, apply the agent's
/// optional extra tool filter (`apply_extra_tool_filters`), write back only
/// files that changed, and register any HTTP upstreams. Several locations may
/// share one FILE (Claude Code's user scope and per-project local scopes both
/// live in `~/.claude.json`), so locations are grouped by path and each file
/// gets one read-modify-write. Codex (TOML) keeps its own
/// `configure_tool_surface`. `read_json_value` returns `{}` for a missing
/// file, so a not-yet-created config is a clean no-op (no write).
pub fn configure_json_mcp_tool_surface(
    agent: &dyn registry::AgentDescriptor,
    base_url: &str,
    inbound_key: &str,
) -> Result<Vec<String>, String> {
    let component = format!("{}:tool", agent.id());
    let mut changes = Vec::new();
    let mut all_http_rewrites: Vec<(String, String)> = Vec::new();

    // Group JSON locations by file, preserving declaration order.
    let mut files: Vec<(std::path::PathBuf, Vec<Vec<String>>)> = Vec::new();
    for location in agent.mcp_configs() {
        let registry::McpConfigFormat::Json { servers_path } = location.format else {
            continue;
        };
        match files.iter_mut().find(|(p, _)| *p == location.path) {
            Some((_, paths)) => paths.push(servers_path),
            None => files.push((location.path, vec![servers_path])),
        }
    }

    // Fail fast on a cross-scope upstream conflict BEFORE any rewrite:
    // kyrisd.yaml keys upstreams by bare server name, so the same HTTP server
    // name in two scopes with different upstream URLs would silently route the
    // agent's effective server to whichever scope was processed last.
    reject_conflicting_http_upstreams(agent.id(), &files, base_url)?;

    for (path, server_paths) in files {
        let mut settings = read_json_value(&path)?;
        let mut file_changed = false;
        for servers_path in &server_paths {
            let mcp_result = rewrite_json_mcp_servers(
                &mut settings,
                servers_path,
                base_url,
                inbound_key,
                agent.canonical_id(),
            );
            file_changed |= mcp_result.changed;
            all_http_rewrites.extend(mcp_result.http_rewrites);
        }
        let extra_changed = agent.apply_extra_tool_filters(&mut settings);

        if file_changed || extra_changed {
            write_json_value(&path, &settings, &component, &WellFormedJsonValidator)?;
            if file_changed {
                changes.push(format!("rewrote MCP servers in {}", path.display()));
            }
            if extra_changed {
                changes.push(format!("applied MCP tool policy in {}", path.display()));
            }
        }
    }

    if !all_http_rewrites.is_empty() {
        upsert_mcp_upstreams(&all_http_rewrites)?;
        changes.push("registered MCP upstream(s) in kyrisd.yaml".to_string());
    }
    Ok(changes)
}

/// Error when the same HTTP MCP server NAME appears in several scopes with
/// DIFFERENT (not-yet-routed) upstream URLs. Already-routed entries (url at
/// kyrisd's `/mcp/` prefix) are skipped — their original upstream lives in
/// `kyrisd.yaml` and a same-name unrouted twin will simply update it.
fn reject_conflicting_http_upstreams(
    agent_id: &str,
    files: &[(std::path::PathBuf, Vec<Vec<String>>)],
    base_url: &str,
) -> Result<(), String> {
    let routed_prefix = format!("{base_url}/mcp/");
    let mut upstreams: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (path, server_paths) in files {
        let Ok(value) = read_json_value(path) else {
            continue;
        };
        for servers_path in server_paths {
            let mut cur = Some(&value);
            for key in servers_path {
                cur = cur.and_then(|v| v.get(key));
            }
            let Some(servers) = cur.and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, server) in servers {
                // Read through cline's transport nesting (no-op for flat shapes).
                let Some(url) = json_mcp_fields(server).get("url").and_then(|v| v.as_str()) else {
                    continue;
                };
                if url.starts_with(&routed_prefix) {
                    continue;
                }
                if let Some(existing) = upstreams.get(name) {
                    if existing != url {
                        return Err(format!(
                            "MCP server '{name}' appears in multiple {agent_id} config scopes \
                             with different upstream URLs ({existing} vs {url}); kyrisd routes \
                             by server name, so one scope would silently reach the other's \
                             upstream. Rename one of the servers, then re-run \
                             `kyris agent setup {agent_id}`."
                        ));
                    }
                } else {
                    upstreams.insert(name.clone(), url.to_string());
                }
            }
        }
    }
    Ok(())
}

/// Shared tool-surface undo for JSON-MCP agents: remove the MCP upstreams from
/// `kyrisd.yaml` (while the server names are still readable from the agent
/// config), then restore every file the tool-surface setup RECORDED in the
/// manifest. Manifest-driven, not enumeration-driven: some locations are
/// discovered relative to the setup-time cwd (Claude Code's `.mcp.json`), so
/// an undo run from elsewhere would never re-enumerate them — the manifest is
/// the only complete record of what setup touched. (The upstream-name
/// collection above is still enumeration-based and therefore best-effort for
/// such locations; a stale `kyrisd.yaml` upstream entry is inert, unlike a
/// stranded wrap.)
pub fn undo_json_mcp_tool_surface(agent: &dyn registry::AgentDescriptor) -> Result<(), String> {
    let mcp_names = mcp_server_names_from_agent(agent);
    remove_mcp_upstreams(&mcp_names)?;
    let component = format!("{}:tool", agent.id());
    for path in crate::state::restore_manifest_component(&component)? {
        println!("Reverted {}", path.display());
    }
    Ok(())
}

pub fn upsert_mcp_upstreams(rewrites: &[(String, String)]) -> Result<bool, String> {
    if rewrites.is_empty() {
        return Ok(false);
    }
    let mut config = crate::state::load_or_init_config()?;
    let mut changed = false;
    for (name, upstream) in rewrites {
        let exists = config.mcp.servers.iter().any(|s| s.name == *name);
        if exists {
            let entry = config
                .mcp
                .servers
                .iter_mut()
                .find(|s| s.name == *name)
                .expect("just confirmed exists");
            if entry.upstream != *upstream {
                entry.upstream.clone_from(upstream);
                changed = true;
            }
        } else {
            config
                .mcp
                .servers
                .push(kyris_core::config::McpServerConfig {
                    name: name.clone(),
                    upstream: upstream.clone(),
                    working_dir: None,
                });
            changed = true;
        }
    }
    if changed {
        if !config.mcp.enabled {
            config.mcp.enabled = true;
        }
        crate::state::save_config(&config)?;
    }
    Ok(changed)
}

/// Ensure a wrap-args list carries `--agent <agent_id>` among the leading
/// flags (after `wrap`/`--server`), inserting it when absent — both for
/// freshly wrapped servers and as an idempotent upgrade of wraps written
/// before the flag existed. Returns whether the list changed. Generic over the
/// config value type via the to/from-string closures (`serde_json` / `toml`).
fn ensure_wrap_agent_flag<V>(
    args: &mut Vec<V>,
    agent_id: &str,
    as_str: impl Fn(&V) -> Option<&str>,
    from_str: impl Fn(&str) -> V,
) -> bool {
    // Skip the leading "wrap" and any flag pairs to find the insertion point.
    let mut i = usize::from(args.first().and_then(&as_str) == Some("wrap"));
    while i < args.len() {
        match as_str(&args[i]) {
            Some("--agent") => return false,
            Some("--server") => i += 2,
            _ => break,
        }
    }
    let insert_at = i.min(args.len());
    args.insert(insert_at, from_str(agent_id));
    args.insert(insert_at, from_str("--agent"));
    true
}

pub fn rewrite_codex_mcp_servers(
    config: &mut toml::Value,
    base_url: &str,
    inbound_key: &str,
    agent_id: &str,
) -> McpRewriteResult {
    let Some(root) = config.as_table_mut() else {
        return McpRewriteResult::unchanged();
    };
    let Some(servers) = root
        .get_mut("mcp_servers")
        .and_then(toml::Value::as_table_mut)
    else {
        return McpRewriteResult::unchanged();
    };

    let mut changed = false;
    let mut http_rewrites = Vec::new();
    for (name, server_value) in servers {
        let Some(server) = server_value.as_table_mut() else {
            continue;
        };

        if let Some(command) = server.get("command").and_then(toml::Value::as_str) {
            if command == "kyris-mcp" {
                // Already wrapped — idempotent upgrade: stamp the agent flag
                // onto wraps written before it existed.
                if let Some(args) = server.get_mut("args").and_then(toml::Value::as_array_mut)
                    && ensure_wrap_agent_flag(args, agent_id, toml::Value::as_str, |s| {
                        toml::Value::String(s.to_string())
                    })
                {
                    changed = true;
                }
                continue;
            }

            let original_args = server
                .get("args")
                .and_then(toml::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut wrapped_args = vec![
                toml::Value::String("wrap".to_string()),
                toml::Value::String("--server".to_string()),
                toml::Value::String(name.clone()),
                toml::Value::String("--agent".to_string()),
                toml::Value::String(agent_id.to_string()),
                toml::Value::String(command.to_string()),
            ];
            wrapped_args.extend(original_args);

            server.insert(
                "command".to_string(),
                toml::Value::String("kyris-mcp".to_string()),
            );
            server.insert("args".to_string(), toml::Value::Array(wrapped_args));
            changed = true;
            continue;
        }

        if let Some(url) = server.get("url").and_then(toml::Value::as_str) {
            let routed_url = format!("{base_url}/mcp/{name}/");
            if url != routed_url {
                let original_url = url.to_string();
                server.insert("url".to_string(), toml::Value::String(routed_url));
                changed = true;
                http_rewrites.push((name.clone(), original_url));
            }

            let headers = server
                .entry("http_headers".to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if !headers.is_table() {
                *headers = toml::Value::Table(toml::Table::new());
            }
            let auth_value = format!("Bearer {inbound_key}");
            let headers_table = headers.as_table_mut().expect("converted to TOML table");
            for (header, value) in [
                ("Authorization", auth_value.as_str()),
                // Attribution for kyrisd's /mcp/ routing (tool-surface live
                // evidence) — the wrap's `--agent` twin for HTTP servers.
                ("x-kyris-agent-id", agent_id),
            ] {
                if headers_table.get(header).and_then(toml::Value::as_str) != Some(value) {
                    headers_table
                        .insert(header.to_string(), toml::Value::String(value.to_string()));
                    changed = true;
                }
            }
        }
    }

    McpRewriteResult {
        changed,
        http_rewrites,
    }
}

/// The sub-value of a JSON MCP server entry that carries `command`/`args`/`url`.
/// Cline's `cline mcp add` wizard nests these under a `transport` object
/// (`{transport:{type:"stdio",command,args}}`); every other agent (and cline's
/// legacy flat form) keeps them at the top level. Returns the `transport`
/// object when present, else the server itself — so the rewrite, probes, and
/// drift detectors all see the real command/url regardless of shape. A no-op
/// for agents that never use `transport`.
pub(crate) fn json_mcp_fields(server: &serde_json::Value) -> &serde_json::Value {
    server
        .get("transport")
        .filter(|t| t.is_object())
        .unwrap_or(server)
}

#[allow(clippy::too_many_lines)]
pub fn rewrite_json_mcp_servers(
    config: &mut serde_json::Value,
    servers_path: &[String],
    base_url: &str,
    inbound_key: &str,
    agent_id: &str,
) -> McpRewriteResult {
    let mut cursor = config.as_object_mut();
    for key in servers_path {
        cursor = cursor
            .and_then(|obj| obj.get_mut(key))
            .and_then(|v| v.as_object_mut());
    }
    let Some(servers) = cursor else {
        return McpRewriteResult::unchanged();
    };

    let ensure_json_agent_flag = |args: &mut Vec<serde_json::Value>| {
        ensure_wrap_agent_flag(args, agent_id, serde_json::Value::as_str, |s| {
            serde_json::json!(s)
        })
    };

    let mut changed = false;
    let mut http_rewrites = Vec::new();
    for (name, server_value) in servers.iter_mut() {
        let Some(server) = server_value.as_object_mut() else {
            continue;
        };
        // Operate on the `transport` sub-object for cline's nested shape; the
        // top-level map otherwise (see `json_mcp_fields`).
        let server = if server
            .get("transport")
            .is_some_and(serde_json::Value::is_object)
        {
            server
                .get_mut("transport")
                .and_then(serde_json::Value::as_object_mut)
                .expect("just checked it is an object")
        } else {
            server
        };

        if let Some(command) = server
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if command == "kyris-mcp" {
                // Already wrapped — idempotent upgrade: stamp the agent flag
                // onto wraps written before it existed.
                if let Some(args) = server.get_mut("args").and_then(|v| v.as_array_mut())
                    && ensure_json_agent_flag(args)
                {
                    changed = true;
                }
                continue;
            }

            let original_args = server
                .get("args")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut wrapped_args = vec![
                serde_json::json!("wrap"),
                serde_json::json!("--server"),
                serde_json::json!(name),
                serde_json::json!("--agent"),
                serde_json::json!(agent_id),
                serde_json::json!(command),
            ];
            wrapped_args.extend(original_args);

            server.insert("command".to_string(), serde_json::json!("kyris-mcp"));
            server.insert("args".to_string(), serde_json::Value::Array(wrapped_args));
            changed = true;
            continue;
        }

        if let Some(cmd_array) = server.get("command").and_then(|v| v.as_array()).cloned() {
            let first = cmd_array
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if first == "kyris-mcp" {
                // Array-command wrap: the flags live in the command list itself
                // (after "kyris-mcp"); upgrade in place.
                if let Some(cmd) = server.get_mut("command").and_then(|v| v.as_array_mut()) {
                    let mut tail: Vec<serde_json::Value> = cmd.drain(1..).collect();
                    let tail_changed = ensure_json_agent_flag(&mut tail);
                    cmd.extend(tail);
                    if tail_changed {
                        changed = true;
                    }
                }
                continue;
            }

            let mut wrapped = vec![
                serde_json::json!("kyris-mcp"),
                serde_json::json!("wrap"),
                serde_json::json!("--server"),
                serde_json::json!(name),
                serde_json::json!("--agent"),
                serde_json::json!(agent_id),
            ];
            wrapped.extend(cmd_array);

            server.insert("command".to_string(), serde_json::Value::Array(wrapped));
            changed = true;
            continue;
        }

        if let Some(url) = server.get("url").and_then(|v| v.as_str()).map(String::from) {
            let routed_url = format!("{base_url}/mcp/{name}/");
            if url != routed_url {
                server.insert("url".to_string(), serde_json::json!(routed_url));
                changed = true;
                http_rewrites.push((name.clone(), url));
            }

            let headers = server
                .entry("headers")
                .or_insert_with(|| serde_json::json!({}));
            if !headers.is_object() {
                *headers = serde_json::json!({});
            }
            let auth_value = format!("Bearer {inbound_key}");
            let headers_obj = headers.as_object_mut().expect("converted to JSON object");
            for (header, value) in [
                ("Authorization", auth_value.as_str()),
                // Attribution for kyrisd's /mcp/ routing (tool-surface live
                // evidence) — the wrap's `--agent` twin for HTTP servers.
                ("x-kyris-agent-id", agent_id),
            ] {
                if headers_obj.get(header).and_then(|v| v.as_str()) != Some(value) {
                    headers_obj.insert(header.to_string(), serde_json::json!(value));
                    changed = true;
                }
            }
        }
    }

    McpRewriteResult {
        changed,
        http_rewrites,
    }
}
