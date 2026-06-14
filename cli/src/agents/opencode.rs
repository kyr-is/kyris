// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

use crate::config_writer::WellFormedJsonValidator;
use crate::integration::{
    remove_json_string_if_equals, set_json_string_path, set_json_value_path, write_json_value,
};
use crate::state::restore_manifest_entry_component;

use super::probe::{ProbeResult, fingerprint, not_detected, probe_config_rewrite_burn_control};
use super::registry::{
    AgentDescriptor, AgentIntegrationPlan, AllowResponse, AttributionMechanism,
    BurnControlMechanism, ExecutionMechanism, HookProtocol, HookRuntime, HookTimeoutPosture,
    McpConfigFormat, McpConfigLocation, McpToolNaming, SurfaceIntegration, ToolMapping,
    ToolMechanism, which_exists,
};

pub struct OpenCode;

pub fn opencode_config_path() -> Result<PathBuf, String> {
    // Target the highest-precedence config opencode would actually load, so an
    // existing higher one cannot shadow kyris's routing (which would make the
    // probe over-claim). opencode precedence: a project file (walked up from
    // cwd, deeper dir wins) overrides the global config, and within one dir
    // `opencode.jsonc` wins over `opencode.json` (config.ts merge order).
    let mut current = std::env::current_dir().ok();
    while let Some(dir) = current {
        for name in ["opencode.jsonc", "opencode.json"] {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        current = dir.parent().map(std::path::Path::to_path_buf);
    }
    let global = crate::integration::home_dir()?
        .join(".config")
        .join("opencode");
    let global_jsonc = global.join("opencode.jsonc");
    if global_jsonc.exists() {
        return Ok(global_jsonc);
    }
    Ok(global.join("opencode.json"))
}

pub fn opencode_config_exists() -> bool {
    opencode_config_path().is_ok_and(|path| path.exists())
}

/// True iff the config is a PROJECT file (not the global `~/.config/opencode`),
/// so kyris is about to write a machine-local secret into a possibly-committed
/// repo file — warned at configure time.
fn opencode_config_is_project(path: &std::path::Path) -> bool {
    crate::integration::home_dir()
        .map(|h| h.join(".config").join("opencode"))
        .is_ok_and(|global| path.parent() != Some(global.as_path()))
}

/// Read an opencode config, tolerating JSONC syntax (`//` and `/* */` comments
/// and trailing commas) which `serde_json` would otherwise reject. JSON strings
/// are preserved so JSONC tokens inside a value are not misread.
fn read_opencode_config(path: &std::path::Path) -> Result<serde_json::Value, String> {
    if !path.exists() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let tolerant = strip_trailing_commas(&strip_jsonc_comments(&raw));
    serde_json::from_str(&tolerant).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// Gate every MUTATING configure path: kyris's shared JSON read/write
/// machinery (plugin registration, MCP wrap) cannot round-trip JSONC syntax
/// without dropping it and losing undo fidelity, so refuse loudly rather than
/// silently mangle it. A file that parses as STRICT JSON (a comment-free
/// `.jsonc` is fine — valid JSON, just the extension) round-trips cleanly.
/// Probing stays tolerant (it never writes), so status still reports such a
/// config. A genuinely-malformed file (neither strict nor tolerant) is left to
/// the downstream reader's own error.
fn require_writable_opencode_config(path: &std::path::Path) -> Result<(), String> {
    if !path.exists() || crate::integration::read_json_value(path).is_ok() {
        return Ok(());
    }
    if read_opencode_config(path).is_ok() {
        return Err(format!(
            "{} uses JSONC syntax (comments and/or trailing commas), which kyris cannot \
             manage without losing it. Convert it to standard JSON (rename to opencode.json \
             or remove the JSONC syntax), then re-run `kyris agent setup opencode`.",
            path.display()
        ));
    }
    Ok(())
}

fn strip_trailing_commas(src: &str) -> String {
    // A trailing comma is a `,` (outside a string) whose next non-whitespace
    // char is `}` or `]`. Buffer the comma + following whitespace, then decide.
    let mut out = String::with_capacity(src.len());
    let (mut in_str, mut escaped, mut pending_comma) = (false, false, false);
    let mut pending_ws = String::new();
    for c in src.chars() {
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if pending_comma {
            if c.is_whitespace() {
                pending_ws.push(c);
                continue;
            }
            if c == '}' || c == ']' {
                out.push_str(&pending_ws); // drop the comma, keep layout + closer
            } else {
                out.push(',');
                out.push_str(&pending_ws);
                if c == '"' {
                    in_str = true;
                }
            }
            out.push(c);
            pending_comma = false;
            pending_ws.clear();
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push('"');
            }
            ',' => pending_comma = true,
            _ => out.push(c),
        }
    }
    if pending_comma {
        out.push(',');
        out.push_str(&pending_ws);
    }
    out
}

fn strip_jsonc_comments(src: &str) -> String {
    // Iterate over CHARS (not bytes) — every structural delimiter (" / * \ \n)
    // is ASCII, but a `b as char` byte cast would mangle any multi-byte UTF-8
    // codepoint in a value. `peekable` lets us look one char ahead for the
    // `//` / `/*` / `*/` sequences.
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let (mut in_str, mut in_line, mut in_block, mut escaped) = (false, false, false, false);
    while let Some(c) = chars.next() {
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push('\n');
            }
            continue;
        }
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push('"');
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                in_line = true;
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

/// Set `permission.{bash,edit,write} = "allow"` so opencode does not re-prompt
/// for the mutating tools kyris already governs through the plugin, WITHOUT the
/// old blunt top-level `permission: "allow"` that also defeated doom-loop
/// detection and the webfetch/question/plan-mode native gates (Finding 16).
/// The user's other permission rules are preserved; a bare-string default
/// (e.g. `"ask"`) is normalized to `{"*": <action>}` so it still applies to
/// ungoverned tools — except a lone `"allow"` / `{"*":"allow"}` (kyris's old
/// value), which is dropped so those native gates return. Returns whether
/// `config` changed.
fn apply_opencode_governed_permissions(config: &mut serde_json::Value) -> bool {
    const GOVERNED: [&str; 3] = ["bash", "edit", "write"];
    let mut perm: serde_json::Map<String, serde_json::Value> = match config.get("permission") {
        Some(serde_json::Value::Object(m)) => {
            let mut m = m.clone();
            // Drop ONLY a lone allow-all (kyris's prior blunt value); a user's
            // `{"*":"allow", x:"deny"}` is left intact.
            if m.len() == 1 && m.get("*").and_then(|v| v.as_str()) == Some("allow") {
                m.clear();
            }
            m
        }
        Some(serde_json::Value::String(s)) if s != "allow" => {
            let mut m = serde_json::Map::new();
            m.insert("*".to_string(), serde_json::json!(s));
            m
        }
        // absent, or a bare "allow" (drop it), or a non-object/non-string → start fresh
        _ => serde_json::Map::new(),
    };
    for tool in GOVERNED {
        perm.insert(tool.to_string(), serde_json::json!("allow"));
    }
    // set_json_value_path is itself no-change-aware, so a stable reconcile
    // (same keys, same order via the preserve-order map) writes nothing.
    set_json_value_path(config, &["permission"], serde_json::Value::Object(perm))
}

/// The kyris governance plugin lives next to the config that registers it, so the
/// path in the `plugin` array resolves regardless of where opencode's config is.
fn opencode_plugin_path() -> Result<PathBuf, String> {
    let config = opencode_config_path()?;
    let dir = config
        .parent()
        .ok_or_else(|| format!("cannot resolve parent of {}", config.display()))?;
    Ok(dir.join("kyris-governance.js"))
}

impl AgentDescriptor for OpenCode {
    fn id(&self) -> &'static str {
        "opencode"
    }
    fn is_installed(&self) -> bool {
        which_exists("opencode") || opencode_config_exists()
    }
    fn probe(&self) -> ProbeResult {
        use super::profile::SurfaceState;
        let detected = opencode_config_exists() || which_exists("opencode");
        if !detected {
            return not_detected();
        }

        let config_path = opencode_config_path().ok();
        // Live-hook adapter: the kyris governance plugin is registered in the
        // config's `plugin` array AND present on disk.
        let plugin_path = opencode_plugin_path().ok();
        let has_live_hook = config_path.as_deref().is_some_and(|p| {
            read_opencode_config(p).is_ok_and(|v| {
                v.get("plugin")
                    .and_then(|a| a.as_array())
                    .is_some_and(|items| {
                        items
                            .iter()
                            .filter_map(|i| i.as_str())
                            .any(|s| s.contains("kyris-governance"))
                    })
            })
        }) && plugin_path.as_deref().is_some_and(std::path::Path::exists);
        let execution = if has_live_hook {
            SurfaceState::adapted(ExecutionMechanism::LiveHookAdapter)
        } else {
            SurfaceState::none()
        };

        let (has_mcp_wrap, has_any_mcp_servers) = super::probe::mcp_locations_status(self);
        let tool = if has_mcp_wrap {
            SurfaceState::adapted(ToolMechanism::McpWrapping)
        } else if !has_any_mcp_servers {
            SurfaceState::not_applicable()
        } else {
            SurfaceState::none()
        };

        // Value-aware: a provider counts only when its baseURL equals the
        // kyrisd endpoint the rewrite would set — any other baseURL (a user's
        // own proxy, or a stale kyrisd address) is not kyris routing.
        let kyrisd_base = super::probe::kyrisd_base_url();
        let burn_control = probe_config_rewrite_burn_control(
            config_path.as_deref(),
            |v| {
                let Some(base) = kyrisd_base else {
                    return false;
                };
                let provider_routed = |name: &str, expected: &str| {
                    v.get("provider")
                        .and_then(|p| p.get(name))
                        .and_then(|a| a.get("options"))
                        .and_then(|o| o.get("baseURL"))
                        .and_then(|u| u.as_str())
                        == Some(expected)
                };
                let v1 = format!("{base}/v1");
                let v1beta = format!("{base}/v1beta");
                provider_routed("anthropic", &v1)
                    || provider_routed("openai", &v1)
                    || provider_routed("google", &v1beta)
            },
            "opencode",
            "ANTHROPIC_BASE_URL",
        );

        let mut managed_files = Vec::new();
        if let Some(path) = config_path.as_deref()
            && let Some(fp) = fingerprint(path)
        {
            managed_files.push(fp);
        }

        ProbeResult {
            detected,
            execution,
            tool,
            burn_control,
            managed_files,
        }
    }
    fn kyris_content_markers(&self) -> &'static [&'static str] {
        &["kyris-governance", "kyris-mcp"]
    }
    fn integration_plan(&self) -> AgentIntegrationPlan {
        super::capabilities::apply_declared_capabilities(
            self.canonical_id(),
            AgentIntegrationPlan {
                // opencode's plugin system (`tool.execute.before`) gives a real
                // live-hook adapter — the kyris governance plugin bridges every
                // tool call to `kyris hook check` → agentpactd, same as the
                // native-hook agents.
                execution: SurfaceIntegration::adapted(&[ExecutionMechanism::LiveHookAdapter]),
                tool: SurfaceIntegration::adapted(&[ToolMechanism::McpWrapping]),
                burn_control: SurfaceIntegration::adapted(&[BurnControlMechanism::ConfigRewrite]),
                attribution: &[
                    AttributionMechanism::KyrisPathShim,
                    AttributionMechanism::NativeHookPayload,
                    AttributionMechanism::ProcessLineage,
                ],
                agentpact_native_attribution: false,
            },
        )
    }
    fn mcp_configs(&self) -> Vec<McpConfigLocation> {
        opencode_config_path()
            .ok()
            .map(|path| McpConfigLocation {
                path,
                format: McpConfigFormat::Json {
                    servers_path: vec!["mcp".to_string()],
                },
            })
            .into_iter()
            .collect()
    }
    fn burn_control_config_paths(&self) -> Vec<PathBuf> {
        opencode_config_path().into_iter().collect()
    }
    fn configure_execution_surface(
        &self,
        _base_url: &str,
        _inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let path = opencode_config_path()?;
        require_writable_opencode_config(&path)?;
        let plugin_path = opencode_plugin_path()?;

        // Execution runs first among the surfaces, so emit the repo-secret
        // warning here once: a project config means a machine-local secret
        // lands in a possibly-committed repo file.
        let mut changes = Vec::new();
        if opencode_config_is_project(&path) {
            changes.push(format!(
                "warning: writing kyris routing into the project config {} — it carries a \
                 machine-local secret (x-kyris-inbound); do not commit it",
                path.display()
            ));
        }

        // Live-hook adapter: write + register the kyris governance plugin, which
        // bridges opencode's `tool.execute.before` to `kyris hook check` → agentpactd.
        changes.extend(super::configure::install_plugin_hook_adapter(
            self.id(),
            "opencode:execution",
            &plugin_path,
            &path,
        )?);

        // Suppress opencode's redundant NATIVE prompt for the tools kyris
        // governs, so the plugin (→ agentpactd) is the effective gate without a
        // double prompt. The plugin's `tool.execute.before` runs BEFORE each
        // tool's internal `ctx.ask`, so a kyris DENY already blocks the native
        // prompt; this only handles the ALLOW case (where the native ask would
        // otherwise still fire). Scoped to the governed mutating keys
        // ({bash, edit, write}) rather than the old blunt `permission: "allow"`,
        // which also disabled doom-loop detection and the webfetch/question/
        // mode-restriction prompts (review Finding 16).
        let mut config = read_opencode_config(&path)?;
        if apply_opencode_governed_permissions(&mut config) {
            write_json_value(
                &path,
                &config,
                "opencode:execution",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!(
                "allowed kyris-governed tools in {} (preserving other native gates)",
                path.display()
            ));
        }

        Ok(changes)
    }
    fn hook_protocol(&self) -> Option<HookProtocol> {
        Some(HookProtocol {
            tool_name_field: "tool_name".to_string(),
            detail_fields: vec!["tool_input".to_string()],
            tool_mappings: vec![
                ToolMapping {
                    tool_name: "bash".to_string(),
                    action: "execute".to_string(),
                    detail_key: Some("command".to_string()),
                },
                ToolMapping {
                    tool_name: "edit".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
                ToolMapping {
                    tool_name: "write".to_string(),
                    action: "write".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
                ToolMapping {
                    tool_name: "read".to_string(),
                    action: "read".to_string(),
                    detail_key: Some("filePath".to_string()),
                },
                // apply_patch is opencode's file-mutation tool on gpt-5-style
                // models (it REPLACES edit/write there — registry.ts usePatch);
                // its input is the full patch text in `patchText`. The hook
                // engine parses the envelope into per-file write/delete
                // decisions (drive_apply_patch). Previously unmapped → DENIED
                // for those models (review Finding 3).
                ToolMapping {
                    tool_name: "apply_patch".to_string(),
                    action: "apply_patch".to_string(),
                    detail_key: Some("patchText".to_string()),
                },
            ],
            // opencode-internal / read-only tools: skip the daemon (mirrors the
            // pass-through lists for the native-hook agents). Ids verified
            // against opencode 1.16.2 `Tool.define` calls (tool/*.ts) — with no
            // native backstop an unmapped tool is DENIED, so a stale name here
            // breaks that tool outright, not just un-governs it.
            pass_through_tools: [
                "glob",
                "grep",
                "todowrite",
                "task",
                "webfetch",
                "websearch",
                "skill",
                "lsp",
                "question",
                "plan_exit",
                "invalid",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            agent_owned_tools: Vec::new(),
            default_action: "call".to_string(),
            // The plugin reads `kyris hook check`'s EXIT CODE (0 allow / 2 deny),
            // not stdout, so the allow shape is the empty default.
            allow_response: AllowResponse::EmptyStdout,
            runtime: HookRuntime {
                // opencode has NO upstream plugin-hook timeout — the plugin's
                // own spawnSync bound (derived from this declaration) is the
                // effective deadline, matching the other agents' 600s.
                agent_hook_timeout_secs: 600,
                // On a spawn timeout the plugin throws (deny); on a missing
                // binary it returns (fail open) — but conservatively declared
                // FailOpen because opencode itself never blocks on hook errors.
                on_timeout: HookTimeoutPosture::FailOpen,
                // kyris itself sets `permission: "allow"` so the plugin is the
                // sole gate — nothing backstops a defer. A defer is a silent
                // allow → the engine denies instead (G1).
                native_backstop: false,
                allow_suppresses_agent_prompt: false,
            },
            // MCP tools surface as `sanitize(client) + "_" + sanitize(tool)`
            // (mcp/index.ts), per-character sanitize. Needed so the no-backstop
            // deny does not break wrap-governed MCP servers.
            permission_request_allow: None,
            mcp_tool_naming: Some(McpToolNaming {
                server_separator: "_".to_string(),
                collapse_sanitize_runs: false,
            }),
            // opencode's `tool.execute.before` plugin can only allow (return) or
            // deny (throw) — no per-call "ask" signal — and its permission
            // config is static per-tool, evaluated independently of the plugin.
            // (The `permission.ask` plugin hook is defined upstream but never
            // triggered.) So there is no native per-call ask channel; the kyris
            // popup is the only approval UX.
            native_ask: None,
        })
    }
    fn configure_burn_control_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        let path = opencode_config_path()?;
        require_writable_opencode_config(&path)?;
        let agent_id = self.canonical_id();
        let v1 = format!("{base_url}/v1");
        let v1beta = format!("{base_url}/v1beta");
        // Each provider's baseURL must carry the suffix its AI SDK provider expects
        // — opencode passes baseURL straight through and the SDK appends its own
        // path (anthropic/openai default `…/v1` then `/messages`,`/chat/completions`;
        // google default `…/v1beta` then `/models/{m}:generateContent`). A bare host
        // → the SDK hits `…/messages` etc. → kyrisd 404.
        let providers: [(&str, &str); 3] = [
            ("anthropic", v1.as_str()),
            ("openai", v1.as_str()),
            ("google", v1beta.as_str()),
        ];

        let mut config = read_opencode_config(&path)?;
        let mut config_changed = false;
        for (provider, provider_base_url) in providers {
            // Route through kyrisd.
            if set_json_string_path(
                &mut config,
                &["provider", provider, "options", "baseURL"],
                provider_base_url,
            ) {
                config_changed = true;
            }
            // Gate secret + agent-id ride in custom headers (the AI SDK merges them
            // alongside the resolved x-api-key — see opencode provider-options.ts).
            for (header, value) in [
                ("x-kyris-inbound", inbound_key),
                ("x-kyris-agent-id", agent_id),
            ] {
                if set_json_string_path(
                    &mut config,
                    &["provider", provider, "options", "headers", header],
                    value,
                ) {
                    config_changed = true;
                }
            }
            // The agent's OWN provider key (env / `opencode auth`) is the upstream
            // credential kyrisd forwards — we must NOT set `apiKey`. Migrate away a
            // stale `apiKey == inbound_key` from older installs (it overrode the real
            // key and was rejected upstream); leave a user's real apiKey untouched.
            if remove_json_string_if_equals(
                &mut config,
                &["provider", provider, "options", "apiKey"],
                inbound_key,
            ) {
                config_changed = true;
            }
        }

        let mut changes = Vec::new();
        if config_changed {
            write_json_value(
                &path,
                &config,
                "opencode:burn-control",
                &WellFormedJsonValidator,
            )?;
            changes.push(format!("updated {}", path.display()));
        }

        Ok(changes)
    }
    fn configure_tool_surface(
        &self,
        base_url: &str,
        inbound_key: &str,
        _agent_specific: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        require_writable_opencode_config(&opencode_config_path()?)?;
        // opencode's `permission` config targets built-in tools, not a
        // per-MCP-server tool denylist, so it uses the default (no) extra filter
        // and relies on the runtime wrap/routing backstop — see configure.rs.
        super::configure::configure_json_mcp_tool_surface(self, base_url, inbound_key)
    }
    fn undo_tool_surface(&self) -> Result<(), String> {
        super::configure::undo_json_mcp_tool_surface(self)
    }
    fn undo_execution_surface(&self) -> Result<(), String> {
        let path = opencode_config_path()?;
        // Reverts both the permissive-permission edit and the `plugin`-array
        // registration recorded under this component.
        if restore_manifest_entry_component(&path, "opencode:execution")? {
            println!("Reverted {}", path.display());
        }
        // Drop the governance plugin file (restore to its pre-state, else delete).
        let plugin_path = opencode_plugin_path()?;
        if !restore_manifest_entry_component(&plugin_path, "opencode:execution")? {
            super::undo::remove_file_if_exists(&plugin_path)?;
        }
        Ok(())
    }
    fn undo_burn_control_surface(&self) -> Result<(), String> {
        for path in self.burn_control_config_paths() {
            if restore_manifest_entry_component(&path, "opencode:burn-control")? {
                println!("Reverted {}", path.display());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testApplyPatchMapsToPatchAction() {
        // Finding 3: apply_patch is the file-mutation tool on gpt-5-style
        // models; it must be governed (per-file via drive_apply_patch), not
        // left unmapped → denied.
        let proto = OpenCode.hook_protocol().expect("hook protocol");
        let m = proto
            .tool_mappings
            .iter()
            .find(|m| m.tool_name == "apply_patch")
            .expect("apply_patch mapping");
        assert_eq!(m.action, "apply_patch");
        assert_eq!(m.detail_key.as_deref(), Some("patchText"));
    }

    #[test]
    fn testGovernedPermissionsAreScopedNotBlanket() {
        // Finding 16: only the governed mutating keys are allowed; doom_loop,
        // webfetch, question, plan/explore restrictions are NOT touched.
        let mut config = serde_json::json!({});
        assert!(apply_opencode_governed_permissions(&mut config));
        let perm = config["permission"].as_object().expect("permission object");
        assert_eq!(perm["bash"], "allow");
        assert_eq!(perm["edit"], "allow");
        assert_eq!(perm["write"], "allow");
        assert!(!perm.contains_key("*"), "no blanket allow-all");
        assert!(!perm.contains_key("doom_loop"));
        // Idempotent.
        assert!(!apply_opencode_governed_permissions(&mut config));
    }

    #[test]
    fn testGovernedPermissionsMigrateOldBlanketAllow() {
        // An old install's `permission: "allow"` (and {"*":"allow"}) is dropped
        // — restoring doom-loop/webfetch native gates.
        for old in [
            serde_json::json!("allow"),
            serde_json::json!({"*": "allow"}),
        ] {
            let mut config = serde_json::json!({ "permission": old });
            apply_opencode_governed_permissions(&mut config);
            let perm = config["permission"].as_object().unwrap();
            assert!(!perm.contains_key("*"), "blanket allow-all dropped");
            assert_eq!(perm["bash"], "allow");
        }
    }

    #[test]
    fn testGovernedPermissionsPreserveUserDefaultAndRules() {
        // A user's bare-string default normalizes to {"*": s}; their explicit
        // rules survive.
        let mut config = serde_json::json!({ "permission": "ask" });
        apply_opencode_governed_permissions(&mut config);
        let perm = config["permission"].as_object().unwrap();
        assert_eq!(
            perm["*"], "ask",
            "user default preserved for ungoverned tools"
        );
        assert_eq!(perm["edit"], "allow");

        let mut config = serde_json::json!({ "permission": {"*": "allow", "webfetch": "deny"} });
        apply_opencode_governed_permissions(&mut config);
        let perm = config["permission"].as_object().unwrap();
        assert_eq!(perm["webfetch"], "deny", "user rule kept");
        assert_eq!(perm["*"], "allow", "multi-key object not stripped");
    }

    #[test]
    fn testStripJsoncComments() {
        let src = r#"{
  // line comment
  "a": 1, /* block */ "b": "http://x//y", /* keep // inside string */
  "c": "/* not a comment */"
}"#;
        let stripped = strip_jsonc_comments(src);
        let v: serde_json::Value = serde_json::from_str(&stripped).expect("valid JSON");
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"], "http://x//y", "slashes inside strings preserved");
        assert_eq!(v["c"], "/* not a comment */");
    }

    #[test]
    fn testStripJsoncPreservesNonAscii() {
        // Regression: a byte-cast strip mangles multi-byte UTF-8.
        let src = r#"{"name": "café", "emoji": "🚀", "path": "/tmp/naïve"}"#;
        let v: serde_json::Value = serde_json::from_str(&strip_jsonc_comments(src)).unwrap();
        assert_eq!(v["name"], "café");
        assert_eq!(v["emoji"], "🚀");
        assert_eq!(v["path"], "/tmp/naïve");
    }

    #[test]
    fn testStripTrailingCommas() {
        let src = r#"{ "a": [1, 2, 3,], "b": { "x": 1, }, "c": "1,]", }"#;
        let v: serde_json::Value = serde_json::from_str(&strip_trailing_commas(src)).unwrap();
        assert_eq!(v["a"], serde_json::json!([1, 2, 3]));
        assert_eq!(v["b"]["x"], 1);
        assert_eq!(v["c"], "1,]", "comma+bracket inside a string is untouched");
    }

    #[test]
    fn testReadOpencodeConfigTolerantRoundTrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("opencode.jsonc");
        std::fs::write(
            &p,
            "{\n  // c\n  \"model\": \"café\",\n  \"plugin\": [\"x\",],\n}",
        )
        .unwrap();
        let v = read_opencode_config(&p).expect("tolerant read");
        assert_eq!(v["model"], "café");
        assert_eq!(v["plugin"], serde_json::json!(["x"]));
        // The strict reader rejects it, so the writable gate must refuse.
        assert!(require_writable_opencode_config(&p).is_err());
    }
}
