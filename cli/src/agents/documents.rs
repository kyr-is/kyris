// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The in-code `AgentPact` `AgentCapabilities` documents kyris ships, one per
//! supported agent — the first instances of the standard adaptation schema
//! (agentpact README §13.3/§13.4). These are byte-identical in shape to what a
//! conformant agent would emit from its `agentpact` command; they flow through
//! the same `manifest::parse_and_validate` gate. `native` is all-false today
//! (no shipping agent enforces `AgentPact` natively); the `adaptation` profile
//! declares how kyris's generic engine governs each non-native surface.
//!
//! Bridge-script content (the per-agent hook adapters referenced by
//! `install_file.template`) lives as template assets resolved by the engine, not
//! in these documents.

/// The in-code `AgentCapabilities` document for a bare agent id, or `None` if the
/// agent has no in-code document (not yet ported to the generic engine).
#[must_use]
pub fn for_agent(id: &str) -> Option<&'static str> {
    match id {
        "cline" => Some(CLINE),
        "opencode" => Some(OPENCODE),
        "claude-code" => Some(CLAUDE_CODE),
        "gemini-cli" => Some(GEMINI_CLI),
        "codex-cli" => Some(CODEX_CLI),
        _ => None,
    }
}

/// cline (standalone CLI). Single static config tree under `~/.cline`,
/// file-hook execution gate, MCP wrapping, and `config_rewrite` model routing
/// into `providers.json`. No compiled-policy fallback, no `provider_routing`
/// env, no native backstop.
pub const CLINE: &str = r#"{
  "apiVersion": "agentpact/v1",
  "kind": "AgentCapabilities",
  "protocol_version": 1,
  "agent": "cline/cline",
  "native": {},
  "adaptation": {
    "detect": {
      "binaries": ["cline"],
      "config_paths": ["hook", "providers"]
    },
    "config_files": {
      "mcp":          { "discovery": { "static": { "path": "~/.cline/data/settings/cline_mcp_settings.json" } }, "format": "json" },
      "providers":    { "discovery": { "static": { "path": "~/.cline/data/settings/providers.json" } }, "format": "json" },
      "hook":         { "discovery": { "static": { "path": "~/.cline/hooks/PreToolUse.cjs" } }, "format": "json" },
      "global_state": { "discovery": { "static": { "path": "~/.cline/data/globalState.json" } }, "format": "json" }
    },
    "surfaces": {
      "execution": {
        "mechanisms": ["live_hook"],
        "configure": [
          { "install_file": { "template": "cline_pretooluse", "dest": "hook", "mode": "0644" } }
        ],
        "probe": [
          { "file_exists": { "file": "hook" } }
        ],
        "undo": [
          { "manifest_restore": { "file": "hook", "scope": "cline:execution", "delete_if_unmanaged": true } }
        ]
      },
      "tool": {
        "mechanisms": ["mcp_wrapping"],
        "mcp": [ { "config": "mcp", "servers_key": ["mcpServers"] } ],
        "configure": [ "route_mcp" ],
        "undo": [ "undo_mcp" ]
      },
      "model_routing": {
        "kind": "config",
        "mechanisms": ["config_rewrite"],
        "configure": [
          { "set_key": { "file": "providers", "path": ["version"], "value": 1 } },
          { "set_key": { "file": "providers", "path": ["providers", "anthropic", "settings", "provider"], "value": "anthropic" } },
          { "set_key": { "file": "providers", "path": ["providers", "anthropic", "settings", "baseUrl"], "value": "{base_url_v1}" } },
          { "set_key": { "file": "providers", "path": ["providers", "anthropic", "updatedAt"], "value": "2026-01-01T00:00:00.000Z" } },
          { "set_key": { "file": "providers", "path": ["providers", "anthropic", "tokenSource"], "value": "manual" } },
          { "set_key": { "file": "providers", "path": ["providers", "anthropic", "settings", "headers", "x-kyris-inbound"], "value": "{inbound_key}" } },
          { "set_key": { "file": "providers", "path": ["providers", "anthropic", "settings", "headers", "x-kyris-agent-id"], "value": "{agent_id}" } }
        ],
        "probe": [
          { "key_equals_kyrisd": { "file": "providers", "path": ["providers", "anthropic", "settings", "baseUrl"], "suffix": "/v1" } }
        ],
        "undo": [
          { "manifest_restore": { "file": "providers", "scope": "cline:burn-control" } }
        ]
      }
    },
    "attribution": ["kyris_path_shim", "native_hook_payload", "process_lineage"],
    "agentpact_native_attribution": false,
    "hook_protocol": {
      "tool_name_field": "tool_name",
      "detail_fields": ["tool_input"],
      "tool_mappings": [
        { "tool_name": "run_commands", "action": "execute", "detail_key": "detail" },
        { "tool_name": "editor", "action": "write", "detail_key": "detail" },
        { "tool_name": "apply_patch", "action": "apply_patch", "detail_key": "detail" }
      ],
      "pass_through_tools": ["read_files", "search_codebase", "fetch_web_content", "ask_question", "skills", "submit_and_exit"],
      "agent_owned_tools": [],
      "default_action": "call",
      "allow_response": "empty_stdout",
      "runtime": {
        "agent_hook_timeout_secs": 120,
        "on_timeout": "fail_open",
        "native_backstop": false,
        "allow_suppresses_agent_prompt": false
      },
      "permission_request_allow": null,
      "mcp_tool_naming": { "server_separator": "__", "collapse_sanitize_runs": true },
      "native_ask": null
    },
    "markers": ["kyris hook check", "kyris-mcp"],
    "settings": []
  }
}"#;

/// opencode. Walk-up `opencode.{jsonc,json}` config (JSONC-tolerant), a JS
/// plugin bridge registered in the config `plugin` array, and `config_rewrite`
/// model routing across three providers (anthropic/openai → /v1, google →
/// /v1beta). No native backstop; kyris sets scoped governed permissions.
pub const OPENCODE: &str = r#"{
  "apiVersion": "agentpact/v1",
  "kind": "AgentCapabilities",
  "protocol_version": 1,
  "agent": "opencode/opencode",
  "native": {},
  "adaptation": {
    "detect": {
      "binaries": ["opencode"],
      "config_paths": ["config"]
    },
    "config_files": {
      "config": {
        "discovery": { "walk_up": { "filenames": ["opencode.jsonc", "opencode.json"], "global_dir": "~/.config/opencode" } },
        "format": "jsonc"
      },
      "plugin": {
        "discovery": { "sibling_of": { "file": "config", "name": "kyris-governance.js" } },
        "format": "json"
      }
    },
    "surfaces": {
      "execution": {
        "mechanisms": ["live_hook"],
        "configure": [
          { "require_writable": { "file": "config" } },
          { "install_plugin": { "dest": "plugin", "register_in": "config" } },
          { "set_governed_permissions": { "file": "config" } }
        ],
        "probe": [
          { "all": { "rules": [
            { "array_contains": { "file": "config", "path": ["plugin"], "value": "kyris-governance" } },
            { "file_exists": { "file": "plugin" } }
          ] } }
        ],
        "undo": [
          { "manifest_restore": { "file": "config", "scope": "opencode:execution" } },
          { "manifest_restore": { "file": "plugin", "scope": "opencode:execution", "delete_if_unmanaged": true } }
        ]
      },
      "tool": {
        "mechanisms": ["mcp_wrapping"],
        "mcp": [ { "config": "config", "servers_key": ["mcp"] } ],
        "configure": [
          { "require_writable": { "file": "config" } },
          "route_mcp"
        ],
        "undo": [ "undo_mcp" ]
      },
      "model_routing": {
        "kind": "config",
        "mechanisms": ["config_rewrite"],
        "configure": [
          { "require_writable": { "file": "config" } },
          { "set_key": { "file": "config", "path": ["provider", "anthropic", "options", "baseURL"], "value": "{base_url_v1}" } },
          { "set_key": { "file": "config", "path": ["provider", "anthropic", "options", "headers", "x-kyris-inbound"], "value": "{inbound_key}" } },
          { "set_key": { "file": "config", "path": ["provider", "anthropic", "options", "headers", "x-kyris-agent-id"], "value": "{agent_id}" } },
          { "set_key": { "file": "config", "path": ["provider", "openai", "options", "baseURL"], "value": "{base_url_v1}" } },
          { "set_key": { "file": "config", "path": ["provider", "openai", "options", "headers", "x-kyris-inbound"], "value": "{inbound_key}" } },
          { "set_key": { "file": "config", "path": ["provider", "openai", "options", "headers", "x-kyris-agent-id"], "value": "{agent_id}" } },
          { "set_key": { "file": "config", "path": ["provider", "google", "options", "baseURL"], "value": "{base_url}/v1beta" } },
          { "set_key": { "file": "config", "path": ["provider", "google", "options", "headers", "x-kyris-inbound"], "value": "{inbound_key}" } },
          { "set_key": { "file": "config", "path": ["provider", "google", "options", "headers", "x-kyris-agent-id"], "value": "{agent_id}" } },
          { "strip_kyris_apikey": { "file": "config", "path": ["provider", "anthropic", "options", "apiKey"] } },
          { "strip_kyris_apikey": { "file": "config", "path": ["provider", "openai", "options", "apiKey"] } },
          { "strip_kyris_apikey": { "file": "config", "path": ["provider", "google", "options", "apiKey"] } }
        ],
        "probe": [
          { "key_equals_kyrisd": { "file": "config", "path": ["provider", "anthropic", "options", "baseURL"], "suffix": "/v1" } },
          { "key_equals_kyrisd": { "file": "config", "path": ["provider", "openai", "options", "baseURL"], "suffix": "/v1" } },
          { "key_equals_kyrisd": { "file": "config", "path": ["provider", "google", "options", "baseURL"], "suffix": "/v1beta" } },
          { "env_points_kyrisd": { "var": "ANTHROPIC_BASE_URL" } }
        ],
        "undo": [
          { "manifest_restore": { "file": "config", "scope": "opencode:burn-control" } }
        ]
      }
    },
    "attribution": ["kyris_path_shim", "native_hook_payload", "process_lineage"],
    "agentpact_native_attribution": false,
    "hook_protocol": {
      "tool_name_field": "tool_name",
      "detail_fields": ["tool_input"],
      "tool_mappings": [
        { "tool_name": "bash", "action": "execute", "detail_key": "command" },
        { "tool_name": "edit", "action": "write", "detail_key": "filePath" },
        { "tool_name": "write", "action": "write", "detail_key": "filePath" },
        { "tool_name": "read", "action": "read", "detail_key": "filePath" },
        { "tool_name": "apply_patch", "action": "apply_patch", "detail_key": "patchText" }
      ],
      "pass_through_tools": ["glob", "grep", "todowrite", "task", "webfetch", "websearch", "skill", "lsp", "question", "plan_exit", "invalid"],
      "agent_owned_tools": [],
      "default_action": "call",
      "allow_response": "empty_stdout",
      "runtime": {
        "agent_hook_timeout_secs": 600,
        "on_timeout": "fail_open",
        "native_backstop": false,
        "allow_suppresses_agent_prompt": false
      },
      "permission_request_allow": null,
      "mcp_tool_naming": { "server_separator": "_", "collapse_sanitize_runs": false },
      "native_ask": null
    },
    "markers": ["kyris-governance", "kyris-mcp"],
    "settings": []
  }
}"#;

/// Claude Code. Live `PreToolUse` hook (command bridge) registered in
/// `~/.claude/settings.json`; three MCP scopes (user `~/.claude.json`, per-project
/// `projects.*`, and walk-up `.mcp.json`) with `permissions.deny` steering;
/// env-proxy model routing across Anthropic's backends. Native ask + allow
/// suppress Claude's own prompt; launch dir anchored at `CLAUDE_PROJECT_DIR`.
pub const CLAUDE_CODE: &str = r#"{
  "apiVersion": "agentpact/v1",
  "kind": "AgentCapabilities",
  "protocol_version": 1,
  "agent": "anthropic/claude-code",
  "native": {},
  "adaptation": {
    "detect": {
      "binaries": ["claude"],
      "config_paths": ["settings", "user_config"]
    },
    "config_files": {
      "settings":    { "discovery": { "static": { "path": "~/.claude/settings.json" } }, "format": "json" },
      "user_config": { "discovery": { "static": { "path": "~/.claude.json" } }, "format": "json" },
      "project_mcp": { "discovery": { "walk_up_optional": { "filenames": [".mcp.json"] } }, "format": "json" },
      "hookscript":  { "discovery": { "static": { "path": "~/.claude/hooks/agentpact_pretooluse.sh" } }, "format": "json" }
    },
    "launch_dir": "CLAUDE_PROJECT_DIR",
    "surfaces": {
      "execution": {
        "mechanisms": ["live_hook"],
        "configure": [
          { "install_hook": { "script": "hookscript", "register_in": "settings", "events": ["PreToolUse"], "nested": true } }
        ],
        "probe": [
          { "all": { "rules": [
            { "contains_marker": { "file": "settings", "marker": "agentpact_pretooluse" } },
            { "hook_script_matches": { "file": "hookscript" } }
          ] } }
        ],
        "undo": [
          { "manifest_restore": { "file": "settings", "scope": "claude-code:execution" } },
          { "manifest_restore": { "file": "hookscript", "scope": "claude-code:execution", "delete_if_unmanaged": true } }
        ]
      },
      "tool": {
        "mechanisms": ["mcp_wrapping"],
        "mcp": [
          { "config": "user_config", "servers_key": ["mcpServers"] },
          { "config": "user_config", "servers_key": ["projects", "*", "mcpServers"], "nested_scope": true },
          { "config": "project_mcp", "servers_key": ["mcpServers"] }
        ],
        "configure": [
          "route_mcp",
          { "mcp_derived_denies": { "file": "settings" } }
        ],
        "undo": [ "undo_mcp" ]
      },
      "model_routing": {
        "kind": "env",
        "mechanisms": ["env_var_proxy"],
        "env": {
          "base_url_vars": [
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_BEDROCK_BASE_URL",
            "ANTHROPIC_VERTEX_BASE_URL",
            "ANTHROPIC_FOUNDRY_BASE_URL",
            "ANTHROPIC_BEDROCK_MANTLE_BASE_URL"
          ],
          "auth_skip_flags": [
            ["CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1"],
            ["CLAUDE_CODE_SKIP_VERTEX_AUTH", "1"]
          ],
          "custom_headers_var": "ANTHROPIC_CUSTOM_HEADERS",
          "header_separator": "\n"
        },
        "probe": [ { "env_points_kyrisd": { "var": "ANTHROPIC_BASE_URL" } } ],
        "undo": [ "delete_env_file" ]
      }
    },
    "attribution": ["kyris_path_shim", "native_hook_payload", "process_lineage"],
    "agentpact_native_attribution": false,
    "hook_protocol": {
      "tool_name_field": "tool_name",
      "detail_fields": ["tool_input", "input"],
      "tool_mappings": [
        { "tool_name": "Bash", "action": "execute", "detail_key": "command" },
        { "tool_name": "bash", "action": "execute", "detail_key": "command" },
        { "tool_name": "Read", "action": "read", "detail_key": "file_path" },
        { "tool_name": "read_file", "action": "read", "detail_key": "file_path" },
        { "tool_name": "Write", "action": "write", "detail_key": "file_path" },
        { "tool_name": "write_file", "action": "write", "detail_key": "file_path" },
        { "tool_name": "Edit", "action": "write", "detail_key": "file_path" },
        { "tool_name": "edit_file", "action": "write", "detail_key": "file_path" },
        { "tool_name": "NotebookEdit", "action": "write", "detail_key": "notebook_path" },
        { "tool_name": "PowerShell", "action": "execute", "detail_key": "command" }
      ],
      "pass_through_tools": ["AskUserQuestion", "TodoWrite", "ExitPlanMode", "EnterPlanMode", "Task", "Agent", "Glob", "Grep", "LSP", "BashOutput", "KillShell", "ToolSearch", "Skill", "Monitor", "ScheduleWakeup", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "TaskOutput", "TaskStop"],
      "agent_owned_tools": ["WebFetch", "WebSearch", "SendMessage", "SlashCommand", "EnterWorktree", "ExitWorktree", "CronCreate", "CronDelete", "CronList", "PushNotification", "RemoteTrigger"],
      "default_action": "call",
      "allow_response": { "json": { "body": { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "approved by AgentPact policy" } } } },
      "runtime": {
        "agent_hook_timeout_secs": 600,
        "on_timeout": "fail_open",
        "native_backstop": true,
        "allow_suppresses_agent_prompt": true
      },
      "permission_request_allow": null,
      "mcp_tool_naming": null,
      "native_ask": { "native_prompt": { "body": { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "AgentPact policy requires your confirmation" } } } }
    },
    "markers": ["agentpact_pretooluse", "kyris-mcp"],
    "settings": [
      { "key": "approval_prompt", "description": "Approval UX for an `ask`: `kyris` (kyris's pending-approval popup — default) or `native` (the agent's own prompt)" }
    ]
  }
}"#;

/// Gemini CLI. Nested `BeforeTool` hook (user-scope `~/.gemini/settings.json`) with
/// a compiled-policy fallback (`policies/agentpact.toml`, compiled ceiling);
/// user + walk-up workspace MCP scopes with `excludeTools`; env-proxy routing
/// gated on a routable, key-backed auth selection; optional `maxSessionTurns`.
pub const GEMINI_CLI: &str = r#"{
  "apiVersion": "agentpact/v1",
  "kind": "AgentCapabilities",
  "protocol_version": 1,
  "agent": "google/gemini-cli",
  "native": {},
  "adaptation": {
    "detect": {
      "binaries": ["gemini"],
      "config_paths": ["user_settings"]
    },
    "config_files": {
      "user_settings":      { "discovery": { "static": { "path": "~/.gemini/settings.json" } }, "format": "json" },
      "workspace_settings": { "discovery": { "walk_up_optional": { "filenames": [".gemini/settings.json"] } }, "format": "json" },
      "policy":             { "discovery": { "static": { "path": "~/.gemini/policies/agentpact.toml" } }, "format": "json" },
      "hookscript":         { "discovery": { "static": { "path": "~/.gemini/hooks/agentpact_beforetool.sh" } }, "format": "json" }
    },
    "launch_dir": "GEMINI_PROJECT_DIR",
    "surfaces": {
      "execution": {
        "mechanisms": ["live_hook", "compiled_policy"],
        "configure": [
          { "install_hook": { "script": "hookscript", "register_in": "user_settings", "events": ["BeforeTool"], "nested": true, "hook_timeout": 600000 } },
          { "write_compiled_policy": { "dest": "policy" } },
          { "remove_legacy_hook": { "file": "workspace_settings", "event": "BeforeTool", "marker": "agentpact_beforetool" } }
        ],
        "probe": [
          { "contains_marker": { "file": "user_settings", "marker": "agentpact_beforetool" } },
          { "contains_marker": { "file": "workspace_settings", "marker": "agentpact_beforetool" } }
        ],
        "fallback": {
          "probe": [ { "compiled_policy_loadable": { "file": "policy" } } ],
          "mechanism": "compiled_policy",
          "ceiling": "compiled"
        },
        "undo": [
          { "restore_component": { "scope": "gemini-cli:execution" } },
          { "delete_file": { "file": "hookscript" } },
          { "delete_file": { "file": "policy" } }
        ]
      },
      "tool": {
        "mechanisms": ["mcp_wrapping"],
        "mcp": [
          { "config": "user_settings", "servers_key": ["mcpServers"] },
          { "config": "workspace_settings", "servers_key": ["mcpServers"] }
        ],
        "exclude_tools": ["mcpServers"],
        "configure": [ "route_mcp" ],
        "undo": [ "undo_mcp" ]
      },
      "model_routing": {
        "kind": "env",
        "mechanisms": ["env_var_proxy"],
        "env": {
          "base_url_vars": ["GOOGLE_GEMINI_BASE_URL", "GOOGLE_VERTEX_BASE_URL"],
          "custom_headers_var": "GEMINI_CLI_CUSTOM_HEADERS",
          "header_separator": ", "
        },
        "configure": [
          { "ensure_routable_auth": { "file": "user_settings" } },
          { "set_setting_from_input": { "file": "user_settings", "path": ["model", "maxSessionTurns"], "input": "maxSessionTurns" } }
        ],
        "probe": [
          { "all": { "rules": [
            { "env_points_kyrisd": { "var": "GOOGLE_GEMINI_BASE_URL" } },
            { "auth_routable": { "file": "user_settings", "alt_file": "workspace_settings" } }
          ] } }
        ],
        "undo": [
          { "restore_component": { "scope": "gemini-cli:burn-control" } },
          "delete_env_file"
        ]
      }
    },
    "attribution": ["kyris_path_shim", "native_hook_payload", "process_lineage"],
    "agentpact_native_attribution": false,
    "hook_protocol": {
      "tool_name_field": "tool_name",
      "detail_fields": ["tool_input"],
      "tool_mappings": [
        { "tool_name": "run_shell_command", "action": "execute", "detail_key": "command" },
        { "tool_name": "read_file", "action": "read", "detail_key": "file_path" },
        { "tool_name": "write_file", "action": "write", "detail_key": "file_path" },
        { "tool_name": "replace", "action": "write", "detail_key": "file_path" }
      ],
      "pass_through_tools": ["glob", "grep_search", "search_file_content", "list_directory", "google_web_search", "update_topic", "read_mcp_resource", "list_mcp_resources", "tracker_create_task", "tracker_update_task", "tracker_get_task", "tracker_list_tasks", "tracker_add_dependency", "tracker_visualize", "write_todos", "list_background_processes", "read_background_output", "invoke_agent", "complete_task", "get_internal_docs"],
      "agent_owned_tools": ["web_fetch", "activate_skill", "read_many_files", "ask_user", "enter_plan_mode", "exit_plan_mode"],
      "default_action": "call",
      "allow_response": { "json": { "body": { "decision": "allow" } } },
      "runtime": {
        "agent_hook_timeout_secs": 600,
        "on_timeout": "fail_open",
        "native_backstop": true,
        "allow_suppresses_agent_prompt": false
      },
      "permission_request_allow": null,
      "mcp_tool_naming": null,
      "native_ask": { "native_prompt": { "body": { "decision": "ask", "reason": "AgentPact policy requires your confirmation" } } }
    },
    "markers": ["agentpact_beforetool", "kyris-mcp", "Generated by Kyris"],
    "settings": [
      { "key": "maxSessionTurns", "description": "Max agent turns per session (writes model.maxSessionTurns to settings.json; 0 or below means unlimited)" },
      { "key": "approval_prompt", "description": "Approval UX for an `ask`: `kyris` (kyris's pending-approval popup — default) or `native` (the agent's own prompt)" }
    ]
  }
}"#;

/// Codex CLI. Its governance *realization* (PreToolUse+PermissionRequest hooks
/// with a week-long trust-baked timeout, the `model_providers.kyris` TOML table,
/// compiled `agentpact.rules` + `[permissions.kyris]`, kyrisd.yaml upstreams,
/// `CodexConfigShape` validation, single read-modify-write) is too irreducible
/// for data ops, so probe/configure/undo are `delegate`d to the `codex-cli`
/// daemon handler. The document still carries all DATA (surfaces, mechanisms,
/// hook IO contract, markers, TOML MCP location). When codex declares a surface
/// native, that surface's delegated realization is bypassed automatically.
pub const CODEX_CLI: &str = r#"{
  "apiVersion": "agentpact/v1",
  "kind": "AgentCapabilities",
  "protocol_version": 1,
  "agent": "openai/codex-cli",
  "native": {},
  "adaptation": {
    "delegate": "codex-cli",
    "detect": {
      "binaries": ["codex"],
      "config_paths": ["config"]
    },
    "config_files": {
      "config": { "discovery": { "env_rooted": { "env": "CODEX_HOME", "subpath": "config.toml", "fallback": "~/.codex/config.toml" } }, "format": "toml" }
    },
    "surfaces": {
      "execution":     { "mechanisms": ["live_hook", "compiled_policy"] },
      "tool":          { "mechanisms": ["mcp_wrapping"], "mcp": [ { "config": "config", "servers_key": ["mcp_servers"] } ] },
      "model_routing": { "kind": "provider_table", "mechanisms": ["kyrisd_model_provider"] }
    },
    "attribution": ["kyris_path_shim", "shell_environment_policy", "native_hook_payload", "peer_process_observed"],
    "agentpact_native_attribution": false,
    "hook_protocol": {
      "tool_name_field": "tool_name",
      "detail_fields": ["tool_input"],
      "tool_mappings": [
        { "tool_name": "Bash", "action": "execute", "detail_key": "command" },
        { "tool_name": "apply_patch", "action": "apply_patch", "detail_key": "command" }
      ],
      "pass_through_tools": ["update_plan", "view_image", "spawn_agent", "wait_agent", "close_agent", "followup_task", "list_agents", "request_user_input", "tool_search", "list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource", "list_available_plugins_to_install"],
      "agent_owned_tools": ["request_permissions", "request_plugin_install", "send_message", "spawn_agents_on_csv", "report_agent_job_result"],
      "default_action": "call",
      "allow_response": "empty_stdout",
      "runtime": {
        "agent_hook_timeout_secs": 604800,
        "on_timeout": "fail_open",
        "native_backstop": true,
        "allow_suppresses_agent_prompt": false
      },
      "permission_request_allow": { "hookSpecificOutput": { "hookEventName": "PermissionRequest", "decision": { "behavior": "allow" } } },
      "mcp_tool_naming": null,
      "native_ask": "defer_to_native_approval"
    },
    "markers": ["kyris-mcp", "kyris_pretooluse", "KYRIS_GOVERNED_SUBPROCESS", "model_provider = \"kyris\"", "[model_providers.kyris]"],
    "settings": [
      { "key": "approval_prompt", "description": "Approval UX for an `ask`: `kyris` (kyris's pending-approval popup — default) or `native` (the agent's own prompt)" }
    ]
  }
}"#;
