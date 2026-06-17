// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use crate::lifecycle::log::InstallLog;
use crate::state::load_or_init_config;

use super::registry;

// Setup/configure helper groups split into sibling submodules. The orchestration
// entry points (`setup_agent`, `configure_agent_surfaces`) and settings
// validation stay here; the re-exports keep external callers resolving
// `super::configure::<item>` / `crate::…::configure::<item>` unchanged.
mod daemons;
mod hooks;
mod mcp;
mod mcp_filters;
// `pub use` re-exports the public entry points so external callers keep
// resolving `super::configure::<item>` unchanged.
pub use daemons::*;
pub use hooks::*;
pub use mcp::*;
pub use mcp_filters::*;
// Crate-internal helpers used by the orchestration core below (and the test
// module via `super::*`): not part of the public surface, so brought in by name.
#[cfg(test)]
use daemons::{agentpactd_reachable_at, governance_daemons_error};
use daemons::{verify_governance_daemons, verify_kyrisd_health};
#[cfg(test)]
use mcp::{json_mcp_server_unwrapped, toml_mcp_server_unwrapped};
#[cfg(test)]
use mcp_filters::add_mcp_tool_denies;

/// Full setup: prestage + configure every adapted surface, then verify kyrisd
/// is reachable.
///
/// All changes are KEPT even when the kyrisd health check fails. The developer
/// explicitly asked for this configuration; the config rewrites that route
/// through kyrisd (base URLs/keys, MCP URL rewrites) take effect the moment
/// kyrisd comes up, so there is nothing to gain by discarding them. We instead
/// apply everything and return an actionable error telling the user to start
/// kyrisd — the surfaces are already in place. Execution-surface changes need
/// only agentpactd and are likewise committed unconditionally.
///
/// An earlier version rolled burn-control changes back on health-check failure;
/// that was deliberately removed. Do not reintroduce it — the kept-changes
/// contract is pinned by `tests/setup_rollback.rs`.
/// Reject any `--set` key the agent does not declare in `supported_settings`,
/// before any side effects run. Without this, an unknown key (e.g. a
/// `max-budget-usd` claude doesn't consume) would be stored and printed as
/// "set …" yet do nothing — false confidence.
fn validate_agent_settings(
    agent: &dyn registry::AgentDescriptor,
    agent_specific: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let supported = agent.supported_settings();
    for key in agent_specific.keys() {
        if !supported.iter().any(|(k, _)| k == key) {
            let detail = if supported.is_empty() {
                format!("{} accepts no --set settings.", agent.id())
            } else {
                let list = supported
                    .iter()
                    .map(|(k, d)| format!("  {k} — {d}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!("Valid --set keys for {}:\n{list}", agent.id())
            };
            return Err(format!(
                "Unknown --set key '{key}' for {}. {detail}",
                agent.id()
            ));
        }
    }
    Ok(())
}

pub fn setup_agent(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;
    validate_agent_settings(agent.as_ref(), agent_specific)?;

    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    // `setup` is idempotent and repairs drift. A bare re-run (no `--set`) must
    // REAPPLY previously-saved settings, not silently reset the agent's config
    // to defaults — so configure the surfaces with the saved settings merged
    // under any new `--set` (new values win). This is what lets `setup` subsume
    // the old `reconcile`: re-running it restores a drifted/reinstalled config
    // with the user's settings intact.
    let mut effective = crate::state::load_agent_profile(agent_id)?
        .map(|p| p.agent_specific)
        .unwrap_or_default();
    effective.extend(agent_specific.iter().map(|(k, v)| (k.clone(), v.clone())));
    let effective = &effective;

    let mut changes = super::prestage::prestage_agent(agent_id)?;

    if agent.is_installed() {
        let plan = agent.integration_plan();
        if plan.requires_path_shim() {
            changes.extend(super::shim::install_shim(agent_id)?);
        }
        if plan.has_adapted_execution() {
            changes.extend(agent.configure_execution_surface(&base_url, inbound_key, effective)?);
        }
        if plan.has_adapted_tool() {
            changes.extend(agent.configure_tool_surface(&base_url, inbound_key, effective)?);
        }
        if plan.has_adapted_burn_control() {
            changes.extend(agent.configure_burn_control_surface(
                &base_url,
                inbound_key,
                effective,
            )?);
        }

        // Execution and tool governance route decisions through agentpactd, so
        // verify it too — otherwise setup would report success while command/MCP
        // governance is silently dormant (the hook fails open → ungoverned).
        let needs_agentpactd = plan.has_adapted_execution() || plan.has_adapted_tool();
        verify_governance_daemons(&base_url, agent_id, needs_agentpactd)?;
    } else {
        // Not installed: only prestaged (no governance surfaces yet), so just
        // kyrisd needs to be reachable for the routing env to work once detected.
        verify_governance_daemons(&base_url, agent_id, false)?;
    }

    clear_disconnected_flag(agent_id)?;

    if !agent_specific.is_empty() {
        save_agent_specific(agent_id, agent_specific)?;
        for (k, v) in agent_specific {
            changes.push(format!("set {k}={v}"));
        }
    }

    if changes.is_empty() {
        println!("No changes needed for {agent_id}.");
    } else {
        if !agent.is_installed() {
            println!(
                "{agent_id} not installed — prestaged only. \
                 Configure will run automatically when the agent is detected."
            );
        }
        println!("Applied setup for {agent_id}:");
        for change in &changes {
            println!("  {change}");
        }
    }

    Ok(())
}

pub(super) fn configure_agent_surfaces(
    agent_id: &str,
    agent_specific: &std::collections::HashMap<String, String>,
    skip_execution: bool,
    skip_tool: bool,
    skip_burn_control: bool,
    log: Option<&InstallLog>,
) -> Result<(), String> {
    let agent =
        registry::agent_by_id(agent_id).ok_or_else(|| format!("Unknown agent: {agent_id}"))?;

    if !agent.is_installed() {
        return Err(format!("{agent_id} is not installed."));
    }

    let config = load_or_init_config()?;
    let base_url = config.base_url();
    let inbound_key = &config.server.inbound_key;

    let mut changes = Vec::new();
    let plan = agent.integration_plan();
    if plan.requires_path_shim() {
        changes.extend(super::shim::install_shim(agent_id)?);
    }
    if !skip_execution && plan.has_adapted_execution() {
        changes.extend(agent.configure_execution_surface(
            &base_url,
            inbound_key,
            agent_specific,
        )?);
    }
    if !skip_tool && plan.has_adapted_tool() {
        changes.extend(agent.configure_tool_surface(&base_url, inbound_key, agent_specific)?);
    }

    if !skip_burn_control && plan.has_adapted_burn_control() {
        changes.extend(agent.configure_burn_control_surface(
            &base_url,
            inbound_key,
            agent_specific,
        )?);

        if let Err(error) = verify_kyrisd_health(&base_url) {
            return Err(format!(
                "kyrisd unreachable ({error}). \
                 Bring kyrisd up (try `launchctl kickstart gui/$UID/is.kyr.kyrisd` or reinstall), then re-run `kyris agent setup {agent_id}`."
            ));
        }
    }

    if changes.is_empty() {
        println!("No changes needed for {agent_id}.");
        if let Some(l) = log {
            l.info(&format!("{agent_id}: no changes needed"));
        }
    } else {
        println!("Configured {agent_id}:");
        if let Some(l) = log {
            l.info(&format!("configured {agent_id}"));
        }
        for change in &changes {
            println!("  {change}");
            if let Some(l) = log {
                l.info(&format!("  {agent_id} {change}"));
            }
        }
    }

    Ok(())
}

fn clear_disconnected_flag(agent_id: &str) -> Result<(), String> {
    if let Some(mut profile) = crate::state::load_agent_profile(agent_id)?
        && profile.disconnected
    {
        profile.disconnected = false;
        crate::state::save_agent_profile(&profile)?;
    }
    Ok(())
}

fn save_agent_specific(
    agent_id: &str,
    settings: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let mut profile = crate::state::load_agent_profile(agent_id)?
        .unwrap_or_else(|| super::profile::AgentProfile::new_empty(agent_id));
    profile
        .agent_specific
        .extend(settings.iter().map(|(k, v)| (k.clone(), v.clone())));
    crate::state::save_agent_profile(&profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn testHookScriptMarksGovernedSubprocessBeforeShellWork() {
        let script = hook_script_source("codex-cli");
        let marker = r#"export KYRIS_GOVERNED_SUBPROCESS="codex-cli""#;
        let marker_idx = script.find(marker).expect("hook script exports marker");
        let lookup_idx = script
            .find("KYRIS_BIN=\"\"")
            .expect("hook script resolves kyris");
        assert!(
            marker_idx < lookup_idx,
            "hook script must mark itself before shell work so shell governance does not recursively prompt"
        );
    }

    #[test]
    fn testJsonMcpServerUnwrappedDetection() {
        // Wrapped (string + array forms) → not flagged.
        assert!(!json_mcp_server_unwrapped(
            &serde_json::json!({"command": "kyris-mcp"})
        ));
        assert!(!json_mcp_server_unwrapped(
            &serde_json::json!({"command": ["kyris-mcp", "wrap"]})
        ));
        // Unwrapped stdio (added after setup) → flagged.
        assert!(json_mcp_server_unwrapped(
            &serde_json::json!({"command": "npx"})
        ));
        assert!(json_mcp_server_unwrapped(
            &serde_json::json!({"command": ["npx", "-y", "srv"]})
        ));
        // URL/HTTP server (no command) → not flagged.
        assert!(!json_mcp_server_unwrapped(
            &serde_json::json!({"url": "https://example.com/mcp"})
        ));
    }

    #[test]
    fn testTomlMcpServerUnwrappedDetection() {
        let wrapped: toml::Value = toml::from_str("command = \"kyris-mcp\"").unwrap();
        assert!(!toml_mcp_server_unwrapped(&wrapped));
        let unwrapped: toml::Value = toml::from_str("command = \"npx\"").unwrap();
        assert!(toml_mcp_server_unwrapped(&unwrapped));
        let url: toml::Value = toml::from_str("url = \"https://example.com/mcp\"").unwrap();
        assert!(!toml_mcp_server_unwrapped(&url));
    }

    #[test]
    fn testGovernanceDaemonsErrorNoneWhenAllUp() {
        assert!(governance_daemons_error("claude-code", None, false).is_none());
    }

    #[test]
    fn testGovernanceDaemonsErrorFlagsAgentpactdDown() {
        let msg = governance_daemons_error("claude-code", None, true).expect("error");
        assert!(msg.contains("agentpactd unreachable"), "{msg}");
        assert!(msg.contains("UNGOVERNED"), "{msg}");
        assert!(msg.contains("governance is NOT active"), "{msg}");
    }

    #[test]
    fn testGovernanceDaemonsErrorFlagsBothDown() {
        let msg =
            governance_daemons_error("codex-cli", Some("dead".to_string()), true).expect("error");
        // Existing tests assert the "kyrisd unreachable" substring — keep it.
        assert!(msg.contains("kyrisd unreachable"), "{msg}");
        assert!(msg.contains("agentpactd unreachable"), "{msg}");
    }

    #[test]
    fn testAgentpactdReachableFalseForMissingSocket() {
        assert!(!agentpactd_reachable_at(
            "/tmp/kyris-test-nonexistent-agentpact.sock"
        ));
    }

    #[test]
    fn testValidateAgentSettingsRejectsUnknownKey() {
        // opencode advertises no --set settings (no native-ask toggle), so the
        // rejection names the "accepts no settings" branch. (claude/codex/gemini
        // now advertise `approval_prompt`.)
        let agent = registry::agent_by_id("opencode").unwrap();
        let settings = HashMap::from([("max-budget-usd".to_string(), "50".to_string())]);
        let err = validate_agent_settings(agent.as_ref(), &settings).expect_err("should reject");
        assert!(err.contains("Unknown --set key 'max-budget-usd'"), "{err}");
        assert!(err.contains("accepts no --set settings"), "{err}");
    }

    #[test]
    fn testValidateAgentSettingsAcceptsKnownKeyAndListsOnUnknown() {
        let agent = registry::agent_by_id("gemini-cli").unwrap();
        // Known key passes.
        let ok = HashMap::from([("maxSessionTurns".to_string(), "100".to_string())]);
        assert!(validate_agent_settings(agent.as_ref(), &ok).is_ok());
        // Unknown key is rejected and the error lists the valid key(s).
        let bad = HashMap::from([("nope".to_string(), "1".to_string())]);
        let err = validate_agent_settings(agent.as_ref(), &bad).expect_err("should reject");
        assert!(err.contains("Unknown --set key 'nope'"), "{err}");
        assert!(err.contains("maxSessionTurns"), "{err}");
    }

    #[test]
    fn testValidateAgentSettingsEmptyIsOk() {
        let agent = registry::agent_by_id("claude-code").unwrap();
        assert!(validate_agent_settings(agent.as_ref(), &HashMap::new()).is_ok());
    }

    #[test]
    fn testClaudeMcpDeniesAddsPresentServerToolsToPermissionsDeny() {
        // The denies land in settings.json; the present-server list comes from
        // the MCP store files (~/.claude.json / .mcp.json) via the caller.
        let mut settings = serde_json::json!({});
        let filters = HashMap::from([
            (
                "fs".to_string(),
                vec!["write".to_string(), "delete".to_string()],
            ),
            // A server NOT present in any scope must be skipped.
            ("other".to_string(), vec!["x".to_string()]),
        ]);

        assert!(add_mcp_tool_denies(
            &mut settings,
            &filters,
            &["fs".to_string()]
        ));
        let deny: Vec<&str> = settings["permissions"]["deny"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(deny.contains(&"mcp__fs__write"));
        assert!(deny.contains(&"mcp__fs__delete"));
        assert!(!deny.iter().any(|d| d.contains("other")));
    }

    #[test]
    fn testClaudeMcpDeniesIsIdempotentAndPreservesExisting() {
        let mut settings = serde_json::json!({
            "permissions": { "deny": ["Bash(rm *)", "mcp__fs__write"] }
        });
        let filters = HashMap::from([("fs".to_string(), vec!["write".to_string()])]);

        // Already present → no change.
        assert!(!add_mcp_tool_denies(
            &mut settings,
            &filters,
            &["fs".to_string()]
        ));
        let deny = settings["permissions"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 2, "must not duplicate or drop existing entries");
        assert!(deny.iter().any(|v| v == "Bash(rm *)"));
    }

    #[test]
    fn testClaudeMcpDeniesEmptyFiltersNoOp() {
        let mut settings = serde_json::json!({});
        assert!(!add_mcp_tool_denies(
            &mut settings,
            &HashMap::new(),
            &["fs".to_string()]
        ));
        assert!(settings.get("permissions").is_none());
    }

    #[test]
    fn testRewriteCodexMcpServers() {
        let mut config: toml::Value = toml::from_str("[mcp_servers.filesystem]\ncommand = \"npx\"\nargs = [\"-y\", \"server\"]\n\n[mcp_servers.remote]\nurl = \"https://example.com/mcp\"\n")
        .expect("parse");

        let result = rewrite_codex_mcp_servers(
            &mut config,
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "openai/codex-cli",
        );
        assert!(result.changed);
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string()),]
        );

        let servers = config["mcp_servers"].as_table().expect("mcp_servers");
        assert_eq!(servers["filesystem"]["command"].as_str(), Some("kyris-mcp"));
        let args: Vec<&str> = servers["filesystem"]["args"]
            .as_array()
            .expect("args")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect();
        assert_eq!(
            args,
            vec![
                "wrap",
                "--server",
                "filesystem",
                "--agent",
                "openai/codex-cli",
                "npx",
                "-y",
                "server"
            ]
        );
        assert_eq!(
            servers["remote"]["url"].as_str(),
            Some("http://127.0.0.1:4710/mcp/remote/")
        );
        assert_eq!(
            servers["remote"]["http_headers"]["x-kyris-agent-id"].as_str(),
            Some("openai/codex-cli")
        );
    }

    #[test]
    fn testRewriteJsonMcpServersClineNestedTransport() {
        // Cline's `cline mcp add` wizard nests command/args under `transport`
        // (review Finding 15). The rewrite must descend into it — wrapping the
        // top level would miss every wizard-written server.
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "fs": {
                    "transport": {"type": "stdio", "command": "uvx", "args": ["fs-mcp"]}
                },
                "remote": {
                    "transport": {"type": "streamableHttp", "url": "https://example.com/mcp"}
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "cline/cline",
        );
        assert!(result.changed);
        let fs = &config["mcpServers"]["fs"]["transport"];
        assert_eq!(fs["command"], "kyris-mcp");
        assert_eq!(fs["type"], "stdio", "transport type preserved");
        assert_eq!(
            fs["args"],
            serde_json::json!([
                "wrap",
                "--server",
                "fs",
                "--agent",
                "cline/cline",
                "uvx",
                "fs-mcp"
            ])
        );
        let remote = &config["mcpServers"]["remote"]["transport"];
        assert_eq!(remote["url"], "http://127.0.0.1:4710/mcp/remote/");
        assert_eq!(remote["headers"]["x-kyris-agent-id"], "cline/cline");
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string())]
        );

        // Drift/routed detectors see the nested form too.
        assert!(!super::json_mcp_server_unwrapped(
            &config["mcpServers"]["fs"]
        ));

        // Idempotent: a second pass on the now-wrapped nested servers is a
        // no-op (the --agent flag is already present in transport.args).
        let again = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "cline/cline",
        );
        assert!(!again.changed, "re-wrap of a nested server must be a no-op");
    }

    #[test]
    fn testRewriteJsonMcpServers() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "server"]
                },
                "remote": {
                    "url": "https://example.com/mcp"
                }
            }
        });

        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "anthropic/claude-code",
        );
        assert!(result.changed);
        assert_eq!(
            result.http_rewrites,
            vec![("remote".to_string(), "https://example.com/mcp".to_string()),]
        );

        let servers = config["mcpServers"].as_object().expect("mcpServers");
        assert_eq!(servers["filesystem"]["command"], "kyris-mcp");
        assert_eq!(
            servers["filesystem"]["args"],
            serde_json::json!([
                "wrap",
                "--server",
                "filesystem",
                "--agent",
                "anthropic/claude-code",
                "npx",
                "-y",
                "server"
            ])
        );
        assert_eq!(
            servers["remote"]["url"],
            "http://127.0.0.1:4710/mcp/remote/"
        );
        assert_eq!(
            servers["remote"]["headers"]["Authorization"],
            "Bearer sk-kyris-test"
        );
        assert_eq!(
            servers["remote"]["headers"]["x-kyris-agent-id"],
            "anthropic/claude-code"
        );
    }

    #[test]
    fn testRewriteJsonMcpServersArrayCommand() {
        let mut config: serde_json::Value = serde_json::json!({
            "mcp": {
                "filesystem": {
                    "command": ["npx", "-y", "my-mcp-server"]
                }
            }
        });

        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcp".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "opencode/opencode",
        );
        assert!(result.changed);
        assert!(result.http_rewrites.is_empty());

        let cmd = config["mcp"]["filesystem"]["command"]
            .as_array()
            .expect("command is array");
        assert_eq!(cmd[0], "kyris-mcp");
        assert_eq!(cmd[1], "wrap");
        assert_eq!(cmd[2], "--server");
        assert_eq!(cmd[3], "filesystem");
        assert_eq!(cmd[4], "--agent");
        assert_eq!(cmd[5], "opencode/opencode");
        assert_eq!(cmd[6], "npx");
        assert_eq!(cmd[7], "-y");
        assert_eq!(cmd[8], "my-mcp-server");
    }

    #[test]
    fn testRewriteJsonMcpServersArrayCommandAlreadyWrapped() {
        // Fully current wrap (has --agent) → untouched. A pre-upgrade wrap
        // (no --agent) → upgraded in place, nothing else rewritten.
        let mut config: serde_json::Value = serde_json::json!({
            "mcp": {
                "current": {
                    "command": ["kyris-mcp", "wrap", "--server", "current",
                                "--agent", "opencode/opencode", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcp".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "opencode/opencode",
        );
        assert!(!result.changed);

        let mut legacy: serde_json::Value = serde_json::json!({
            "mcp": {
                "legacy": {
                    "command": ["kyris-mcp", "wrap", "--server", "legacy", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut legacy,
            &["mcp".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "opencode/opencode",
        );
        assert!(result.changed, "pre-upgrade wrap gains the --agent flag");
        assert_eq!(
            legacy["mcp"]["legacy"]["command"],
            serde_json::json!([
                "kyris-mcp",
                "wrap",
                "--server",
                "legacy",
                "--agent",
                "opencode/opencode",
                "npx"
            ])
        );
    }

    #[test]
    fn testRewriteJsonMcpServersSkipsAlreadyWrapped() {
        // Fully current wrap → no change; pre-upgrade wrap → only the
        // --agent flag is added (never re-wrapped).
        let mut config: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "wrapped": {
                    "command": "kyris-mcp",
                    "args": ["wrap", "--server", "wrapped",
                             "--agent", "anthropic/claude-code", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut config,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "anthropic/claude-code",
        );
        assert!(!result.changed);
        assert!(result.http_rewrites.is_empty());

        let mut legacy: serde_json::Value = serde_json::json!({
            "mcpServers": {
                "wrapped": {
                    "command": "kyris-mcp",
                    "args": ["wrap", "--server", "wrapped", "npx"]
                }
            }
        });
        let result = rewrite_json_mcp_servers(
            &mut legacy,
            &["mcpServers".to_string()],
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "anthropic/claude-code",
        );
        assert!(result.changed);
        assert_eq!(
            legacy["mcpServers"]["wrapped"]["args"],
            serde_json::json!([
                "wrap",
                "--server",
                "wrapped",
                "--agent",
                "anthropic/claude-code",
                "npx"
            ])
        );
    }

    #[test]
    fn testRewriteCodexMcpServersIdempotent() {
        let mut config: toml::Value = toml::from_str(
            "[mcp_servers.remote]\nurl = \"http://127.0.0.1:4710/mcp/remote/\"\n\n[mcp_servers.remote.http_headers]\nAuthorization = \"Bearer sk-kyris-test\"\n\"x-kyris-agent-id\" = \"openai/codex-cli\"\n"
        ).expect("parse");

        let result = rewrite_codex_mcp_servers(
            &mut config,
            "http://127.0.0.1:4710",
            "sk-kyris-test",
            "openai/codex-cli",
        );
        assert!(!result.changed);
        assert!(result.http_rewrites.is_empty());
    }
}
