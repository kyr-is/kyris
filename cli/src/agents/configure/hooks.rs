// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Live-hook and plugin-hook adapter installation: the generic, agent-id
//! templated bridges that route every tool call to the shared `kyris hook
//! check` engine, plus the code that writes them into each agent's config.
use super::registry;
use crate::config_writer::{NoopValidator, WellFormedJsonValidator};
use crate::integration::{
    ensure_json_array_contains, ensure_json_command_hook, read_json_value, write_json_value,
};
use crate::state::write_managed_file;

pub fn hook_script_source(agent_id: &str) -> String {
    // Discover the kyris binary at runtime instead of hardcoding a single
    // path. Preserves the original design's preference for the managed copy
    // at ~/.kyris/bin/kyris (writeable by `kyris install`, stable across
    // PATH changes) but falls back to common install locations when the
    // managed copy doesn't exist — covers install.sh-only users who never
    // ran `kyris install`, brew installs, and post-cleanup re-installs.
    //
    // PATH lookup is last because PATH could be attacker-influenced in
    // some hook-invocation contexts; a real kyris binary at a well-known
    // absolute path is preferred to whatever PATH resolves to.
    //
    // Fail-open with a stderr warning when no kyris is reachable: matches
    // AgentPact §11.1's "not installed" state (agent runs ungoverned).
    let template = r#"#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Kyris
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

export KYRIS_GOVERNED_SUBPROCESS="__AGENT_ID__"

KYRIS_BIN=""
for candidate in \
  "$HOME/.kyris/bin/kyris" \
  "$HOME/.local/bin/kyris" \
  "/opt/homebrew/bin/kyris" \
  "/usr/local/bin/kyris"; do
  if [ -x "$candidate" ]; then
    KYRIS_BIN="$candidate"
    break
  fi
done
if [ -z "$KYRIS_BIN" ] && command -v kyris >/dev/null 2>&1; then
  KYRIS_BIN="$(command -v kyris)"
fi
if [ -z "$KYRIS_BIN" ]; then
  echo "[agentpact-hook] kyris binary not found; skipping governance check" >&2
  exit 0
fi

exec "$KYRIS_BIN" hook check --agent __AGENT_ID__
"#;
    template.replace("__AGENT_ID__", agent_id)
}

pub fn shell_command(path: &std::path::Path) -> String {
    // POSIX single-quote escaping: the only character that cannot appear
    // inside single-quoted strings is the single-quote itself, which we
    // escape by ending the quote, inserting a literal \', and reopening.
    let escaped = path.display().to_string().replace('\'', "'\\''");
    format!("bash '{escaped}'")
}

pub fn install_live_hook_adapter(
    agent_id: &str,
    component: &str,
    // One registration per hook EVENT, same script for all (the engine
    // branches on the payload's hook_event_name) — codex registers both
    // PreToolUse and PermissionRequest; claude/gemini one event each.
    hook_phases: &[&str],
    script_path: &std::path::Path,
    hooks_file_path: &std::path::Path,
    nested: bool,
    // Per-hook timeout in the agent's units; see `ensure_json_command_hook`.
    // Set it when the agent's default hook timeout is below kyris's ~590s
    // no-TTY approval window (e.g. Gemini's 60s default).
    hook_timeout: Option<i64>,
) -> Result<Vec<String>, String> {
    let script_source = hook_script_source(agent_id);
    let mut changes = Vec::new();

    // Hook script is opaque shell — no schema to validate against.
    if write_managed_file(
        script_path,
        &script_source,
        component,
        Some(0o755),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", script_path.display()));
    }

    let mut hooks = read_json_value(hooks_file_path)?;
    let mut hooks_changed = false;
    for hook_phase in hook_phases {
        hooks_changed |= ensure_json_command_hook(
            &mut hooks,
            hook_phase,
            &shell_command(script_path),
            nested,
            hook_timeout,
        );
    }
    if hooks_changed {
        // Hooks file format varies per agent (claude/cline/codex/gemini have
        // different shapes); well-formedness is the safe baseline. Per-agent
        // shape validators can be added incrementally.
        write_json_value(hooks_file_path, &hooks, component, &WellFormedJsonValidator)?;
        changes.push(format!("updated {}", hooks_file_path.display()));
    }

    Ok(changes)
}

/// The JS plugin that delivers the live-hook adapter for agents whose
/// extension point is an in-process plugin (e.g. opencode) rather than a native
/// shell-script hook. It is the plugin-delivery twin of [`hook_script_source`]:
/// a GENERIC, agent-id-templated bridge that, on every tool call, asks the SAME
/// shared decision engine (`kyris hook check --agent <id>` → agentpactd) and
/// blocks the tool by throwing when governance denies. Reusable by any future
/// plugin-hook agent — the agent id and the spawn timeout (from the agent's
/// declared `HookRuntime`) are substituted.
pub fn plugin_hook_source(agent_id: &str) -> Result<String, String> {
    let spawn_timeout_ms = registry::agent_by_id(agent_id)
        .and_then(|a| a.hook_protocol())
        .map(|p| p.runtime.bridge_spawn_timeout_ms())
        .ok_or_else(|| {
            format!("{agent_id} declares no hook protocol — cannot derive the plugin spawn timeout")
        })?;
    let template = r#"// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
// Generated by Kyris — AgentPact live governance for __AGENT_ID__.
// On every tool call, ask `kyris hook check` (→ agentpactd) for a decision and
// block the tool (throw) when governance denies it. This is the plugin-delivery
// twin of the native shell-hook adapter; the decision engine is shared.
//
// The check runs via ASYNC spawn (not spawnSync): this plugin runs INSIDE the
// long-lived opencode server process, so a synchronous wait during a kyris
// approval hold would freeze every session, the HTTP API, and abort delivery
// for the whole hold window. The hook is awaited, so the event loop stays free.
import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { homedir } from "node:os"

// Prefer the managed copy, then well-known absolute install paths, then PATH —
// mirrors the shell adapter's resolution (a real binary at a known path is
// preferred to whatever PATH resolves to).
function kyrisBin() {
  for (const candidate of [
    homedir() + "/.kyris/bin/kyris",
    homedir() + "/.local/bin/kyris",
    "/opt/homebrew/bin/kyris",
    "/usr/local/bin/kyris",
  ]) {
    if (existsSync(candidate)) return candidate
  }
  return "kyris"
}

const KYRIS_BIN = kyrisBin()

// Resolve to {status} on a clean exit, {timedOut} if the engine outran the
// deadline (we SIGKILL it), or {error} if the binary could not run at all.
function runKyrisCheck(payload, cwd) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(KYRIS_BIN, ["hook", "check", "--agent", "__AGENT_ID__"], {
        cwd,
        env: { ...process.env, KYRIS_GOVERNED_SUBPROCESS: "__AGENT_ID__" },
      })
    } catch (e) {
      resolve({ error: e })
      return
    }
    let stdout = "", stderr = "", settled = false
    const finish = (r) => { if (!settled) { settled = true; clearTimeout(timer); resolve(r) } }
    const timer = setTimeout(() => { try { child.kill("SIGKILL") } catch {} finish({ timedOut: true }) }, __SPAWN_TIMEOUT_MS__)
    child.on("error", (e) => finish({ error: e })) // ENOENT etc. (fires async)
    child.stdout.on("data", (d) => { stdout += d })
    child.stderr.on("data", (d) => { stderr += d })
    child.on("close", (status) => finish({ status, stdout, stderr }))
    // A write to a dead child surfaces an ASYNC 'error' on the stdin stream that
    // a try/catch cannot catch; without this handler it would throw inside the
    // opencode server event loop. Fail open (a dead child → not-installed).
    child.stdin.on("error", (e) => finish({ error: e }))
    try { child.stdin.write(payload); child.stdin.end() } catch (e) { finish({ error: e }) }
  })
}

export const KyrisGovernance = async (input) => {
  // `cwd` is the permitted-domain anchor agentpactd resolves policy from
  // (opencode has no launch-dir env var, so it must ride in the payload). It
  // lives on the plugin-factory input (PluginInput.directory), NOT the per-hook
  // input.
  const cwd = input.directory
  return {
    "tool.execute.before": async (inp, out) => {
      const payload = JSON.stringify({ tool_name: inp.tool, tool_input: out?.args ?? {}, cwd })
      const res = await runKyrisCheck(payload, cwd)
      // A hung engine fails CLOSED: this agent has no native permission backstop
      // behind the plugin, so an unresolved check must become a deny, not a
      // silent allow. Only a missing/unrunnable binary fails open ("kyris not
      // installed → ungoverned", matching the shell adapter).
      if (res.timedOut) throw new Error("kyris governance check timed out before a decision")
      if (res.error) return
      // exit 0 = allow; nonzero (2 = deny) blocks this one tool call. The reason
      // arrives on stderr as "[agentpact] <reason>".
      if (res.status !== 0) {
        const reason = (res.stderr || res.stdout || "").trim().replace(/^\[agentpact\]\s*/, "")
        throw new Error(reason || "blocked by kyris governance")
      }
    },
  }
}
"#;
    Ok(template
        .replace("__AGENT_ID__", agent_id)
        .replace("__SPAWN_TIMEOUT_MS__", &spawn_timeout_ms.to_string()))
}

/// Install the live-hook adapter for a PLUGIN-hook agent: write the generic
/// kyris governance plugin and register it in the agent's config `plugin` array.
/// Plugin-delivery twin of [`install_live_hook_adapter`]; pairs with the agent's
/// `hook_protocol()` and the shared `kyris hook check` engine.
pub fn install_plugin_hook_adapter(
    agent_id: &str,
    component: &str,
    plugin_path: &std::path::Path,
    config_path: &std::path::Path,
) -> Result<Vec<String>, String> {
    let mut changes = Vec::new();

    if write_managed_file(
        plugin_path,
        &plugin_hook_source(agent_id)?,
        component,
        Some(0o644),
        &NoopValidator,
    )? {
        changes.push(format!("wrote {}", plugin_path.display()));
    }

    let mut config = if config_path.exists() {
        read_json_value(config_path)?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    let plugin_spec = plugin_path.to_string_lossy();
    if ensure_json_array_contains(&mut config, &["plugin"], &plugin_spec) {
        write_json_value(config_path, &config, component, &WellFormedJsonValidator)?;
        changes.push(format!(
            "registered kyris governance plugin in {}",
            config_path.display()
        ));
    }

    Ok(changes)
}
