// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{Path, Permission, id_to_shell, load_merged_policy};

/// Gemini in-file priority for compiled DENY rules: near the top of the user
/// tier (effective `4 + 900/1000`), so a kyris deny is hard to shadow
/// accidentally — only a deliberately higher user rule or the admin tier (5.x)
/// outranks it.
const GEMINI_DENY_PRIORITY: u32 = 900;
/// Compiled ALLOW rules sit LOW in the user tier (effective `4.100`): they
/// beat gemini's defaults (1.x) — which is what suppresses the redundant
/// native prompt for catalog-auto commands — while any user-authored rule
/// above 100, and every kyris deny, still wins.
const GEMINI_ALLOW_PRIORITY: u32 = 100;

pub fn compile_gemini_permissions(
    policy_path: Option<&Path>,
) -> Result<(serde_json::Value, u32), String> {
    let level = load_merged_policy(policy_path)?;

    // Only allow + deny compile. Ask rules are deliberately DROPPED: the live
    // hook owns asks (kyris popup), and a user-tier ask rule (4.x) would both
    // re-prompt natively after a kyris approval AND override the user's own
    // gemini-side "Always allow" persistence (3.95). In hook-less compiled-only
    // fallback the dropped asks fall to gemini's defaults — the recorded
    // CoverageCeiling::Compiled degradation.
    let mut ask_dropped: u32 = 0;
    let mut decision_for = |perm: &Permission| -> Option<(&'static str, u32)> {
        match perm {
            Permission::Auto => Some(("allow", GEMINI_ALLOW_PRIORITY)),
            Permission::Deny => Some(("deny", GEMINI_DENY_PRIORITY)),
            Permission::Ask => {
                ask_dropped += 1;
                None
            }
        }
    };

    let mut rules = Vec::new();

    for (command_id, perm) in &level.commands {
        let Some((decision, priority)) = decision_for(perm) else {
            continue;
        };
        // `commandPrefix` is gemini's own convenience: ITS loader compiles the
        // prefix into the correct regex against the NUL-delimited
        // stable-stringified args. A hand-built `argsPattern` like
        // `^git status…` can never match that representation — the old shape
        // every rule used, one of the reasons the file was dead.
        rules.push(serde_json::json!({
            "toolName": "run_shell_command",
            "commandPrefix": id_to_shell(command_id),
            "decision": decision,
            "priority": priority,
        }));
    }

    for (path_pattern, perm) in &level.paths {
        let Some((decision, priority)) = decision_for(perm) else {
            continue;
        };
        let escaped = regex::escape(path_pattern).replace(r"\*", ".*");
        // Anchor BOTH ends to the argument FIELD (mirroring gemini's own
        // commandRegex compilation against stable-stringified args). The
        // leading `"file_path":"` cannot occur inside an escaped JSON string
        // value, so file CONTENT mentioning a path can't trip the rule; the
        // trailing `"` closes the value so an exact path (no glob) matches
        // ONLY that path — without it an allow on `/tmp/safe` would also
        // auto-approve `/tmp/safeEVIL`. A glob's trailing `.*` still consumes
        // up to the closing quote, so wildcards stay broad.
        let pattern = format!("\"file_path\":\"{escaped}\"");
        for tool_name in ["read_file", "write_file", "replace"] {
            rules.push(serde_json::json!({
                "toolName": tool_name,
                "argsPattern": pattern,
                "decision": decision,
                "priority": priority,
            }));
        }
    }

    for ((server, tool), perm) in &level.mcp {
        let Some((decision, priority)) = decision_for(perm) else {
            continue;
        };
        rules.push(serde_json::json!({
            "toolName": format!("mcp_{server}_{tool}"),
            "decision": decision,
            "priority": priority,
        }));
    }

    rules.sort_by(|a, b| {
        let tool_cmp = a["toolName"]
            .as_str()
            .unwrap_or("")
            .cmp(b["toolName"].as_str().unwrap_or(""));
        tool_cmp
            .then_with(|| {
                a["commandPrefix"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["commandPrefix"].as_str().unwrap_or(""))
            })
            .then_with(|| {
                a["argsPattern"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["argsPattern"].as_str().unwrap_or(""))
            })
    });

    Ok((serde_json::Value::Array(rules), ask_dropped))
}

/// One compiled rule, serialized to a `[[rule]]` table (gemini's loader key —
/// a `[[rules]]` array is silently ignored). Field order is the emitted order.
/// Pattern fields are real TOML strings (NOT hand-quoted literals) so the
/// `toml` serializer escapes quotes/backslashes — a prefix like `tr -d "'"`
/// carries a single quote that a `'…'` literal would terminate early,
/// producing invalid TOML that breaks Gemini's policy load.
#[derive(serde::Serialize)]
struct GeminiPolicyRule {
    #[serde(rename = "toolName", skip_serializing_if = "Option::is_none")]
    tool_name: Option<String>,
    #[serde(rename = "commandPrefix", skip_serializing_if = "Option::is_none")]
    command_prefix: Option<String>,
    #[serde(rename = "argsPattern", skip_serializing_if = "Option::is_none")]
    args_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u32>,
}

#[derive(serde::Serialize)]
struct GeminiPolicyFile {
    rule: Vec<GeminiPolicyRule>,
}

/// Whether a policy TOML would actually LOAD rules in Gemini CLI. This mirrors
/// gemini's loader contract (`policy/toml-loader.ts`, verified at 0567b25a2):
/// rules live in a top-level **`[[rule]]`** array-of-tables; `toolName`,
/// `decision`, and `priority` are all REQUIRED (one rule failing zod makes
/// gemini skip the ENTIRE file); decision is the lowercase enum
/// `allow | deny | ask_user`; priority is an integral number in `0..=999`
/// (gemini's check is JS `Number.isInteger`, so a zero-fraction TOML float
/// passes). A file failing any of this loads ZERO rules — silently — so the
/// probe must not count it as an adapted surface.
///
/// Single-source note: this validator and [`serialize_gemini_policy_toml`]
/// together define kyris's understanding of gemini's contract; the serializer
/// output must satisfy the validator
/// (`testSerializerOutputLoadsInGemini`).
pub fn gemini_policy_file_is_loadable(contents: &str) -> bool {
    // `toml::from_str` parses a DOCUMENT; `str::parse::<toml::Value>` would
    // parse a single value and reject `[[rule]]` tables.
    let Ok(value) = toml::from_str::<toml::Value>(contents) else {
        return false;
    };
    let Some(rules) = value.get("rule").and_then(toml::Value::as_array) else {
        return false;
    };
    if rules.is_empty() {
        return false;
    }
    rules.iter().all(|rule| {
        let Some(table) = rule.as_table() else {
            return false;
        };
        let tool_ok = match table.get("toolName") {
            Some(toml::Value::String(_)) => true,
            Some(toml::Value::Array(names)) => {
                !names.is_empty() && names.iter().all(toml::Value::is_str)
            }
            _ => false,
        };
        let decision_ok = table
            .get("decision")
            .and_then(toml::Value::as_str)
            .is_some_and(|d| matches!(d, "allow" | "deny" | "ask_user"));
        let priority_ok = match table.get("priority") {
            Some(toml::Value::Integer(p)) => (0..=999).contains(p),
            Some(toml::Value::Float(p)) => p.fract() == 0.0 && (0.0..=999.0).contains(p),
            _ => false,
        };
        tool_ok && decision_ok && priority_ok
    })
}

pub fn serialize_gemini_policy_toml(rules: &serde_json::Value) -> String {
    let mut out = String::from("# Generated by Kyris — AgentPact compiled policy for Gemini CLI\n");
    out.push_str(
        "# Loads at the USER tier (~/.gemini/policies = effective priority 4.x);\n\
         # kyris denies sit at 900 (hard to shadow), allows at 100 (any user rule\n\
         # above 100 and every deny outranks them). Admin tier (5.x) always wins.\n\n",
    );
    let Some(arr) = rules.as_array() else {
        return out;
    };
    if arr.is_empty() {
        return out;
    }

    let policy = GeminiPolicyFile {
        rule: arr
            .iter()
            .map(|rule| GeminiPolicyRule {
                tool_name: rule["toolName"].as_str().map(str::to_string),
                command_prefix: rule["commandPrefix"].as_str().map(str::to_string),
                args_pattern: rule["argsPattern"].as_str().map(str::to_string),
                decision: rule["decision"].as_str().map(str::to_string),
                priority: rule["priority"]
                    .as_u64()
                    .and_then(|p| u32::try_from(p).ok()),
            })
            .collect(),
    };
    // toml::to_string emits `[[rule]]` array-of-tables and escapes every string
    // value correctly — no manual quoting, so no quote/backslash can break the file.
    match toml::to_string(&policy) {
        Ok(body) => out.push_str(&body),
        // A serialize failure here is not expected (all values are plain
        // scalars); surface it as a comment rather than emitting a broken file.
        Err(e) => {
            use std::fmt::Write;
            let _ = writeln!(out, "# ERROR: failed to serialize policy: {e}");
        }
    }
    out
}
