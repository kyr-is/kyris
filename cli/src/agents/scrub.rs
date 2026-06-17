// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Manifest-independent removal (and detection) of kyris residue in an agent's
//! config files.
//!
//! The manifest-driven undo (`undo_agent` → `manifest_restore`) is correct when
//! the manifest faithfully records every edit. But it silently leaves residue
//! whenever the manifest is stale, missing, or never recorded an edit — e.g. a
//! `strip_*` op that was a no-op at setup, or a hook registration written by a
//! prior kyris version. This pass closes that gap: it walks each agent's config
//! by KYRIS SIGNATURE (not by manifest) and removes only kyris-authored content,
//! so `kyris uninstall` and `kyris agent disconnect` leave nothing behind, and
//! [`contains_kyris_residue`] lets uninstall VERIFY the result.
//!
//! Signatures are kyris's own namespaced tokens (`sk-kyris-`, `x-kyris-*`,
//! `kyris-governance`, …) plus the LIVE kyrisd authority passed in by the
//! caller. The kyrisd address is never hardcoded — `127.0.0.1:4710` is only the
//! dev default; production listens elsewhere — so it is resolved from config at
//! call time via [`authority_of`].

use std::path::Path;

use serde_json::Value;

use crate::integration::is_kyris_key;

/// Object keys kyris injects to authenticate/attribute a request to kyrisd.
const KYRIS_HEADER_KEYS: &[&str] = &["x-kyris-inbound", "x-kyris-agent-id"];

/// Base-URL key names kyris writes alongside its auth header. Removed as a
/// sibling whenever a kyris auth header is present in the same object — host- and
/// port-independent, so it works on whatever address kyrisd is configured with.
const BASEURL_KEYS: &[&str] = &["baseURL", "baseUrl", "base_url"];

/// Substrings that prove a JSON value (string, array entry, or sub-object key)
/// is kyris-authored. Used to drop whole entries — a plugin reference, an MCP
/// server, a hook command — that the agent's config would otherwise keep
/// pointing at a now-removed kyris binary.
pub const KYRIS_CONTENT_MARKERS: &[&str] = &[
    "kyris-governance",
    "kyris-mcp",
    "kyris-hook",
    "kyris hook check",
    "agentpact_pretooluse",
    "agentpact_beforetool",
    "kyris_pretooluse",
    "/.kyris/",
];

/// kyris signatures for a RAW config-file scan (uninstall verification). All are
/// kyris's own namespaced tokens — host/port-INDEPENDENT — so verification never
/// hardcodes a kyrisd address. The live kyrisd authority is appended by the
/// caller (from config) when it is known.
pub const RESIDUE_SCAN_MARKERS: &[&str] = &[
    "sk-kyris",
    "x-kyris-",
    "kyris-governance",
    "kyris-mcp",
    "kyris-hook",
    "kyris hook check",
    "agentpact_pretooluse",
    "agentpact_beforetool",
    "kyris_pretooluse",
    "/.kyris/",
    "model_providers.kyris",
    "KYRIS_GOVERNED_SUBPROCESS",
];

/// The authority (`host:port`) of a kyrisd base URL —
/// `http://127.0.0.1:4710/v1` → `127.0.0.1:4710`. Derived from the LIVE kyris
/// config at call time (never a hardcoded constant), so it matches whatever
/// address kyrisd actually listens on. `None` for an empty/malformed URL.
#[must_use]
pub fn authority_of(base_url: &str) -> Option<&str> {
    let rest = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or(rest);
    (!authority.is_empty()).then_some(authority)
}

/// True when a string value is kyris routing/credential: a kyris-issued key, or
/// a URL on the live kyrisd authority (when known).
fn is_kyris_value(s: &str, kyrisd_authority: Option<&str>) -> bool {
    is_kyris_key(s) || kyrisd_authority.is_some_and(|a| s.contains(a))
}

/// True when `path`'s contents carry a kyris content marker — the gate before
/// deleting a hook/plugin SCRIPT file kyris installed, so a same-named file owned
/// by someone else is left untouched.
pub fn file_has_kyris_marker(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|c| KYRIS_CONTENT_MARKERS.iter().any(|m| c.contains(m)))
}

/// Whether a JSON subtree (key or value) contains any kyris CONTENT marker —
/// used to drop kyris array entries (a `plugin` reference, a hook matcher).
fn json_has_kyris_marker(v: &Value) -> bool {
    match v {
        Value::String(s) => KYRIS_CONTENT_MARKERS.iter().any(|m| s.contains(m)),
        Value::Array(a) => a.iter().any(json_has_kyris_marker),
        Value::Object(o) => o.iter().any(|(k, vv)| {
            KYRIS_CONTENT_MARKERS.iter().any(|m| k.contains(m)) || json_has_kyris_marker(vv)
        }),
        _ => false,
    }
}

/// Recursively remove kyris-signature content from a parsed agent config.
/// Returns `true` if anything was removed. `kyrisd_authority` is the live
/// `host:port` kyrisd listens on (from [`authority_of`]), or `None` when it
/// can't be resolved — in which case URL residue is matched only via the
/// `x-kyris` header sibling, while keys/headers/markers are still removed.
///
/// Surgical by construction: it deletes the kyris auth headers, a kyris-issued
/// `apiKey`, any kyrisd-routing URL, kyris array entries (plugins/hooks), and
/// kyris-keyed sub-objects (MCP servers) — and collapses any wrapper object
/// (`headers`/`options`, or a whole provider stub) that kyris removal emptied —
/// but never a user's surrounding structure or an object that still holds user
/// data.
pub fn scrub_kyris_json(v: &mut Value, kyrisd_authority: Option<&str>) -> bool {
    match v {
        Value::Object(map) => {
            let mut changed = false;
            // This object is a kyris routing block if it carries a kyris auth
            // header directly OR nested in a `headers`/`http_headers` child (the
            // usual shape: `{ baseURL, headers: { x-kyris-inbound } }`).
            let had_kyris_header = KYRIS_HEADER_KEYS.iter().any(|h| map.contains_key(*h))
                || ["headers", "http_headers"].iter().any(|hk| {
                    map.get(*hk)
                        .and_then(Value::as_object)
                        .is_some_and(|h| KYRIS_HEADER_KEYS.iter().any(|kh| h.contains_key(*kh)))
                });

            for k in KYRIS_HEADER_KEYS {
                if map.remove(*k).is_some() {
                    changed = true;
                }
            }
            // Any key whose value is a kyris-issued key (sk-kyris-…) or a URL on
            // the live kyrisd authority — catches every base-URL variant
            // (`baseURL`, `anthropicBaseUrl`, …) without a hardcoded host.
            let kyris_valued: Vec<String> = map
                .iter()
                .filter(|(_, val)| {
                    val.as_str()
                        .is_some_and(|s| is_kyris_value(s, kyrisd_authority))
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in kyris_valued {
                map.remove(&k);
                changed = true;
            }
            // A base URL written next to a kyris auth header is kyris's routing
            // too — drop it even when the live authority is unknown (config wiped).
            if had_kyris_header {
                for k in BASEURL_KEYS {
                    if map.remove(*k).is_some() {
                        changed = true;
                    }
                }
            }

            for key in map.keys().cloned().collect::<Vec<_>>() {
                // A whole sub-object keyed by a kyris marker (e.g. an MCP server
                // entry named `kyris-mcp-…`) is entirely kyris's — drop it.
                if KYRIS_CONTENT_MARKERS.iter().any(|m| key.contains(m)) {
                    map.remove(&key);
                    changed = true;
                    continue;
                }
                let child = map.get_mut(&key).expect("key just listed");
                if let Value::Array(arr) = child {
                    let before = arr.len();
                    arr.retain(|e| !json_has_kyris_marker(e));
                    changed |= arr.len() != before;
                    for e in arr.iter_mut() {
                        changed |= scrub_kyris_json(e, kyrisd_authority);
                    }
                    continue;
                }
                // Object (recurse) or scalar (a no-op). An object emptied ENTIRELY
                // by removing kyris content was kyris's own (a `headers` wrapper, a
                // provider's `options`, or a whole provider stub) — so prune it.
                // Pruning only when our OWN removal emptied it leaves a user's
                // pre-existing empty object untouched.
                if scrub_kyris_json(child, kyrisd_authority) {
                    changed = true;
                    if child.as_object().is_some_and(serde_json::Map::is_empty) {
                        map.remove(&key);
                    }
                }
            }
            changed
        }
        Value::Array(arr) => {
            let before = arr.len();
            arr.retain(|e| !json_has_kyris_marker(e));
            for e in arr.iter_mut() {
                let _ = scrub_kyris_json(e, kyrisd_authority);
            }
            arr.len() != before
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A sample dev authority — only a TEST fixture; production code resolves it
    // from config via `authority_of`, never a hardcoded constant.
    const AUTH: Option<&str> = Some("127.0.0.1:4710");

    fn scrub(s: &str) -> Value {
        let mut v: Value = serde_json::from_str(s).unwrap();
        scrub_kyris_json(&mut v, AUTH);
        v
    }

    #[test]
    fn testAuthorityOfStripsSchemeAndPath() {
        assert_eq!(
            authority_of("http://127.0.0.1:4710/v1"),
            Some("127.0.0.1:4710")
        );
        assert_eq!(
            authority_of("https://kyrisd.example.com:8443"),
            Some("kyrisd.example.com:8443")
        );
        assert_eq!(authority_of(""), None);
    }

    #[test]
    fn testScrubsOpencodeStaleKeyHeadersAndBaseUrl() {
        let v = scrub(
            r#"{"provider":{"anthropic":{"options":{
                "baseURL":"http://127.0.0.1:4710/v1",
                "apiKey":"sk-kyris-53d867STALE",
                "headers":{"x-kyris-inbound":"sk-kyris-50c3","x-kyris-agent-id":"opencode/opencode"},
                "model":"claude-haiku-4-5"
            }}}}"#,
        );
        let opts = &v["provider"]["anthropic"]["options"];
        assert!(opts.get("apiKey").is_none(), "stale kyris apiKey removed");
        assert!(opts.get("baseURL").is_none(), "kyrisd baseURL removed");
        assert!(
            opts.get("headers").is_none(),
            "emptied kyris headers pruned"
        );
        assert_eq!(opts["model"], "claude-haiku-4-5", "user field survives");
    }

    #[test]
    fn testScrubsClineGlobalStateBaseUrlsByAuthority() {
        // cline mirrors the kyrisd base URL into its state cache under
        // non-standard key names with NO sibling header — only the live
        // authority identifies them.
        let v = scrub(
            r#"{"anthropicBaseUrl":"http://127.0.0.1:4710","openAiBaseUrl":"http://127.0.0.1:4710/v1","welcomeViewCompleted":false}"#,
        );
        assert!(v.get("anthropicBaseUrl").is_none());
        assert!(v.get("openAiBaseUrl").is_none());
        assert_eq!(v["welcomeViewCompleted"], false, "user state survives");
    }

    #[test]
    fn testHeaderSiblingBaseUrlRemovedWithoutAuthority() {
        // Even with NO live authority, a baseURL next to a kyris header is dropped.
        let mut v: Value = serde_json::from_str(
            r#"{"settings":{"baseUrl":"http://anything:9999","headers":{"x-kyris-inbound":"sk-kyris-x"}}}"#,
        )
        .unwrap();
        scrub_kyris_json(&mut v, None);
        assert!(
            v["settings"].get("baseUrl").is_none(),
            "sibling baseUrl removed"
        );
        assert!(
            v["settings"].get("headers").is_none(),
            "emptied headers pruned"
        );
    }

    #[test]
    fn testCollapsesAllKyrisProviderStubs() {
        let v = scrub(
            r#"{
                "permission":{"bash":{"ls":"allow"}},
                "provider":{
                    "anthropic":{"options":{"apiKey":"sk-kyris-53d8","baseURL":"http://127.0.0.1:4710"}},
                    "openai":{"options":{"apiKey":"sk-kyris-53d8","baseURL":"http://127.0.0.1:4710/v1"}},
                    "google":{"options":{"apiKey":"sk-kyris-53d8","baseURL":"http://127.0.0.1:4710"}}
                }
            }"#,
        );
        assert!(
            v.get("provider").is_none(),
            "all-kyris provider block collapses"
        );
        assert_eq!(
            v["permission"]["bash"]["ls"], "allow",
            "user config survives"
        );
    }

    #[test]
    fn testKeepsProviderWithUserOptionsAlongsideKyris() {
        let v = scrub(
            r#"{"provider":{"anthropic":{"options":{"apiKey":"sk-kyris-x","model":"claude-haiku-4-5"}}}}"#,
        );
        let opts = &v["provider"]["anthropic"]["options"];
        assert!(opts.get("apiKey").is_none());
        assert_eq!(opts["model"], "claude-haiku-4-5");
    }

    #[test]
    fn testRemovesPluginEntryButKeepsUserPlugins() {
        let v = scrub(
            r#"{"plugin":["/Users/x/.config/opencode/kyris-governance.js","my-other-plugin"]}"#,
        );
        assert_eq!(v["plugin"], serde_json::json!(["my-other-plugin"]));
    }

    #[test]
    fn testRemovesKyrisHookMatcherFromClaudeSettings() {
        let v = scrub(
            r#"{"hooks":{"PreToolUse":[
                {"matcher":"*","hooks":[{"type":"command","command":"~/.claude/hooks/agentpact_pretooluse.sh"}]},
                {"matcher":"Edit","hooks":[{"type":"command","command":"my-linter"}]}
            ]}}"#,
        );
        let arr = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "only the user's matcher remains");
        assert_eq!(arr[0]["matcher"], "Edit");
    }

    #[test]
    fn testRemovesKyrisMcpServerByKey() {
        let v = scrub(
            r#"{"mcpServers":{"kyris-mcp-fs":{"command":"kyris-mcp"},"my-server":{"command":"x"}}}"#,
        );
        let servers = v["mcpServers"].as_object().unwrap();
        assert!(!servers.contains_key("kyris-mcp-fs"));
        assert!(servers.contains_key("my-server"));
    }

    #[test]
    fn testLeavesRealProviderKeyAndUserBaseUrl() {
        let v = scrub(
            r#"{"provider":{"anthropic":{"options":{"apiKey":"sk-ant-REAL","baseURL":"https://api.anthropic.com"}}}}"#,
        );
        let opts = &v["provider"]["anthropic"]["options"];
        assert_eq!(opts["apiKey"], "sk-ant-REAL");
        assert_eq!(opts["baseURL"], "https://api.anthropic.com");
    }

    #[test]
    fn testNoKyrisContentIsNoOp() {
        let mut v: Value = serde_json::from_str(r#"{"a":{"b":[1,2,3]},"c":"d"}"#).unwrap();
        assert!(
            !scrub_kyris_json(&mut v, AUTH),
            "no change when nothing kyris"
        );
    }
}
