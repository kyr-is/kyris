// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Structural diff and patch-unapply for JSON value trees.
//!
//! Mirrors the design of [`crate::toml_patch`]: operates on the parsed value
//! tree rather than text, so it is insensitive to whitespace or formatting
//! changes and survives user edits to unrelated parts of a config file.
//!
//! # Array handling
//!
//! Arrays are treated as atomic: if the array at a path changed, a `Replace`
//! op records the old array so it can be fully restored.  Element-level array
//! diffing (e.g. removing only the kyris hook from a hooks array that the user
//! also extended) is a planned improvement; the current approach is safe and
//! correct when the user has not added their own elements to the same array.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One reversible operation on a JSON value tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum JsonOp {
    /// A key at `path` was added; remove it on unapply.
    Add { path: Vec<String>, value: Value },
    /// A key at `path` existed with `old` value and was overwritten; restore it.
    Replace { path: Vec<String>, old: Value },
    /// A key at `path` existed with `old` value and was deleted; restore it.
    Remove { path: Vec<String>, old: Value },
}

/// Compute the ops that transform `old` into `new`.
pub fn diff(old: &Value, new: &Value) -> Vec<JsonOp> {
    let mut ops = Vec::new();
    diff_recursive(&[], old, new, &mut ops);
    ops
}

fn diff_recursive(prefix: &[String], old: &Value, new: &Value, ops: &mut Vec<JsonOp>) {
    match (old, new) {
        (Value::Object(old_m), Value::Object(new_m)) => {
            for (key, new_val) in new_m {
                let path = child_path(prefix, key);
                match old_m.get(key) {
                    Some(old_val) if old_val == new_val => {}
                    Some(old_val) => diff_recursive(&path, old_val, new_val, ops),
                    None => ops.push(JsonOp::Add {
                        path,
                        value: new_val.clone(),
                    }),
                }
            }
            for (key, old_val) in old_m {
                if !new_m.contains_key(key) {
                    ops.push(JsonOp::Remove {
                        path: child_path(prefix, key),
                        old: old_val.clone(),
                    });
                }
            }
        }
        _ => {
            if old != new {
                ops.push(JsonOp::Replace {
                    path: prefix.to_vec(),
                    old: old.clone(),
                });
            }
        }
    }
}

/// Reverse the ops on `root`, restoring the file to its pre-install state.
///
/// Best-effort: each op is tried independently; failures append a warning
/// string rather than aborting.
pub fn unapply(root: &mut Value, ops: &[JsonOp]) -> Vec<String> {
    let mut warnings = Vec::new();
    for op in ops.iter().rev() {
        match op {
            JsonOp::Add { path, value } => unapply_add(root, path, value, &mut warnings),
            JsonOp::Replace { path, old } => {
                if let Err(w) = set_at_path(root, path, old.clone()) {
                    warnings.push(format!("replace at {}: {w}", fmt_path(path)));
                }
            }
            JsonOp::Remove { path, old } => {
                if let Err(w) = set_at_path(root, path, old.clone()) {
                    warnings.push(format!("restore removed key at {}: {w}", fmt_path(path)));
                }
            }
        }
    }
    warnings
}

fn unapply_add(root: &mut Value, path: &[String], value: &Value, warnings: &mut Vec<String>) {
    if path.is_empty() {
        return;
    }
    if let Value::Object(added_m) = value {
        for (key, child_val) in added_m {
            unapply_add(root, &child_path(path, key), child_val, warnings);
        }
        if object_at_path(root, path).is_some_and(serde_json::Map::is_empty)
            && let Err(w) = remove_at_path(root, path)
        {
            warnings.push(format!("cleanup empty object at {}: {w}", fmt_path(path)));
        }
    } else {
        match remove_at_path(root, path) {
            Ok(_) => {}
            Err(w) => warnings.push(format!("remove at {}: {w}", fmt_path(path))),
        }
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn child_path(prefix: &[String], key: &str) -> Vec<String> {
    let mut p = prefix.to_vec();
    p.push(key.to_string());
    p
}

fn fmt_path(path: &[String]) -> String {
    path.join(".")
}

fn split_path(path: &[String]) -> Result<(&[String], &String), String> {
    path.split_last()
        .map(|(last, rest)| (rest, last))
        .ok_or_else(|| "path is empty".to_string())
}

fn object_at_path<'a>(
    root: &'a Value,
    path: &[String],
) -> Option<&'a serde_json::Map<String, Value>> {
    let mut cur = root.as_object()?;
    for seg in path {
        cur = cur.get(seg)?.as_object()?;
    }
    Some(cur)
}

fn object_at_path_mut<'a>(
    root: &'a mut Value,
    path: &[String],
) -> Option<&'a mut serde_json::Map<String, Value>> {
    let mut cur = root.as_object_mut()?;
    for seg in path {
        cur = cur.get_mut(seg)?.as_object_mut()?;
    }
    Some(cur)
}

fn remove_at_path(root: &mut Value, path: &[String]) -> Result<bool, String> {
    let (parent, key) = split_path(path)?;
    let Some(obj) = object_at_path_mut(root, parent) else {
        return Ok(false);
    };
    Ok(obj.remove(key).is_some())
}

fn set_at_path(root: &mut Value, path: &[String], value: Value) -> Result<(), String> {
    let (parent, key) = split_path(path)?;
    let mut cur = root
        .as_object_mut()
        .ok_or_else(|| "root is not an object".to_string())?;
    for seg in parent {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        cur = entry
            .as_object_mut()
            .ok_or_else(|| format!("'{seg}' is not an object"))?;
    }
    cur.insert(key.clone(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn assert_roundtrip(old: Value, new: Value) {
        let ops = diff(&old, &new);
        let mut result = new.clone();
        let warnings = unapply(&mut result, &ops);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(result, old, "roundtrip mismatch\nops: {ops:#?}");
    }

    #[test]
    fn diffIdenticalProducesNoOps() {
        let v = json!({"a": {"b": 1}});
        assert!(diff(&v, &v).is_empty());
    }

    #[test]
    fn diffTopLevelAdd() {
        let ops = diff(&json!({}), &json!({"key": "value"}));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], JsonOp::Add { path, .. } if path == &["key"]));
    }

    #[test]
    fn diffTopLevelReplace() {
        let ops = diff(&json!({"key": "old"}), &json!({"key": "new"}));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], JsonOp::Replace { path, old }
                if path == &["key"] && old == "old"));
    }

    #[test]
    fn diffTopLevelRemove() {
        let ops = diff(&json!({"key": "value"}), &json!({}));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], JsonOp::Remove { path, .. } if path == &["key"]));
    }

    #[test]
    fn diffNestedObjectAdd() {
        let ops = diff(
            &json!({}),
            &json!({"mcpServers": {"kyris-mcp": {"url": "http://..."}}}),
        );
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], JsonOp::Add { path, .. } if path == &["mcpServers"]));
    }

    #[test]
    fn diffNestedKeyInExistingObject() {
        let ops = diff(
            &json!({"mcpServers": {"other": {}}}),
            &json!({"mcpServers": {"other": {}, "kyris-mcp": {"url": "http://..."}}}),
        );
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], JsonOp::Add { path, .. }
                if path == &["mcpServers", "kyris-mcp"]));
    }

    #[test]
    fn diffArrayChangeProducesReplace() {
        let ops = diff(&json!({"arr": [1, 2]}), &json!({"arr": [1, 2, 3]}));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], JsonOp::Replace { path, .. } if path == &["arr"]));
    }

    #[test]
    fn unapplyAddedKeyRemoved() {
        let mut result = json!({"key": "value"});
        let ops = vec![JsonOp::Add {
            path: vec!["key".into()],
            value: json!("value"),
        }];
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result, json!({}));
    }

    #[test]
    fn unapplyReplacedValueRestored() {
        let mut result = json!({"key": "new"});
        let ops = vec![JsonOp::Replace {
            path: vec!["key".into()],
            old: json!("old"),
        }];
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result["key"], "old");
    }

    #[test]
    fn unapplyRemovedKeyRestored() {
        let mut result = json!({});
        let ops = vec![JsonOp::Remove {
            path: vec!["key".into()],
            old: json!("value"),
        }];
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn unapplyPreservesUserKeysInKyrisCreatedObject() {
        let old = json!({});
        let new_at_install = json!({"mcpServers": {"kyris-mcp": {"url": "http://..."}}});
        let ops = diff(&old, &new_at_install);

        let mut current = json!({
            "mcpServers": {
                "kyris-mcp": {"url": "http://..."},
                "user-mcp": {"url": "http://user"}
            }
        });
        let warnings = unapply(&mut current, &ops);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        let servers = current["mcpServers"].as_object().unwrap();
        assert!(!servers.contains_key("kyris-mcp"), "kyris key removed");
        assert!(servers.contains_key("user-mcp"), "user key preserved");
    }

    #[test]
    fn unapplyEmptiedObjectCleanedUp() {
        let old = json!({});
        let new = json!({"section": {"kyris_key": 1}});
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert!(result.as_object().unwrap().get("section").is_none());
    }

    #[test]
    fn unapplyAlreadyAbsentIsNoop() {
        let ops = vec![JsonOp::Add {
            path: vec!["key".into()],
            value: json!("value"),
        }];
        let mut already_clean = json!({});
        let warnings = unapply(&mut already_clean, &ops);
        assert!(warnings.is_empty());
    }

    #[test]
    fn unapplyTwiceIsIdempotent() {
        let old = json!({"x": 1});
        let new = json!({"x": 1, "y": 2});
        let ops = diff(&old, &new);
        let mut result = new;
        unapply(&mut result, &ops);
        let warnings = unapply(&mut result, &ops);
        assert!(warnings.is_empty(), "second pass: {warnings:?}");
        assert_eq!(result, old);
    }

    #[test]
    fn roundtripTopLevelAdd() {
        assert_roundtrip(
            json!({"existing": 1}),
            json!({"existing": 1, "new": "hello"}),
        );
    }

    #[test]
    fn roundtripNestedObject() {
        assert_roundtrip(
            json!({"existing": 1}),
            json!({"existing": 1, "mcpServers": {"kyris-mcp": {"url": "http://..."}}}),
        );
    }

    #[test]
    fn roundtripMultipleChanges() {
        assert_roundtrip(
            json!({"url": "http://old", "enabled": false}),
            json!({"url": "http://new", "enabled": true, "added": {"key": "val"}}),
        );
    }

    #[test]
    fn roundtripRemovedKey() {
        assert_roundtrip(json!({"a": 1, "b": 2}), json!({"a": 1}));
    }

    #[test]
    fn roundtripReplaceUserValueRestoresOriginal() {
        // kyris overwrites a value the user already set — unapply restores the
        // user's, not kyris's.
        assert_roundtrip(
            json!({"baseUrl": "https://user.example"}),
            json!({"baseUrl": "http://127.0.0.1:4710"}),
        );
    }

    #[test]
    fn roundtripArrayValueRestored() {
        assert_roundtrip(
            json!({"args": ["--foo"]}),
            json!({"args": ["--foo", "--kyris"]}),
        );
    }

    #[test]
    fn roundtripAgentConfigFullKyrisSetup() {
        // A realistic agent JSON config (cline/opencode shape) gaining the full
        // kyris integration — a routing baseUrl, an mcpServers.kyris-mcp block
        // (with the inbound auth header), and a hooks entry — and unapply must
        // restore the user's original config EXACTLY, leaving their own
        // mcpServers.other and apiProvider untouched. Mirrors the codex TOML
        // round-trip on the JSON side.
        let original = json!({
            "apiProvider": "anthropic",
            "mcpServers": {"other": {"command": "x"}},
        });
        let kyris_configured = json!({
            "apiProvider": "anthropic",
            "baseUrl": "http://127.0.0.1:4710",
            "mcpServers": {
                "other": {"command": "x"},
                "kyris-mcp": {"url": "http://127.0.0.1:4710/mcp", "headers": {"x-kyris-inbound": "sk-kyris-abc"}},
            },
            "hooks": {"PreToolUse": [{"command": "kyris_pretooluse"}]},
        });
        assert_roundtrip(original, kyris_configured);
    }
}
