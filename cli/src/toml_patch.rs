// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Structural diff and patch-unapply for TOML value trees.
//!
//! Unlike unified text diffs, these operations work on the parsed value tree,
//! so they are insensitive to whitespace or formatting changes and remain
//! correct when the user edits unrelated parts of the file after install.
//!
//! # Unapply semantics for `Add`
//!
//! When the added value is a Table, only the keys that kyris added are removed —
//! keys the user added to the same table after install are preserved.  If the
//! table becomes empty after removal, the table itself is also removed.
//! Non-table added values (scalars, arrays) are removed outright.

use serde::{Deserialize, Serialize};

/// One reversible operation on a TOML value tree.
///
/// A `Vec<TomlOp>` produced by [`diff`] records the transformation applied at
/// install time.  Passing it to [`unapply`] on the current file content
/// reverses the change without touching anything kyris did not modify.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TomlOp {
    /// A key at `path` was added by kyris; remove it on unapply.
    /// `value` is stored for debuggability; only `path` is used by unapply.
    Add {
        path: Vec<String>,
        value: toml::Value,
    },
    /// A key at `path` existed with `old` value and was overwritten; restore
    /// `old` on unapply.
    Replace { path: Vec<String>, old: toml::Value },
    /// A key at `path` existed with `old` value and was deleted; restore it on
    /// unapply.
    Remove { path: Vec<String>, old: toml::Value },
}

/// Compute the ops that transform `old` into `new`.
///
/// Applying [`unapply`] with the returned ops to `new` (or any state of the
/// file that still contains the kyris-added content) reverses the change.
///
/// The diff recurses into Tables so each op targets the smallest unit of change.
/// For example, adding `model_providers.kyris` when `model_providers` already
/// exists produces `Add { path: ["model_providers", "kyris"], .. }` rather than
/// replacing the whole `model_providers` section.
pub fn diff(old: &toml::Value, new: &toml::Value) -> Vec<TomlOp> {
    let mut ops = Vec::new();
    diff_recursive(&[], old, new, &mut ops);
    ops
}

fn diff_recursive(prefix: &[String], old: &toml::Value, new: &toml::Value, ops: &mut Vec<TomlOp>) {
    match (old, new) {
        (toml::Value::Table(old_t), toml::Value::Table(new_t)) => {
            for (key, new_val) in new_t {
                let path = child_path(prefix, key);
                match old_t.get(key) {
                    Some(old_val) if old_val == new_val => {} // identical — no op
                    Some(old_val) => diff_recursive(&path, old_val, new_val, ops),
                    None => ops.push(TomlOp::Add {
                        path,
                        value: new_val.clone(),
                    }),
                }
            }
            for (key, old_val) in old_t {
                if !new_t.contains_key(key) {
                    ops.push(TomlOp::Remove {
                        path: child_path(prefix, key),
                        old: old_val.clone(),
                    });
                }
            }
        }
        _ => {
            if old != new {
                ops.push(TomlOp::Replace {
                    path: prefix.to_vec(),
                    old: old.clone(),
                });
            }
        }
    }
}

/// Reverse the ops on `root`, restoring the file to its pre-install state.
///
/// Best-effort: each op is attempted independently.  If an op cannot be applied
/// (e.g. the key was already removed by the user), a warning string is appended
/// to the returned `Vec` rather than aborting.  The caller should log warnings
/// but continue the uninstall.
///
/// Ops are processed in reverse order so nested removals happen before their
/// parents are examined for emptiness.
pub fn unapply(root: &mut toml::Value, ops: &[TomlOp]) -> Vec<String> {
    let mut warnings = Vec::new();
    for op in ops.iter().rev() {
        match op {
            TomlOp::Add { path, value } => unapply_add(root, path, value, &mut warnings),
            TomlOp::Replace { path, old } => {
                if let Err(w) = set_at_path(root, path, old.clone()) {
                    warnings.push(format!("replace at {}: {w}", fmt_path(path)));
                }
            }
            TomlOp::Remove { path, old } => {
                if let Err(w) = set_at_path(root, path, old.clone()) {
                    warnings.push(format!("restore removed key at {}: {w}", fmt_path(path)));
                }
            }
        }
    }
    warnings
}

/// Unapply an `Add` op surgically.
///
/// If `value` is a Table, only the keys that appear in `value` are removed from
/// the current table at `path` — any keys the user added to the same table
/// after kyris install are left untouched.  After removing kyris's keys, if the
/// table at `path` is now empty it is also removed.
///
/// Non-table `value`s (scalars, arrays) remove `path` outright.
fn unapply_add(
    root: &mut toml::Value,
    path: &[String],
    value: &toml::Value,
    warnings: &mut Vec<String>,
) {
    if path.is_empty() {
        return;
    }
    if let toml::Value::Table(added_t) = value {
        // Recurse: remove only the keys kyris added, preserving user-added ones.
        for (key, child_val) in added_t {
            unapply_add(root, &child_path(path, key), child_val, warnings);
        }
        // Clean up the parent if it is now empty.
        if table_at_path(root, path).is_some_and(toml::map::Map::is_empty)
            && let Err(w) = remove_at_path(root, path)
        {
            warnings.push(format!("cleanup empty table at {}: {w}", fmt_path(path)));
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

fn table_at_path<'a>(root: &'a toml::Value, path: &[String]) -> Option<&'a toml::Table> {
    let mut cur = root.as_table()?;
    for seg in path {
        cur = cur.get(seg)?.as_table()?;
    }
    Some(cur)
}

fn table_at_path_mut<'a>(
    root: &'a mut toml::Value,
    path: &[String],
) -> Option<&'a mut toml::Table> {
    let mut cur = root.as_table_mut()?;
    for seg in path {
        cur = cur.get_mut(seg)?.as_table_mut()?;
    }
    Some(cur)
}

/// Remove the key at `path` from `root`.  Returns `Ok(false)` if the path was
/// already absent (idempotent).
fn remove_at_path(root: &mut toml::Value, path: &[String]) -> Result<bool, String> {
    let (parent, key) = split_path(path)?;
    let Some(table) = table_at_path_mut(root, parent) else {
        return Ok(false); // parent absent → key already gone
    };
    Ok(table.remove(key).is_some())
}

/// Set the key at `path` in `root` to `value`, creating intermediate Tables as
/// needed.
fn set_at_path(root: &mut toml::Value, path: &[String], value: toml::Value) -> Result<(), String> {
    let (parent, key) = split_path(path)?;
    let mut cur = root
        .as_table_mut()
        .ok_or_else(|| "root is not a table".to_string())?;
    for seg in parent {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = entry
            .as_table_mut()
            .ok_or_else(|| format!("'{seg}' is not a table"))?;
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

    fn parse(s: &str) -> toml::Value {
        toml::from_str(s).expect("valid TOML")
    }

    /// Apply the diff of `old→new` to `new` and assert the result equals `old`.
    fn assert_roundtrip(old_src: &str, new_src: &str) {
        let old = parse(old_src);
        let new = parse(new_src);
        let ops = diff(&old, &new);
        let mut result = new.clone();
        let warnings = unapply(&mut result, &ops);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(result, old, "roundtrip mismatch\nops: {ops:#?}");
    }

    // -----------------------------------------------------------------------
    // diff — basic cases
    // -----------------------------------------------------------------------

    #[test]
    fn diffIdenticalProducesNoOps() {
        let v = parse("[a]\nb = 1\n");
        assert!(diff(&v, &v).is_empty());
    }

    #[test]
    fn diffEmptyToEmptyProducesNoOps() {
        assert!(diff(&parse(""), &parse("")).is_empty());
    }

    #[test]
    fn diffTopLevelAdd() {
        let ops = diff(&parse(""), &parse("key = \"value\"\n"));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Add { path, .. } if path == &["key"]));
    }

    #[test]
    fn diffTopLevelReplace() {
        let ops = diff(&parse("key = \"old\"\n"), &parse("key = \"new\"\n"));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Replace { path, old }
                if path == &["key"] && old.as_str() == Some("old")));
    }

    #[test]
    fn diffTopLevelRemove() {
        let ops = diff(&parse("key = \"value\"\n"), &parse(""));
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Remove { path, .. } if path == &["key"]));
    }

    #[test]
    fn diffBooleanToggle() {
        let ops = diff(
            &parse("[features]\ncod_hooks = false\n"),
            &parse("[features]\ncod_hooks = true\n"),
        );
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Replace { path, old }
                if path == &["features", "cod_hooks"] && old.as_bool() == Some(false)));
    }

    #[test]
    fn diffNewSectionWhenParentAbsent() {
        // model_providers didn't exist in old → entire section is one Add
        let ops = diff(
            &parse(""),
            &parse("[model_providers.kyris]\nname = \"Kyris\"\n"),
        );
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Add { path, .. } if path == &["model_providers"]));
    }

    #[test]
    fn diffNewKeyInsideExistingTable() {
        // model_providers existed; kyris adds a sub-section
        let ops = diff(
            &parse("[model_providers]\nother = 1\n"),
            &parse("[model_providers]\nother = 1\n\n[model_providers.kyris]\nname = \"Kyris\"\n"),
        );
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Add { path, .. }
                if path == &["model_providers", "kyris"]));
    }

    #[test]
    fn diffMultipleChangesCountedCorrectly() {
        let old = parse("base_url = \"http://old\"\n[features]\ncod = false\n");
        let new = parse(
            "base_url = \"http://new\"\n[features]\ncod = true\n[model_providers.kyris]\nname = \"K\"\n",
        );
        // Expect: Replace base_url, Replace features.cod, Add model_providers
        assert_eq!(diff(&old, &new).len(), 3);
    }

    #[test]
    fn diffArrayChangeProducesReplace() {
        let old = parse("items = [1, 2]\n");
        let new = parse("items = [1, 2, 3]\n");
        let ops = diff(&old, &new);
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Replace { path, .. } if path == &["items"]));
    }

    #[test]
    fn diffUnchangedKeysProduceNoOps() {
        let old = parse("keep = \"me\"\n[section]\nstable = 99\n");
        let new = parse("keep = \"me\"\n[section]\nstable = 99\nadded = true\n");
        let ops = diff(&old, &new);
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], TomlOp::Add { path, .. }
                if path == &["section", "added"]));
    }

    // -----------------------------------------------------------------------
    // unapply — correctness
    // -----------------------------------------------------------------------

    #[test]
    fn unapplyAddedKeyIsRemoved() {
        let old = parse("");
        let new = parse("key = \"value\"\n");
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result, old);
    }

    #[test]
    fn unapplyReplacedValueIsRestored() {
        let old = parse("key = \"old\"\n");
        let new = parse("key = \"new\"\n");
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result["key"].as_str(), Some("old"));
    }

    #[test]
    fn unapplyRemovedKeyIsRestored() {
        let old = parse("key = \"value\"\n");
        let new = parse("");
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result["key"].as_str(), Some("value"));
    }

    #[test]
    fn unapplyNestedSectionIsRemoved() {
        let old = parse("");
        let new = parse("[model_providers.kyris]\nname = \"Kyris\"\n");
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert!(result.as_table().unwrap().is_empty());
    }

    #[test]
    fn unapplyBooleanRestoredToFalse() {
        let old = parse("[features]\nenabled = false\n");
        let new = parse("[features]\nenabled = true\n");
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert_eq!(result["features"]["enabled"].as_bool(), Some(false));
    }

    // -----------------------------------------------------------------------
    // unapply — surgical table removal (key preservation)
    // -----------------------------------------------------------------------

    #[test]
    fn unapplyPreservesUserKeysInKyrisCreatedTable() {
        // kyris creates model_providers (didn't exist), user adds their own provider
        let old = parse("");
        let new_at_install = parse("[model_providers.kyris]\nname = \"Kyris\"\n");
        let ops = diff(&old, &new_at_install);

        // User adds their own provider between install and uninstall
        let mut current = parse(
            "[model_providers.kyris]\nname = \"Kyris\"\n\
             [model_providers.my_provider]\nbase_url = \"http://other\"\n",
        );
        let warnings = unapply(&mut current, &ops);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        let table = current["model_providers"].as_table().unwrap();
        assert!(!table.contains_key("kyris"), "kyris key should be removed");
        assert!(
            table.contains_key("my_provider"),
            "user key should be preserved"
        );
    }

    #[test]
    fn unapplyPreservesUserKeysAddedToExistingTable() {
        // model_providers existed; kyris adds kyris sub-section; user adds another
        let old = parse("[model_providers]\nother = 1\n");
        let new_at_install =
            parse("[model_providers]\nother = 1\n\n[model_providers.kyris]\nname = \"K\"\n");
        let ops = diff(&old, &new_at_install);

        let mut current = parse(
            "[model_providers]\nother = 1\n\
             [model_providers.kyris]\nname = \"K\"\n\
             [model_providers.user_added]\nurl = \"http://user\"\n",
        );
        let warnings = unapply(&mut current, &ops);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        let table = current["model_providers"].as_table().unwrap();
        assert!(!table.contains_key("kyris"), "kyris removed");
        assert!(table.contains_key("other"), "pre-existing key preserved");
        assert!(
            table.contains_key("user_added"),
            "user post-install key preserved"
        );
    }

    #[test]
    fn unapplyEmptiedTableIsCleanedUp() {
        // After removing kyris's only key, the empty section itself is removed.
        let old = parse("");
        let new = parse("[section]\nkyris_key = 1\n");
        let ops = diff(&old, &new);
        let mut result = new;
        assert!(unapply(&mut result, &ops).is_empty());
        assert!(
            result.as_table().unwrap().get("section").is_none(),
            "empty section should be removed"
        );
    }

    #[test]
    fn unapplyNonEmptyTableIsNotRemoved() {
        // kyris adds one key to a section; user key remains → section stays.
        let old = parse("[section]\nuser_key = 42\n");
        let new = parse("[section]\nuser_key = 42\nkyris_key = true\n");
        let ops = diff(&old, &new);
        let mut result = parse("[section]\nuser_key = 42\nkyris_key = true\n");
        assert!(unapply(&mut result, &ops).is_empty());
        let section = result["section"].as_table().unwrap();
        assert!(!section.contains_key("kyris_key"));
        assert!(section.contains_key("user_key"));
        // Section itself must still exist because it has user_key
        assert!(result.as_table().unwrap().contains_key("section"));
    }

    // -----------------------------------------------------------------------
    // unapply — idempotency and resilience
    // -----------------------------------------------------------------------

    #[test]
    fn unapplyAlreadyAbsentKeyIsNoop() {
        let old = parse("");
        let new = parse("key = \"value\"\n");
        let ops = diff(&old, &new);
        // Key already removed — unapply on the clean state should not error
        let mut already_clean = parse("");
        let warnings = unapply(&mut already_clean, &ops);
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
    }

    #[test]
    fn unapplyTwiceIsIdempotent() {
        let old = parse("x = 1\n");
        let new = parse("x = 1\ny = 2\n");
        let ops = diff(&old, &new);
        let mut result = new;
        unapply(&mut result, &ops);
        let warnings = unapply(&mut result, &ops); // second pass
        assert!(warnings.is_empty(), "second unapply should be clean");
        assert_eq!(result, old);
    }

    // -----------------------------------------------------------------------
    // Round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn roundtripTopLevelKey() {
        assert_roundtrip("existing = 1\n", "existing = 1\nnew_key = \"hello\"\n");
    }

    #[test]
    fn roundtripNewSection() {
        assert_roundtrip("existing = 1\n", "existing = 1\n[section]\na = 1\nb = 2\n");
    }

    #[test]
    fn roundtripBoolToggle() {
        assert_roundtrip(
            "[features]\nenabled = false\n",
            "[features]\nenabled = true\n",
        );
    }

    #[test]
    fn roundtripMultipleChanges() {
        assert_roundtrip(
            "url = \"http://old\"\n[features]\nflag = false\n",
            "url = \"http://new\"\n[features]\nflag = true\n[new_section]\nkey = \"val\"\n",
        );
    }

    #[test]
    fn roundtripRemovedKey() {
        assert_roundtrip("key_a = 1\nkey_b = 2\n", "key_a = 1\n");
    }

    #[test]
    fn roundtripDeepNesting() {
        assert_roundtrip("[a]\nx = 1\n", "[a]\nx = 1\n\n[a.b.c]\ndeep = \"added\"\n");
    }

    #[test]
    fn roundtripEmptyOldToRich() {
        assert_roundtrip(
            "",
            "top = true\n[providers.kyris]\nname = \"Kyris\"\nurl = \"http://...\"\n[mcp.kyris-mcp]\ntype = \"http\"\n",
        );
    }

    #[test]
    fn roundtripReplaceUserValueRestoresOriginal() {
        // kyris overwrites a key the user already set — unapply must restore the
        // USER's value, not leave kyris's (or delete the key).
        assert_roundtrip(
            "openai_base_url = \"https://my-proxy.example/v1\"\n",
            "openai_base_url = \"http://127.0.0.1:4710/v1\"\n",
        );
    }

    #[test]
    fn roundtripArrayOfTables() {
        assert_roundtrip(
            "[[servers]]\nname = \"a\"\n",
            "[[servers]]\nname = \"a\"\n\n[[servers]]\nname = \"b\"\n",
        );
    }

    #[test]
    fn roundtripCodexConfigFullKyrisSetup() {
        // The exact codex setup->undo scenario, as a structural round-trip: a
        // vanilla codex config gains the FULL kyris routing — `model_provider`,
        // `default_permissions`, `[features] hooks`, `[model_providers.kyris]`,
        // a shell env marker, and a `[permissions.kyris]` tree — and unapply
        // must restore the vanilla config EXACTLY, leaving the user's own
        // `model`, `[model_providers.openai]` untouched.
        let vanilla = "model = \"gpt-5\"\n\n[model_providers.openai]\nname = \"OpenAI\"\nbase_url = \"https://api.openai.com/v1\"\nwire_api = \"responses\"\n";
        let kyris_configured = "\
model = \"gpt-5\"\n\
model_provider = \"kyris\"\n\
default_permissions = \"kyris\"\n\
\n[features]\nhooks = true\n\
\n[model_providers.openai]\nname = \"OpenAI\"\nbase_url = \"https://api.openai.com/v1\"\nwire_api = \"responses\"\n\
\n[model_providers.kyris]\nname = \"Kyris\"\nbase_url = \"http://127.0.0.1:4710/v1\"\nwire_api = \"responses\"\nrequires_openai_auth = true\nsupports_websockets = false\n\
\n[model_providers.kyris.http_headers]\nx-kyris-inbound = \"sk-kyris-abc\"\n\
\n[permissions.kyris.filesystem]\n\"./src\" = \"write\"\n";
        assert_roundtrip(vanilla, kyris_configured);
    }
}
