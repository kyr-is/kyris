// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

use crate::config_writer::ConfigValidator;

pub fn read_json_value(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))
}

/// Write a JSON config file and record the structural diff in the manifest.
///
/// Serializes `value` once, validates the result, then passes the string
/// directly to [`crate::state::write_managed_json`] — no second serialization.
pub fn write_json_value(
    path: &Path,
    value: &Value,
    component: &str,
    validator: &dyn ConfigValidator,
) -> Result<bool, String> {
    let mut serialized = serde_json::to_string_pretty(value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    serialized.push('\n');
    validator
        .validate(&serialized)
        .map_err(|e| format!("validation failed for {}: {e}", path.display()))?;
    let file_existed = path.exists();
    let old = read_json_value(path)?;
    crate::state::write_managed_json(
        path,
        &old,
        value,
        &serialized,
        file_existed,
        component,
        Some(0o600),
    )
}

pub fn read_toml_value(path: &Path) -> Result<toml::Value, String> {
    if !path.exists() {
        return Ok(toml::Value::Table(toml::Table::new()));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    toml::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))
}

/// Write a TOML config file and record the structural diff in the manifest.
///
/// Serializes `value` once, validates the result, then passes the string
/// directly to [`crate::state::write_managed_toml`] — no second serialization.
pub fn write_toml_value(
    path: &Path,
    value: &toml::Value,
    component: &str,
    validator: &dyn ConfigValidator,
) -> Result<bool, String> {
    let mut serialized = toml::to_string_pretty(value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    serialized.push('\n');
    validator
        .validate(&serialized)
        .map_err(|e| format!("validation failed for {}: {e}", path.display()))?;
    let file_existed = path.exists();
    let old = read_toml_value(path)?;
    crate::state::write_managed_toml(
        path,
        &old,
        value,
        &serialized,
        file_existed,
        component,
        Some(0o600),
    )
}

pub fn ensure_json_command_hook(
    root: &mut Value,
    phase: &str,
    command: &str,
    nested: bool,
    // Optional per-hook execution timeout in the agent's own units (Claude &
    // Gemini both use a `timeout` field — seconds and milliseconds
    // respectively). Set it when the agent's default hook timeout is shorter
    // than kyris's no-TTY approval poll window, so the agent doesn't kill the
    // hook mid-wait. `None` leaves the agent's default.
    timeout: Option<i64>,
) -> bool {
    let object = as_json_object(root);
    let hooks = object
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks_object = as_json_object(hooks);
    let phase_hooks = hooks_object
        .entry(phase.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let hooks_array = as_json_array(phase_hooks);

    let already_present = hooks_array
        .iter()
        .any(|entry| entry_has_command(entry, command));
    if already_present {
        return false;
    }

    let mut inner = json!({"type": "command", "command": command});
    if let Some(t) = timeout {
        inner["timeout"] = json!(t);
    }
    let entry = if nested {
        json!({ "matcher": "", "hooks": [inner] })
    } else {
        inner
    };
    hooks_array.push(entry);
    true
}

pub fn remove_json_command_hook(root: &mut Value, phase: &str, command_substr: &str) -> bool {
    let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) else {
        return false;
    };
    let Some(phase_hooks) = hooks.get_mut(phase).and_then(Value::as_array_mut) else {
        return false;
    };

    let before = phase_hooks.len();
    phase_hooks.retain(|entry| !entry_has_command_substr(entry, command_substr));
    phase_hooks.len() != before
}

fn entry_has_command(entry: &Value, command: &str) -> bool {
    if entry.get("type").and_then(Value::as_str) == Some("command")
        && entry.get("command").and_then(Value::as_str) == Some(command)
    {
        return true;
    }
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|nested| {
            nested.iter().any(|hook| {
                hook.get("type").and_then(Value::as_str) == Some("command")
                    && hook.get("command").and_then(Value::as_str) == Some(command)
            })
        })
}

fn entry_has_command_substr(entry: &Value, substr: &str) -> bool {
    if entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|cmd| cmd.contains(substr))
    {
        return true;
    }
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|nested| {
            nested.iter().any(|hook| {
                hook.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|cmd| cmd.contains(substr))
            })
        })
}

pub fn set_json_string_path(root: &mut Value, path: &[&str], value: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    let mut cursor = root;
    for key in &path[..path.len() - 1] {
        let object = as_json_object(cursor);
        cursor = object
            .entry((*key).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }

    let object = as_json_object(cursor);
    let leaf = path[path.len() - 1].to_string();
    if object.get(&leaf).and_then(Value::as_str) == Some(value) {
        return false;
    }
    object.insert(leaf, Value::String(value.to_string()));
    true
}

pub fn set_json_value_path(root: &mut Value, path: &[&str], value: Value) -> bool {
    if path.is_empty() {
        return false;
    }

    let mut cursor = root;
    for key in &path[..path.len() - 1] {
        let object = as_json_object(cursor);
        cursor = object
            .entry((*key).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }

    let object = as_json_object(cursor);
    let leaf = path[path.len() - 1].to_string();
    if object.get(&leaf) == Some(&value) {
        return false;
    }
    object.insert(leaf, value);
    true
}

pub fn ensure_toml_string_path(root: &mut toml::Value, path: &[&str], value: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    let mut cursor = root;
    for key in &path[..path.len() - 1] {
        let table = as_toml_table(cursor);
        cursor = table
            .entry((*key).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    }

    let table = as_toml_table(cursor);
    let leaf = path[path.len() - 1].to_string();
    if table.get(&leaf).and_then(toml::Value::as_str) == Some(value) {
        return false;
    }
    table.insert(leaf, toml::Value::String(value.to_string()));
    true
}

pub fn ensure_toml_bool_path(root: &mut toml::Value, path: &[&str], value: bool) -> bool {
    if path.is_empty() {
        return false;
    }

    let mut cursor = root;
    for key in &path[..path.len() - 1] {
        let table = as_toml_table(cursor);
        cursor = table
            .entry((*key).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    }

    let table = as_toml_table(cursor);
    let leaf = path[path.len() - 1].to_string();
    if table.get(&leaf).and_then(toml::Value::as_bool) == Some(value) {
        return false;
    }
    table.insert(leaf, toml::Value::Boolean(value));
    true
}

/// Navigate to the TOML table at `table_path` (creating intermediate tables
/// as needed), then insert every entry from `entries` as a string value.
/// Returns `true` if any value was inserted or changed.
pub fn merge_toml_string_entries(
    root: &mut toml::Value,
    table_path: &[&str],
    entries: &std::collections::BTreeMap<String, String>,
) -> bool {
    if entries.is_empty() {
        return false;
    }
    let mut cursor = root;
    for key in table_path {
        let table = as_toml_table(cursor);
        cursor = table
            .entry((*key).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    }
    let table = as_toml_table(cursor);
    let mut changed = false;
    for (key, value) in entries {
        if table.get(key).and_then(toml::Value::as_str) != Some(value.as_str()) {
            table.insert(key.clone(), toml::Value::String(value.clone()));
            changed = true;
        }
    }
    changed
}

/// Remove all entries whose keys are in `keys` from the TOML table at
/// `table_path`. Removes the table itself (and any now-empty parent tables
/// in `table_path`) when it becomes empty. Returns `true` if anything changed.
pub fn remove_toml_table_entries(
    root: &mut toml::Value,
    table_path: &[&str],
    keys: Option<&[&str]>,
) -> bool {
    if table_path.is_empty() {
        return false;
    }
    // Navigate to the parent of the target table so we can prune upward.
    let mut cursor = root;
    for key in &table_path[..table_path.len() - 1] {
        let Some(next) = as_toml_table(cursor).get_mut(*key) else {
            return false;
        };
        cursor = next;
    }
    let leaf = table_path[table_path.len() - 1];
    let table = as_toml_table(cursor);
    let Some(target) = table.get_mut(leaf) else {
        return false;
    };
    match keys {
        Some(remove_keys) => {
            let t = as_toml_table(target);
            let mut changed = false;
            for k in remove_keys {
                if t.remove(*k).is_some() {
                    changed = true;
                }
            }
            if t.is_empty() {
                table.remove(leaf);
            }
            changed
        }
        None => table.remove(leaf).is_some(),
    }
}

pub fn find_upwards(relative_path: &str) -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let candidate = current.join(relative_path);
        if candidate.exists() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

pub fn home_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home))
}

fn as_json_object(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }
    value
        .as_object_mut()
        .expect("value converted to JSON object")
}

fn as_json_array(value: &mut Value) -> &mut Vec<Value> {
    if !value.is_array() {
        *value = Value::Array(Vec::new());
    }
    value.as_array_mut().expect("value converted to JSON array")
}

fn as_toml_table(value: &mut toml::Value) -> &mut toml::Table {
    if !value.is_table() {
        *value = toml::Value::Table(toml::Table::new());
    }
    value.as_table_mut().expect("value converted to TOML table")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testEnsureNestedHookWritesMatcherShape() {
        let mut root = json!({});
        assert!(ensure_json_command_hook(
            &mut root,
            "PreToolUse",
            "bash /tmp/hook.sh",
            true,
            Some(600),
        ));
        let entry = &root["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "");
        assert_eq!(entry["hooks"][0]["type"], "command");
        assert_eq!(entry["hooks"][0]["command"], "bash /tmp/hook.sh");
        assert_eq!(entry["hooks"][0]["timeout"], 600);
    }

    #[test]
    fn testEnsureFlatHookWritesDirectShape() {
        let mut root = json!({});
        assert!(ensure_json_command_hook(
            &mut root,
            "BeforeTool",
            "bash /tmp/hook.sh",
            false,
            Some(600_000),
        ));
        let entry = &root["hooks"]["BeforeTool"][0];
        assert_eq!(entry["type"], "command");
        assert_eq!(entry["command"], "bash /tmp/hook.sh");
        assert!(entry.get("matcher").is_none());
        assert!(entry.get("hooks").is_none());
        assert_eq!(entry["timeout"], 600_000);
    }

    #[test]
    fn testEnsureHookIdempotentBothShapes() {
        let mut root = json!({});
        assert!(ensure_json_command_hook(
            &mut root,
            "PreToolUse",
            "bash /tmp/a.sh",
            true,
            None,
        ));
        assert!(!ensure_json_command_hook(
            &mut root,
            "PreToolUse",
            "bash /tmp/a.sh",
            true,
            None,
        ));
        // None leaves no timeout field — agent default applies.
        assert!(
            root["hooks"]["PreToolUse"][0]["hooks"][0]
                .get("timeout")
                .is_none()
        );

        let mut root = json!({});
        assert!(ensure_json_command_hook(
            &mut root,
            "BeforeTool",
            "bash /tmp/b.sh",
            false,
            None,
        ));
        assert!(!ensure_json_command_hook(
            &mut root,
            "BeforeTool",
            "bash /tmp/b.sh",
            false,
            None,
        ));
    }

    #[test]
    fn testRemoveNestedHook() {
        let mut root = json!({});
        ensure_json_command_hook(
            &mut root,
            "PreToolUse",
            "bash /tmp/kyris_hook.sh",
            true,
            None,
        );
        assert!(remove_json_command_hook(
            &mut root,
            "PreToolUse",
            "kyris_hook"
        ));
        assert!(root["hooks"]["PreToolUse"].as_array().unwrap().is_empty());
    }

    #[test]
    fn testRemoveFlatHook() {
        let mut root = json!({});
        ensure_json_command_hook(
            &mut root,
            "BeforeTool",
            "bash /tmp/kyris_hook.sh",
            false,
            None,
        );
        assert!(remove_json_command_hook(
            &mut root,
            "BeforeTool",
            "kyris_hook"
        ));
        assert!(root["hooks"]["BeforeTool"].as_array().unwrap().is_empty());
    }

    #[test]
    fn testRemoveHookLeavesOtherEntries() {
        let mut root = json!({});
        ensure_json_command_hook(&mut root, "PreToolUse", "bash /tmp/kyris.sh", true, None);
        ensure_json_command_hook(&mut root, "PreToolUse", "bash /tmp/other.sh", true, None);
        assert!(remove_json_command_hook(&mut root, "PreToolUse", "kyris"));
        assert_eq!(root["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }
}
