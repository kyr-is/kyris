// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

use crate::state::write_managed_file;

pub fn read_json_value(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))
}

pub fn write_json_value(path: &Path, value: &Value, component: &str) -> Result<bool, String> {
    let contents = serde_json::to_string_pretty(value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    write_managed_file(path, &contents, component, Some(0o600))
}

pub fn read_toml_value(path: &Path) -> Result<toml::Value, String> {
    if !path.exists() {
        return Ok(toml::Value::Table(toml::Table::new()));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    toml::from_str(&contents).map_err(|e| format!("Cannot parse {}: {e}", path.display()))
}

pub fn write_toml_value(path: &Path, value: &toml::Value, component: &str) -> Result<bool, String> {
    let contents = toml::to_string_pretty(value)
        .map_err(|e| format!("Cannot serialize {}: {e}", path.display()))?;
    write_managed_file(path, &contents, component, Some(0o600))
}

pub fn ensure_json_command_hook(root: &mut Value, phase: &str, command: &str) -> bool {
    let object = as_json_object(root);
    let hooks = object
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks_object = as_json_object(hooks);
    let phase_hooks = hooks_object
        .entry(phase.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let hooks_array = as_json_array(phase_hooks);

    let already_present = hooks_array.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|nested| {
                nested.iter().any(|hook| {
                    hook.get("type").and_then(Value::as_str) == Some("command")
                        && hook.get("command").and_then(Value::as_str) == Some(command)
                })
            })
    });
    if already_present {
        return false;
    }

    hooks_array.push(json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": command,
            }
        ]
    }));
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
    phase_hooks.retain(|entry| {
        !entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|nested| {
                nested.iter().any(|hook| {
                    hook.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|cmd| cmd.contains(command_substr))
                })
            })
    });
    phase_hooks.len() != before
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
