// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use kyris_core::agentpact::ToolAnnotations;

pub fn is_tools_call(message: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(String::from))
        .is_some_and(|m| m == "tools/call")
}

pub fn is_tools_list_response(message: &[u8]) -> bool {
    let v: serde_json::Value = match serde_json::from_slice(message) {
        Ok(v) => v,
        Err(_) => return false,
    };
    v.get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .is_some()
}

pub fn is_tools_list_changed(message: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(String::from))
        .is_some_and(|m| m == "notifications/tools/list_changed")
}

pub fn extract_tool_annotations(message: &[u8]) -> Vec<(String, ToolAnnotations)> {
    let v: serde_json::Value = match serde_json::from_slice(message) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(tools) = v
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
    else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|tool| {
            let name = tool.get("name")?.as_str()?.to_string();
            let annotations = tool.get("annotations").cloned().unwrap_or_default();
            Some((
                name,
                ToolAnnotations {
                    read_only_hint: annotations
                        .get("readOnlyHint")
                        .and_then(serde_json::Value::as_bool),
                    destructive_hint: annotations
                        .get("destructiveHint")
                        .and_then(serde_json::Value::as_bool),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testIsToolsCall() {
        assert!(is_tools_call(br#"{"method":"tools/call","params":{}}"#));
        assert!(!is_tools_call(br#"{"method":"ping"}"#));
        assert!(!is_tools_call(b"not json"));
    }

    #[test]
    fn testIsToolsCallWithExtraFields() {
        let msg = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash","arguments":{"command":"ls"}}}"#;
        assert!(is_tools_call(msg));
    }

    #[test]
    fn testIsToolsCallEmptyInput() {
        assert!(!is_tools_call(b""));
    }

    #[test]
    fn testIsToolsCallPartialMethodMatch() {
        assert!(!is_tools_call(br#"{"method":"tools/call_result"}"#));
        assert!(!is_tools_call(br#"{"method":"tools/list"}"#));
    }

    #[test]
    fn testIsToolsCallNotificationWithoutId() {
        let msg = br#"{"method":"tools/call","params":{"name":"test"}}"#;
        assert!(is_tools_call(msg));
    }

    #[test]
    fn testIsToolsCallMethodNotString() {
        assert!(!is_tools_call(br#"{"method":42}"#));
        assert!(!is_tools_call(br#"{"method":null}"#));
    }

    #[test]
    fn testIsToolsListResponse() {
        let msg = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","annotations":{"readOnlyHint":true}}]}}"#;
        assert!(is_tools_list_response(msg));
    }

    #[test]
    fn testIsToolsListResponseFalseForOtherResults() {
        assert!(!is_tools_list_response(
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#
        ));
        assert!(!is_tools_list_response(br#"{"method":"tools/call"}"#));
        assert!(!is_tools_list_response(b"not json"));
    }

    #[test]
    fn testIsToolsListChanged() {
        assert!(is_tools_list_changed(
            br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#
        ));
        assert!(!is_tools_list_changed(br#"{"method":"tools/call"}"#));
    }

    #[test]
    fn testExtractToolAnnotations() {
        let msg = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[
            {"name":"read_file","annotations":{"readOnlyHint":true}},
            {"name":"delete_file","annotations":{"destructiveHint":true}},
            {"name":"list_dir"}
        ]}}"#;
        let annotations = extract_tool_annotations(msg);
        assert_eq!(annotations.len(), 3);
        assert_eq!(annotations[0].0, "read_file");
        assert_eq!(annotations[0].1.read_only_hint, Some(true));
        assert_eq!(annotations[0].1.destructive_hint, None);
        assert_eq!(annotations[1].0, "delete_file");
        assert_eq!(annotations[1].1.destructive_hint, Some(true));
        assert_eq!(annotations[2].0, "list_dir");
        assert_eq!(annotations[2].1.read_only_hint, None);
    }

    #[test]
    fn testExtractToolAnnotationsInvalidJson() {
        assert!(extract_tool_annotations(b"not json").is_empty());
    }

    #[test]
    fn testExtractToolAnnotationsNoTools() {
        assert!(extract_tool_annotations(br#"{"result":{}}"#).is_empty());
    }
}
