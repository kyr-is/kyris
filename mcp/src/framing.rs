// SPDX-License-Identifier: Apache-2.0

pub fn is_tools_call(message: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(String::from))
        .is_some_and(|m| m == "tools/call")
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
}
