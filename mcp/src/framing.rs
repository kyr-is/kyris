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
}
