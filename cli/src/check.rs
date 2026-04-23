// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Args)]
pub struct CheckArgs {
    pub command: String,
}

pub fn run(args: CheckArgs) {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let sock = agentpact_socket();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let request = serde_json::json!({
        "id": format!("kyris-{timestamp}"),
        "method": "permission.request",
        "action": "execute",
        "detail": args.command,
        "context": {
            "working_dir": cwd,
        },
        "preview": true,
    });

    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot connect to agentpactd at {sock}: {e}");
            std::process::exit(1);
        }
    };

    let mut payload = serde_json::to_vec(&request).expect("serialize request");
    payload.push(b'\n');
    if let Err(e) = stream.write_all(&payload) {
        eprintln!("Failed to send request: {e}");
        std::process::exit(1);
    }
    if let Err(e) = stream.shutdown(std::net::Shutdown::Write) {
        eprintln!("Failed to signal end of request: {e}");
        std::process::exit(1);
    }

    let mut response_buf = Vec::new();
    if let Err(e) = stream.read_to_end(&mut response_buf) {
        eprintln!("Failed to read response: {e}");
        std::process::exit(1);
    }
    trim_socket_message(&mut response_buf);

    let response: serde_json::Value = match serde_json::from_slice(&response_buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid response from agentpactd: {e}");
            std::process::exit(1);
        }
    };

    let (decision, rule, reason) = parse_check_response(&response);

    println!("Decision: {decision}");
    if let Some(r) = rule {
        println!("Matched rule: {r}");
    }
    if let Some(r) = reason {
        println!("Reason: {r}");
    }

    std::process::exit(decision_to_exit_code(decision));
}

fn decision_to_exit_code(decision: &str) -> i32 {
    match decision {
        "auto" | "inform" => 0,
        "ask" => 2,
        _ => 1,
    }
}

fn agentpact_socket() -> String {
    std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    })
}

fn trim_socket_message(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
}

fn parse_check_response(response: &serde_json::Value) -> (&str, Option<&str>, Option<&str>) {
    let decision = response
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let rule = response
        .get("matched_rule")
        .and_then(|v| v.as_str())
        .or_else(|| response.get("rule_id").and_then(|v| v.as_str()));
    let reason = response
        .get("reason")
        .and_then(|v| v.as_str())
        .or_else(|| response.get("error").and_then(|v| v.as_str()));
    (decision, rule, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testDecisionToExitCodeAuto() {
        assert_eq!(decision_to_exit_code("auto"), 0);
        assert_eq!(decision_to_exit_code("inform"), 0);
    }

    #[test]
    fn testDecisionToExitCodeDeny() {
        assert_eq!(decision_to_exit_code("deny"), 1);
        assert_eq!(decision_to_exit_code("unknown"), 1);
        assert_eq!(decision_to_exit_code(""), 1);
    }

    #[test]
    fn testDecisionToExitCodeAsk() {
        assert_eq!(decision_to_exit_code("ask"), 2);
    }

    #[test]
    fn testParseCheckResponse() {
        let resp = serde_json::json!({
            "decision": "auto",
            "matched_rule": "allow-all",
            "reason": "default policy"
        });
        let (decision, rule, reason) = parse_check_response(&resp);
        assert_eq!(decision, "auto");
        assert_eq!(rule, Some("allow-all"));
        assert_eq!(reason, Some("default policy"));
    }

    #[test]
    fn testParseCheckResponseMinimal() {
        let resp = serde_json::json!({"decision": "deny"});
        let (decision, rule, reason) = parse_check_response(&resp);
        assert_eq!(decision, "deny");
        assert_eq!(rule, None);
        assert_eq!(reason, None);
    }

    #[test]
    fn testParseCheckResponseFallsBackToRuleId() {
        let resp = serde_json::json!({
            "decision": "auto",
            "rule_id": "cmd:git.status"
        });
        let (decision, rule, reason) = parse_check_response(&resp);
        assert_eq!(decision, "auto");
        assert_eq!(rule, Some("cmd:git.status"));
        assert_eq!(reason, None);
    }

    #[test]
    fn testParseCheckResponseFallsBackToError() {
        let resp = serde_json::json!({
            "code": "PACT_POLICY_ERROR",
            "error": "working_dir not allowed"
        });
        let (decision, rule, reason) = parse_check_response(&resp);
        assert_eq!(decision, "unknown");
        assert_eq!(rule, None);
        assert_eq!(reason, Some("working_dir not allowed"));
    }

    #[test]
    fn testParseCheckResponseMissing() {
        let resp = serde_json::json!({});
        let (decision, rule, reason) = parse_check_response(&resp);
        assert_eq!(decision, "unknown");
        assert_eq!(rule, None);
        assert_eq!(reason, None);
    }
}
