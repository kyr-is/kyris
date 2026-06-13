// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};

use crate::state::load_or_init_config;

#[derive(Args)]
pub struct PendingArgs {}

#[derive(Deserialize)]
struct PendingResponse {
    requests: Vec<PendingRequest>,
}

#[derive(Deserialize)]
struct PendingRequest {
    id: String,
    server: String,
    tool: Option<String>,
    code: Option<String>,
    agent: String,
    state: String,
    held_since_ms: u64,
    /// Daemon's authoritative signal: whether answering "always" would persist
    /// a standing override.
    allow_always: bool,
}

#[allow(clippy::too_many_lines)]
pub fn run(_args: PendingArgs) {
    let config = load_or_init_config().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    let base_url = config.base_url();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    rt.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{base_url}/api/pending"))
            .header(
                "authorization",
                format!("Bearer {}", config.server.operator_key),
            )
            .send()
            .await;

        match resp {
            Ok(r) => {
                if !r.status().is_success() {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    eprintln!("Failed to list pending requests: {status}");
                    if !body.is_empty() {
                        eprintln!("{body}");
                    }
                    std::process::exit(1);
                }

                let pending: PendingResponse = r.json().await.unwrap_or_else(|e| {
                    eprintln!("Invalid response from kyrisd: {e}");
                    std::process::exit(1);
                });
                if pending.requests.is_empty() {
                    println!("No pending requests.");
                    return;
                }

                for request in pending.requests {
                    println!(
                        "{}  {}{}  state={}  held={}s",
                        request.id,
                        request.server,
                        request
                            .tool
                            .as_deref()
                            .map(|tool| format!("/{tool}"))
                            .unwrap_or_default(),
                        request.state,
                        request.held_since_ms / 1000,
                    );

                    let stdin = std::io::stdin();
                    let mut reader = BufReader::new(stdin.lock());
                    let mut writer = std::io::stdout().lock();
                    kyris_core::prompt_log::record_now(
                        &request.id,
                        "cli",
                        "displayed",
                        &request.server,
                        request.tool.as_deref(),
                        request.code.as_deref().or(request.tool.as_deref()),
                        &request.agent,
                        request.allow_always,
                        None,
                    );
                    let Some(decision) = prompt_decision(&request, &mut reader, &mut writer) else {
                        continue;
                    };
                    kyris_core::prompt_log::record_now(
                        &request.id,
                        "cli",
                        "decision_submitted",
                        &request.server,
                        request.tool.as_deref(),
                        request.code.as_deref().or(request.tool.as_deref()),
                        &request.agent,
                        request.allow_always,
                        Some(decision),
                    );

                    let resolve = client
                        .post(format!("{base_url}/api/pending/{}/resolve", request.id))
                        .header(
                            "authorization",
                            format!("Bearer {}", config.server.operator_key),
                        )
                        .json(&serde_json::json!({ "decision": decision }))
                        .send()
                        .await;

                    match resolve {
                        Ok(response) if response.status().is_success() => {
                            println!("Resolved {} as {}.", request.id, decision);
                        }
                        Ok(response) => {
                            eprintln!("Failed to resolve {}: {}", request.id, response.status());
                        }
                        Err(error) => {
                            eprintln!("Failed to resolve {}: {}", request.id, error);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to reach kyrisd: {e}");
                std::process::exit(1);
            }
        }
    });
}

/// Display the approval prompt and read the user's response. The reader and
/// writer are injected so unit tests can drive the prompt without real stdin.
fn prompt_decision<R: BufRead, W: Write>(
    request: &PendingRequest,
    reader: &mut R,
    writer: &mut W,
) -> Option<&'static str> {
    let tool = request.tool.as_deref().unwrap_or("unknown");
    // Offer "always" only when the daemon says a grant would actually persist.
    let choices = if request.allow_always {
        "[y/n/always/skip]"
    } else {
        "[y/n/skip]"
    };
    write!(writer, "Approve {} / {}? {choices} ", request.server, tool).ok()?;
    writer.flush().ok()?;

    let mut input = String::new();
    if reader.read_line(&mut input).is_err() {
        return None;
    }

    parse_decision(&input, request.allow_always)
}

fn parse_decision(input: &str, allow_always: bool) -> Option<&'static str> {
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => Some("approved"),
        "n" | "no" => Some("denied"),
        // "always" sticks only when persistable; otherwise the daemon would
        // refuse to persist anyway, so honor it as a one-time approval.
        "a" | "always" => Some(if allow_always { "always" } else { "approved" }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testParseDecisionApproved() {
        assert_eq!(parse_decision("y", true), Some("approved"));
        assert_eq!(parse_decision("yes", true), Some("approved"));
        assert_eq!(parse_decision("  Y  ", true), Some("approved"));
        assert_eq!(parse_decision("YES", true), Some("approved"));
    }

    #[test]
    fn testParseDecisionDenied() {
        assert_eq!(parse_decision("n", true), Some("denied"));
        assert_eq!(parse_decision("no", true), Some("denied"));
        assert_eq!(parse_decision("  NO  ", true), Some("denied"));
    }

    #[test]
    fn testParseDecisionAlwaysWhenPersistable() {
        assert_eq!(parse_decision("a", true), Some("always"));
        assert_eq!(parse_decision("always", true), Some("always"));
        assert_eq!(parse_decision("ALWAYS", true), Some("always"));
    }

    #[test]
    fn testParseDecisionAlwaysWhenNotPersistableMapsToApproved() {
        // The daemon won't persist this grant, so "always" can only mean
        // approve-once — never a standing override.
        assert_eq!(parse_decision("a", false), Some("approved"));
        assert_eq!(parse_decision("always", false), Some("approved"));
    }

    #[test]
    fn testParseDecisionSkipReturnsNone() {
        assert_eq!(parse_decision("skip", true), None);
        assert_eq!(parse_decision("", true), None);
        assert_eq!(parse_decision("maybe", true), None);
    }

    #[test]
    fn testPendingRequestDeserialization() {
        let json = r#"{"id":"req-1","server":"github","tool":"read_file","code":null,"agent":"test-agent","state":"held","held_since_ms":5000,"allow_always":true}"#;
        let req: PendingRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, "req-1");
        assert_eq!(req.tool, Some("read_file".to_string()));
        assert_eq!(req.agent, "test-agent");
        assert_eq!(req.held_since_ms, 5000);
        assert!(req.allow_always);
    }

    #[test]
    fn testPendingRequestRequiresAgentAndAllowAlways() {
        let missing_agent = r#"{"id":"req-1","server":"github","tool":"read_file","code":null,"state":"held","held_since_ms":5000,"allow_always":true}"#;
        let missing_allow_always = r#"{"id":"req-1","server":"github","tool":"read_file","code":null,"agent":"test-agent","state":"held","held_since_ms":5000}"#;

        assert!(serde_json::from_str::<PendingRequest>(missing_agent).is_err());
        assert!(serde_json::from_str::<PendingRequest>(missing_allow_always).is_err());
    }

    #[test]
    fn testPendingResponseDeserialization() {
        let json = r#"{"requests":[{"id":"req-1","server":"s","tool":null,"code":null,"agent":"codex-cli","state":"held","held_since_ms":0,"allow_always":true}]}"#;
        let resp: PendingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.requests.len(), 1);
        assert!(resp.requests[0].tool.is_none());
    }

    fn fixture(server: &str, tool: Option<&str>) -> PendingRequest {
        fixture_aa(server, tool, true)
    }

    fn fixture_aa(server: &str, tool: Option<&str>, allow_always: bool) -> PendingRequest {
        PendingRequest {
            id: "req-1".to_string(),
            server: server.to_string(),
            tool: tool.map(str::to_string),
            code: tool.map(str::to_string),
            agent: "test-agent".to_string(),
            state: "held".to_string(),
            held_since_ms: 0,
            allow_always,
        }
    }

    fn run_prompt(server: &str, tool: Option<&str>, input: &str) -> (Option<&'static str>, String) {
        run_prompt_req(fixture(server, tool), input)
    }

    fn run_prompt_req(req: PendingRequest, input: &str) -> (Option<&'static str>, String) {
        let mut reader = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut writer: Vec<u8> = Vec::new();
        let decision = prompt_decision(&req, &mut reader, &mut writer);
        (decision, String::from_utf8(writer).expect("utf8"))
    }

    #[test]
    fn testPromptHidesAlwaysWhenNotPersistable() {
        // allow_always=false → the prompt must not advertise "always", and an
        // "always" answer collapses to a one-time approval.
        let (decision, displayed) =
            run_prompt_req(fixture_aa("github", Some("read_file"), false), "always\n");
        assert!(
            displayed.contains("[y/n/skip]"),
            "must hide always when not persistable: {displayed}"
        );
        assert!(
            !displayed.contains("always"),
            "must not advertise always: {displayed}"
        );
        assert_eq!(decision, Some("approved"));
    }

    #[test]
    fn testPromptDisplaysServerToolAndChoices() {
        let (_, displayed) = run_prompt("github", Some("read_file"), "y\n");
        assert!(
            displayed.contains("Approve"),
            "missing 'Approve' verb in: {displayed}"
        );
        assert!(
            displayed.contains("github"),
            "missing server name in: {displayed}"
        );
        assert!(
            displayed.contains("read_file"),
            "missing tool name in: {displayed}"
        );
        assert!(
            displayed.contains("[y/n/always/skip]"),
            "missing choice list in: {displayed}"
        );
    }

    #[test]
    fn testPromptUnknownToolDisplaysPlaceholder() {
        let (_, displayed) = run_prompt("github", None, "n\n");
        assert!(
            displayed.contains("unknown"),
            "missing 'unknown' placeholder for null tool in: {displayed}"
        );
    }

    #[test]
    fn testPromptApprovedReturnsApproved() {
        let (decision, _) = run_prompt("github", Some("read_file"), "y\n");
        assert_eq!(decision, Some("approved"));
    }

    #[test]
    fn testPromptDeniedReturnsDenied() {
        let (decision, _) = run_prompt("github", Some("read_file"), "n\n");
        assert_eq!(decision, Some("denied"));
    }

    #[test]
    fn testPromptAlwaysReturnsAlways() {
        let (decision, _) = run_prompt("github", Some("read_file"), "always\n");
        assert_eq!(decision, Some("always"));
    }

    #[test]
    fn testPromptSkipReturnsNone() {
        let (decision, _) = run_prompt("github", Some("read_file"), "skip\n");
        assert!(
            decision.is_none(),
            "skip should map to None (treated as no-op by caller)"
        );
    }

    #[test]
    fn testPromptEmptyInputReturnsNone() {
        let (decision, _) = run_prompt("github", Some("read_file"), "\n");
        assert!(decision.is_none(), "empty input should map to None");
    }

    #[test]
    fn testPromptEofReturnsNone() {
        // Empty buffer simulates EOF — read_line returns Ok(0) which we treat
        // as no decision; tests the path that catches stdin closure.
        let (decision, _) = run_prompt("github", Some("read_file"), "");
        assert!(decision.is_none(), "EOF should map to None");
    }

    #[test]
    fn testPromptIsFlushedBeforeRead() {
        // Verifies the prompt is fully written before we try to read input —
        // without flush, the prompt could sit in the buffer while the user
        // types blind. Vec<u8> writes are synchronous so flush is a no-op
        // there, but the call must still succeed (no panic, returns Some).
        let (decision, displayed) = run_prompt("github", Some("read_file"), "y\n");
        assert_eq!(decision, Some("approved"));
        // The full prompt must appear before any decision logic completes.
        assert!(displayed.ends_with("[y/n/always/skip] "));
    }
}
