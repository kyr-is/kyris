// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use serde::Deserialize;
use std::io::Write;

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
    state: String,
    held_since_ms: u64,
}

pub fn run(_args: PendingArgs) {
    let config = load_or_init_config().unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    let base_url = format!("http://{}", config.server.listen);

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

                    let Some(decision) = prompt_decision(&request) else {
                        continue;
                    };

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

fn prompt_decision(request: &PendingRequest) -> Option<&'static str> {
    let tool = request.tool.as_deref().unwrap_or("unknown");
    print!("Approve {} / {}? [y/n/always/skip] ", request.server, tool);
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return None;
    }

    parse_decision(&input)
}

fn parse_decision(input: &str) -> Option<&'static str> {
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => Some("approved"),
        "n" | "no" => Some("denied"),
        "a" | "always" => Some("always"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testParseDecisionApproved() {
        assert_eq!(parse_decision("y"), Some("approved"));
        assert_eq!(parse_decision("yes"), Some("approved"));
        assert_eq!(parse_decision("  Y  "), Some("approved"));
        assert_eq!(parse_decision("YES"), Some("approved"));
    }

    #[test]
    fn testParseDecisionDenied() {
        assert_eq!(parse_decision("n"), Some("denied"));
        assert_eq!(parse_decision("no"), Some("denied"));
        assert_eq!(parse_decision("  NO  "), Some("denied"));
    }

    #[test]
    fn testParseDecisionAlways() {
        assert_eq!(parse_decision("a"), Some("always"));
        assert_eq!(parse_decision("always"), Some("always"));
        assert_eq!(parse_decision("ALWAYS"), Some("always"));
    }

    #[test]
    fn testParseDecisionSkipReturnsNone() {
        assert_eq!(parse_decision("skip"), None);
        assert_eq!(parse_decision(""), None);
        assert_eq!(parse_decision("maybe"), None);
    }

    #[test]
    fn testPendingRequestDeserialization() {
        let json = r#"{"id":"req-1","server":"github","tool":"read_file","state":"held","held_since_ms":5000}"#;
        let req: PendingRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, "req-1");
        assert_eq!(req.tool, Some("read_file".to_string()));
        assert_eq!(req.held_since_ms, 5000);
    }

    #[test]
    fn testPendingResponseDeserialization() {
        let json = r#"{"requests":[{"id":"req-1","server":"s","tool":null,"state":"held","held_since_ms":0}]}"#;
        let resp: PendingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.requests.len(), 1);
        assert!(resp.requests[0].tool.is_none());
    }
}
