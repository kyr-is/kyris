// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris continue` — resume sessions held up by the circuit breaker.
//!
//! Two modes:
//! - `kyris continue` (no arg): reset every session that's currently
//!   tripped. Common case — most users don't know or care which
//!   specific session ID is held up; they just want routing back.
//! - `kyris continue <session>`: reset that specific session.
//!
//! Both routes through kyrisd's HTTP API. Idempotent: exits 0 with a
//! "no sessions tripped" message when there's nothing to do.
use clap::Args;

/// Resume sessions held up by the circuit breaker.
///
/// With no argument, resets every currently-tripped session in one
/// call. With a session ID, resets just that session. Idempotent —
/// exits 0 with "No sessions are currently tripped." when there's
/// nothing to do.
#[derive(Args)]
pub struct ContinueArgs {
    /// Specific session ID to reset. Omit to reset every tripped
    /// session in one call.
    pub session: Option<String>,
}

pub fn run(args: ContinueArgs) {
    let conn = kyris_core::config::load_kyrisd_connection().unwrap_or_else(|| {
        eprintln!("kyrisd not configured — run `kyris enroll` first");
        std::process::exit(1);
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    rt.block_on(async {
        let client = reqwest::Client::new();
        if let Some(session) = args.session {
            reset_one(&client, &conn, &session).await;
        } else {
            reset_all(&client, &conn).await;
        }
    });
}

async fn reset_one(
    client: &reqwest::Client,
    conn: &kyris_core::config::KyrisdConnection,
    session: &str,
) {
    let resp = client
        .post(format!("{}/api/circuit-breaker/reset", conn.base_url))
        .header("authorization", format!("Bearer {}", conn.operator_key))
        .json(&serde_json::json!({ "session_id": session }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            println!("Circuit breaker reset. Session resumed.");
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            eprintln!("Reset failed ({status}): {body}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to reach kyrisd: {e}");
            std::process::exit(1);
        }
    }
}

async fn reset_all(client: &reqwest::Client, conn: &kyris_core::config::KyrisdConnection) {
    let resp = client
        .post(format!("{}/api/circuit-breaker/reset-all", conn.base_url))
        .header("authorization", format!("Bearer {}", conn.operator_key))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let payload: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
            let cleared: Vec<String> = payload
                .get("cleared")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if cleared.is_empty() {
                println!("No sessions are currently tripped.");
            } else {
                println!(
                    "Reset {} tripped session{}:",
                    cleared.len(),
                    if cleared.len() == 1 { "" } else { "s" }
                );
                for id in cleared {
                    println!("  - {id}");
                }
            }
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            eprintln!("Reset-all failed ({status}): {body}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to reach kyrisd: {e}");
            std::process::exit(1);
        }
    }
}
