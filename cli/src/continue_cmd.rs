// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;

#[derive(Args)]
pub struct ContinueArgs {
    pub session: String,
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
        let resp = client
            .post(format!("{}/api/circuit-breaker/reset", conn.base_url))
            .header("authorization", format!("Bearer {}", conn.operator_key))
            .json(&serde_json::json!({ "session_id": &args.session }))
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
    });
}
