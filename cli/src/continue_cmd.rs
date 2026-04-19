// SPDX-License-Identifier: Apache-2.0
use clap::Args;

use crate::state::load_or_init_config;

#[derive(Args)]
pub struct ContinueArgs {
    pub session: Option<String>,
}

pub fn run(args: ContinueArgs) {
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
            .post(format!("{base_url}/api/circuit-breaker/reset"))
            .header(
                "authorization",
                format!("Bearer {}", config.server.operator_key),
            )
            .json(&serde_json::json!({ "session_id": args.session }))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                println!("Circuit breaker reset. Session resumed.");
            }
            Ok(r) => {
                eprintln!("Reset failed: {}", r.status());
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Failed to reach kyrisd: {e}");
                std::process::exit(1);
            }
        }
    });
}
