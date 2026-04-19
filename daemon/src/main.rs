// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
#![cfg_attr(test, allow(non_snake_case))]

mod adapter;
mod auth;
mod circuit_breaker;
mod config;
mod cost;
mod mcp_routing;
mod metering;
mod notify;
mod pending;
mod platform;
mod pricing_fetch;
mod server;
mod storage;
mod streaming;
mod sync;
mod trace_attach;
mod tray;

use tracing_subscriber::EnvFilter;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("schema") {
        let schema = kyris_core::schema::generate();
        println!(
            "{}",
            serde_json::to_string_pretty(&schema).expect("serialize schema")
        );
        return;
    }

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = config::load_config();

    tray::spawn_tray();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        server::run(config).await;
    });
}
