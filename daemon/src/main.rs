// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
#![cfg_attr(test, allow(non_snake_case))]

use kyrisd::{config, server, tray};
use tracing_subscriber::EnvFilter;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("kyrisd {}", env!("CARGO_PKG_VERSION"));
        return;
    }
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

    let config = match args.first().map(String::as_str) {
        Some("--config") => {
            let path = args.get(1).unwrap_or_else(|| {
                eprintln!("--config requires a path argument");
                std::process::exit(1);
            });
            config::load_config_from(std::path::Path::new(path))
        }
        _ => config::load_config(),
    };

    // Tokio runs on a background thread so the main thread is free to host
    // the macOS AppKit run loop required by `tray-icon`.
    let tokio_handle = std::thread::Builder::new()
        .name("kyrisd-tokio".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            rt.block_on(async {
                server::run(config).await;
            });
        })
        .expect("spawn kyrisd-tokio thread");

    tray::run_event_loop(&tokio_handle);

    let _ = tokio_handle.join();
}
