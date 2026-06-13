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

use std::time::Instant;

use kyrisd::{build_info, config, crash, logging, server};

fn main() {
    // Must run before anything else: core dumps off, ptrace attach denied,
    // loader env vars cleared. Fail-fast inside on error.
    agentpact_hardening::pre_main_hardening();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("{}", build_info::version_line());
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

    let started_at = Instant::now();
    // Install the early panic hook *before* anything that might
    // panic (tracing init, config loading) so we always get a crash
    // report. The hook is retargeted in run() once config has loaded
    // and the real crash directory is known.
    crash::install_early_panic_hook(started_at);
    logging::init();

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

    tracing::info!(
        version = build_info::VERSION,
        commit = build_info::COMMIT,
        build_date = build_info::BUILD_DATE,
        features = %build_info::features_label(),
        pid = std::process::id(),
        "kyrisd starting",
    );

    run(config);
}

#[cfg(feature = "tray")]
fn run(config: kyris_core::config::KyrisdConfig) {
    // A dedicated/test instance sets KYRIS_NO_TRAY to run HEADLESS on this same
    // (tray-built) binary — no menu-bar icon, no AppKit run loop. Without it,
    // every short-lived test kyrisd would pop a tray icon and clutter the bar.
    if std::env::var_os("KYRIS_NO_TRAY").is_some() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(async {
            server::run(config).await;
        });
        return;
    }

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

    // run_event_loop owns the tokio handle from here. It never
    // returns — tao's event loop calls process::exit when the
    // ControlFlow::Exit branch fires (which happens once tokio
    // shuts down and the watchdog wakes the loop). So tokio_handle
    // .join() and any code that would have followed live inside
    // the watchdog thread instead.
    kyrisd::tray::run_event_loop(tokio_handle);
}

#[cfg(not(feature = "tray"))]
fn run(config: kyris_core::config::KyrisdConfig) {
    // Headless: tokio owns the main thread. No AppKit runloop is
    // needed because there's no UI to drive.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(async {
        server::run(config).await;
    });
}
