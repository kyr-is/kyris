// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris daemon` — inspect kyrisd's service state.
//!
//! Today this is a single-subcommand shape (`kyris daemon status`).
//! Start/stop moved to top-level `kyris start` / `kyris stop`; log
//! discovery moved to top-level `kyris logs`. What's left here is
//! the focused "is the launchd plist loaded and is /healthz happy?"
//! probe — it's narrow enough that we keep the `daemon` namespace
//! for future kyrisd-specific introspection without rewriting it.
use clap::Args;

use crate::service::{ServiceKind, service_state};
use crate::state::load_config;

#[derive(Args)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommand,
}

#[derive(clap::Subcommand)]
pub enum DaemonCommand {
    Status,
}

pub fn run(args: DaemonArgs) {
    match args.command {
        DaemonCommand::Status => status(),
    }
}

fn configured_base_url() -> String {
    load_config().map_or_else(
        |_| "http://127.0.0.1:4710".to_string(),
        |config| config.base_url(),
    )
}

fn status() {
    let base_url = configured_base_url();
    let state = service_state(ServiceKind::Kyrisd);
    if state.managed_by_homebrew {
        println!(
            "Service: Homebrew ({})",
            state.homebrew_status.as_deref().unwrap_or("unknown")
        );
    } else if state.launchd_loaded {
        println!("Service: launchd loaded");
    } else {
        println!("Service: not loaded");
    }

    match health_status(&base_url) {
        Ok(status_code) if status_code.is_success() => {
            println!("Health: healthy at {base_url}/healthz");
        }
        Ok(status_code) => {
            println!("Health: unhealthy at {base_url}/healthz ({status_code})");
        }
        Err(error) => {
            println!("Health: unreachable at {base_url}/healthz ({error})");
        }
    }
}

fn health_status(base_url: &str) -> Result<reqwest::StatusCode, String> {
    let url = format!("{base_url}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for daemon status: {e}"))?;

    runtime.block_on(async {
        reqwest::get(&url)
            .await
            .map(|response| response.status())
            .map_err(|e| e.to_string())
    })
}
