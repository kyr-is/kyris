// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;

use crate::service::{ServiceKind, service_state, stop_service};
use crate::state::restore_all_manifest_entries;

#[derive(Args)]
pub struct UninstallArgs {}

pub fn run(_args: UninstallArgs) {
    println!("Reversing all install actions...");

    let state = service_state(ServiceKind::Kyrisd);
    if state.managed_by_homebrew || state.launchd_loaded {
        match stop_service(ServiceKind::Kyrisd) {
            Ok(()) => println!("Stopped Kyrisd"),
            Err(error) => eprintln!("Could not stop Kyrisd: {error}"),
        }
    }

    match restore_all_manifest_entries() {
        Ok(actions) if actions.is_empty() => {
            println!("No managed install actions were recorded.");
        }
        Ok(actions) => {
            for action in actions {
                println!("{action}");
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
