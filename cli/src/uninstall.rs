// SPDX-License-Identifier: Apache-2.0
use clap::Args;

use crate::service::{ServiceKind, service_state, stop_service};
use crate::state::restore_all_manifest_entries;

#[derive(Args)]
pub struct UninstallArgs {}

pub fn run(_args: UninstallArgs) {
    println!("Reversing all install actions...");

    for service in [ServiceKind::Kyrisd, ServiceKind::Agentpactd] {
        let state = service_state(service);
        if state.managed_by_homebrew || state.launchd_loaded {
            match stop_service(service) {
                Ok(()) => println!("Stopped {:?}", service),
                Err(error) => eprintln!("Could not stop {:?}: {error}", service),
            }
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
