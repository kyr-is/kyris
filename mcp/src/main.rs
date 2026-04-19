// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

mod framing;
mod relay;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 || args[1] != "wrap" {
        eprintln!("Usage: kyris-mcp wrap --server <name> <cmd> [args...]");
        return ExitCode::from(1);
    }

    let mut server_name = None;
    let mut cmd_start = 2;

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--server" && i + 1 < args.len() {
            server_name = Some(args[i + 1].clone());
            cmd_start = i + 2;
            break;
        }
        i += 1;
    }

    let server_name = server_name.unwrap_or_else(|| "unknown".to_string());

    if cmd_start >= args.len() {
        eprintln!("Usage: kyris-mcp wrap --server <name> <cmd> [args...]");
        return ExitCode::from(1);
    }

    let cmd = &args[cmd_start];
    let cmd_args = &args[cmd_start + 1..];

    let has_tty = check_tty();
    if !has_tty {
        eprintln!("[kyris-mcp] no controlling terminal — ask actions will be denied");
    }

    let mcp_config = kyris_core::config::load_mcp_config();
    let socket_timeout = std::time::Duration::from_millis(mcp_config.socket_timeout_ms);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        match relay::run_wrapper(&server_name, cmd, cmd_args, has_tty, socket_timeout).await {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("[kyris-mcp] error: {e}");
                ExitCode::from(1)
            }
        }
    })
}

fn check_tty() -> bool {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        false
    }
}
