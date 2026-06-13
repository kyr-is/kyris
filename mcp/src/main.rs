// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Stdio MCP wrapper (`kyris-mcp`). Sits between an AI agent and an MCP
//! server, intercepting JSON-RPC `tools/call` requests over stdin/stdout.
//! Each tool invocation is checked against `AgentPact` policy via UDS before
//! being forwarded to the wrapped server process.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(test, allow(non_snake_case))]

mod framing;
mod policy;
mod relay;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 || args[1] != "wrap" {
        eprintln!("Usage: kyris-mcp wrap --server <name> [--agent <id>] <cmd> [args...]");
        return ExitCode::from(1);
    }

    // Leading flags before the wrapped command, in any order. `--agent` is the
    // owning agent's id (stamped by the kyris MCP rewrite) used only for
    // tool-surface live-evidence attribution; pre-upgrade wraps omit it.
    let mut server_name = None;
    let mut agent_id: Option<String> = None;
    let mut cmd_start = 2;
    while cmd_start < args.len() {
        match args[cmd_start].as_str() {
            "--server" if cmd_start + 1 < args.len() => {
                server_name = Some(args[cmd_start + 1].clone());
                cmd_start += 2;
            }
            "--agent" if cmd_start + 1 < args.len() => {
                agent_id = Some(args[cmd_start + 1].clone());
                cmd_start += 2;
            }
            _ => break,
        }
    }

    let server_name = server_name.unwrap_or_else(|| "unknown".to_string());

    if cmd_start >= args.len() {
        eprintln!("Usage: kyris-mcp wrap --server <name> [--agent <id>] <cmd> [args...]");
        return ExitCode::from(1);
    }

    let cmd = &args[cmd_start];
    let cmd_args = &args[cmd_start + 1..];

    let has_tty = check_tty();
    if !has_tty {
        eprintln!(
            "[kyris-mcp] no controlling terminal — ask actions will delegate to kyrisd, or deny if kyrisd is unreachable"
        );
    }

    let mcp_config = kyris_core::config::load_mcp_config();
    let socket_timeout = std::time::Duration::from_millis(mcp_config.socket_timeout_ms);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async {
        match relay::run_wrapper(
            &server_name,
            agent_id.as_deref(),
            cmd,
            cmd_args,
            has_tty,
            socket_timeout,
        )
        .await
        {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                let msg = format!("server={server_name} {e}");
                eprintln!("[kyris-mcp] error: {msg}");
                log_error(&msg);
                ExitCode::from(1)
            }
        }
    })
}

fn log_error(msg: &str) {
    let path = kyris_core::paths::log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write as _;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts = epoch_to_utc(secs);
        let _ = writeln!(file, "{ts} [kyris-mcp] [ERROR] {msg}");
    }
}

/// Minimal UTC timestamp formatter — avoids a chrono/time dependency in the
/// mcp crate which is intentionally kept lean.
fn epoch_to_utc(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86_400;
    let day_secs = epoch_secs % secs_per_day;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    let days = epoch_secs / secs_per_day;
    let (year, month, day) = days_to_ymd(days + 719_468);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(z: u64) -> (u64, u64, u64) {
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d)
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
