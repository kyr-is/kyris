// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use std::io::Read;

use crate::service::{
    ServiceKind, candidate_log_paths, service_state, start_service, stop_service,
};
use crate::state::load_config;

#[derive(Args)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommand,
}

#[derive(clap::Subcommand)]
pub enum DaemonCommand {
    Start,
    Stop,
    Status,
    Logs,
}

pub fn run(args: DaemonArgs) {
    match args.command {
        DaemonCommand::Start => start(),
        DaemonCommand::Stop => stop(),
        DaemonCommand::Status => status(),
        DaemonCommand::Logs => logs(),
    }
}

fn configured_listen() -> String {
    load_config()
        .map(|config| config.server.listen)
        .unwrap_or_else(|_| "127.0.0.1:4710".to_string())
}

fn start() {
    match start_service(ServiceKind::Kyrisd) {
        Ok(()) => {
            println!("kyrisd started.");
        }
        Err(error) => {
            eprintln!("Failed to start kyrisd: {error}");
            std::process::exit(1);
        }
    }
}

fn stop() {
    match stop_service(ServiceKind::Kyrisd) {
        Ok(()) => {
            println!("kyrisd stopped.");
        }
        Err(error) => {
            eprintln!("Failed to stop kyrisd: {error}");
            std::process::exit(1);
        }
    }
}

fn status() {
    let listen = configured_listen();
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

    match health_status(&listen) {
        Ok(status_code) if status_code.is_success() => {
            println!("Health: healthy at http://{listen}/healthz");
        }
        Ok(status_code) => {
            println!("Health: unhealthy at http://{listen}/healthz ({status_code})");
        }
        Err(error) => {
            println!("Health: unreachable at http://{listen}/healthz ({error})");
        }
    }
}

fn logs() {
    let Some(log_path) = candidate_log_paths(ServiceKind::Kyrisd)
        .into_iter()
        .find(|path| path.exists())
    else {
        eprintln!("No kyrisd log file found.");
        std::process::exit(1);
    };

    // Read last 8KB of the log file (roughly last ~100 lines)
    let file = std::fs::File::open(&log_path).unwrap_or_else(|e| {
        eprintln!("Cannot open {}: {e}", log_path.display());
        std::process::exit(1);
    });

    let metadata = file.metadata().unwrap_or_else(|e| {
        eprintln!("Cannot stat {}: {e}", log_path.display());
        std::process::exit(1);
    });

    let size = metadata.len();
    let offset = size.saturating_sub(8192);

    let mut reader = std::io::BufReader::new(file);
    if offset > 0 {
        use std::io::Seek;
        reader
            .seek(std::io::SeekFrom::Start(offset))
            .unwrap_or_else(|e| {
                eprintln!("Cannot seek in {}: {e}", log_path.display());
                std::process::exit(1);
            });
    }

    let mut buf = String::new();
    reader.read_to_string(&mut buf).unwrap_or_else(|e| {
        eprintln!("Cannot read {}: {e}", log_path.display());
        std::process::exit(1);
    });

    // If we seeked into the middle of a line, skip the partial first line
    if offset > 0
        && let Some(pos) = buf.find('\n')
    {
        buf = buf[pos + 1..].to_string();
    }

    print!("{buf}");
}

#[cfg(test)]
fn tail_log_content(content: &[u8], max_bytes: usize) -> String {
    let len = content.len();
    if len <= max_bytes {
        return String::from_utf8_lossy(content).to_string();
    }
    let offset = len - max_bytes;
    let slice = &content[offset..];
    let text = String::from_utf8_lossy(slice);
    if let Some(pos) = text.find('\n') {
        text[pos + 1..].to_string()
    } else {
        text.to_string()
    }
}

fn health_status(listen: &str) -> Result<reqwest::StatusCode, String> {
    let url = format!("http://{listen}/healthz");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testTailLogContentShortContent() {
        let content = b"line1\nline2\nline3\n";
        let result = tail_log_content(content, 1024);
        assert_eq!(result, "line1\nline2\nline3\n");
    }

    #[test]
    fn testTailLogContentTruncatesAndSkipsPartialLine() {
        let content = b"aaaa\nbbbb\ncccc\ndddd\n";
        // 20 bytes, last 10 = "cccc\ndddd\n", partial first line "cccc" skipped
        let result = tail_log_content(content, 10);
        assert_eq!(result, "dddd\n");
    }

    #[test]
    fn testTailLogContentExactSize() {
        let content = b"hello\n";
        let result = tail_log_content(content, 6);
        assert_eq!(result, "hello\n");
    }

    #[test]
    fn testTailLogContentEmpty() {
        let result = tail_log_content(b"", 1024);
        assert_eq!(result, "");
    }
}
