// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use clap::Args;

#[derive(Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: McpCommand,
}

#[derive(clap::Subcommand)]
pub enum McpCommand {
    Wrap(McpWrapArgs),
}

#[derive(Args)]
pub struct McpWrapArgs {
    #[arg(long)]
    pub server: Option<String>,
    pub cmd: String,
    pub args: Vec<String>,
}

pub fn run(args: McpArgs) {
    match args.command {
        McpCommand::Wrap(wrap_args) => exec_wrap(wrap_args),
    }
}

fn exec_wrap(wrap_args: McpWrapArgs) {
    let server = wrap_args
        .server
        .unwrap_or_else(|| infer_server_name(&wrap_args.cmd));

    let mut cmd = std::process::Command::new("kyris-mcp");
    cmd.arg("wrap")
        .arg("--server")
        .arg(&server)
        .arg(&wrap_args.cmd)
        .args(&wrap_args.args);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        eprintln!("Failed to exec kyris-mcp: {err}");
        std::process::exit(1);
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status().unwrap_or_else(|e| {
            eprintln!("Failed to run kyris-mcp: {e}");
            std::process::exit(1);
        });
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn infer_server_name(cmd: &str) -> String {
    std::path::Path::new(cmd)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testInferServerName() {
        assert_eq!(infer_server_name("node"), "node");
        assert_eq!(infer_server_name("/usr/bin/python3"), "python3");
        assert_eq!(infer_server_name("./server.js"), "server");
    }
}
