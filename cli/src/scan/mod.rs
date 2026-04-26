// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Security scanning. Discovers running AI agents, exposed API keys, MCP
//! server configurations, and network traffic patterns. Outputs reports
//! in terminal, JSON, or HTML format.
pub mod agents;
pub mod keys;
pub mod mcp;
pub mod report;
pub mod scanner;
pub mod traffic;

use clap::Args;

#[derive(Args)]
pub struct ScanArgs {
    #[command(subcommand)]
    pub command: ScanCommand,
}

#[derive(clap::Subcommand)]
pub enum ScanCommand {
    Run(ScanRunArgs),
    Patterns(ScanPatternsArgs),
}

#[derive(Args)]
pub struct ScanRunArgs {
    #[arg(long, default_value = "terminal")]
    pub format: String,
    #[arg(short, long)]
    pub output: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub scanners: Option<Vec<String>>,
}

#[derive(Args)]
pub struct ScanPatternsArgs {
    #[command(subcommand)]
    pub command: PatternsCommand,
}

#[derive(clap::Subcommand)]
pub enum PatternsCommand {
    List,
}

pub fn run(args: ScanArgs) {
    match args.command {
        ScanCommand::Run(run_args) => run_scan(run_args),
        ScanCommand::Patterns(pattern_args) => match pattern_args.command {
            PatternsCommand::List => list_patterns(),
        },
    }
}

fn run_scan(args: ScanRunArgs) {
    let enabled = args.scanners.as_ref();
    let mut findings = Vec::new();

    let should_run = |name: &str| enabled.is_none_or(|list| list.iter().any(|s| s == name));

    if should_run("keys") {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        findings.extend(keys::scan(&cwd));
    }

    if should_run("agents") {
        findings.extend(agents::scan());
    }

    if should_run("mcp") {
        findings.extend(mcp::scan());
    }

    if should_run("traffic") {
        findings.extend(traffic::scan());
    }

    match args.format.as_str() {
        "json" => report::json::render(&findings),
        "html" => report::html::render(&findings),
        _ => report::terminal::render(&findings),
    }
}

fn list_patterns() {
    println!("Available scanners:");
    println!("  keys      - API key detection in source files");
    println!("  agents    - Ungoverned AI agent detection");
    println!("  mcp       - Unwrapped MCP server detection");
    println!("  traffic   - Direct LLM traffic detection");
    println!();
    println!("Known API key patterns:");
    for name in keys::pattern_names() {
        println!("  {name}");
    }
}
