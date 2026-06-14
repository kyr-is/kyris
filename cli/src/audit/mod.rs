// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris debug audit` — forensic governance-coverage check, NOT a daily
//! command. Detects LLM traffic that is *bypassing* kyris: provider base-URL
//! env vars not pointed at kyrisd, and agent history files showing direct
//! calls. This is the inverse of `kyris activity` (which records traffic that
//! *went through* kyris); a debug/diagnostics tool for "is anything escaping
//! governance?". Reports in terminal (default), JSON, or HTML.
pub mod report;
pub mod scanner;
pub mod traffic;

use clap::Args;

#[derive(Args)]
pub struct AuditArgs {
    /// Output format: `terminal` (default), `json`, or `html`.
    #[arg(long, default_value = "terminal")]
    pub format: String,
    /// Write the report to this file (json/html formats only).
    #[arg(short, long)]
    pub output: Option<String>,
}

pub fn run(args: AuditArgs) {
    let findings = traffic::scan();

    match args.format.as_str() {
        format if format != "json" && format != "html" => {
            if args.output.is_some() {
                eprintln!("warning: --output is ignored for terminal format");
            }
            report::terminal::render(&findings);
        }
        format => {
            let content = match format {
                "json" => report::json::build(&findings),
                _ => report::html::build_html(&findings), // "html"
            };
            match args.output.as_deref() {
                Some(path) => {
                    if let Err(e) = std::fs::write(path, &content) {
                        eprintln!("error: could not write to {path}: {e}");
                        std::process::exit(1);
                    }
                    eprintln!("Report written to {path}");
                }
                None => print!("{content}"),
            }
        }
    }
}
