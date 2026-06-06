// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris stats` — aggregate usage over a window, computed by kyrisd from the
//! unified timeline and rendered here.
use clap::Args;

use crate::operator;
use crate::query::render;

#[derive(Args)]
pub struct StatsArgs {
    /// Window like `7d`, `24h`, `30m`.
    #[arg(long, default_value = "7d")]
    pub since: String,
}

pub fn run(args: StatsArgs) {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(since) = operator::relative_since(&args.since) {
        query.push(("since", since));
    } else {
        eprintln!(
            "unrecognized --since '{}' (use e.g. 7d, 24h, 30m)",
            args.since
        );
        std::process::exit(1);
    }
    let stats = operator::fetch_stats(&query).unwrap_or_else(|e| e.report());
    render::print_stats(&stats);
}
