// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris timeline` — render the unified event↔record timeline kyrisd joins.
use clap::Args;

use crate::operator;
use crate::query::render;

#[derive(Args)]
pub struct TimelineArgs {
    #[arg(long, default_value = "20")]
    pub last: usize,
}

pub fn run(args: TimelineArgs) {
    let page = operator::fetch_timeline(&[("limit", args.last.to_string())])
        .unwrap_or_else(|e| e.report());
    render::print_timeline(&page.entries);
}
