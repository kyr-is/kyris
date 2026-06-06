// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris trace <trace_id>` — show the rows sharing a model-call trace: the
//! governance think event and its model-call detail, already joined by kyrisd
//! (the single join owner). Paste a `trace_id` and see the full story.
use clap::Args;

use crate::operator;
use crate::query::render;

#[derive(Args)]
pub struct TraceArgs {
    pub id: String,
}

pub fn run(args: TraceArgs) {
    let page =
        operator::fetch_timeline(&[("trace_id", args.id.clone()), ("limit", "100".to_string())])
            .unwrap_or_else(|e| e.report());

    if page.entries.is_empty() {
        println!("no entries for trace {}", args.id);
        return;
    }
    render::print_timeline(&page.entries);
}
