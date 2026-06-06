// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris replay <session>` — replay one session's timeline in chronological
//! order. A thin renderer over kyrisd's `/operator/timeline` (filtered by
//! session); kyrisd already joined the model calls in.
use clap::Args;

use crate::operator;
use crate::query::render;

#[derive(Args)]
pub struct ReplayArgs {
    pub session: String,
}

pub fn run(args: ReplayArgs) {
    let page = operator::fetch_timeline(&[
        ("session", args.session.clone()),
        ("limit", "500".to_string()),
    ])
    .unwrap_or_else(|e| e.report());

    if page.entries.is_empty() {
        println!("no entries for session {}", args.session);
        return;
    }
    // The timeline is newest-first; a replay reads oldest-first.
    let mut entries = page.entries;
    entries.reverse();
    render::print_timeline(&entries);
}
