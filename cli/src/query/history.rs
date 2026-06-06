// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris history` — filtered timeline rows. A thin renderer over kyrisd's
//! `/operator/timeline`; filters map to query params, and `--sync-state`
//! narrows to a kyrisd-stamped sync state client-side.
use clap::Args;

use crate::operator;
use crate::query::render;

#[derive(Args)]
pub struct HistoryArgs {
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub action: Option<String>,
    #[arg(long)]
    pub decision: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    #[arg(long)]
    pub dir: Option<String>,
    /// Show only rows with this sync state: `synced` | `pending` | `local`.
    #[arg(long)]
    pub sync_state: Option<String>,
}

pub fn run(args: HistoryArgs) {
    let mut query: Vec<(&str, String)> = vec![("limit", "200".to_string())];
    let mut push = |k: &'static str, v: &Option<String>| {
        if let Some(v) = v {
            query.push((k, v.clone()));
        }
    };
    push("agent", &args.agent);
    push("action", &args.action);
    push("decision", &args.decision);
    push("since", &args.since);
    push("until", &args.until);
    push("dir", &args.dir);

    let page = operator::fetch_timeline(&query).unwrap_or_else(|e| e.report());

    // kyrisd stamps sync_state but doesn't filter on it; narrow here.
    let entries: Vec<_> = match &args.sync_state {
        Some(want) => page
            .entries
            .into_iter()
            .filter(|e| e.sync_state.as_deref() == Some(want.as_str()))
            .collect(),
        None => page.entries,
    };
    render::print_timeline(&entries);
}
