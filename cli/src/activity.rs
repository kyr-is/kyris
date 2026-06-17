// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris activity` — inspect governed commands, tool calls, and model usage.
//!
//! The bare command (with optional filters) lists the unified event↔record
//! timeline kyrisd joins — recent rows by default, filtered when any filter is
//! given (the former `timeline` and `history` are one command here, since both
//! are the same `/operator/timeline` query). Subcommands cover the focused
//! views: `stats`, `replay <session>`, `trace <id>`, and `approvals` (the
//! popup-decision recall log).
use clap::{Args, Subcommand};

use crate::operator;
use crate::query::render;

#[derive(Args)]
pub struct ActivityArgs {
    #[command(subcommand)]
    pub command: Option<ActivityCommand>,

    /// Max rows to show (default 20; raised to 200 when any filter is set).
    #[arg(long)]
    pub last: Option<usize>,
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

#[derive(Subcommand)]
pub enum ActivityCommand {
    /// Aggregate usage over a window
    Stats(crate::query::stats::StatsArgs),
    /// Replay one session's timeline oldest-first
    Replay(crate::query::replay::ReplayArgs),
    /// Show every row sharing a model-call trace id
    Trace(crate::query::trace::TraceArgs),
    /// Recall view over popup-resolved approval decisions
    Approvals(crate::query::approvals::ApprovalsArgs),
}

pub fn run(args: ActivityArgs) {
    match args.command {
        Some(ActivityCommand::Stats(a)) => crate::query::stats::run(a),
        Some(ActivityCommand::Replay(a)) => crate::query::replay::run(a),
        Some(ActivityCommand::Trace(a)) => crate::query::trace::run(a),
        Some(ActivityCommand::Approvals(a)) => crate::query::approvals::run(a),
        None => list(args),
    }
}

/// The merged `timeline` + `history` view: recent rows, narrowed by any filters.
fn list(args: ActivityArgs) {
    let has_filter = args.agent.is_some()
        || args.action.is_some()
        || args.decision.is_some()
        || args.since.is_some()
        || args.until.is_some()
        || args.dir.is_some()
        || args.sync_state.is_some();

    // Default depth: a quick recent glance unfiltered, a deeper scan when
    // filtering (you're hunting for something specific).
    let limit = args.last.unwrap_or(if has_filter { 200 } else { 20 });

    let mut query: Vec<(&str, String)> = vec![("limit", limit.to_string())];
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
