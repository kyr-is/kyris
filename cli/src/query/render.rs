// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Terminal rendering of the timeline data kyrisd serves. The CLI is the user
//! interface; kyrisd returns structured `TimelineEntry` / `TimelineStats` and
//! all human formatting lives here.

use std::fmt::Write as _;

use kyris_core::timeline::{TimelineEntry, TimelineStats};

/// Render timeline rows, one per line, in the order given.
pub fn print_timeline(entries: &[TimelineEntry]) {
    if entries.is_empty() {
        println!("(no entries)");
        return;
    }
    for e in entries {
        println!("{}", format_row(e));
        // A compound command the agent issued as one line: show how each split
        // segment was governed, indented under the single row.
        for s in &e.segments {
            println!("    └─ {:<8} {}", s.decision.to_string(), s.command);
        }
    }
}

/// `<ts>  <agent>      <action>   <decision> [<coverage>] <detail>  [in→out]  $cost  [sync]`
fn format_row(e: &TimelineEntry) -> String {
    let agent = e.agent.as_deref().unwrap_or("-");
    let decision = e.decision.as_deref().unwrap_or("-");
    let detail = e.detail.as_deref().unwrap_or("");
    let mut line = format!(
        "{}  {agent:<15} {:<10} {decision:<8} [{:<8}] {detail}",
        e.timestamp, e.action, e.coverage_state,
    );
    if let (Some(ti), Some(to)) = (e.tokens_in, e.tokens_out) {
        let _ = write!(line, "  [{ti}\u{2192}{to}]");
    }
    if let Some(cost) = e.cost_usd {
        let _ = write!(line, "  ${cost:.4}");
    }
    // `local` is the common (unsynced) case — only annotate the notable states.
    if let Some(state) = &e.sync_state
        && state != "local"
    {
        let _ = write!(line, "  [{state}]");
    }
    line
}

/// Render aggregate usage stats. Sections mirror the previous `kyris stats`
/// layout (decisions, agents, coverage, tokens, spend, models, metering).
#[allow(clippy::cast_precision_loss)]
pub fn print_stats(s: &TimelineStats) {
    println!("Decisions:");
    if s.actions_by_decision.is_empty() {
        println!("  (none)");
    }
    for d in &s.actions_by_decision {
        println!("  {:<10} {}", d.decision, d.count);
    }

    println!("\nAgents:");
    if s.agents.is_empty() {
        println!("  (none)");
    }
    for a in &s.agents {
        println!(
            "  {:<20} total={:<6} auto={:<6} ask={:<5} denied={}",
            a.agent, a.total, a.auto, a.ask, a.denied
        );
    }

    println!("\nCoverage:");
    if s.coverage.is_empty() {
        println!("  (none)");
    }
    for c in &s.coverage {
        println!("  {:<16} {}", c.coverage_state, c.count);
    }

    println!("\nTokens:");
    println!(
        "  in={}  out={}  cache_create={}  cache_read={}",
        s.tokens.input, s.tokens.output, s.tokens.cache_create, s.tokens.cache_read
    );

    println!("\nSpend:  ${:.4} total", s.total_cost_usd);
    for p in &s.spend_by_provider {
        println!("  {:<16} ${:.4}", p.provider, p.cost_usd);
    }

    println!("\nModels:");
    if s.models.is_empty() {
        println!("  (none)");
    }
    for m in &s.models {
        println!("  {:<30} calls={:<6} ${:.4}", m.model, m.calls, m.cost_usd);
    }

    println!(
        "\nMetering:  available={}  unavailable={}",
        s.metering_available, s.metering_unavailable
    );
}
