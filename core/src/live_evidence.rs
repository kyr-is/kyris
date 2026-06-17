// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Per-agent, per-surface **live evidence** breadcrumbs: proof that an adapted
//! governance surface actually worked end-to-end at least once, not merely that
//! its config artifact exists on disk.
//!
//! Recorded by the components that *are* the surface when they run for real:
//! `kyris hook check` (execution — a decision round-tripped agentpactd),
//! `kyris-mcp wrap` / kyrisd's `/mcp/` routing (tool — a `tools/call` was
//! mediated), and kyrisd's provider adapters (burn-control — a request arrived
//! carrying `x-kyris-agent-id`). Probes and `kyris agent status` read these to
//! distinguish "configured (unverified)" from "verified live" — see the
//! agent-interface review's fourth gap (probes over-claiming on artifact
//! existence).
//!
//! Distinct from the `.native-seen` breadcrumb, which records evidence of
//! NATIVE `AgentPact` protocol support and drives surface promotion; this records
//! that the *adapted* path is alive and is refreshed (debounced) rather than
//! written once.

use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

pub const SURFACE_EXECUTION: &str = "execution";
pub const SURFACE_TOOL: &str = "tool";
pub const SURFACE_BURN_CONTROL: &str = "burn_control";

/// Refresh window: a breadcrumb younger than this is not rewritten, so
/// high-frequency surfaces (every LLM request, every hook check) cost one
/// `stat` per event, not one write.
const REFRESH_SECS: u64 = 60;

/// Agent ids arrive in two forms: the bare kyris registry handle
/// (`claude-code`) and the canonical `vendor/product` form that rides the
/// `x-kyris-agent-id` header (`anthropic/claude-code`). The canonical form
/// embeds the bare id as its final segment (locked by the kyris CLI registry's
/// `testCanonicalIdsMatchAgentpactVendorProduct`), so the file key is always
/// the bare segment — also keeping the path single-level. Public because the
/// daemon's breadcrumb writers key files the same way.
#[must_use]
pub fn bare_agent_id(agent_id: &str) -> &str {
    agent_id.rsplit('/').next().unwrap_or(agent_id)
}

/// `~/.kyris/agents/.live-seen/` — sibling of reconcile's `.native-seen`.
fn live_seen_dir() -> PathBuf {
    crate::paths::agents_dir().join(".live-seen")
}

/// The bare id becomes a path component, and burn/tool ids arrive from request
/// headers — reject anything that is empty or not a plain token so a malformed
/// header cannot key a file outside `.live-seen` (e.g. `vendor/..`).
fn valid_bare_id(bare: &str) -> bool {
    !bare.is_empty()
        && bare != "."
        && bare != ".."
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn surface_path(dir: &Path, agent_id: &str, surface: &str) -> Option<PathBuf> {
    let bare = bare_agent_id(agent_id);
    valid_bare_id(bare).then(|| dir.join(bare).join(surface))
}

/// Record that `surface` for `agent_id` was observed working live, debounced
/// to one write per [`REFRESH_SECS`]. Best-effort: failures are swallowed —
/// evidence is an observability aid, never load-bearing for a decision.
pub fn record(agent_id: &str, surface: &str) {
    record_in(&live_seen_dir(), agent_id, surface);
}

/// When `surface` for `agent_id` was last observed working live, if ever.
#[must_use]
pub fn last_seen(agent_id: &str, surface: &str) -> Option<DateTime<Utc>> {
    last_seen_in(&live_seen_dir(), agent_id, surface)
}

// Directory-explicit cores, so tests run against a tempdir without mutating
// process-global env (HOME races across parallel tests).
fn record_in(dir: &Path, agent_id: &str, surface: &str) {
    let Some(path) = surface_path(dir, agent_id, surface) else {
        return;
    };
    if let Ok(meta) = std::fs::metadata(&path)
        && let Ok(modified) = meta.modified()
        && std::time::SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age.as_secs() < REFRESH_SECS)
    {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, Utc::now().to_rfc3339());
}

fn last_seen_in(dir: &Path, agent_id: &str, surface: &str) -> Option<DateTime<Utc>> {
    let contents = std::fs::read_to_string(surface_path(dir, agent_id, surface)?).ok()?;
    contents
        .trim()
        .parse::<DateTime<chrono::FixedOffset>>()
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRecordAndReadRoundTrip() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        assert!(last_seen_in(temp.path(), "claude-code", SURFACE_EXECUTION).is_none());
        record_in(temp.path(), "claude-code", SURFACE_EXECUTION);
        let seen = last_seen_in(temp.path(), "claude-code", SURFACE_EXECUTION).expect("recorded");
        assert!((Utc::now() - seen).num_seconds().abs() < 5);
    }

    #[test]
    fn testCanonicalIdNormalizesToBareSegment() {
        // The daemon records under the canonical header form; the CLI reads
        // under the bare registry handle. Both must hit the same file.
        let temp = tempfile::TempDir::new().expect("tempdir");
        record_in(temp.path(), "anthropic/claude-code", SURFACE_BURN_CONTROL);
        assert!(last_seen_in(temp.path(), "claude-code", SURFACE_BURN_CONTROL).is_some());
    }

    #[test]
    fn testRecordDebouncesRecentBreadcrumb() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        record_in(temp.path(), "codex-cli", SURFACE_TOOL);
        let path = surface_path(temp.path(), "codex-cli", SURFACE_TOOL).expect("valid id");
        let first = std::fs::read_to_string(&path).unwrap();
        record_in(temp.path(), "codex-cli", SURFACE_TOOL);
        let second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first, second, "second write inside the window must skip");
    }

    #[test]
    fn testRecordRejectsMalformedIds() {
        // Header-supplied ids must not key files outside .live-seen or write
        // under an empty component.
        let temp = tempfile::TempDir::new().expect("tempdir");
        for bad in ["", "vendor/..", "..", "a b", "a/"] {
            record_in(temp.path(), bad, SURFACE_BURN_CONTROL);
        }
        let entries: Vec<_> = std::fs::read_dir(temp.path())
            .map(|d| d.filter_map(Result::ok).collect())
            .unwrap_or_default();
        assert!(entries.is_empty(), "no breadcrumb for malformed ids");
    }
}
