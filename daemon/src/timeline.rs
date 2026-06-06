// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The unified timeline — the single event↔record join, owned by kyrisd.
//!
//! kyrisd is the one local process that holds both streams natively: it owns
//! the gateway records (its `DuckDB` table) and reads agentpact's
//! `events.jsonl`. So it performs the join exactly once, here, and hands
//! finished [`TimelineEntry`] rows to the CLI (read-time) and the relay (sync).
//! Nobody else joins.
//!
//! Two callers, one join definition. The operator API reads the event log via
//! `DuckDB` `read_json` (it needs an arbitrary "last N + filters" slice, and
//! `DuckDB` handles log rotation and `.gz` transparently), then joins in Rust;
//! sync reads new event lines incrementally by byte offset, then joins in Rust.
//! Both converge on [`TimelineEventRow`] and the shared [`join`] +
//! [`entry_from_event`] / [`entry_from_orphan_record`] mappers, so local and
//! cloud are byte-for-byte consistent.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kyris_core::event::{Event, Segment};
use kyris_core::record::GatewayRecord;
use kyris_core::timeline::{
    AgentActivity, CoverageCount, DecisionCount, ModelStat, ProviderSpend, TimelineEntry,
    TimelineStats, TokenTotals,
};

use crate::storage::DuckDbWriter;

/// The agentpact rotating event-log directory kyrisd reads to build timelines.
/// agentpact writes here (`$XDG_STATE_HOME/agentpact/log`, else
/// `~/.local/state/agentpact/log`); kyrisd mirrors that resolution so it reads
/// from the same place agentpact writes.
#[must_use]
pub fn agentpact_log_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(explicit).join("agentpact").join("log");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.local/state/agentpact/log"))
}

/// Filters for a timeline query. All present filters AND together. They map to
/// the governance-event columns; the cost/model fields come along via the join.
#[derive(Debug, Default, Clone)]
pub struct TimelineFilter {
    pub agent: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
    pub session: Option<String>,
    pub trace_id: Option<String>,
    /// `working_dir` prefix (a directory and everything under it).
    pub dir: Option<String>,
    /// RFC3339 lower bound (inclusive). Lexicographic compare — valid for the
    /// Z-suffixed RFC3339 timestamps agentpact and kyrisd both emit.
    pub since: Option<String>,
    /// RFC3339 upper bound (inclusive).
    pub until: Option<String>,
    pub limit: u32,
}

/// The governance-event side of a timeline row, after coverage derivation.
/// Produced either by reading the event log via `DuckDB` (operator API) or by
/// converting a parsed [`Event`] (sync) — both feed the same [`join`].
#[derive(Debug, Clone)]
pub struct TimelineEventRow {
    pub id: String,
    pub timestamp: String,
    pub agent: Option<String>,
    pub action: String,
    pub detail: Option<String>,
    pub decision: Option<String>,
    pub coverage_state: String,
    pub working_dir: Option<String>,
    pub git_remote_origin: Option<String>,
    pub session: Option<String>,
    pub mode: Option<String>,
    pub rule_kind: Option<String>,
    pub rule_id: Option<String>,
    pub trace_id: Option<String>,
    /// Per-segment breakdown for a compound command; empty otherwise.
    pub segments: Vec<Segment>,
}

impl From<&Event> for TimelineEventRow {
    fn from(e: &Event) -> Self {
        let coverage =
            kyris_core::coverage::derive(e.action, e.attribution_method, &e.mode).to_string();
        let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
        Self {
            id: e.id.clone(),
            timestamp: e.timestamp.clone(),
            agent: opt(&e.agent),
            action: e.action.to_string(),
            detail: opt(&e.detail),
            decision: Some(e.decision.to_string()),
            coverage_state: coverage,
            working_dir: e.working_dir.clone(),
            git_remote_origin: e.git_remote_origin.clone(),
            session: e.session.clone(),
            mode: opt(&e.mode),
            rule_kind: e.rule_kind.clone(),
            rule_id: e.rule_id.clone(),
            trace_id: e.trace_id.clone(),
            segments: e.segments.clone(),
        }
    }
}

/// Scope metadata used to stamp the sync state of event-only rows (records
/// carry their own `synced` flag). Mirrors the relay's scope contract.
#[derive(Debug, Clone, Default)]
pub struct SyncScope {
    pub patterns: Vec<String>,
    pub last_synced_at: Option<String>,
}

impl SyncScope {
    /// Load the scope kyrisd last synced under, from its `sync_metadata` row.
    pub fn load(db: &DuckDbWriter) -> Self {
        db.with_conn(|conn| {
            let row = conn
                .query_row(
                    "SELECT scope_json, last_synced_at FROM sync_metadata WHERE id = 1",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .ok();
            match row {
                Some((scope_json, last_synced_at)) => Self {
                    patterns: serde_json::from_str(&scope_json).unwrap_or_default(),
                    last_synced_at,
                },
                None => Self::default(),
            }
        })
    }

    /// Sync state for an event-only row at `working_dir`. `None` when the row is
    /// unscoped (no working dir) or kyrisd has never synced (no scope).
    fn event_state(&self, working_dir: Option<&str>) -> Option<String> {
        if self.patterns.is_empty() {
            return None;
        }
        let wd = working_dir?;
        let home = std::env::var("HOME").unwrap_or_default();
        let in_scope = self.patterns.iter().any(|p| {
            let expanded = p
                .strip_prefix('~')
                .map_or_else(|| p.clone(), |rest| format!("{home}{rest}"));
            if let Some(prefix) = expanded.strip_suffix('*') {
                wd.starts_with(prefix)
            } else {
                wd == expanded || wd.starts_with(&format!("{expanded}/"))
            }
        });
        // In scope but unsynced from this metadata alone — `entry_from_event`
        // refines "pending" to "synced" by comparing the row's own timestamp to
        // `last_synced_at` (which this helper doesn't have).
        if in_scope {
            Some("pending".to_string())
        } else {
            Some("local".to_string())
        }
    }
}

/// Coverage for a row, reflecting burn-control. A `think` row is normally
/// `observed` (metered, not blocked), but flips to `enforced` when kyrisd's
/// token circuit breaker rejected the call — the one place burn is *stopped*,
/// not just watched (kyris.md §16.7). This is the timeline's view of
/// burn-control governance, so it must survive the join.
fn coverage_with_burn(rec: Option<&GatewayRecord>, fallback: &str) -> String {
    match rec {
        Some(r) if r.status == kyris_core::record::RecordStatus::CircuitBreaker => {
            "enforced".to_string()
        }
        _ => fallback.to_string(),
    }
}

/// Sync state for a row backed by a gateway record. The record's `synced` flag
/// is authoritative; an unsynced-but-syncable record is `pending`.
fn record_sync_state(rec: &GatewayRecord) -> String {
    if rec.synced {
        "synced".to_string()
    } else if rec.working_dir.is_some() {
        "pending".to_string()
    } else {
        "local".to_string()
    }
}

/// Map a governance event (optionally enriched with its model-call record) to a
/// timeline entry. This is half of the single join definition.
#[must_use]
pub fn entry_from_event(
    row: &TimelineEventRow,
    rec: Option<&GatewayRecord>,
    scope: &SyncScope,
) -> TimelineEntry {
    // The record's synced flag wins when present; otherwise derive from scope.
    let sync_state = match rec {
        Some(r) => Some(record_sync_state(r)),
        None => scope.event_state(row.working_dir.as_deref()).map(|s| {
            // Refine "pending" vs "synced" by comparing this row's own
            // timestamp to the last-synced watermark.
            if s == "pending"
                && scope
                    .last_synced_at
                    .as_deref()
                    .is_some_and(|ts| row.timestamp.as_str() <= ts)
            {
                "synced".to_string()
            } else {
                s
            }
        }),
    };
    TimelineEntry {
        id: row.id.clone(),
        timestamp: row.timestamp.clone(),
        trace_id: row.trace_id.clone(),
        agent: row.agent.clone(),
        action: row.action.clone(),
        detail: row.detail.clone(),
        decision: row.decision.clone(),
        // A breaker-stopped model call is `enforced`, even though the event's
        // own coverage derives to `observed` — the join is where that crosses.
        coverage_state: coverage_with_burn(rec, &row.coverage_state),
        source: "agent".to_string(),
        working_dir: row.working_dir.clone(),
        git_remote_origin: row.git_remote_origin.clone(),
        session: row.session.clone(),
        mode: row.mode.clone(),
        rule_kind: row.rule_kind.clone(),
        rule_id: row.rule_id.clone(),
        sync_state,
        hostname: None,
        provider: rec.map(|r| r.provider.clone()),
        model: rec.map(|r| r.model.clone()),
        tokens_in: rec.and_then(|r| r.tokens_in),
        tokens_out: rec.and_then(|r| r.tokens_out),
        tokens_cache_create: rec.and_then(|r| r.tokens_cache_create),
        tokens_cache_read: rec.and_then(|r| r.tokens_cache_read),
        cost_usd: rec.and_then(|r| r.cost_usd),
        latency_ms: rec.map(|r| r.latency_ms),
        status: rec.map(|r| r.status.to_string()),
        metering: rec.map(|r| r.metering.to_string()),
        plan_status: rec.map(|r| r.plan_status.to_string()),
        mcp_server: rec.and_then(|r| r.mcp_server.clone()),
        mcp_tool: rec.and_then(|r| r.mcp_tool.clone()),
        segments: row.segments.clone(),
    }
}

/// Map a model-call record with no matching governance event to a model-only
/// ("orphan") timeline row. The other half of the join definition.
#[must_use]
pub fn entry_from_orphan_record(rec: &GatewayRecord) -> TimelineEntry {
    TimelineEntry {
        id: rec.id.clone(),
        timestamp: rec.timestamp.clone(),
        trace_id: Some(rec.trace_id.clone()),
        // Burn is attributed to the agent kyrisd recorded; `None` if the agent
        // didn't identify itself (we don't mislabel it as the provider).
        agent: rec.agent.clone(),
        action: "think".to_string(),
        detail: Some(rec.model.clone()),
        decision: None,
        coverage_state: coverage_with_burn(Some(rec), "observed"),
        source: "synthetic".to_string(),
        working_dir: rec.working_dir.clone(),
        git_remote_origin: None,
        session: rec.session_id.clone(),
        mode: None,
        rule_kind: None,
        rule_id: None,
        sync_state: Some(record_sync_state(rec)),
        hostname: None,
        provider: Some(rec.provider.clone()),
        model: Some(rec.model.clone()),
        tokens_in: rec.tokens_in,
        tokens_out: rec.tokens_out,
        tokens_cache_create: rec.tokens_cache_create,
        tokens_cache_read: rec.tokens_cache_read,
        cost_usd: rec.cost_usd,
        latency_ms: Some(rec.latency_ms),
        status: Some(rec.status.to_string()),
        metering: Some(rec.metering.to_string()),
        plan_status: Some(rec.plan_status.to_string()),
        mcp_server: rec.mcp_server.clone(),
        mcp_tool: rec.mcp_tool.clone(),
        // Orphan model-only rows are never compound commands.
        segments: Vec::new(),
    }
}

/// THE join: governance events LEFT JOIN model-call records on `trace_id`
/// (events enriched with the record's cost/model/tokens), plus records with no
/// matching event as their own model-only rows. Newest first.
#[must_use]
pub fn join(
    events: Vec<TimelineEventRow>,
    records: Vec<GatewayRecord>,
    scope: &SyncScope,
) -> Vec<TimelineEntry> {
    let by_trace: HashMap<&str, &GatewayRecord> =
        records.iter().map(|r| (r.trace_id.as_str(), r)).collect();
    let event_traces: std::collections::HashSet<&str> = events
        .iter()
        .filter_map(|e| e.trace_id.as_deref())
        .collect();

    let mut entries: Vec<TimelineEntry> = events
        .iter()
        .map(|row| {
            let rec = row
                .trace_id
                .as_deref()
                .and_then(|t| by_trace.get(t).copied());
            entry_from_event(row, rec, scope)
        })
        .collect();

    // Orphan (model-only) records: a record whose trace has no event row.
    for rec in &records {
        if !event_traces.contains(rec.trace_id.as_str()) {
            entries.push(entry_from_orphan_record(rec));
        }
    }

    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then(b.id.cmp(&a.id)));
    entries
}

/// Read-time timeline for the operator API: read the event log via `DuckDB`,
/// join to records, newest-first, capped by `filter.limit`.
pub fn query_timeline(
    db: &DuckDbWriter,
    log_dir: &Path,
    filter: &TimelineFilter,
) -> Vec<TimelineEntry> {
    let scope = SyncScope::load(db);
    let limit = filter.limit.clamp(1, 10_000);

    let events = read_event_rows(db, log_dir, filter, limit).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "timeline: reading event log failed");
        Vec::new()
    });
    let records = read_records_for(db, filter, limit);

    let mut entries = join(events, records, &scope);
    entries.truncate(limit as usize);
    entries
}

/// Aggregate statistics for the operator API. Computed over every entry in the
/// window (so the caller should pass a wide `limit` + a `since`), not last-N.
#[must_use]
pub fn compute_stats(entries: &[TimelineEntry]) -> TimelineStats {
    let mut decisions: HashMap<String, u64> = HashMap::new();
    let mut agents: HashMap<String, AgentActivity> = HashMap::new();
    let mut coverage: HashMap<String, u64> = HashMap::new();
    let mut tokens = TokenTotals::default();
    let mut total_cost = 0.0_f64;
    let mut provider_spend: HashMap<String, f64> = HashMap::new();
    let mut models: HashMap<String, ModelStat> = HashMap::new();
    let mut metering_available = 0u64;
    let mut metering_unavailable = 0u64;

    for e in entries {
        if let Some(d) = &e.decision {
            *decisions.entry(d.clone()).or_default() += 1;
            let agent = e.agent.clone().unwrap_or_else(|| "unknown".to_string());
            let a = agents
                .entry(agent.clone())
                .or_insert_with(|| AgentActivity {
                    agent,
                    ..AgentActivity::default()
                });
            a.total += 1;
            match d.as_str() {
                "auto" => a.auto += 1,
                "ask" => a.ask += 1,
                "deny" => a.denied += 1,
                _ => {}
            }
        }
        *coverage.entry(e.coverage_state.clone()).or_default() += 1;

        tokens.input += e.tokens_in.unwrap_or(0);
        tokens.output += e.tokens_out.unwrap_or(0);
        tokens.cache_create += e.tokens_cache_create.unwrap_or(0);
        tokens.cache_read += e.tokens_cache_read.unwrap_or(0);

        let errored = matches!(e.status.as_deref(), Some("error" | "circuit_breaker"));
        if let Some(cost) = e.cost_usd
            && !errored
        {
            total_cost += cost;
            if let Some(p) = &e.provider {
                *provider_spend.entry(p.clone()).or_default() += cost;
            }
        }
        if let Some(model) = &e.model {
            let m = models.entry(model.clone()).or_insert_with(|| ModelStat {
                model: model.clone(),
                ..ModelStat::default()
            });
            m.calls += 1;
            if !errored {
                m.cost_usd += e.cost_usd.unwrap_or(0.0);
            }
        }
        match e.metering.as_deref() {
            Some("unavailable") => metering_unavailable += 1,
            Some("available") => metering_available += 1,
            _ => {}
        }
    }

    let mut actions_by_decision: Vec<DecisionCount> = decisions
        .into_iter()
        .map(|(decision, count)| DecisionCount { decision, count })
        .collect();
    actions_by_decision.sort_by_key(|d| std::cmp::Reverse(d.count));

    let mut agents: Vec<AgentActivity> = agents.into_values().collect();
    agents.sort_by_key(|a| std::cmp::Reverse(a.total));

    let mut coverage: Vec<CoverageCount> = coverage
        .into_iter()
        .map(|(coverage_state, count)| CoverageCount {
            coverage_state,
            count,
        })
        .collect();
    coverage.sort_by_key(|c| std::cmp::Reverse(c.count));

    let mut spend_by_provider: Vec<ProviderSpend> = provider_spend
        .into_iter()
        .map(|(provider, cost_usd)| ProviderSpend { provider, cost_usd })
        .collect();
    spend_by_provider.sort_by(|a, b| b.cost_usd.total_cmp(&a.cost_usd));

    let mut models: Vec<ModelStat> = models.into_values().collect();
    models.sort_by_key(|m| std::cmp::Reverse(m.calls));

    TimelineStats {
        actions_by_decision,
        agents,
        coverage,
        tokens,
        total_cost_usd: total_cost,
        spend_by_provider,
        models,
        metering_available,
        metering_unavailable,
    }
}

// --- internal: DuckDB-backed reads for the operator API ---

/// The explicit `read_json` column set. Naming each column makes the schema
/// deterministic regardless of which optional fields appear in the log
/// (`read_json_auto` would error referencing a field absent from every line —
/// e.g. a fresh log with no think event yet has no `trace_id` column).
const EVENT_COLUMNS: &str = "{\
    id: 'VARCHAR', timestamp: 'VARCHAR', agent: 'VARCHAR', action: 'VARCHAR', \
    detail: 'VARCHAR', decision: 'VARCHAR', working_dir: 'VARCHAR', trace_id: 'VARCHAR', \
    git_remote_origin: 'VARCHAR', session: 'VARCHAR', mode: 'VARCHAR', \
    rule_kind: 'VARCHAR', rule_id: 'VARCHAR', attribution_method: 'VARCHAR', \
    segments: 'JSON'\
}";

/// Bracketed `read_json` source list over the event log, gating each glob to
/// the ones that actually match ≥1 file (`DuckDB` errors on a zero-match glob).
/// `None` when the dir holds no event-log files.
fn event_log_sources(log_dir: &Path) -> Option<String> {
    let dir = log_dir.to_string_lossy();
    let sources: Vec<String> = [("*.jsonl", ".jsonl"), ("*.jsonl.gz", ".jsonl.gz")]
        .into_iter()
        .filter(|(_, suffix)| dir_has_suffix(log_dir, suffix))
        .map(|(glob, _)| format!("'{dir}/{glob}'"))
        .collect();
    (!sources.is_empty()).then(|| format!("[{}]", sources.join(", ")))
}

fn dir_has_suffix(log_dir: &Path, suffix: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(suffix))
    })
}

fn read_event_rows(
    db: &DuckDbWriter,
    log_dir: &Path,
    filter: &TimelineFilter,
    limit: u32,
) -> duckdb::Result<Vec<TimelineEventRow>> {
    let Some(sources) = event_log_sources(log_dir) else {
        return Ok(Vec::new());
    };
    let coverage = kyris_core::coverage::sql_expr();
    // `ignore_errors` skips a partially-written trailing line agentpact may be
    // mid-append; the next read picks it up once complete.
    let mut sql = format!(
        "SELECT id, timestamp, agent, action, detail, decision, working_dir, trace_id, \
                git_remote_origin, session, mode, rule_kind, rule_id, {coverage} AS coverage_state, \
                CAST(segments AS VARCHAR) AS segments \
         FROM read_json({sources}, columns = {EVENT_COLUMNS}, \
                        format = 'newline_delimited', ignore_errors = true) \
         WHERE 1 = 1"
    );
    let mut params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();
    let mut eq = |col: &str, val: &Option<String>, sql: &mut String| {
        if let Some(v) = val {
            let _ = write!(sql, " AND {col} = ?");
            params.push(Box::new(v.clone()));
        }
    };
    eq("agent", &filter.agent, &mut sql);
    eq("action", &filter.action, &mut sql);
    eq("decision", &filter.decision, &mut sql);
    eq("session", &filter.session, &mut sql);
    eq("trace_id", &filter.trace_id, &mut sql);
    // Compare as real timestamps, not VARCHAR text. The event log stores
    // `timestamp` as a JSON string, so a bare `timestamp >= ?` is a lexical
    // compare that silently mis-filters when the bound's formatting differs
    // (e.g. `Z` vs `+00:00`) — and tolerates a non-timestamp bound entirely,
    // diverging from the typed gateway-record reader. `TRY_CAST` makes both
    // sides genuine timestamps (a malformed bound yields NULL → no match, and
    // the handler already 400s a non-RFC3339 bound before we get here).
    if let Some(since) = &filter.since {
        sql.push_str(" AND TRY_CAST(timestamp AS TIMESTAMP) >= TRY_CAST(? AS TIMESTAMP)");
        params.push(Box::new(since.clone()));
    }
    if let Some(until) = &filter.until {
        sql.push_str(" AND TRY_CAST(timestamp AS TIMESTAMP) <= TRY_CAST(? AS TIMESTAMP)");
        params.push(Box::new(until.clone()));
    }
    if let Some(dir) = &filter.dir {
        sql.push_str(" AND (working_dir = ? OR working_dir LIKE ?)");
        params.push(Box::new(dir.clone()));
        params.push(Box::new(format!("{dir}/%")));
    }
    let _ = write!(sql, " ORDER BY timestamp DESC LIMIT {limit}");

    db.with_conn(|conn| {
        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn duckdb::ToSql> =
            params.iter().map(std::convert::AsRef::as_ref).collect();
        let rows = stmt.query_map(&param_refs[..], |row| {
            Ok(TimelineEventRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                agent: row.get(2)?,
                action: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                detail: row.get(4)?,
                decision: row.get(5)?,
                working_dir: row.get(6)?,
                trace_id: row.get(7)?,
                git_remote_origin: row.get(8)?,
                session: row.get(9)?,
                mode: row.get(10)?,
                rule_kind: row.get(11)?,
                rule_id: row.get(12)?,
                coverage_state: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
                segments: row
                    .get::<_, Option<String>>(14)?
                    .and_then(|s| serde_json::from_str::<Vec<Segment>>(&s).ok())
                    .unwrap_or_default(),
            })
        })?;
        rows.collect()
    })
}

/// Records relevant to a timeline slice: filtered the same way as the events
/// where the column exists, capped generously so orphan detection and
/// enrichment both have what they need.
fn read_records_for(db: &DuckDbWriter, filter: &TimelineFilter, limit: u32) -> Vec<GatewayRecord> {
    let rec_filter = crate::storage::GatewayRecordFilter {
        session_id: filter.session.as_deref(),
        trace_id: filter.trace_id.as_deref(),
        since: filter.since.as_deref(),
        // Fetch enough records to enrich/orphan the event window.
        limit: Some(limit.saturating_mul(2).clamp(limit, 10_000)),
        ..Default::default()
    };
    db.query_gateway_records(rec_filter).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "timeline: reading gateway records failed");
        Vec::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kyris_core::record::{Metering, PlanStatus, RecordStatus};

    fn rec(trace: &str, synced: bool, wd: Option<&str>) -> GatewayRecord {
        GatewayRecord {
            id: format!("rec-{trace}"),
            trace_id: trace.to_string(),
            timestamp: "2026-04-12T00:00:01Z".to_string(),
            provider: "anthropic".to_string(),
            model: "claude-4-opus".to_string(),
            tokens_in: Some(100),
            tokens_out: Some(50),
            tokens_cache_create: None,
            tokens_cache_read: None,
            cost_usd: Some(0.02),
            latency_ms: 250,
            status: RecordStatus::Success,
            session_id: Some("ses_1".to_string()),
            synced,
            mcp_server: None,
            mcp_tool: None,
            metering: Metering::Available,
            plan_status: PlanStatus::Overage,
            working_dir: wd.map(str::to_string),
            agent: Some("claude".to_string()),
        }
    }

    fn ev(id: &str, action: &str, trace: Option<&str>) -> TimelineEventRow {
        TimelineEventRow {
            id: id.to_string(),
            timestamp: "2026-04-12T00:00:00Z".to_string(),
            agent: Some("claude".to_string()),
            action: action.to_string(),
            detail: Some("detail".to_string()),
            decision: Some("auto".to_string()),
            coverage_state: "observed".to_string(),
            working_dir: Some("/work/repo".to_string()),
            git_remote_origin: None,
            session: Some("ses_1".to_string()),
            mode: Some("enforce".to_string()),
            rule_kind: None,
            rule_id: None,
            trace_id: trace.map(str::to_string),
            segments: Vec::new(),
        }
    }

    #[test]
    fn testThinkEventEnrichedWithRecordCost() {
        // A think event LEFT JOINs to its record: the entry carries cost/model.
        let scope = SyncScope::default();
        let entries = join(
            vec![ev("evt-1", "think", Some("trace-1"))],
            vec![rec("trace-1", false, Some("/work/repo"))],
            &scope,
        );
        assert_eq!(entries.len(), 1, "no orphan: the record matched the event");
        let e = &entries[0];
        assert_eq!(e.source, "agent");
        assert_eq!(e.cost_usd, Some(0.02));
        assert_eq!(e.model.as_deref(), Some("claude-4-opus"));
        assert_eq!(e.tokens_in, Some(100));
        assert!(e.has_model_call());
    }

    #[test]
    fn testOrphanRecordBecomesSyntheticRow() {
        // A record with no matching event becomes a model-only synthetic row.
        let scope = SyncScope::default();
        let entries = join(
            vec![],
            vec![rec("trace-x", true, Some("/work/repo"))],
            &scope,
        );
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.source, "synthetic");
        assert_eq!(e.action, "think");
        assert_eq!(e.trace_id.as_deref(), Some("trace-x"));
        assert_eq!(e.cost_usd, Some(0.02));
        assert_eq!(e.sync_state.as_deref(), Some("synced"));
    }

    #[test]
    fn testGovernanceEventHasNoModelCall() {
        let scope = SyncScope::default();
        let entries = join(vec![ev("evt-2", "execute", None)], vec![], &scope);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(!e.has_model_call());
        assert_eq!(e.cost_usd, None);
        assert_eq!(e.action, "execute");
    }

    #[test]
    fn testCircuitBreakerRowIsEnforced() {
        // Burn-control firing is the one place a `think` is enforced, not just
        // observed — it must survive into the timeline, as an orphan row and as
        // an enriched think event (whose own coverage derives to observed).
        let scope = SyncScope::default();
        let mut breaker = rec("trace-cb", false, Some("/work/repo"));
        breaker.status = RecordStatus::CircuitBreaker;

        let orphan = join(vec![], vec![breaker.clone()], &scope);
        assert_eq!(orphan[0].coverage_state, "enforced", "orphan breaker row");

        let enriched = join(
            vec![ev("evt-cb", "think", Some("trace-cb"))],
            vec![breaker],
            &scope,
        );
        assert_eq!(
            enriched[0].coverage_state, "enforced",
            "enriched breaker row keeps the burn-control signal"
        );
    }

    #[test]
    fn testNewestFirstOrdering() {
        let scope = SyncScope::default();
        let mut older = ev("evt-old", "execute", None);
        older.timestamp = "2026-04-12T00:00:00Z".to_string();
        let mut newer = ev("evt-new", "execute", None);
        newer.timestamp = "2026-04-12T09:00:00Z".to_string();
        let entries = join(vec![older, newer], vec![], &scope);
        assert_eq!(entries[0].id, "evt-new");
        assert_eq!(entries[1].id, "evt-old");
    }

    #[test]
    fn testRecordSyncStateAuthoritativeOverScope() {
        // A synced record makes the row 'synced' regardless of scope.
        let scope = SyncScope::default();
        let entries = join(
            vec![ev("evt-3", "think", Some("trace-3"))],
            vec![rec("trace-3", true, Some("/work/repo"))],
            &scope,
        );
        assert_eq!(entries[0].sync_state.as_deref(), Some("synced"));
    }

    #[test]
    fn testComputeStatsAggregates() {
        let scope = SyncScope::default();
        let entries = join(
            vec![
                ev("e1", "execute", None),
                ev("e2", "think", Some("trace-1")),
            ],
            vec![rec("trace-1", false, Some("/work/repo"))],
            &scope,
        );
        let stats = compute_stats(&entries);
        assert_eq!(stats.tokens.input, 100);
        assert_eq!(stats.tokens.output, 50);
        assert!((stats.total_cost_usd - 0.02).abs() < 1e-9);
        assert_eq!(stats.models.len(), 1);
        assert_eq!(stats.models[0].calls, 1);
        // Both rows have decision 'auto' (think rows keep the event's decision).
        let auto = stats
            .actions_by_decision
            .iter()
            .find(|d| d.decision == "auto")
            .map(|d| d.count);
        assert_eq!(auto, Some(2));
    }

    #[test]
    fn testEventLogSourcesNoneWhenEmpty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(event_log_sources(dir.path()).is_none());
    }

    #[test]
    fn testEventLogSourcesGatesGlobs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events.jsonl"), b"{}\n").unwrap();
        let sources = event_log_sources(dir.path()).expect("some sources");
        assert!(sources.contains("/*.jsonl'"), "{sources}");
        assert!(!sources.contains("*.jsonl.gz"), "{sources}");
    }

    #[test]
    fn testEventRowFromEventDerivesCoverage() {
        let json = r#"{"id":"e1","timestamp":"2026-04-12T00:00:00Z","agent":"claude",
            "action":"execute","detail":"git status","decision":"auto","mode":"enforce",
            "attribution_method":"lineage","binary":"claude"}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        let row = TimelineEventRow::from(&event);
        assert_eq!(row.action, "execute");
        assert_eq!(row.coverage_state, "enforced");
        assert_eq!(row.decision.as_deref(), Some("auto"));
    }
    // NOTE: the read-time join over a *real* DuckDB + *real* `events.jsonl` (via
    // `read_json`) is exercised by the live e2e (`kyris timeline` reads `execute`
    // events from the log through this path) rather than a unit test: `read_json`
    // is unreliable when ~30 DuckDB-using tests run concurrently in one process
    // (a duckdb-rs limitation, not a kyrisd-runtime one — production kyrisd uses a
    // single mutex-guarded connection). The join logic itself is covered
    // deterministically by `testThinkEventEnrichedWithRecordCost` above.
}
