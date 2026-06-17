// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! The single, shared timeline shape.
//!
//! A timeline is the read-time join of two streams that kyrisd owns locally:
//! agentpact **governance events** (`events.jsonl` — commands, decisions,
//! coverage) and kyrisd **gateway records** (model calls — provider, model,
//! tokens, cost). kyrisd performs that join exactly once and emits
//! [`TimelineEntry`] rows; the CLI renders them, and the relay coordinates them
//! across machines for the org-wide dashboard. There is no second join.
//!
//! This is a flattened **display/wire projection**, not a storage schema: the
//! categorical fields are plain strings (the same values the strongly-typed
//! enums in [`crate::event`] and [`crate::record`] serialize to) because the
//! rows are sourced from a SQL join and rendered, never re-evaluated as policy.
//! It is deliberately a superset of what any single renderer shows so that no
//! event-or-record detail is lost once the raw streams stop being stored.

use serde::{Deserialize, Serialize};

fn default_source() -> String {
    "agent".to_string()
}

/// One row of the unified timeline: either a governance event (optionally
/// enriched with its model call's cost/model/tokens) or a model-only "orphan"
/// record that had no matching event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TimelineEntry {
    /// Stable row id. The event id for event rows; the gateway record id for
    /// orphan (model-only) rows.
    pub id: String,
    /// RFC 3339 timestamp.
    pub timestamp: String,
    /// The model-call correlation key shared by an event and its record. Only
    /// think events and model-call records carry one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    // --- governance event fields ---
    pub agent: Option<String>,
    pub action: String,
    pub detail: Option<String>,
    pub decision: Option<String>,
    /// `enforced` | `observed` | `vendor_reported` | `unknown`. Typed as
    /// [`crate::event::CoverageState`] in generated clients via the `value_type`
    /// hint, while staying a plain string on the wire.
    #[cfg_attr(feature = "openapi", schema(value_type = crate::event::CoverageState))]
    pub coverage_state: String,
    /// Provenance of the row: `agent` | `synthetic` (model-only record) |
    /// `fail-open` (spooled while the daemon was unreachable). Defaults to
    /// `agent` when absent.
    #[serde(default = "default_source")]
    pub source: String,
    pub working_dir: Option<String>,
    pub git_remote_origin: Option<String>,
    pub session: Option<String>,
    pub mode: Option<String>,
    pub rule_kind: Option<String>,
    pub rule_id: Option<String>,
    /// Prompt-reduction telemetry carried from the governance event: the
    /// command's most-salient resource class (`workspace`, `sensitive:secret`,
    /// `network:unknown`, `remote`, …). `None` for model-only rows or events
    /// that predate the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_class: Option<String>,
    /// Prompt-reduction telemetry: whether answering "Always" would have stuck
    /// (session-grantable). Lets `stats` show how many prompts could have been
    /// remembered. `None` for model-only rows or pre-field events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantable: Option<bool>,
    /// kyrisd-stamped sync state: `synced` | `pending` | `local`. kyrisd is the
    /// one process that holds both the rows and the sync cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_state: Option<String>,
    /// Hostname of the originating machine. `None` locally; the relay fills it
    /// from its machine registry when coordinating the org-wide dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    // --- model-call fields (from the joined gateway record) ---
    pub provider: Option<String>,
    pub model: Option<String>,
    pub tokens_in: Option<i64>,
    pub tokens_out: Option<i64>,
    pub tokens_cache_create: Option<i64>,
    pub tokens_cache_read: Option<i64>,
    pub cost_usd: Option<f64>,
    pub latency_ms: Option<i64>,
    /// `success` | `error` | `circuit_breaker` | `cache_hit`.
    pub status: Option<String>,
    /// `available` | `unavailable` — whether the upstream usage block parsed.
    pub metering: Option<String>,
    /// `included` | `overage` | `unknown` — plan-covered vs billable.
    pub plan_status: Option<String>,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    /// Per-segment breakdown when this row is a compound `execute` command the
    /// agent issued as one line. Empty (omitted) for single commands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<crate::event::Segment>,
}

impl TimelineEntry {
    /// True when this row carries model-call detail (i.e. an enriched event or
    /// an orphan record), as opposed to an event with no associated model call.
    #[must_use]
    pub fn has_model_call(&self) -> bool {
        self.provider.is_some() || self.model.is_some() || self.cost_usd.is_some()
    }
}

/// kyrisd's `/operator/timeline` response: the joined rows plus the cursor a
/// caller can pass back for the next page (newest-first).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TimelinePage {
    pub entries: Vec<TimelineEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Aggregated usage statistics over a time window, computed by kyrisd from the
/// unified timeline. The CLI renders these; kyrisd does no formatting.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TimelineStats {
    /// Number of governance decisions, grouped by decision (auto/ask/deny/...).
    pub actions_by_decision: Vec<DecisionCount>,
    /// Per-agent activity counts.
    pub agents: Vec<AgentActivity>,
    /// Governance coverage breakdown (`enforced`/`observed`/`vendor_reported`/`unknown`).
    pub coverage: Vec<CoverageCount>,
    pub tokens: TokenTotals,
    /// Total cost of model calls (excludes errored/circuit-broken records).
    pub total_cost_usd: f64,
    /// Cost grouped by provider.
    pub spend_by_provider: Vec<ProviderSpend>,
    /// Per-model call counts and cost.
    pub models: Vec<ModelStat>,
    /// Count of model calls whose upstream usage block parsed vs. did not.
    pub metering_available: u64,
    pub metering_unavailable: u64,
    /// Prompt-reduction breakdown: `ask` decisions grouped by resource class,
    /// with how many were session-grantable (could have been remembered with
    /// "Always"). The empirical "what is prompting, and could it stick?" view.
    #[serde(default)]
    pub prompts_by_resource: Vec<PromptBucket>,
}

/// One resource-class bucket of approval prompts, with how many were
/// session-grantable. Sorted by `count` descending in [`TimelineStats`].
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PromptBucket {
    /// The command's most-salient resource class (`unclassified` when the event
    /// carried none).
    pub resource_class: String,
    /// Number of `ask` decisions in this bucket.
    pub count: u64,
    /// How many of those were session-grantable (answering "Always" would stick).
    pub grantable: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DecisionCount {
    pub decision: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AgentActivity {
    pub agent: String,
    pub total: u64,
    pub auto: u64,
    pub ask: u64,
    pub denied: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CoverageCount {
    pub coverage_state: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TokenTotals {
    pub input: i64,
    pub output: i64,
    pub cache_create: i64,
    pub cache_read: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProviderSpend {
    pub provider: String,
    pub cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ModelStat {
    pub model: String,
    pub calls: u64,
    pub cost_usd: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TimelineEntry {
        TimelineEntry {
            id: "evt-1".to_string(),
            timestamp: "2026-04-12T00:00:00Z".to_string(),
            trace_id: Some("trace-1".to_string()),
            agent: Some("claude".to_string()),
            action: "think".to_string(),
            detail: Some("model call".to_string()),
            decision: Some("auto".to_string()),
            coverage_state: "observed".to_string(),
            source: "agent".to_string(),
            working_dir: Some("/tmp/project".to_string()),
            git_remote_origin: None,
            session: Some("ses_abc".to_string()),
            mode: Some("enforce".to_string()),
            rule_kind: None,
            rule_id: None,
            resource_class: None,
            grantable: None,
            sync_state: Some("local".to_string()),
            hostname: None,
            provider: Some("anthropic".to_string()),
            model: Some("claude-4-opus".to_string()),
            tokens_in: Some(100),
            tokens_out: Some(50),
            tokens_cache_create: None,
            tokens_cache_read: None,
            cost_usd: Some(0.0151),
            latency_ms: Some(250),
            status: Some("success".to_string()),
            metering: Some("available".to_string()),
            plan_status: Some("included".to_string()),
            mcp_server: None,
            mcp_tool: None,
            segments: Vec::new(),
        }
    }

    #[test]
    fn testTimelineEntryRoundTrip() {
        let entry = sample();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TimelineEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
        assert_eq!(parsed.cost_usd, Some(0.0151));
        assert!(parsed.has_model_call());
    }

    #[test]
    fn testOmittedOptionalsDeserialize() {
        // A minimal event-only row (no model call, no cursor extras) must parse;
        // optional fields default to None.
        let json = r#"{
            "id": "evt-2",
            "timestamp": "2026-04-12T00:00:00Z",
            "agent": "claude",
            "action": "execute",
            "detail": "git status",
            "decision": "auto",
            "coverage_state": "enforced",
            "source": "agent",
            "working_dir": null,
            "git_remote_origin": null,
            "session": null,
            "mode": "enforce",
            "rule_kind": null,
            "rule_id": null,
            "provider": null,
            "model": null,
            "tokens_in": null,
            "tokens_out": null,
            "tokens_cache_create": null,
            "tokens_cache_read": null,
            "cost_usd": null,
            "latency_ms": null,
            "status": null,
            "metering": null,
            "plan_status": null,
            "mcp_server": null,
            "mcp_tool": null
        }"#;
        let entry: TimelineEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.id, "evt-2");
        assert!(entry.trace_id.is_none());
        assert!(entry.sync_state.is_none());
        assert!(entry.hostname.is_none());
        assert!(!entry.has_model_call());
    }

    #[test]
    fn testTimelinePageRoundTrip() {
        let page = TimelinePage {
            entries: vec![sample()],
            cursor: Some("2026-04-12T00:00:00Z|evt-1".to_string()),
        };
        let json = serde_json::to_string(&page).unwrap();
        let parsed: TimelinePage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.cursor.as_deref(), Some("2026-04-12T00:00:00Z|evt-1"));
    }
}
