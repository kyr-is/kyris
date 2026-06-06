// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Thin client for kyrisd's operator API.
//!
//! kyrisd is the single owner of the timeline join (it holds the gateway
//! records and reads agentpact's event log). The CLI is a pure renderer: it
//! asks kyrisd for finished `TimelineEntry` / `TimelineStats` data and formats
//! it — mirroring how the web app asks the relay. No `DuckDB`, no file reads, so
//! the old exclusive-lock problem (kyrisd holds the DB open) simply can't occur.

use kyris_core::config::load_kyrisd_connection;
use kyris_core::timeline::{TimelinePage, TimelineStats};
use serde::de::DeserializeOwned;

/// Why an operator query could not be served.
pub enum OperatorError {
    /// kyrisd is unreachable (not running / wrong address). Degraded, indicated
    /// — the CLI says so rather than silently reading files behind its back.
    NotRunning,
    /// kyrisd answered, but with an error (auth, 5xx, malformed body).
    Request(String),
}

impl OperatorError {
    /// Print a one-line, actionable message and exit non-zero.
    pub fn report(&self) -> ! {
        match self {
            Self::NotRunning => eprintln!(
                "kyrisd is not running — start it with `kyris daemon start`. \
                 Timeline and stats are served by the daemon (it owns the records)."
            ),
            Self::Request(e) => eprintln!("kyrisd query failed: {e}"),
        }
        std::process::exit(1);
    }
}

fn get_json<T: DeserializeOwned>(path: &str, query: &[(&str, String)]) -> Result<T, OperatorError> {
    let conn = load_kyrisd_connection().ok_or(OperatorError::NotRunning)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| OperatorError::Request(e.to_string()))?;
    let mut url = reqwest::Url::parse(&format!("{}{path}", conn.base_url))
        .map_err(|e| OperatorError::Request(e.to_string()))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in query {
            pairs.append_pair(k, v);
        }
    }
    rt.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .bearer_auth(&conn.operator_key)
            .send()
            .await
            .map_err(|e| {
                // A refused/timed-out connection means the daemon isn't there;
                // anything else is a genuine request failure.
                if e.is_connect() || e.is_timeout() {
                    OperatorError::NotRunning
                } else {
                    OperatorError::Request(e.to_string())
                }
            })?;
        if !resp.status().is_success() {
            return Err(OperatorError::Request(format!(
                "kyrisd returned {}",
                resp.status()
            )));
        }
        resp.json::<T>()
            .await
            .map_err(|e| OperatorError::Request(e.to_string()))
    })
}

/// Fetch the unified timeline (newest first). `query` is the operator API's
/// filter set (`limit`, `agent`, `action`, `decision`, `session`, `trace_id`,
/// `dir`, `since`, `until`).
pub fn fetch_timeline(query: &[(&str, String)]) -> Result<TimelinePage, OperatorError> {
    get_json("/operator/timeline", query)
}

/// Fetch aggregate usage stats over a window.
pub fn fetch_stats(query: &[(&str, String)]) -> Result<TimelineStats, OperatorError> {
    get_json("/operator/stats", query)
}

/// Convert a relative window like `7d` / `24h` / `30m` to an RFC3339 lower
/// bound (`now - window`). Returns `None` if the spec is unparseable, in which
/// case the caller should omit the bound rather than guess.
#[must_use]
pub fn relative_since(spec: &str) -> Option<String> {
    let spec = spec.trim();
    let (num, unit) = spec.split_at(spec.len().checked_sub(1)?);
    let n: i64 = num.parse().ok()?;
    let dur = match unit {
        "d" => chrono::Duration::try_days(n)?,
        "h" => chrono::Duration::try_hours(n)?,
        "m" => chrono::Duration::try_minutes(n)?,
        _ => return None,
    };
    Some((chrono::Utc::now() - dur).to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testRelativeSinceParsesUnits() {
        assert!(relative_since("7d").is_some());
        assert!(relative_since("24h").is_some());
        assert!(relative_since("30m").is_some());
    }

    #[test]
    fn testRelativeSinceRejectsGarbage() {
        assert!(relative_since("").is_none());
        assert!(relative_since("7y").is_none());
        assert!(relative_since("abc").is_none());
        assert!(relative_since("d").is_none());
    }
}
