// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! `kyris diag` — operational diagnostics. Currently exposes
//! runtime log-filter control against a running kyrisd via the
//! `/operator/diag/log-filter` HTTP endpoint.
//!
//! Typical workflow when chasing a misbehaving request:
//!
//! ```text
//! kyris diag trace-on --duration 60s    # flip to verbose for 60s
//! # … reproduce the bug …
//! kyris logs trace <trace_id>           # vacuum logs for that request
//! # … 60s later, filter auto-reverts ; no manual cleanup needed
//! ```
//!
//! For when HTTP is unavailable (daemon stuck, no operator key,
//! TCP listener down), `kill -USR2 $(cat ~/.kyris/kyrisd.pid)`
//! toggles between `log.filter` and `log.verbose_filter` from
//! the daemon's config. The SIGUSR2 path has no auto-revert.

use clap::{Args, Subcommand};

use crate::state::load_or_init_config;

const DEFAULT_TRACE_DURATION_SECS: u64 = 60;
const DEFAULT_TRACE_FILTER: &str = "kyrisd::adapter=trace,kyrisd::auth=debug,kyrisd=debug";

#[derive(Args)]
pub struct DiagArgs {
    #[command(subcommand)]
    pub command: DiagCommand,
}

#[derive(Subcommand)]
pub enum DiagCommand {
    /// Flip kyrisd's log filter to a verbose preset (default:
    /// `kyrisd::adapter=trace,kyrisd::auth=debug,kyrisd=debug`)
    /// for a bounded window, then auto-revert.
    TraceOn(TraceOnArgs),
    /// Revert kyrisd's log filter to the baseline from its config
    /// immediately.
    TraceOff,
    /// Show the currently-active log filter.
    Status,
}

#[derive(Args)]
pub struct TraceOnArgs {
    /// `EnvFilter` directive (override the default verbose preset).
    /// Example: `kyrisd::adapter::anthropic=trace`.
    #[arg(long)]
    pub filter: Option<String>,
    /// Auto-revert window in seconds. Default 60s. Pass 0 to
    /// disable auto-revert (the filter sticks until the next
    /// `trace-off` / `trace-on` / daemon restart).
    #[arg(long, default_value_t = DEFAULT_TRACE_DURATION_SECS)]
    pub duration_secs: u64,
}

pub fn run(args: DiagArgs) {
    let result = match args.command {
        DiagCommand::TraceOn(a) => trace_on(a),
        DiagCommand::TraceOff => trace_off(),
        DiagCommand::Status => status(),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn trace_on(args: TraceOnArgs) -> Result<(), String> {
    let filter = args
        .filter
        .unwrap_or_else(|| DEFAULT_TRACE_FILTER.to_string());
    let duration = if args.duration_secs == 0 {
        None
    } else {
        Some(args.duration_secs)
    };

    let resp = post_log_filter(&filter, duration)?;
    println!("log filter: {} → {}", resp.previous_filter, resp.new_filter);
    if let Some(when) = resp.reverts_at {
        println!("reverts at: {when}");
    } else {
        println!("(no auto-revert; run `kyris diag trace-off` to restore)");
    }
    Ok(())
}

fn trace_off() -> Result<(), String> {
    let config = load_or_init_config()?;
    let baseline = config.log.filter.clone();
    let resp = post_log_filter(&baseline, None)?;
    println!(
        "log filter reverted: {} → {}",
        resp.previous_filter, resp.new_filter
    );
    Ok(())
}

fn status() -> Result<(), String> {
    let body = get_log_filter()?;
    let current = body
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    println!("active log filter: {current}");
    Ok(())
}

#[derive(serde::Deserialize)]
struct DiagLogFilterResponse {
    previous_filter: String,
    new_filter: String,
    #[serde(default)]
    reverts_at: Option<String>,
}

fn post_log_filter(
    filter: &str,
    duration_secs: Option<u64>,
) -> Result<DiagLogFilterResponse, String> {
    let config = load_or_init_config()?;
    let base = config.base_url();
    if config.server.operator_key.is_empty() {
        return Err(
            "operator_key not found in installed config; run `kyris install` to populate it"
                .to_string(),
        );
    }
    let key = config.server.operator_key.clone();

    let url = format!("{base}/operator/diag/log-filter");
    let mut body = serde_json::json!({ "filter": filter });
    if let Some(d) = duration_secs {
        body["duration_secs"] = serde_json::json!(d);
    }

    let response = blocking_request(&url, "POST", &key, Some(body))?;
    serde_json::from_value(response).map_err(|e| format!("parse diag response: {e}"))
}

fn get_log_filter() -> Result<serde_json::Value, String> {
    let config = load_or_init_config()?;
    let base = config.base_url();
    if config.server.operator_key.is_empty() {
        return Err(
            "operator_key not found in installed config; run `kyris install` to populate it"
                .to_string(),
        );
    }
    let key = config.server.operator_key.clone();
    let url = format!("{base}/operator/diag/log-filter");
    blocking_request(&url, "GET", &key, None)
}

/// Minimal blocking HTTP. Spins a one-shot tokio runtime so this
/// CLI command stays as a normal `fn` — matches the pattern used by
/// `kyris always`, `kyris pending`, etc.
fn blocking_request(
    url: &str,
    method: &str,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build tokio runtime: {e}"))?;

    runtime.block_on(async {
        let client = reqwest::Client::new();
        let req = match method {
            "GET" => client.get(url),
            "POST" => client.post(url),
            other => return Err(format!("unsupported method: {other}")),
        };
        let mut req = req
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json");
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.map_err(|e| format!("request: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| format!("read body: {e}"))?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {body}"));
        }
        if body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_str(&body).map_err(|e| format!("parse response: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testDefaultDurationIs60Seconds() {
        assert_eq!(DEFAULT_TRACE_DURATION_SECS, 60);
    }

    #[test]
    fn testDefaultFilterCoversTheThreeUsualSuspects() {
        // adapter (where the bug we shipped to debug lived),
        // auth (header-related issues), and the daemon broad layer.
        assert!(DEFAULT_TRACE_FILTER.contains("kyrisd::adapter=trace"));
        assert!(DEFAULT_TRACE_FILTER.contains("kyrisd::auth=debug"));
        assert!(DEFAULT_TRACE_FILTER.contains("kyrisd=debug"));
    }
}
