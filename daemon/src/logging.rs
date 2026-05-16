// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Daemon logging setup. Picks JSON format when stderr is not a
//! terminal (i.e. under launchd, systemd, or piped) and human-readable
//! text when attached to a tty. Honors `KYRIS_LOG` for filter
//! directives (falls back to `RUST_LOG`, then `kyrisd=info`). Honors
//! `KYRIS_LOG_FORMAT` (`json` | `text`) to override the auto-detected
//! format.
//!
//! When built with `--features oslog` (macOS) or `--features journald`
//! (Linux), a native sink is layered on top so platform-aware tooling
//! — Console.app, `log show`, journalctl — gets structured fields
//! with proper severity and metadata.
//!
//! A file sink always appends INFO+ events to the path returned by
//! `kyris_core::paths::log_path` (default
//! `~/.local/state/kyris/log/kyris.log`) in the format
//! `TIMESTAMP [kyrisd] [LEVEL] message`, interleaved with entries from
//! `kyris install`, `kyris update`, and other components.

use std::io::IsTerminal;
use std::io::Write as _;
use std::path::PathBuf;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialize the global tracing subscriber. Safe to call once at
/// startup.
pub fn init() {
    let filter = resolve_filter();
    let format = resolve_format();

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr);

    let registry = tracing_subscriber::registry().with(filter);

    let file_layer = KyrisFileLayer::new();

    if format == "json" {
        let layered = registry.with(stderr_layer.json()).with(file_layer);
        install(layered);
    } else {
        let layered = registry.with(stderr_layer).with(file_layer);
        install(layered);
    }
}

fn resolve_filter() -> EnvFilter {
    std::env::var("KYRIS_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .and_then(|raw| EnvFilter::try_new(&raw).ok())
        .unwrap_or_else(|| EnvFilter::new("kyrisd=info"))
}

fn resolve_format() -> String {
    std::env::var("KYRIS_LOG_FORMAT").ok().map_or_else(
        || {
            if std::io::stderr().is_terminal() {
                "text".to_string()
            } else {
                "json".to_string()
            }
        },
        |s| s.to_ascii_lowercase(),
    )
}

/// Stack the optional native sinks on top of the base subscriber and
/// call `.init()`. Each cfg arm is a no-op when its feature isn't
/// enabled.
fn install<S>(subscriber: S)
where
    S: tracing::Subscriber + Send + Sync + 'static,
    for<'a> S: tracing_subscriber::registry::LookupSpan<'a>,
{
    #[cfg(all(target_os = "macos", feature = "oslog"))]
    let subscriber = subscriber.with(tracing_oslog::OsLogger::new("is.kyr.kyrisd", "default"));

    #[cfg(all(target_os = "linux", feature = "journald"))]
    let subscriber = match tracing_journald::layer() {
        Ok(layer) => subscriber.with(Some(layer)),
        Err(e) => {
            eprintln!("kyrisd: journald connect failed, skipping native sink: {e}");
            subscriber.with(None::<tracing_journald::Layer>)
        }
    };

    subscriber.init();
}

// ── File sink ────────────────────────────────────────────────────────

/// Tracing layer that appends INFO+ events to the kyris log file
/// (see `kyris_core::paths::log_path`, default `~/.local/state/kyris/log/kyris.log`).
///
/// Opens the file fresh on every write (`O_APPEND`) so concurrent
/// writers from other kyris components produce interleaved but
/// non-corrupted output. Opening per-write is acceptable because
/// this path is only exercised for INFO/WARN/ERROR events, not the
/// hot per-command path.
struct KyrisFileLayer {
    path: Option<PathBuf>,
}

impl KyrisFileLayer {
    fn new() -> Self {
        let path = kyris_core::paths::log_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self { path: Some(path) }
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{value:?}");
        }
    }
}

impl<S: Subscriber> Layer<S> for KyrisFileLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(ref path) = self.path else { return };

        let level = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG | Level::TRACE => return,
        };

        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let msg = visitor.0;

        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let line = format!("{ts} [kyrisd] [{level}] {msg}\n");

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}
