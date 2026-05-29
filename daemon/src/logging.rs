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
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Initialize the global tracing subscriber. Safe to call once at
/// startup. After this returns, [`try_set_filter`] /
/// [`current_filter`] / [`try_toggle_verbose`] are usable.
pub fn init() {
    let initial = resolve_filter_string();
    let format = resolve_format();

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr);

    let parsed = EnvFilter::try_new(&initial).unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    // Reloadable filter: wraps the EnvFilter so we can swap it
    // atomically at runtime via [`try_set_filter`]. Adds ~10ns per
    // event check (one RwLock::read on the parking_lot fast path)
    // and lets a long-running daemon flip into DEBUG / TRACE for a
    // bounded window without restart.
    let (reloadable, handle) = tracing_subscriber::reload::Layer::new(parsed);

    let registry = tracing_subscriber::registry().with(reloadable);

    let file_layer = KyrisFileLayer::new();

    if format == "json" {
        let layered = registry.with(stderr_layer.json()).with(file_layer);
        install(layered);
    } else {
        let layered = registry.with(stderr_layer).with(file_layer);
        install(layered);
    }

    // Stash a type-erased modifier closure so the diag admin endpoint
    // and the SIGUSR2 handler can mutate the filter without knowing
    // the subscriber's nested generic types. The closure captures
    // `handle` and our mirror of the current filter string.
    let current = Arc::new(Mutex::new(initial));
    let current_for_setter = Arc::clone(&current);
    let setter: FilterSetter = Box::new(move |raw: &str| {
        let new = EnvFilter::try_new(raw).map_err(|e| e.to_string())?;
        handle
            .modify(|f| *f = new)
            .map_err(|e| format!("filter reload failed: {e}"))?;
        *current_for_setter
            .lock()
            .expect("filter mirror lock poisoned") = raw.to_string();
        Ok(())
    });
    let _ = FILTER_SETTER.set(setter);
    let _ = CURRENT_FILTER.set(current);
}

/// Default filter when nothing is set via env or config.
const DEFAULT_FILTER: &str = "kyrisd=info";

/// Type-erased closure that swaps the active `EnvFilter`. Stored in
/// a `OnceLock` so any module (signal handler, admin endpoint, CLI)
/// can call [`try_set_filter`] without knowing the subscriber's
/// nested generic types.
type FilterSetter = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

static FILTER_SETTER: OnceLock<FilterSetter> = OnceLock::new();
static CURRENT_FILTER: OnceLock<Arc<Mutex<String>>> = OnceLock::new();

/// Attempt to swap the active log filter to `new_filter`. On
/// success, mirrors the new string into the process-global so
/// [`current_filter`] returns it. On parse failure, returns the
/// parser error string and leaves the filter unchanged.
///
/// # Errors
/// Returns an error string if the filter isn't yet initialized
/// or if `new_filter` fails `EnvFilter::try_new`.
pub fn try_set_filter(new_filter: &str) -> Result<(), String> {
    let setter = FILTER_SETTER
        .get()
        .ok_or_else(|| "log filter not initialized".to_string())?;
    setter(new_filter)
}

/// The currently-active filter string (last value passed to
/// [`try_set_filter`], or the startup value).
#[must_use]
pub fn current_filter() -> Option<String> {
    CURRENT_FILTER
        .get()
        .and_then(|cf| cf.lock().ok().map(|s| s.clone()))
}

/// Toggle between the configured baseline filter and the verbose
/// filter (both from `KyrisdConfig.log`). Returns the new active
/// filter on success. Used by the SIGUSR2 handler.
///
/// # Errors
/// Returns the error string from [`try_set_filter`] when the swap
/// fails (parse error or uninitialized).
pub fn try_toggle_verbose(baseline: &str, verbose: &str) -> Result<String, String> {
    let current = current_filter().unwrap_or_else(|| DEFAULT_FILTER.to_string());
    let next = if current == verbose {
        baseline
    } else {
        verbose
    };
    try_set_filter(next)?;
    Ok(next.to_string())
}

/// Resolve the startup filter as a string (the form `EnvFilter`
/// accepts via `try_new`). We return the string rather than a
/// parsed `EnvFilter` so the caller can mirror the same value
/// into `CURRENT_FILTER` for `current_filter()` to report later.
fn resolve_filter_string() -> String {
    std::env::var("KYRIS_LOG")
        .ok()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .filter(|raw| EnvFilter::try_new(raw).is_ok())
        .unwrap_or_else(|| DEFAULT_FILTER.to_string())
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
