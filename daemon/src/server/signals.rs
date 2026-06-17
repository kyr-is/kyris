// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;
use std::time::Duration;

use kyris_agentpact_client as agentpact;
use tokio::sync::mpsc;

use crate::config;
use crate::server::{AppState, reload_loop};

/// Owned bundle of signal streams installed BEFORE the listener binds.
/// Creating the streams up front means tokio installs its OS-level
/// signal handlers immediately; signals delivered during the rest of
/// startup are queued internally rather than killing the process via
/// Rust's default handler. See `run()` for why this matters.
#[cfg(unix)]
pub(crate) struct ShutdownSignals {
    pub sighup: tokio::signal::unix::Signal,
    pub sigusr1: tokio::signal::unix::Signal,
    pub sigusr2: tokio::signal::unix::Signal,
    pub shutdown: ShutdownStreams,
}

#[cfg(not(unix))]
pub(crate) struct ShutdownSignals {
    pub sighup: (),
    pub sigusr1: (),
    pub sigusr2: (),
    pub shutdown: ShutdownStreams,
}

#[cfg(unix)]
pub(crate) struct ShutdownStreams {
    pub sigterm: tokio::signal::unix::Signal,
    pub sigint: tokio::signal::unix::Signal,
}

#[cfg(not(unix))]
pub(crate) struct ShutdownStreams;

impl ShutdownSignals {
    pub fn install() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Self {
                sighup: signal(SignalKind::hangup()).expect("install SIGHUP handler"),
                sigusr1: signal(SignalKind::user_defined1()).expect("install SIGUSR1 handler"),
                sigusr2: signal(SignalKind::user_defined2()).expect("install SIGUSR2 handler"),
                shutdown: ShutdownStreams {
                    sigterm: signal(SignalKind::terminate()).expect("install SIGTERM handler"),
                    sigint: signal(SignalKind::interrupt()).expect("install SIGINT handler"),
                },
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                sighup: (),
                sigusr1: (),
                sigusr2: (),
                shutdown: ShutdownStreams,
            }
        }
    }
}

/// Probe agentpactd every second and reflect reachability into the
/// tray's issue set. The tray icon goes amber when the policy daemon
/// stops servicing requests (e.g. crashed, bootout'd, kyris-stopped, or
/// wedged) so the user notices without having to run a check command.
///
/// Uses a real `daemon.health` round-trip rather than a bare
/// `connect()`: a bare connect succeeds as long as the kernel queues the
/// connection — it can't tell "alive" from "accept loop hung" — and,
/// because it is dropped immediately, it races the server's `accept()`
/// and shows up there as a transient `ENOTCONN` logged once per probe.
/// The round-trip both means something and closes cleanly.
pub(super) async fn agentpactd_health_poller() {
    let socket_path = std::env::var("AGENTPACT_SOCK").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.agentpact/agentpact.sock")
    });
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        // The probe is blocking I/O (connect + write + read); run it off
        // the async worker so a wedged daemon can't stall the runtime.
        let socket = socket_path.clone();
        let reachable = tokio::task::spawn_blocking(move || {
            agentpact::probe_daemon_health(&socket, Duration::from_secs(2))
        })
        .await
        .unwrap_or(false);
        if reachable {
            crate::tray::clear_issue("agentpactd");
        } else {
            crate::tray::report_issue(
                "agentpactd",
                format!("policy daemon socket not responding at {socket_path}"),
            );
        }
    }
}

/// Event-driven watcher on the user-level `pact.yaml`. Resolves the
/// effective mode once at startup, then re-resolves only when the
/// `user_policy_dir` actually changes — same pattern agentpactd's
/// own policy watcher uses, just narrowed to "tell the tray icon
/// when mode flips."
///
/// The tray is a system-wide indicator with no working-directory
/// context, so we resolve against `home` (no cwd) — repo overrides
/// are surfaced by `kyris status` / `doctor` instead. Uses
/// `agentpact::policy::resolution` so this watcher and the CLI's
/// headline can't drift.
///
/// If the filesystem watcher fails to register (vanishingly rare
/// on supported platforms — would require missing inotify on Linux
/// or `FSEvents` on macOS), we log a warning and continue with
/// whatever mode was resolved at startup. No polling fallback —
/// "either event-driven, or static-from-boot" is easier to reason
/// about than a silent polling fallback that wastes CPU.
pub(super) async fn watch_policy_mode() {
    // `agentpact` is locally aliased to `kyris_agentpact_client` (the
    // wire-types crate, no `policy`/`config`/`protocol` modules);
    // reach the agentpact server lib via the fully-qualified
    // `::agentpact` path.
    use ::agentpact::policy::resolution::{SYSTEM_POLICY_DIR, resolve_mode_for};
    use kyris_core::agentpact::Mode;
    use notify_debouncer_mini::new_debouncer;

    let Some(home) = std::env::var("HOME").ok().map(std::path::PathBuf::from) else {
        tracing::warn!("HOME unset; tray policy-mode indicator will stay at default");
        return;
    };
    let user_dir = ::agentpact::config::default_user_policy_dir(&home);
    let system_dir = std::path::Path::new(SYSTEM_POLICY_DIR);

    // Capture the resolved mode and push to the tray.
    let push_to_tray = || {
        let log_mode = resolve_mode_for(&home, &home, &user_dir, system_dir).mode == Mode::Log;
        crate::tray::set_log_mode(log_mode);
    };
    push_to_tray();

    // notify thread → async task. Capacity 1 because any pending
    // wakeup means "re-resolve"; coalescing extras is correct.
    let (fs_tx, mut fs_rx) = tokio::sync::mpsc::channel::<()>(1);

    // 100ms debounce matches agentpactd's policy watcher.
    let debouncer = match new_debouncer(Duration::from_millis(100), move |_| {
        let _ = fs_tx.try_send(());
    }) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to create policy mode watcher; tray mode will be static"
            );
            return;
        }
    };
    let mut debouncer = debouncer;

    if let Err(e) = debouncer
        .watcher()
        .watch(&user_dir, notify::RecursiveMode::NonRecursive)
    {
        tracing::warn!(
            dir = %user_dir.display(),
            error = %e,
            "could not watch user-policy directory; tray mode will be static"
        );
        return;
    }
    tracing::info!(dir = %user_dir.display(), "watching for policy mode changes");

    // Hold `debouncer` on this task's stack so the underlying
    // watcher thread lives as long as the task does. The task
    // itself lives until process exit.
    while fs_rx.recv().await.is_some() {
        push_to_tray();
    }
    drop(debouncer);
}

#[cfg(unix)]
pub(super) async fn sighup_reload(state: Arc<AppState>, mut hup: tokio::signal::unix::Signal) {
    let (reload_tx, reload_rx) = mpsc::channel(8);

    tokio::spawn(async move {
        loop {
            hup.recv().await;
            if reload_tx.send(()).await.is_err() {
                break;
            }
        }
    });

    reload_loop(state, reload_rx, || async { config::try_load_config() }).await;
}

#[cfg(not(unix))]
pub(super) async fn sighup_reload(state: Arc<AppState>, _hup: ()) {
    let _ = state;
    // SIGHUP is not available on non-unix platforms.
    std::future::pending::<()>().await;
}

#[cfg(unix)]
pub(super) async fn shutdown_signal(mut streams: ShutdownStreams) {
    tokio::select! {
        _ = streams.sigint.recv() => {
            tracing::info!("SIGINT received, shutting down");
        }
        _ = streams.sigterm.recv() => {
            tracing::info!("SIGTERM received, shutting down");
        }
    }
}

#[cfg(not(unix))]
pub(super) async fn shutdown_signal(_streams: ShutdownStreams) {
    tokio::signal::ctrl_c()
        .await
        .expect("install ctrl+c handler");
    tracing::info!("shutdown signal received");
}
