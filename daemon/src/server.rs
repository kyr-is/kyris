// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::Router;
use kyris_agentpact_client as agentpact;
use kyris_core::config::{KyrisdConfig, ProviderConfig};
use tokio::sync::mpsc;
use tower_http::limit::RequestBodyLimitLayer;

use crate::adapter;
use crate::auth;
use crate::circuit_breaker::CircuitBreaker;
use crate::cost::CostCalculator;
use crate::mcp_routing;
use crate::metering::StatsEvent;
use crate::pending::PendingStore;
use crate::storage;

mod breaker_routes;
mod diagnostics;
mod lifecycle;
mod middleware;
mod operator_routes;
mod pending_routes;
mod signals;

#[cfg(test)]
mod tests;

use breaker_routes::{circuit_breaker_reset, circuit_breaker_reset_all, circuit_breaker_stop};
use diagnostics::{
    diag_log_filter_get, diag_log_filter_set, sigusr1_diagnostics, sigusr2_toggle_log_filter,
};
use lifecycle::{
    check_crash_recovery, drain_and_flush_stats, reap_stray_daemons, remove_pid_file,
    run_pending_prune, write_pid_file,
};
use middleware::{request_log_middleware, response_framing_check_middleware};
use operator_routes::{
    healthz, hook_log, operator_gateway_records, operator_session_token, operator_stats,
    operator_stream, operator_timeline,
};
use pending_routes::{cancel_pending, hold_pending, list_pending, pending_status, resolve_pending};
use signals::{agentpactd_health_poller, shutdown_signal, sighup_reload, watch_policy_mode};

// Re-export the signal bundle so `crate::server::ShutdownSignals` continues to
// resolve for any in-crate caller after the types moved into `signals`.
use signals::ShutdownSignals;

// Test-only re-exports: `server/tests.rs` uses `use super::*`, so the moved
// items it exercises must be reachable through this module's namespace. They
// have no non-test caller here, hence the `#[cfg(test)]` gate to avoid
// unused-import warnings in the normal build.
#[cfg(all(test, unix))]
use lifecycle::is_kyrisd_executable;
#[cfg(test)]
use operator_routes::HookLogBody;
#[cfg(test)]
use pending_routes::{ResolveDecision, decision_for_approval_outcome, parse_resolve_decision};

pub struct AppState {
    pub config: Arc<ArcSwap<KyrisdConfig>>,
    pub circuit_breaker: Arc<CircuitBreaker>,
    /// Open "continue or stop?" prompts for runaway sessions, keyed by session.
    /// A trip holds the request here until the human answers (via the desktop
    /// dialog, the tray, or the app's Stop/Continue control).
    pub gate: Arc<crate::gate::GateRegistry>,
    pub cost_calculator: CostCalculator,
    pub stats_tx: mpsc::Sender<StatsEvent>,
    pub db: Arc<storage::DuckDbWriter>,
    pub provider_clients: ArcSwap<HashMap<String, reqwest::Client>>,
    /// Shared upstream HTTP client used for the fresh-install passthrough case
    /// (no `providers[]` configured, so `provider_clients` has no matching
    /// entry) and as the fallback for any unconfigured provider name. Reusing
    /// one tuned client keeps connections warm (keep-alive) and bounds connect
    /// time; constructing a fresh `reqwest::Client` per request instead leaks a
    /// new connection pool every call and, lacking a connect timeout, lets a
    /// stalled connect hang to the full per-request timeout.
    pub default_provider_client: reqwest::Client,
    pub pending: Arc<PendingStore>,
    pub agentpact_socket: Option<std::path::PathBuf>,
    pub mcp_annotation_cache: mcp_routing::AnnotationCache,
}

pub fn build_provider_client(_provider: &ProviderConfig) -> reqwest::Client {
    build_default_provider_client()
}

/// The shared upstream HTTP client (see [`AppState::default_provider_client`]).
///
/// Tuned for a long-lived proxy talking to a small set of upstreams:
/// - `connect_timeout` bounds a stalled TCP/TLS connect (a lost SYN or a slow
///   handshake) so it fails fast instead of hanging to the per-request timeout
///   — the failure signature behind the observed 30 s `/v1/responses` 502.
/// - `tcp_keepalive` lets the OS probe idle keep-alive connections so a
///   half-open one is reset and evicted rather than handed out and hung on.
/// - `pool_idle_timeout` is kept below the typical upstream idle-close so we
///   drop connections before the server does, avoiding the use-after-close race.
pub fn build_default_provider_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_mins(1))
        .pool_max_idle_per_host(20)
        .connect_timeout(Duration::from_secs(10))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("build reqwest client")
}

pub fn build_provider_clients(config: &KyrisdConfig) -> HashMap<String, reqwest::Client> {
    config
        .providers
        .iter()
        .map(|p| (p.name.clone(), build_provider_client(p)))
        .collect()
}

pub async fn run(config: KyrisdConfig) {
    if let Err(e) = config.tls.validate() {
        tracing::error!("{e}");
        std::process::exit(1);
    }

    // Install signal streams BEFORE anything else (in particular,
    // before the TCP listener binds). Creating any stream for a signal
    // causes tokio to install its OS-level handler, which overrides
    // Rust's default (SIGINT/SIGTERM → terminate with non-zero exit).
    // Until this point, a signal that arrives while we're still doing
    // startup work kills the process ungracefully — no drain, no
    // socket cleanup, exit 130 (SIGINT) or 143 (SIGTERM).
    //
    // The streams themselves queue signals internally, so any signal
    // delivered between this point and the select loop is captured
    // and processed when we eventually call .recv().
    let signals = ShutdownSignals::install();

    let listen_addr = config.server.listen.clone();
    let tls_enabled = config.tls.enabled;
    let max_body = config.server.max_request_body_bytes;
    let drain_timeout = config.server.drain_timeout_seconds;

    let (stats_tx, stats_rx) = mpsc::channel::<StatsEvent>(config.stats.channel_capacity);

    let db = Arc::new(storage::open_db());
    let clients = build_provider_clients(&config);

    let circuit_breaker = Arc::new(CircuitBreaker::new());
    let stored_sessions = db.load_session_tokens();
    circuit_breaker.rebuild_from(&stored_sessions, config.circuit_breaker.max_tokens as i64);
    tracing::info!(
        sessions = stored_sessions.len(),
        "rebuilt circuit breaker from DuckDB"
    );

    let agentpact_socket = probe_agentpact_socket();

    check_crash_recovery();
    // Singleton enforcement: a canonical (launchd) start reaps stray kyrisd
    // siblings. A dedicated/test instance sets `KYRIS_NO_STRAY_REAP` so it
    // neither kills the installed daemon nor fights other dedicated instances
    // (test isolation — multiple kyrisd on distinct ports coexist).
    if std::env::var_os("KYRIS_NO_STRAY_REAP").is_none() {
        reap_stray_daemons().await;
    }
    write_pid_file();

    let stats_config = config.stats.clone();
    let spend_config = config.spend.clone();
    let session_idle_minutes = config.circuit_breaker.session_idle_minutes;
    let tls_config = config.tls.clone();

    let state = Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(config)),
        circuit_breaker: circuit_breaker.clone(),
        gate: Arc::new(crate::gate::GateRegistry::new()),
        cost_calculator: CostCalculator::new(),
        stats_tx: stats_tx.clone(),
        db: db.clone(),
        provider_clients: ArcSwap::from_pointee(clients),
        default_provider_client: build_default_provider_client(),
        pending: Arc::new(PendingStore::new()),
        agentpact_socket,
        mcp_annotation_cache: mcp_routing::AnnotationCache::default(),
    });

    let stats_writer_handle = tokio::spawn(storage::stats_writer(
        stats_rx,
        db.clone(),
        circuit_breaker,
        stats_config,
        spend_config,
        session_idle_minutes,
    ));

    // Single, visible statement of mode at startup, on two independent axes:
    //   - relay.url (config)  -> live pricing (no enrollment needed)
    //   - enrollment (creds)  -> event sync + included-vs-overage billing
    // Each degraded axis is announced; neither is a hard failure.
    let relay_url = state.config.load().relay.url.clone();
    if relay_url.trim().is_empty() {
        tracing::warn!(
            "no `relay.url` configured: live pricing disabled, using last cached/bundled table"
        );
    } else {
        tracing::info!(relay_url = %relay_url, "live pricing enabled from relay");
    }
    if let Some(creds) = kyris_core::credentials::load() {
        tracing::info!(machine_id = %creds.machine_id, "enrolled: event sync enabled");
        crate::tray::clear_issue("enrollment");
    } else {
        tracing::warn!(
            "standalone (not enrolled): event sync disabled — run `kyris enroll` (pricing is unaffected)"
        );
        // Surface standalone as a tray indicator (warning overlay). It clears on
        // the next startup after `kyris enroll` (which restarts kyrisd). `doctor`
        // distinguishes this from real failures by the issue's reason string.
        crate::tray::report_issue(
            "enrollment",
            "standalone (not enrolled) — run `kyris enroll` to enable event sync",
        );
    }

    tokio::spawn(crate::sync::daemon_sync::run_sync_loop(state.clone()));
    tokio::spawn(crate::pricing_fetch::run_pricing_fetch(state.clone()));
    tokio::spawn(run_pending_prune(state.pending.clone()));
    tokio::spawn(crate::reconcile_watcher::run_reconcile_loop(state.clone()));

    let inbound_auth_config = state.config.clone();
    let routed_routes = Router::new()
        .merge(adapter::routes(state.clone()))
        .merge(mcp_routing::routes(state.clone()))
        .layer(axum::middleware::from_fn_with_state(
            inbound_auth_config,
            auth::inbound_auth_middleware,
        ));

    let operator_auth_config = state.config.clone();
    let operator_routes = authed_operational_routes(state.clone()).layer(
        axum::middleware::from_fn_with_state(operator_auth_config, auth::operator_auth_middleware),
    );

    let app = Router::new()
        .merge(routed_routes)
        .merge(operator_routes)
        .merge(health_routes(state.clone()))
        .layer(RequestBodyLimitLayer::new(max_body))
        // Per-request access log (boundary). Reads trace_id from the
        // extension stamped by the outer trace_id_middleware below.
        .layer(axum::middleware::from_fn(request_log_middleware))
        // Response-side framing sanity check: catches known-bad
        // body-framing header combinations BEFORE hyper rejects them
        // and writes nothing. The most common silent failure mode is
        // a hop-by-hop or content-encoding header copied verbatim from
        // an upstream response onto our own (smaller, decompressed,
        // re-collected) body. This layer surfaces the conflict at
        // ERROR with the constructed-response context.
        .layer(axum::middleware::from_fn(response_framing_check_middleware))
        // Outermost layer: mint or accept the trace_id, attach to
        // extensions + span, echo as x-kyris-trace-id. EVERY layer
        // below (auth, body-limit, the framing check) runs inside
        // the trace span, so even rejected requests carry the id in
        // their log lines. "No log entry for this trace_id" must
        // reliably mean "the request never reached the daemon."
        .layer(axum::middleware::from_fn(
            crate::trace_id::trace_id_middleware,
        ));

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("bind listen address");

    let scheme = if tls_enabled { "https" } else { "http" };
    tracing::info!(listen = %listen_addr, %scheme, "kyrisd listening");

    tokio::spawn(sighup_reload(state.clone(), signals.sighup));
    tokio::spawn(sigusr1_diagnostics(signals.sigusr1));
    tokio::spawn(sigusr2_toggle_log_filter(state.clone(), signals.sigusr2));
    tokio::spawn(agentpactd_health_poller());
    tokio::spawn(watch_policy_mode());

    if tls_enabled {
        serve_tls_with_graceful_shutdown(
            listener,
            app,
            &tls_config,
            shutdown_signal(signals.shutdown),
        )
        .await
        .expect("TLS server error");
    } else {
        serve_with_graceful_shutdown(listener, app, shutdown_signal(signals.shutdown))
            .await
            .expect("server error");
    }

    match drain_and_flush_stats(
        stats_tx,
        stats_writer_handle,
        Duration::from_secs(drain_timeout),
    )
    .await
    {
        Ok(()) => tracing::info!("stats flushed, shutdown complete"),
        Err(error) => tracing::warn!(%error, "stats flush incomplete on shutdown"),
    }

    remove_pid_file();
}

async fn serve_with_graceful_shutdown<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

async fn serve_tls_with_graceful_shutdown<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    tls: &kyris_core::config::TlsConfig,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::TlsAcceptor;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&tls.cert_path)
        .expect("read TLS certificate file")
        .collect::<Result<Vec<_>, _>>()
        .expect("parse TLS certificates");

    let key = PrivateKeyDer::from_pem_file(&tls.key_path).expect("read TLS private key file");

    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build TLS server config");

    let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let (tcp_stream, remote_addr) = accepted?;
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(tcp_stream).await else {
                        tracing::debug!(%remote_addr, "TLS handshake failed");
                        return;
                    };
                    let stream = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app.into_service());
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(stream, service)
                    .await
                    {
                        tracing::debug!(%remote_addr, error = %e, "connection error");
                    }
                });
            }
        }
    }
    Ok(())
}

impl AppState {
    pub fn resolve_agentpact_socket(&self) -> Option<std::path::PathBuf> {
        if let Some(ref path) = self.agentpact_socket {
            return Some(path.clone());
        }
        let socket = agentpact::default_socket_path();
        if socket.exists() { Some(socket) } else { None }
    }
}

fn probe_agentpact_socket() -> Option<std::path::PathBuf> {
    let socket = agentpact::default_socket_path();
    if socket.exists() {
        tracing::info!(path = %socket.display(), "agentpactd socket found");
        Some(socket)
    } else {
        tracing::info!("agentpactd socket not found — trace relay disabled");
        None
    }
}

fn agentpact_socket_path() -> String {
    agentpact::default_socket_path().display().to_string()
}

/// Resolve the agentpact socket path, preferring an explicit `AppState` override
/// (set in tests) and falling back to the env-var/default lookup used by the
/// rest of the codebase.
pub(super) fn agentpact_socket_for(state: &AppState) -> String {
    state
        .agentpact_socket
        .as_ref()
        .map_or_else(agentpact_socket_path, |p| p.display().to_string())
}

/// Routes that require auth: circuit-breaker reset, pending requests, and
/// the `/operator/*` data-inspection endpoints used by tests and dashboards.
fn authed_operational_routes(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, post};

    Router::new()
        .route(
            "/api/circuit-breaker/reset",
            post(circuit_breaker_reset).with_state(state.clone()),
        )
        .route(
            "/api/circuit-breaker/reset-all",
            post(circuit_breaker_reset_all).with_state(state.clone()),
        )
        .route(
            "/api/circuit-breaker/stop",
            post(circuit_breaker_stop).with_state(state.clone()),
        )
        .route("/api/hook/log", post(hook_log).with_state(state.clone()))
        .route("/api/pending", get(list_pending).with_state(state.clone()))
        .route(
            "/api/pending/{id}/resolve",
            post(resolve_pending).with_state(state.clone()),
        )
        .route(
            "/api/pending/hold",
            post(hold_pending).with_state(state.clone()),
        )
        .route(
            "/api/pending/{id}/cancel",
            delete(cancel_pending).with_state(state.clone()),
        )
        .route(
            "/api/pending/{id}/status",
            get(pending_status).with_state(state.clone()),
        )
        .route(
            "/operator/gateway-records",
            get(operator_gateway_records).with_state(state.clone()),
        )
        .route(
            "/operator/timeline",
            get(operator_timeline).with_state(state.clone()),
        )
        .route(
            "/operator/stats",
            get(operator_stats).with_state(state.clone()),
        )
        .route(
            "/operator/stream",
            get(operator_stream).with_state(state.clone()),
        )
        .route(
            "/operator/session-tokens/{session_id}",
            get(operator_session_token).with_state(state.clone()),
        )
        .route(
            "/operator/diag/log-filter",
            get(diag_log_filter_get)
                .post(diag_log_filter_set)
                .with_state(state),
        )
}

/// Health/readiness route -- no auth required.
/// Returns 200 only when kyrisd is fully initialised and ready to serve
/// requests: at least one provider configured, DB writable, no dropped writes.
fn health_routes(state: Arc<AppState>) -> Router {
    use axum::routing::get;

    Router::new().route("/healthz", get(healthz).with_state(state))
}

fn provider_configs_match(old: &ProviderConfig, new: &ProviderConfig) -> bool {
    old.name == new.name
        && old.format == new.format
        && old.upstream == new.upstream
        && old.models == new.models
        && old.timeout_seconds == new.timeout_seconds
        && old.streaming_timeout_seconds == new.streaming_timeout_seconds
}

fn rebuild_provider_clients_preserving_unchanged(
    current_config: &KyrisdConfig,
    current_clients: &HashMap<String, reqwest::Client>,
    new_config: &KyrisdConfig,
) -> HashMap<String, reqwest::Client> {
    new_config
        .providers
        .iter()
        .map(|provider| {
            let client = current_config
                .providers
                .iter()
                .find(|existing| provider_configs_match(existing, provider))
                .and_then(|existing| current_clients.get(&existing.name))
                .cloned()
                .unwrap_or_else(|| build_provider_client(provider));
            (provider.name.clone(), client)
        })
        .collect()
}

fn apply_reloaded_config(state: &Arc<AppState>, new_config: KyrisdConfig) {
    let current_config = state.config.load();
    let current_clients = state.provider_clients.load();
    let new_clients = rebuild_provider_clients_preserving_unchanged(
        current_config.as_ref(),
        current_clients.as_ref(),
        &new_config,
    );
    state.provider_clients.store(Arc::new(new_clients));
    state.config.store(Arc::new(new_config));
}

pub(super) async fn reload_loop<F, Fut>(
    state: Arc<AppState>,
    mut reload_events: mpsc::Receiver<()>,
    mut load_config: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<KyrisdConfig, String>>,
{
    while reload_events.recv().await.is_some() {
        tracing::info!("SIGHUP received, reloading config");
        match load_config().await {
            Ok(new_config) => {
                apply_reloaded_config(&state, new_config);
                tracing::info!("config reloaded");
            }
            Err(error) => {
                tracing::error!(error = %error, "config reload failed, keeping current config");
            }
        }
    }
}
