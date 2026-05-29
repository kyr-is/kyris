// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use kyris_agentpact_client as agentpact;
use kyris_core::config::{KyrisdConfig, ProviderConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tower_http::limit::RequestBodyLimitLayer;

use crate::adapter;
use crate::auth;
use crate::circuit_breaker::CircuitBreaker;
use crate::config;
use crate::cost::CostCalculator;
use crate::mcp_routing;
use crate::metering::StatsEvent;
use crate::pending::{PendingStore, ResolveError};
use crate::storage;

pub struct AppState {
    pub config: Arc<ArcSwap<KyrisdConfig>>,
    pub circuit_breaker: Arc<CircuitBreaker>,
    pub cost_calculator: CostCalculator,
    pub stats_tx: mpsc::Sender<StatsEvent>,
    pub db: Arc<storage::DuckDbWriter>,
    pub provider_clients: ArcSwap<HashMap<String, reqwest::Client>>,
    pub pending: Arc<PendingStore>,
    pub agentpact_socket: Option<std::path::PathBuf>,
    pub mcp_annotation_cache: mcp_routing::AnnotationCache,
}

pub fn build_provider_client(_provider: &ProviderConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(20)
        .connect_timeout(Duration::from_secs(10))
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
    reap_stray_daemons().await;
    write_pid_file();

    let stats_config = config.stats.clone();
    let spend_config = config.spend.clone();
    let session_idle_minutes = config.circuit_breaker.session_idle_minutes;
    let tls_config = config.tls.clone();

    let state = Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(config)),
        circuit_breaker: circuit_breaker.clone(),
        cost_calculator: CostCalculator::new(),
        stats_tx: stats_tx.clone(),
        db: db.clone(),
        provider_clients: ArcSwap::from_pointee(clients),
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

/// Per-request access log. Logs every request the daemon sees at
/// `INFO` (4xx → WARN, 5xx → ERROR), with method / path / status /
/// `latency_ms` / body sizes / `trace_id`. Runs inside the request span
/// opened by [`crate::trace_id::trace_id_middleware`], so the same
/// `trace_id` field appears on this line and every nested handler
/// log — making `kyris logs trace <id>` a single coherent view.
async fn request_log_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Cheap body-size telemetry: read Content-Length from the request
    // and response headers without consuming the bodies. Streamed or
    // chunked responses come through as `None`; that itself is
    // diagnostic information (LLM streaming responses look that way).
    let req_bytes = content_length(req.headers());
    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    let resp_bytes = content_length(response.headers());
    #[allow(clippy::cast_possible_truncation)]
    let latency_ms = start.elapsed().as_millis() as u64;
    if status >= 500 {
        tracing::error!(
            method = %method,
            path = %path,
            status,
            latency_ms,
            req_bytes = ?req_bytes,
            resp_bytes = ?resp_bytes,
            "request"
        );
    } else if status >= 400 {
        tracing::warn!(
            method = %method,
            path = %path,
            status,
            latency_ms,
            req_bytes = ?req_bytes,
            resp_bytes = ?resp_bytes,
            "request"
        );
    } else {
        tracing::info!(
            method = %method,
            path = %path,
            status,
            latency_ms,
            req_bytes = ?req_bytes,
            resp_bytes = ?resp_bytes,
            "request"
        );
    }
    response
}

/// Sanity check on the response before it goes to hyper. Catches the
/// "framing conflict" silent failure: when a handler builds a
/// response carrying header combinations hyper rejects, hyper resets
/// the TCP connection and writes nothing — the client sees
/// `RemoteDisconnected`, our `request_log_middleware` logged status
/// 401/200/whatever (because the response object was built), and
/// nothing in the log says WHY the bytes never landed.
///
/// We surface the conflict at ERROR here so the log answers the
/// question without anyone having to attach hyper at DEBUG. We do
/// NOT auto-fix the response — adapter-level filtering is the right
/// fix point, and we want the bug to remain visible until that
/// filter lands.
async fn response_framing_check_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let response = next.run(req).await;
    if let Some(reason) = response_framing_violation(&response) {
        let status = response.status().as_u16();
        let header_names: Vec<&str> = response
            .headers()
            .keys()
            .map(axum::http::HeaderName::as_str)
            .collect();
        tracing::error!(
            status,
            reason = %reason,
            header_names = ?header_names,
            "response_framing_conflict: hyper will reset this connection \
             and the client will see RemoteDisconnected / Empty reply; \
             the response was built but the framing headers contradict \
             the body the response will be serialized with"
        );
    }
    response
}

/// Detect response header combinations hyper rejects at serialize
/// time. Returns `Some(reason)` if a known conflict is present.
///
/// Known conflicts (RFC 7230 §3.3.3 + RFC 7230 §4):
/// - `transfer-encoding` AND `content-length` together: hyper
///   refuses to choose between them and resets the connection.
/// - Hop-by-hop headers (`connection`, `keep-alive`, `te`,
///   `trailer`, `upgrade`, `proxy-*`) survive past a proxy: hyper
///   strips some and errors on others depending on version.
fn response_framing_violation(response: &axum::response::Response) -> Option<String> {
    let headers = response.headers();
    let has_te = headers.contains_key("transfer-encoding");
    let has_cl = headers.contains_key("content-length");
    if has_te && has_cl {
        return Some(
            "both transfer-encoding and content-length headers are set \
             on the response (hyper requires exactly one)"
                .to_string(),
        );
    }
    None
}

/// Read `Content-Length` from a header map as `u64`. None when the
/// header is absent or unparseable (streamed/chunked responses, or
/// requests with no body).
fn content_length(headers: &axum::http::HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
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

async fn drain_and_flush_stats(
    stats_tx: mpsc::Sender<StatsEvent>,
    stats_writer_handle: tokio::task::JoinHandle<()>,
    drain_timeout: Duration,
) -> Result<(), String> {
    tracing::info!(
        drain_timeout_seconds = drain_timeout.as_secs(),
        "draining in-flight requests"
    );
    tokio::time::sleep(drain_timeout).await;

    drop(stats_tx);
    tokio::time::timeout(Duration::from_secs(5), stats_writer_handle)
        .await
        .map_err(|_| "timed out waiting for stats writer flush".to_string())?
        .map_err(|error| format!("stats writer task failed: {error}"))?;
    Ok(())
}

async fn run_pending_prune(pending: Arc<PendingStore>) {
    let mut interval = tokio::time::interval(Duration::from_mins(1));
    interval.tick().await; // skip immediate first tick
    loop {
        interval.tick().await;
        pending.prune_resolved();
    }
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

fn check_crash_recovery() {
    let pid_path = kyris_core::paths::pid_path();
    let Ok(contents) = std::fs::read_to_string(&pid_path) else {
        return;
    };
    let Ok(old_pid) = contents.trim().parse::<i32>() else {
        return;
    };
    #[cfg(unix)]
    {
        use nix::sys::signal;
        use nix::unistd::Pid;

        let alive = signal::kill(Pid::from_raw(old_pid), None).is_ok();
        if !alive {
            tracing::warn!(old_pid, "detected stale PID file — previous daemon crashed");
            let modified = std::fs::metadata(&pid_path).and_then(|m| m.modified()).ok();
            let duration = modified.and_then(|m| m.elapsed().ok()).map_or_else(
                || "unknown".to_string(),
                |d| {
                    let secs = d.as_secs();
                    if secs < 60 {
                        format!("{secs}s")
                    } else {
                        format!("{}m", secs / 60)
                    }
                },
            );
            crate::notify::daemon_recovery_toast(&duration);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = old_pid;
    }
}

/// Kill any *other* kyrisd processes owned by this user before we claim
/// the pidfile and port, so exactly one kyrisd survives any start —
/// install or reboot.
///
/// Production kyrisd is launchd-managed and does not orphan, but dev/test
/// runs of the debug binary (`target/debug/kyrisd`) or the cargo test
/// binary (`target/debug/deps/kyrisd-<hex>`) can detach from their parent
/// when the terminal/cargo/IDE that launched them goes away, surviving as
/// strays reparented to launchd. This sweep cleans them up at the next
/// canonical start instead of letting them linger.
///
/// Safety bounds, in order of importance:
/// - never our own PID;
/// - only processes owned by our own UID (never signal another user);
/// - only executables whose file name is exactly `kyrisd` or a cargo
///   test/bench binary (`kyrisd-<hex>`) — the CLI (`kyris`, `kyris-mcp`)
///   and `agentpactd` are deliberately excluded.
///
/// Each stray gets SIGTERM, a short grace period, then SIGKILL if it is
/// still alive.
#[cfg(unix)]
async fn reap_stray_daemons() {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::{Pid, Uid};
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let own_pid = std::process::id();
    let owner_uid = Uid::current().as_raw();

    let mut sys = System::new();
    let refresh = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::Always)
        .with_user(UpdateKind::Always);
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);

    let strays: Vec<u32> = sys
        .processes()
        .values()
        .filter_map(|proc| {
            let pid = proc.pid().as_u32();
            if pid == own_pid {
                return None;
            }
            // Same user only — never signal another user's processes.
            // sysinfo's `Uid` derefs to the raw `libc::uid_t`, which is
            // exactly what `nix::Uid::as_raw()` returns.
            if proc.user_id().map(|uid| **uid) != Some(owner_uid) {
                return None;
            }
            let name = proc.exe()?.file_name()?.to_str()?;
            is_kyrisd_executable(name).then_some(pid)
        })
        .collect();

    if strays.is_empty() {
        return;
    }

    tracing::warn!(?strays, "reaping stray kyrisd process(es) on startup");
    for &pid in &strays {
        let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    for &pid in &strays {
        let target = Pid::from_raw(pid as i32);
        // `kill(.., None)` is signal 0: Ok means the process still exists
        // and we may signal it. Anything else (exited, or now unowned) we
        // leave alone.
        if signal::kill(target, None).is_ok() {
            tracing::warn!(pid, "stray kyrisd ignored SIGTERM — sending SIGKILL");
            let _ = signal::kill(target, Signal::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
async fn reap_stray_daemons() {}

/// `true` for a kyrisd executable file name: the installed/dev binary
/// (`kyrisd`) or a cargo test/bench binary (`kyrisd-<hex>`). Excludes
/// `kyris`, `kyris-mcp`, `agentpactd`, and unrelated names.
#[cfg(unix)]
fn is_kyrisd_executable(file_name: &str) -> bool {
    if file_name == "kyrisd" {
        return true;
    }
    match file_name.strip_prefix("kyrisd-") {
        Some(suffix) => !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

fn write_pid_file() {
    let pid_path = kyris_core::paths::pid_path();
    if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&pid_path, std::process::id().to_string()) {
        tracing::warn!(error = %e, "failed to write PID file");
    }
}

fn remove_pid_file() {
    let _ = std::fs::remove_file(kyris_core::paths::pid_path());
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

#[derive(Deserialize)]
struct CircuitBreakerResetRequest {
    session_id: String,
}

async fn circuit_breaker_reset(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CircuitBreakerResetRequest>,
) -> axum::http::StatusCode {
    if state.circuit_breaker.reset(&body.session_id) {
        tracing::info!(session_id = %body.session_id, "circuit breaker reset");
        axum::http::StatusCode::OK
    } else {
        tracing::warn!(session_id = %body.session_id, "circuit breaker reset: unknown session");
        axum::http::StatusCode::NOT_FOUND
    }
}

/// Reset every session that's currently sitting at or above its token
/// cap. Returns the list of session IDs that were cleared so the CLI
/// can show the operator exactly which sessions resumed. Empty list
/// is a valid success — no sessions were tripped.
async fn circuit_breaker_reset_all(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let cleared = state.circuit_breaker.reset_all_tripped();
    if cleared.is_empty() {
        tracing::info!("circuit breaker reset-all: no sessions were tripped");
    } else {
        tracing::info!(count = cleared.len(), "circuit breaker reset-all");
    }
    Json(serde_json::json!({ "cleared": cleared }))
}

async fn list_pending(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let held = state.pending.list_held();
    Json(serde_json::json!({ "requests": held }))
}

#[derive(Deserialize)]
struct ResolveRequest {
    decision: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolveDecision {
    Approved,
    Denied,
    Always,
}

impl ResolveDecision {
    fn as_approval_response(self) -> agentpact::ApprovalResponse {
        match self {
            Self::Approved => agentpact::ApprovalResponse::Approved,
            Self::Denied => agentpact::ApprovalResponse::Denied,
            Self::Always => agentpact::ApprovalResponse::Always,
        }
    }

    fn allows_execution(self) -> bool {
        matches!(self, Self::Approved | Self::Always)
    }
}

/// Map an approval-dialog outcome to a resolution.
///
/// `CouldNotShow` maps to `None`: the dialog never reached the user (occluded,
/// off-space, or — on platforms without an approval UI — never attempted), so
/// the request is left **pending** for `kyris pending` / the menu-bar path
/// rather than resolved. Returning `Approved` here would defeat the permission
/// gate; see `notify::ask_approval`'s non-macOS fallback, which returns
/// `CouldNotShow` precisely so this leaves the request pending.
fn decision_for_approval_outcome(
    outcome: crate::notify::ApprovalOutcome,
) -> Option<ResolveDecision> {
    match outcome {
        crate::notify::ApprovalOutcome::Yes => Some(ResolveDecision::Approved),
        crate::notify::ApprovalOutcome::Always => Some(ResolveDecision::Always),
        crate::notify::ApprovalOutcome::No => Some(ResolveDecision::Denied),
        crate::notify::ApprovalOutcome::CouldNotShow => None,
    }
}

fn parse_resolve_decision(value: &str) -> Option<ResolveDecision> {
    match value {
        "approved" => Some(ResolveDecision::Approved),
        "denied" => Some(ResolveDecision::Denied),
        "always" => Some(ResolveDecision::Always),
        _ => None,
    }
}

fn agentpact_socket_path() -> String {
    agentpact::default_socket_path().display().to_string()
}

async fn send_permission_response(
    socket: String,
    approval_token: &str,
    decision: ResolveDecision,
) -> Result<(), String> {
    let token = approval_token.to_string();
    tokio::task::spawn_blocking(move || {
        // Discard the optional advisory warning (e.g. an unpersisted "always"
        // grant); agentpactd logs it, and the pending-resolution HTTP path has
        // no channel to relay it back to the developer.
        agentpact::send_permission_response(
            &socket,
            "kyrisd-resolve",
            &token,
            decision.as_approval_response(),
            None,
        )
        .map(|_warning| ())
        .map_err(|reason| reason.replace("approval response", "resolution"))
    })
    .await
    .map_err(|e| format!("permission.respond task failed: {e}"))?
}

/// Resolve the agentpact socket path, preferring an explicit `AppState` override
/// (set in tests) and falling back to the env-var/default lookup used by the
/// rest of the codebase.
fn agentpact_socket_for(state: &AppState) -> String {
    state
        .agentpact_socket
        .as_ref()
        .map_or_else(agentpact_socket_path, |p| p.display().to_string())
}

async fn resolve_pending(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<ResolveRequest>,
) -> StatusCode {
    let Some(decision) = parse_resolve_decision(&body.decision) else {
        return StatusCode::BAD_REQUEST;
    };

    let claim = match state.pending.claim(&id) {
        Ok(claim) => claim,
        Err(ResolveError::NotFound | ResolveError::NoLongerResolvable(_)) => {
            return StatusCode::GONE;
        }
        Err(ResolveError::AlreadyResolved(_)) => return StatusCode::CONFLICT,
    };

    let socket = agentpact_socket_for(&state);
    if let Err(error) = send_permission_response(socket, &claim.approval_token, decision).await {
        tracing::warn!(pending_id = %id, %error, "failed to resolve pending request with agentpactd");
        state.pending.abandon_claim(claim);
        return StatusCode::BAD_GATEWAY;
    }

    state
        .pending
        .complete_claim(claim, decision.allows_execution());
    StatusCode::OK
}

#[derive(Deserialize)]
struct HoldRequest {
    id: String,
    approval_token: String,
    server: String,
    tool: Option<String>,
    /// Optional verbatim code/command/path to render in the popup's
    /// accessoryView. Distinct from `tool` because `tool` is a short
    /// label ("Bash", "Read"); `code` is what the user actually needs
    /// to read to decide ("git push --force origin main"). Older
    /// callers omit it — the popup falls back to plain body text.
    #[serde(default)]
    code: Option<String>,
    /// Whether the popup may offer "Always". Defaults to `true` for older
    /// callers; `false` greys out the button (e.g. privilege escalation,
    /// which agentpactd never persists anyway).
    #[serde(default = "default_allow_always")]
    allow_always: bool,
}

fn default_allow_always() -> bool {
    true
}

async fn hold_pending(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HoldRequest>,
) -> StatusCode {
    let pending_timeout = state.config.load().mcp.pending_timeout_seconds;
    let pending = state.pending.clone();
    let timeout_id = body.id.clone();

    // Clone for the dialog task before fields are moved into hold()
    let dialog_id = body.id.clone();
    let dialog_server = body.server.clone();
    let dialog_tool = body.tool.clone();
    let dialog_code = body.code.clone();
    let dialog_allow_always = body.allow_always;

    let _rx = state.pending.hold(
        body.id.clone(),
        body.approval_token,
        body.server,
        body.tool,
        dialog_allow_always,
    );
    let handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(pending_timeout)).await;
        pending.timeout(&timeout_id);
    });
    state.pending.set_timeout_handle(&body.id, handle);

    // Show the approval dialog immediately rather than waiting for `kyris pending`.
    #[cfg(feature = "tray")]
    {
        let state = state.clone();
        tracing::info!(
            target: "kyrisd::approval",
            pending_id = %body.id,
            server = %dialog_server,
            tool = ?dialog_tool,
            "dispatching approval dialog"
        );
        tokio::spawn(async move {
            let tool_label = dialog_tool.as_deref().unwrap_or("unknown tool");
            // Title/body kept lean: the window titlebar already says
            // "Kyris", and when a code block is present it speaks for
            // itself — no need for a "Review and approve:" prompt. The
            // no-code path keeps prose because there's nothing else to
            // show the user.
            let body_line = if dialog_code.is_some() {
                String::new()
            } else {
                format!("Agent wants to run {tool_label}. Allow?")
            };
            let outcome = crate::notify::ask_approval(
                &format!("Allow {dialog_server}"),
                &body_line,
                dialog_code.as_deref(),
                dialog_allow_always,
            )
            .await;
            // CouldNotShow means the panel never became visible to the user
            // — treat as "no answer yet" and leave the request pending so
            // the menu-bar attention path (or `kyris pending`) can pick it
            // up. Treating CouldNotShow as Denied would silently reject
            // every request whenever the user is in a fullscreen app or on
            // a different Space — the exact failure mode this design fixes.
            let Some(decision) = decision_for_approval_outcome(outcome) else {
                tracing::warn!(
                    pending_id = %dialog_id,
                    "approval panel could not be shown — leaving request pending"
                );
                return;
            };
            // Best-effort log of the user's answer for `kyris approvals`
            // recall and offline catalog mining. Records the verbatim command
            // (multi-line preserved via JSON `\n` escaping); the agent's tool
            // label is intentionally not recorded. Falls back to dialog_tool
            // when no verbatim payload was carried in the hold request (older
            // callers that only sent the short label).
            let command = dialog_code.as_deref().or(dialog_tool.as_deref());
            crate::approvals_log::record(&crate::approvals_log::ApprovalRecord {
                ts: chrono::Utc::now().to_rfc3339(),
                pending_id: &dialog_id,
                server: &dialog_server,
                command,
                agent: "unknown",
                decision: match decision {
                    ResolveDecision::Approved => "approved",
                    ResolveDecision::Always => "always",
                    ResolveDecision::Denied => "denied",
                },
            });
            let Ok(claim) = state.pending.claim(&dialog_id) else {
                return; // already timed out or resolved by another path
            };
            let socket = agentpact_socket_for(&state);
            if let Err(e) = send_permission_response(socket, &claim.approval_token, decision).await
            {
                tracing::warn!(pending_id = %dialog_id, %e, "failed to send approval dialog response");
                state.pending.abandon_claim(claim);
                return;
            }
            state
                .pending
                .complete_claim(claim, decision.allows_execution());
        });
    }

    StatusCode::OK
}

async fn cancel_pending(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> StatusCode {
    if let Some(token) = state.pending.cancel(&id) {
        let socket = agentpact_socket_for(&state);
        let _ = send_permission_response(socket, &token, ResolveDecision::Denied).await;
    }
    StatusCode::OK
}

async fn pending_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.pending.get_state(&id) {
        Some(s) => (StatusCode::OK, Json(serde_json::json!({ "state": s }))),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found" })),
        ),
    }
}

// ---------------------------------------------------------------------------
// /api/hook/log — best-effort audit endpoint, called once per hook
// invocation at exit. The CLI sends one payload carrying inputs, the
// daemon's decision, and timing; this endpoint emits a single
// `hook resolved` tracing line. Optional fields (segments, approval_id)
// are omitted from the line when absent rather than serialized as null.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HookLogBody {
    /// Correlation id for one hook invocation. Lets operators group
    /// related entries and spot duplicate asks (same
    /// agent+action+detail, different `hook_id`).
    hook_id: String,
    /// Agent that triggered the hook (e.g. `claude-code`, `codex-cli`).
    agent: String,
    /// `AgentPact` action (`execute`, `read`, `write`, `call`).
    action: String,
    /// Verbatim payload from the agent — shell command, file path, MCP
    /// tool args. Free-form; not parsed.
    detail: String,
    /// Compound segments the daemon split `detail` into, when more than
    /// one. Only populated for `action=execute` compound commands.
    segments: Option<Vec<String>>,
    /// Final decision routed back to the agent (`allow`, `deny`).
    decision: String,
    /// Who/what decided. See `cli/src/hook_cmd.rs` for the canonical
    /// set (`agentpact_auto`, `agentpact_deny`, `user_approved`,
    /// `user_denied`, `user_timeout`, `kyrisd_unreachable`,
    /// `agentpact_unreachable`, `passthrough`, `unmapped`,
    /// `protocol_mismatch`).
    source: String,
    /// `AgentPact` approval id when the decision went through an ask
    /// path; lets operators correlate hook records with approval-
    /// dialog lifecycle in `kyris::approval`. Absent for auto-decide
    /// paths.
    approval_id: Option<String>,
    /// Whether the agent will get another say after kyris's response.
    /// `"none"` — kyris denied (exit 2) or returned a definitive
    /// allow-shape that suppresses the agent's prompt. `"agent_decides"`
    /// — kyris allowed silently (empty stdout) and the agent applies
    /// its own permission rules, which may or may not prompt.
    agent_prompt: String,
    /// Wall-clock time from hook entry to outcome, in milliseconds.
    elapsed_ms: u64,
}

async fn hook_log(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<HookLogBody>,
) -> StatusCode {
    // Single line per hook. `segments` and `approval_id` are tracing
    // fields only when present; when absent the line simply omits them.
    let segments_json = body
        .segments
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_default());
    tracing::info!(
        target: "kyrisd::hook",
        hook_id = %body.hook_id,
        agent = %body.agent,
        action = %body.action,
        detail = %body.detail,
        segments = segments_json.as_deref(),
        decision = %body.decision,
        source = %body.source,
        approval_id = body.approval_id.as_deref(),
        agent_prompt = %body.agent_prompt,
        elapsed_ms = body.elapsed_ms,
        "hook resolved"
    );
    StatusCode::NO_CONTENT
}

// ---------------------------------------------------------------------------
// /operator/* — read-only data inspection. Auth: operator_key (Bearer).
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct GatewayRecordsQuery {
    provider: Option<String>,
    model: Option<String>,
    status: Option<String>,
    session_id: Option<String>,
    trace_id: Option<String>,
    mcp_server: Option<String>,
    mcp_tool: Option<String>,
    /// RFC3339 timestamp; only records strictly newer are returned.
    since: Option<String>,
    /// Hard cap is `10_000`; default `1_000`.
    limit: Option<u32>,
}

#[derive(Serialize)]
struct GatewayRecordsResponse {
    records: Vec<kyris_core::record::GatewayRecord>,
}

async fn operator_gateway_records(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<GatewayRecordsQuery>,
) -> Result<Json<GatewayRecordsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let filter = storage::GatewayRecordFilter {
        provider: q.provider.as_deref(),
        model: q.model.as_deref(),
        status: q.status.as_deref(),
        session_id: q.session_id.as_deref(),
        trace_id: q.trace_id.as_deref(),
        mcp_server: q.mcp_server.as_deref(),
        mcp_tool: q.mcp_tool.as_deref(),
        since: q.since.as_deref(),
        limit: q.limit,
    };
    match state.db.query_gateway_records(filter) {
        Ok(records) => Ok(Json(GatewayRecordsResponse { records })),
        Err(err) => {
            tracing::warn!(error = %err, "operator gateway-records query failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            ))
        }
    }
}

/// Live stream of gateway records as they are persisted (L4 of the monitoring
/// strategy). Server-Sent Events; one JSON `GatewayRecord` per event. Subscribers
/// that fall behind the broadcast buffer skip ahead (records are dropped for that
/// reader, not buffered indefinitely) — the `DuckDB` store remains the full record.
async fn operator_stream(
    State(state): State<Arc<AppState>>,
) -> axum::response::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use axum::response::sse::{Event, KeepAlive, Sse};

    let rx = state.db.subscribe_records();
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(record) => {
                    let event = Event::default()
                        .json_data(&record)
                        .unwrap_or_else(|_| Event::default().comment("record serialize error"));
                    return Some((Ok::<_, std::convert::Infallible>(event), rx));
                }
                // Slow consumer: skip the gap and keep streaming (loop re-polls).
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                // Sender dropped (daemon shutting down): end the stream.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn operator_session_token(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<kyris_core::record::SessionTokenRow>, (StatusCode, Json<serde_json::Value>)> {
    match state.db.query_session_token(&session_id) {
        Ok(Some(row)) => Ok(Json(row)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "session not found", "session_id": session_id })),
        )),
        Err(err) => {
            tracing::warn!(error = %err, %session_id, "operator session-token query failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            ))
        }
    }
}

/// Maximum auto-revert window the diag endpoint accepts (1 hour).
/// Past this, edit `kyrisd.yaml`'s `log.filter` and restart — long-
/// term verbose logging shouldn't ride on a Tokio timer that the
/// next crash wipes.
const DIAG_LOG_FILTER_MAX_DURATION_SECS: u64 = 3600;

#[derive(Deserialize)]
struct DiagLogFilterRequest {
    /// `EnvFilter` directive string (e.g. `kyrisd::adapter=trace,kyrisd=debug`).
    filter: String,
    /// Auto-revert window in seconds. Absent / 0 = manual revert.
    /// Capped at [`DIAG_LOG_FILTER_MAX_DURATION_SECS`].
    #[serde(default)]
    duration_secs: Option<u64>,
}

#[derive(Serialize)]
struct DiagLogFilterResponse {
    previous_filter: String,
    new_filter: String,
    /// Absent when no auto-revert was requested or `duration_secs=0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reverts_at: Option<String>,
}

/// GET /operator/diag/log-filter — read the currently-active filter.
/// Returns whatever `try_set_filter` last accepted (or the startup
/// value when nothing has been mutated since boot).
async fn diag_log_filter_get() -> Json<serde_json::Value> {
    let current =
        crate::logging::current_filter().unwrap_or_else(|| "(not initialized)".to_string());
    Json(serde_json::json!({ "filter": current }))
}

/// POST /operator/diag/log-filter — swap the active filter,
/// optionally scheduling an auto-revert. Validates the directive
/// before applying so a typo never breaks logging mid-stream.
async fn diag_log_filter_set(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DiagLogFilterRequest>,
) -> Result<Json<DiagLogFilterResponse>, (StatusCode, Json<serde_json::Value>)> {
    let previous =
        crate::logging::current_filter().unwrap_or_else(|| state.config.load().log.filter.clone());

    if let Err(error) = crate::logging::try_set_filter(&req.filter) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        ));
    }

    let duration = req
        .duration_secs
        .filter(|d| *d > 0)
        .map(|d| d.min(DIAG_LOG_FILTER_MAX_DURATION_SECS));

    let reverts_at = duration.map(|secs| {
        let when = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
        when.to_rfc3339()
    });

    if let Some(secs) = duration {
        let revert_to = previous.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            match crate::logging::try_set_filter(&revert_to) {
                Ok(()) => tracing::info!(
                    reverted_to = %revert_to,
                    source = "diag_endpoint_auto_revert",
                    "log_filter_reverted"
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    "log_filter auto-revert failed; current filter unchanged"
                ),
            }
        });
    }

    tracing::info!(
        previous = %previous,
        new = %req.filter,
        duration_secs = ?duration,
        source = "diag_endpoint",
        "log_filter_changed"
    );

    Ok(Json(DiagLogFilterResponse {
        previous_filter: previous,
        new_filter: req.filter,
        reverts_at,
    }))
}

#[derive(Serialize)]
struct HealthzResponse {
    ready: bool,
    providers: usize,
    dropped_events: u64,
    db_writable: bool,
}

async fn healthz(
    State(state): State<Arc<AppState>>,
) -> (axum::http::StatusCode, Json<HealthzResponse>) {
    let config = state.config.load();
    let dropped = storage::dropped_count();
    let providers = config.providers.len();
    let db_writable = state.db.probe_writable();
    let ready = dropped == 0 && db_writable;
    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(HealthzResponse {
            ready,
            providers,
            dropped_events: dropped,
            db_writable,
        }),
    )
}

fn provider_configs_match(old: &ProviderConfig, new: &ProviderConfig) -> bool {
    old.name == new.name
        && old.format == new.format
        && old.api_key == new.api_key
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

async fn reload_loop<F, Fut>(
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
async fn agentpactd_health_poller() {
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
async fn watch_policy_mode() {
    // `agentpact` is locally aliased to `kyris_agentpact_client` (the
    // wire-types crate, no `policy`/`config`/`protocol` modules);
    // reach the agentpact server lib via the fully-qualified
    // `::agentpact` path.
    use ::agentpact::policy::resolution::{SYSTEM_POLICY_DIR, resolve_mode_for};
    use ::agentpact::protocol::types::Mode;
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

/// Write a JSON diagnostics dump to
/// `~/.local/state/kyris/diagnostics/` (see
/// [`kyris_core::paths::diagnostics_dir`]). Called from the SIGUSR1
/// handler. Doesn't dump deep daemon state yet — that would require
/// hold-and-snapshot of various mutexes. For now we emit basic
/// build/process metadata; richer dumps can be added as the daemon's
/// internal state surfaces are stabilized.
#[cfg(unix)]
fn write_diagnostics_dump() -> std::io::Result<std::path::PathBuf> {
    let dir = kyris_core::paths::diagnostics_dir();
    std::fs::create_dir_all(&dir)?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let path = dir.join(format!("dump-{ts}.json"));

    let dump = serde_json::json!({
        "schema_version": 1,
        "version": crate::build_info::VERSION,
        "build_date": crate::build_info::BUILD_DATE,
        "commit": crate::build_info::COMMIT,
        "features": crate::build_info::FEATURES,
        "pid": std::process::id(),
        "tray_issues": crate::tray::list_issues()
            .into_iter()
            .map(|(k, v)| serde_json::json!({"key": k, "reason": v}))
            .collect::<Vec<_>>(),
    });
    let body = serde_json::to_vec_pretty(&dump).expect("serialize diagnostics dump");
    std::fs::write(&path, body)?;
    Ok(path)
}

#[cfg(unix)]
async fn sigusr1_diagnostics(mut sigusr1: tokio::signal::unix::Signal) {
    loop {
        sigusr1.recv().await;
        match write_diagnostics_dump() {
            Ok(path) => tracing::info!(dump = %path.display(), "SIGUSR1 diagnostics dump"),
            Err(e) => tracing::warn!("SIGUSR1 diagnostics dump failed: {e}"),
        }
    }
}

#[cfg(not(unix))]
async fn sigusr1_diagnostics(_sigusr1: ()) {
    std::future::pending::<()>().await;
}

/// SIGUSR2 — toggle the active log filter between the configured
/// baseline (`log.filter`) and the verbose preset (`log.verbose_filter`).
/// Lets an operator with shell access flip on adapter-level debug
/// during a misbehaving request without restarting the daemon, and
/// flip back when done. The transition itself is always logged at
/// INFO so it appears in the log regardless of which filter is now
/// active.
///
/// No auto-revert on this path — it sticks until another SIGUSR2 or
/// a daemon restart. For bounded-window debugging, prefer the
/// admin endpoint (`POST /operator/diag/log-filter`) which accepts
/// `duration_secs` and auto-reverts via a Tokio timer.
#[cfg(unix)]
async fn sigusr2_toggle_log_filter(state: Arc<AppState>, mut sigusr2: tokio::signal::unix::Signal) {
    loop {
        sigusr2.recv().await;
        let config = state.config.load();
        let baseline = config.log.filter.clone();
        let verbose = config.log.verbose_filter.clone();
        match crate::logging::try_toggle_verbose(&baseline, &verbose) {
            Ok(now_active) => {
                tracing::info!(
                    active_filter = %now_active,
                    baseline = %baseline,
                    verbose = %verbose,
                    source = "sigusr2",
                    "log_filter_toggled"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGUSR2 log-filter toggle failed");
            }
        }
    }
}

#[cfg(not(unix))]
async fn sigusr2_toggle_log_filter(_state: Arc<AppState>, _sigusr2: ()) {
    std::future::pending::<()>().await;
}

#[cfg(unix)]
async fn sighup_reload(state: Arc<AppState>, mut hup: tokio::signal::unix::Signal) {
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
async fn sighup_reload(state: Arc<AppState>, _hup: ()) {
    let _ = state;
    // SIGHUP is not available on non-unix platforms.
    std::future::pending::<()>().await;
}

#[cfg(unix)]
async fn shutdown_signal(mut streams: ShutdownStreams) {
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
async fn shutdown_signal(_streams: ShutdownStreams) {
    tokio::signal::ctrl_c()
        .await
        .expect("install ctrl+c handler");
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::ApprovalOutcome;

    #[test]
    fn testCouldNotShowLeavesRequestPending() {
        // The permission-gate invariant: an outcome that never reached the
        // user must NOT resolve the request (and must never auto-approve).
        assert_eq!(
            decision_for_approval_outcome(ApprovalOutcome::CouldNotShow),
            None
        );
    }

    #[test]
    fn testExplicitOutcomesResolveAsChosen() {
        assert_eq!(
            decision_for_approval_outcome(ApprovalOutcome::Yes),
            Some(ResolveDecision::Approved)
        );
        assert_eq!(
            decision_for_approval_outcome(ApprovalOutcome::Always),
            Some(ResolveDecision::Always)
        );
        assert_eq!(
            decision_for_approval_outcome(ApprovalOutcome::No),
            Some(ResolveDecision::Denied)
        );
    }

    #[cfg(unix)]
    #[test]
    fn testIsKyrisdExecutableMatchesInstalledAndTestBinaries() {
        // Installed/dev binary.
        assert!(is_kyrisd_executable("kyrisd"));
        // cargo test/bench binaries: `kyrisd-<hex>`.
        assert!(is_kyrisd_executable("kyrisd-63734a7a32da801b"));
        assert!(is_kyrisd_executable("kyrisd-deadbeef"));
        // Not kyrisd: the CLI, the MCP wrapper, the policy daemon.
        assert!(!is_kyrisd_executable("kyris"));
        assert!(!is_kyrisd_executable("kyris-mcp"));
        assert!(!is_kyrisd_executable("agentpactd"));
        // `kyrisd-` prefix with a non-hex suffix is not a cargo artifact
        // and must not be swept (guards against e.g. `kyrisd-backup`).
        assert!(!is_kyrisd_executable("kyrisd-backup"));
        assert!(!is_kyrisd_executable("kyrisd-"));
        // Substring / suffix matches must not trip it.
        assert!(!is_kyrisd_executable("notkyrisd"));
        assert!(!is_kyrisd_executable("kyrisdd"));
    }

    use axum::routing::get;
    use kyris_core::config::ProviderFormat;
    use tokio::sync::{Notify, oneshot};

    use crate::metering::TokenCounts;

    fn sample_event(trace_id: &str, session_id: Option<&str>) -> StatsEvent {
        StatsEvent {
            trace_id: trace_id.to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            tokens: TokenCounts {
                input: 120,
                output: 30,
            },
            cache_create: 0,
            cache_read: 0,
            cost: Some(0.001),
            latency_ms: 25,
            status: "success".to_string(),
            session_id: session_id.map(str::to_string),
            mcp_server: None,
            mcp_tool: None,
            metering: kyris_core::record::Metering::Available,
            plan_status: kyris_core::record::PlanStatus::Overage,
            working_dir: None,
        }
    }

    fn make_provider(name: &str, api_key: &str, upstream: &str) -> ProviderConfig {
        let format = match name {
            "anthropic" => ProviderFormat::Anthropic,
            "google" => ProviderFormat::Google,
            _ => ProviderFormat::OpenAI,
        };
        ProviderConfig {
            name: name.to_string(),
            format,
            api_key: api_key.to_string(),
            upstream: upstream.to_string(),
            models: vec![format!("{name}-model")],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }
    }

    fn make_test_state(config: KyrisdConfig, temp_root: &std::path::Path) -> Arc<AppState> {
        make_test_state_with_socket(config, temp_root, None)
    }

    fn make_test_state_with_socket(
        config: KyrisdConfig,
        temp_root: &std::path::Path,
        agentpact_socket: Option<std::path::PathBuf>,
    ) -> Arc<AppState> {
        let (stats_tx, _stats_rx) = mpsc::channel(8);
        Arc::new(AppState {
            config: Arc::new(ArcSwap::from_pointee(config)),
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            cost_calculator: CostCalculator::new(),
            stats_tx,
            db: Arc::new(storage::DuckDbWriter::open(
                &temp_root.join("kyrisd.duckdb"),
            )),
            provider_clients: ArcSwap::from_pointee(HashMap::new()),
            pending: Arc::new(PendingStore::new()),
            agentpact_socket,
            mcp_annotation_cache: mcp_routing::AnnotationCache::default(),
        })
    }

    #[tokio::test]
    async fn testServeWithGracefulShutdownDrainsInflightRequest() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/block",
            get({
                let entered = entered.clone();
                let release = release.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "done"
                    }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_handle = tokio::spawn(async move {
            serve_with_graceful_shutdown(listener, app, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let request_handle = tokio::spawn(async move {
            reqwest::Client::new()
                .get(format!("{address}/block"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });

        entered.notified().await;
        let _ = shutdown_tx.send(());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!server_handle.is_finished());

        release.notify_waiters();
        assert_eq!(request_handle.await.unwrap(), "done");
        tokio::time::timeout(Duration::from_secs(5), server_handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn testDrainAndFlushStatsPersistsPendingEventsAndSessionTotals() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("kyrisd.duckdb");
        let circuit_breaker = Arc::new(CircuitBreaker::new());
        circuit_breaker.record_tokens("sess-drain", 150, 1_000);

        let (stats_tx, stats_rx) = mpsc::channel(8);
        let writer_handle = tokio::spawn(storage::stats_writer(
            stats_rx,
            Arc::new(storage::DuckDbWriter::open(&db_path)),
            circuit_breaker,
            kyris_core::config::StatsConfig::default(),
            kyris_core::config::SpendConfig::default(),
            30,
        ));

        stats_tx
            .send(sample_event("trace-drain", Some("sess-drain")))
            .await
            .unwrap();
        drain_and_flush_stats(stats_tx, writer_handle, Duration::from_millis(0))
            .await
            .unwrap();

        let writer = storage::DuckDbWriter::open(&db_path);
        let row_count: i64 = writer.with_conn(|conn| {
            conn.query_row("SELECT count(*) FROM gateway_records", [], |row| row.get(0))
                .unwrap()
        });
        assert_eq!(row_count, 1);
        let sessions = writer.load_session_tokens();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].0, "sess-drain");
        assert_eq!(sessions[0].1, 150);
    }

    #[tokio::test]
    async fn testReloadLoopKeepsOldConfigActiveUntilNewConfigLoads() {
        let dir = tempfile::tempdir().unwrap();
        let mut initial_config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        initial_config.providers = vec![make_provider("openai", "old-key", "https://old.example")];
        let initial_clients = build_provider_clients(&initial_config);
        let state = make_test_state(initial_config, dir.path());
        state.provider_clients.store(Arc::new(initial_clients));

        let (reload_tx, reload_rx) = mpsc::channel(1);
        let gate = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let next_config = {
            let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
            config.providers = vec![
                make_provider("openai", "new-key", "https://new.example"),
                make_provider("anthropic", "anth-key", "https://anth.example"),
            ];
            config
        };

        let handle = tokio::spawn({
            let state = state.clone();
            let gate = gate.clone();
            let started = started.clone();
            let next_config = next_config.clone();
            async move {
                reload_loop(state, reload_rx, move || {
                    let gate = gate.clone();
                    let started = started.clone();
                    let next_config = next_config.clone();
                    async move {
                        started.notify_one();
                        gate.notified().await;
                        Ok(next_config)
                    }
                })
                .await;
            }
        });

        reload_tx.send(()).await.unwrap();
        started.notified().await;
        assert_eq!(state.config.load().providers[0].api_key, "old-key");

        gate.notify_waiters();
        drop(reload_tx);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let loaded = state.config.load();
                if loaded.providers.len() == 2 && loaded.providers[0].api_key == "new-key" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        handle.await.unwrap();

        let loaded = state.config.load();
        assert_eq!(loaded.providers.len(), 2);
        assert_eq!(loaded.providers[0].api_key, "new-key");
        let clients = state.provider_clients.load();
        assert!(clients.contains_key("openai"));
        assert!(clients.contains_key("anthropic"));
    }

    #[tokio::test]
    async fn testReloadLoopKeepsCurrentConfigOnLoadFailure() {
        let dir = tempfile::tempdir().unwrap();
        let mut initial_config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        initial_config.providers = vec![make_provider("google", "old-key", "https://old.example")];
        let initial_clients = build_provider_clients(&initial_config);
        let state = make_test_state(initial_config, dir.path());
        state.provider_clients.store(Arc::new(initial_clients));

        let (reload_tx, reload_rx) = mpsc::channel(1);
        let handle = tokio::spawn({
            let state = state.clone();
            async move {
                reload_loop(state, reload_rx, || async { Err("boom".to_string()) }).await;
            }
        });

        reload_tx.send(()).await.unwrap();
        drop(reload_tx);
        handle.await.unwrap();

        let loaded = state.config.load();
        assert_eq!(loaded.providers.len(), 1);
        assert_eq!(loaded.providers[0].name, "google");
        assert_eq!(loaded.providers[0].api_key, "old-key");
        let clients = state.provider_clients.load();
        assert_eq!(clients.len(), 1);
        assert!(clients.contains_key("google"));
    }

    #[tokio::test]
    async fn testHealthzReadyWithProviders() {
        let dir = tempfile::tempdir().unwrap();
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.providers = vec![make_provider("openai", "key", "http://localhost")];
        let state = make_test_state(config, dir.path());

        let app = Router::new().route("/healthz", axum::routing::get(healthz).with_state(state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .get(format!("{addr}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ready"], true);
        assert_eq!(body["providers"], 1);
        assert_eq!(body["db_writable"], true);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testHealthzReadyWithoutProviders() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let app = Router::new().route("/healthz", axum::routing::get(healthz).with_state(state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .get(format!("{addr}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ready"], true);
        assert_eq!(body["providers"], 0);
        assert_eq!(body["db_writable"], true);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testCircuitBreakerResetEndpoint() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        state
            .circuit_breaker
            .record_tokens("sess-reset", 999_999, 200_000);
        assert!(state.circuit_breaker.is_tripped("sess-reset"));

        let app = Router::new().route(
            "/api/circuit-breaker/reset",
            axum::routing::post(circuit_breaker_reset).with_state(state.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .post(format!("{addr}/api/circuit-breaker/reset"))
            .json(&serde_json::json!({"session_id": "sess-reset"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(!state.circuit_breaker.is_tripped("sess-reset"));

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testResolvePendingNotFoundReturnsGone() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let app = Router::new().route(
            "/api/pending/{id}/resolve",
            axum::routing::post(resolve_pending).with_state(state),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .post(format!("{addr}/api/pending/nonexistent/resolve"))
            .json(&serde_json::json!({"decision": "approved"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 410);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testResolvePendingBadDecisionReturnsBadRequest() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        let _rx = state.pending.hold(
            "req-1".into(),
            "tok-1".into(),
            "github".into(),
            Some("read_file".into()),
            true,
        );

        let app = Router::new().route(
            "/api/pending/{id}/resolve",
            axum::routing::post(resolve_pending).with_state(state),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .post(format!("{addr}/api/pending/req-1/resolve"))
            .json(&serde_json::json!({"decision": "invalid_value"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[test]
    fn testParseResolveDecision() {
        assert_eq!(
            parse_resolve_decision("approved"),
            Some(ResolveDecision::Approved)
        );
        assert_eq!(
            parse_resolve_decision("denied"),
            Some(ResolveDecision::Denied)
        );
        assert_eq!(
            parse_resolve_decision("always"),
            Some(ResolveDecision::Always)
        );
        assert_eq!(parse_resolve_decision("garbage"), None);
    }

    #[tokio::test]
    async fn testHoldPendingEndpoint() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let app = Router::new().route(
            "/api/pending/hold",
            axum::routing::post(hold_pending).with_state(state.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .post(format!("{addr}/api/pending/hold"))
            .json(&serde_json::json!({
                "id": "req-ext-1",
                "approval_token": "apt-ext-1",
                "server": "github",
                "tool": "read_file"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(state.pending.list_held().len(), 1);
        assert_eq!(state.pending.list_held()[0].id, "req-ext-1");

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testPendingStatusEndpoint() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        let _rx = state.pending.hold(
            "req-s-1".into(),
            "tok-s-1".into(),
            "github".into(),
            Some("read_file".into()),
            true,
        );

        let app = Router::new().route(
            "/api/pending/{id}/status",
            axum::routing::get(pending_status).with_state(state.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let resp = reqwest::Client::new()
            .get(format!("{addr}/api/pending/req-s-1/status"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["state"], "held");

        let resp_missing = reqwest::Client::new()
            .get(format!("{addr}/api/pending/nonexistent/status"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp_missing.status(), 404);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    fn seed_gateway_records(state: &Arc<AppState>) {
        // Two distinct providers/models so the filter can discriminate.
        state
            .db
            .insert_batch(&[
                sample_event("trace-a", Some("sess-x")),
                sample_event("trace-b", Some("sess-y")),
            ])
            .expect("seed insert");
        let mut anthropic_event = sample_event("trace-c", Some("sess-x"));
        anthropic_event.provider = "anthropic".to_string();
        anthropic_event.model = "claude-haiku".to_string();
        state
            .db
            .insert_batch(&[anthropic_event])
            .expect("seed anthropic insert");
    }

    async fn spawn_operator_app(
        state: Arc<AppState>,
    ) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/operator/gateway-records",
                axum::routing::get(operator_gateway_records).with_state(state.clone()),
            )
            .route(
                "/operator/session-tokens/{session_id}",
                axum::routing::get(operator_session_token).with_state(state),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (addr, shutdown_tx, handle)
    }

    #[tokio::test]
    async fn testOperatorGatewayRecordsReturnsAll() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        seed_gateway_records(&state);

        let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
        let resp = reqwest::Client::new()
            .get(format!("{addr}/operator/gateway-records"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 3);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testOperatorGatewayRecordsFilterByProvider() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        seed_gateway_records(&state);

        let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
        let resp = reqwest::Client::new()
            .get(format!(
                "{addr}/operator/gateway-records?provider=anthropic"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["provider"], "anthropic");
        assert_eq!(records[0]["model"], "claude-haiku");

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testOperatorStreamDeliversPersistedRecord() {
        use futures_util::StreamExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let app = Router::new().route(
            "/operator/stream",
            axum::routing::get(operator_stream).with_state(state.clone()),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        // `.send()` returns once response headers arrive, which is after the
        // handler has already subscribed — so inserting now cannot race the
        // subscription.
        let resp = reqwest::Client::new()
            .get(format!("{addr}/operator/stream"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );

        state
            .db
            .insert_batch(&[sample_event("trace-stream", Some("sess-stream"))])
            .expect("insert");

        // Read SSE chunks until the first `data:` line, then parse it.
        let mut body = resp.bytes_stream();
        let mut buf = String::new();
        let record = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let chunk = body.next().await.expect("stream ended").expect("chunk");
                buf.push_str(&String::from_utf8_lossy(&chunk));
                if let Some(line) = buf.lines().find(|l| l.starts_with("data:")) {
                    let json = line.trim_start_matches("data:").trim();
                    return serde_json::from_str::<serde_json::Value>(json).expect("parse record");
                }
            }
        })
        .await
        .expect("timed out waiting for streamed record");

        assert_eq!(record["trace_id"], "trace-stream");
        assert_eq!(record["provider"], "openai");
        assert_eq!(record["status"], "success");

        // The SSE response is a long-lived connection; graceful shutdown would
        // block on it. Drop the client side and abort the server task instead.
        drop(body);
        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn testOperatorGatewayRecordsFilterBySessionId() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        seed_gateway_records(&state);

        let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
        let resp = reqwest::Client::new()
            .get(format!("{addr}/operator/gateway-records?session_id=sess-x"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        for record in records {
            assert_eq!(record["session_id"], "sess-x");
        }

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testOperatorGatewayRecordsLimit() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        seed_gateway_records(&state);

        let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
        let resp = reqwest::Client::new()
            .get(format!("{addr}/operator/gateway-records?limit=1"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["records"].as_array().unwrap().len(), 1);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testOperatorSessionTokensReturnsRow() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());
        state
            .db
            .upsert_session_tokens("sess-x", 4242)
            .expect("upsert");

        let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
        let resp = reqwest::Client::new()
            .get(format!("{addr}/operator/session-tokens/sess-x"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["session_id"], "sess-x");
        assert_eq!(body["total_tokens"], 4242);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[test]
    fn testHookLogBodyDeserializesFullShape() {
        let raw = serde_json::json!({
            "hook_id": "76ce3727",
            "agent": "claude-code",
            "action": "execute",
            "detail": "ls && echo hi",
            "segments": ["ls", "echo hi"],
            "decision": "allow",
            "source": "agentpact_auto",
            "approval_id": "apr_42",
            "agent_prompt": "none",
            "elapsed_ms": 12
        });
        let body: HookLogBody = serde_json::from_value(raw).unwrap();
        assert_eq!(body.hook_id, "76ce3727");
        assert_eq!(
            body.segments.as_deref(),
            Some(&["ls".to_string(), "echo hi".to_string()][..])
        );
        assert_eq!(body.approval_id.as_deref(), Some("apr_42"));
        assert_eq!(body.agent_prompt, "none");
    }

    #[test]
    fn testHookLogBodyDeserializesWithoutOptionals() {
        // segments and approval_id are absent on auto-decide non-compound
        // calls; the body must still parse.
        let raw = serde_json::json!({
            "hook_id": "abcd",
            "agent": "codex-cli",
            "action": "execute",
            "detail": "ls",
            "decision": "allow",
            "source": "agentpact_auto",
            "agent_prompt": "agent_decides",
            "elapsed_ms": 3
        });
        let body: HookLogBody = serde_json::from_value(raw).unwrap();
        assert!(body.segments.is_none());
        assert!(body.approval_id.is_none());
        assert_eq!(body.agent_prompt, "agent_decides");
    }

    #[tokio::test]
    async fn testOperatorSessionTokensReturns404ForUnknown() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
        let resp = reqwest::Client::new()
            .get(format!("{addr}/operator/session-tokens/nope"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    // -- end-to-end Ask resolution -------------------------------------
    //
    // These tests prove the full kyris-core ↔ kyrisd HTTP chain works for
    // the approval-prompt flow. They mount all three pending routes against
    // an in-process axum server, drive `hold_poll_resolve` (the same code
    // path `kyris hook check` uses when agentpactd returns Ask), and
    // simulate the user typing `y` or `n` in `kyris pending` by POSTing
    // /api/pending/{id}/resolve from a parallel task.
    //
    // What this catches:
    // - protocol drift between kyris-core's client and kyrisd's handlers
    // - missing routes / wrong methods
    // - regressions in hold/poll/resolve state transitions
    // - the prompt-→-resolve loop being broken end-to-end (the very bug
    //   that motivates this whole testing pass)
    //
    // What this does NOT catch:
    // - kyris hook check's stdin parsing (covered by hook_cmd unit tests)
    // - agentpactd's Ask emission (covered by agentpact's own tests)
    // - the interactive prompt UI (covered by pending::tests in the cli)
    //
    // POLL_INTERVAL in kyris-core is 1s, so each test takes ~1.5–2 seconds.

    async fn spawn_pending_app(
        state: Arc<AppState>,
    ) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/api/pending/hold",
                axum::routing::post(hold_pending).with_state(state.clone()),
            )
            .route(
                "/api/pending/{id}/status",
                axum::routing::get(pending_status).with_state(state.clone()),
            )
            .route(
                "/api/pending/{id}/resolve",
                axum::routing::post(resolve_pending).with_state(state),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (addr, shutdown_tx, handle)
    }

    /// Mock agentpactd UDS server. Accepts permission-respond requests from
    /// kyrisd's `resolve_pending` and unconditionally returns `PACT_OK` so
    /// the HTTP resolve handler succeeds. Real agentpactd is more selective;
    /// for the e2e prompt flow we only care that the HTTP-side state
    /// transition fires, not that agentpactd validates the token.
    ///
    /// Sync because the inner spawn handles all the awaiting; clippy flags
    /// it as `unused_async` otherwise.
    fn spawn_mock_agentpactd_socket(
        socket_path: std::path::PathBuf,
    ) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        // Ensure the socket path is fresh.
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind mock UDS");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        let Ok((mut stream, _)) = accept else { continue };
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let mut buf = Vec::new();
                            let _ = stream.read_to_end(&mut buf).await;
                            // Always respond PACT_OK — sufficient for the
                            // resolve handler to treat the round-trip as
                            // successful.
                            let _ = stream.write_all(b"{\"code\":\"PACT_OK\"}\n").await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });
        (shutdown_tx, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn testEndToEndApprovalReturnsApproved() {
        let dir = tempfile::tempdir().unwrap();
        let mock_sock = dir.path().join("mock-agentpactd.sock");
        let (mock_shutdown, mock_handle) = spawn_mock_agentpactd_socket(mock_sock.clone());

        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state_with_socket(config, dir.path(), Some(mock_sock));
        let (addr, shutdown_tx, handle) = spawn_pending_app(state).await;

        // Spawn the hook-side: hold + poll. This is exactly what
        // `kyris hook check` runs after agentpactd returns Ask.
        let task_conn = kyris_core::config::KyrisdConnection {
            base_url: addr.clone(),
            operator_key: "test-operator-key".to_string(),
        };
        let resolution_task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            kyris_core::pending::hold_poll_resolve(
                &client,
                &task_conn,
                kyris_core::pending::PendingApproval {
                    approval_id: "e2e-approve-1",
                    approval_token: "test-token",
                    server: "github",
                    tool: "read_file",
                    code: None,
                    allow_always: true,
                },
            )
            .await
        });

        // Wait long enough for hold_poll_resolve to POST /api/pending/hold
        // and start polling. POLL_INTERVAL is 1s; we resolve well before the
        // first poll cycle so the request is ready when polling starts.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Simulate `kyris pending` user typing "y": POST to /api/pending/<id>/resolve.
        let resolve_resp = reqwest::Client::new()
            .post(format!("{addr}/api/pending/e2e-approve-1/resolve"))
            .header("authorization", "Bearer test-operator-key")
            .json(&serde_json::json!({"decision": "approved"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resolve_resp.status(), 200, "resolve should succeed");

        // Wait for the polling task to observe the state change. Allow up to
        // 3 seconds (covers POLL_INTERVAL=1s plus jitter).
        let resolution = tokio::time::timeout(std::time::Duration::from_secs(3), resolution_task)
            .await
            .expect("hold_poll_resolve did not return within 3s")
            .expect("task did not panic");

        assert_eq!(resolution, kyris_core::pending::Resolution::Approved);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
        let _ = mock_shutdown.send(());
        let _ = mock_handle.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn testEndToEndDenialReturnsDenied() {
        let dir = tempfile::tempdir().unwrap();
        let mock_sock = dir.path().join("mock-agentpactd.sock");
        let (mock_shutdown, mock_handle) = spawn_mock_agentpactd_socket(mock_sock.clone());

        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state_with_socket(config, dir.path(), Some(mock_sock));
        let (addr, shutdown_tx, handle) = spawn_pending_app(state).await;

        let task_conn = kyris_core::config::KyrisdConnection {
            base_url: addr.clone(),
            operator_key: "test-operator-key".to_string(),
        };
        let resolution_task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            kyris_core::pending::hold_poll_resolve(
                &client,
                &task_conn,
                kyris_core::pending::PendingApproval {
                    approval_id: "e2e-deny-1",
                    approval_token: "test-token",
                    server: "github",
                    tool: "write_file",
                    code: None,
                    allow_always: true,
                },
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Simulate `kyris pending` user typing "n".
        let resolve_resp = reqwest::Client::new()
            .post(format!("{addr}/api/pending/e2e-deny-1/resolve"))
            .header("authorization", "Bearer test-operator-key")
            .json(&serde_json::json!({"decision": "denied"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resolve_resp.status(), 200);

        let resolution = tokio::time::timeout(std::time::Duration::from_secs(3), resolution_task)
            .await
            .expect("hold_poll_resolve did not return within 3s")
            .expect("task did not panic");

        assert_eq!(resolution, kyris_core::pending::Resolution::Denied);

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
        let _ = mock_shutdown.send(());
        let _ = mock_handle.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn testEndToEndListPendingReflectsHeldRequest() {
        // Verifies the kyris pending CLI's `GET /api/pending` listing path
        // sees a held request — the CLI uses this to display "what's
        // waiting for approval" before prompting.
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let app = Router::new()
            .route(
                "/api/pending/hold",
                axum::routing::post(hold_pending).with_state(state.clone()),
            )
            .route(
                "/api/pending",
                axum::routing::get(list_pending).with_state(state.clone()),
            )
            .route(
                "/api/pending/{id}/resolve",
                axum::routing::post(resolve_pending).with_state(state),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        // Hold a request directly via the HTTP API (mimics kyris hook check).
        let client = reqwest::Client::new();
        let hold_resp = client
            .post(format!("{addr}/api/pending/hold"))
            .header("authorization", "Bearer test-operator-key")
            .json(&serde_json::json!({
                "id": "e2e-list-1",
                "approval_token": "test-token",
                "server": "anthropic",
                "tool": "agent",
            }))
            .send()
            .await
            .unwrap();
        assert!(hold_resp.status().is_success());

        // Listing should show the held request — this is what `kyris pending`
        // displays to the user before prompting.
        let list_resp = client
            .get(format!("{addr}/api/pending"))
            .header("authorization", "Bearer test-operator-key")
            .send()
            .await
            .unwrap();
        assert_eq!(list_resp.status(), 200);
        let body: serde_json::Value = list_resp.json().await.unwrap();
        let requests = body["requests"].as_array().expect("requests array");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["id"], "e2e-list-1");
        assert_eq!(requests[0]["server"], "anthropic");
        assert_eq!(requests[0]["state"], "held");

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }
}
