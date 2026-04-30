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
    if config.tls.enabled {
        tracing::error!(
            "TLS is configured but not yet implemented — refusing to start without encryption guarantee"
        );
        std::process::exit(1);
    }

    let listen_addr = config.server.listen.clone();
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
    write_pid_file();

    let stats_config = config.stats.clone();
    let session_idle_minutes = config.circuit_breaker.session_idle_minutes;

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
        session_idle_minutes,
    ));

    tokio::spawn(crate::sync::daemon_sync::run_sync_loop(state.clone()));
    tokio::spawn(crate::pricing_fetch::run_pricing_fetch(state.clone()));
    tokio::spawn(run_pending_prune(state.pending.clone()));

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
        .layer(RequestBodyLimitLayer::new(max_body));

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("bind listen address");

    tracing::info!(listen = %listen_addr, "kyrisd listening");

    tokio::spawn(sighup_reload(state.clone()));

    serve_with_graceful_shutdown(listener, app, shutdown_signal())
        .await
        .expect("server error");

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
    let home = std::env::var("HOME").unwrap_or_default();
    let pid_path = format!("{home}/.kyris/kyrisd.pid");
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

fn write_pid_file() {
    let home = std::env::var("HOME").unwrap_or_default();
    let pid_path = format!("{home}/.kyris/kyrisd.pid");
    if let Some(parent) = std::path::Path::new(&pid_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&pid_path, std::process::id().to_string()) {
        tracing::warn!(error = %e, "failed to write PID file");
    }
}

fn remove_pid_file() {
    let home = std::env::var("HOME").unwrap_or_default();
    let pid_path = format!("{home}/.kyris/kyrisd.pid");
    let _ = std::fs::remove_file(pid_path);
}

/// Routes that require auth: circuit-breaker reset, pending requests.
fn authed_operational_routes(state: Arc<AppState>) -> Router {
    use axum::routing::{delete, get, post};

    Router::new()
        .route(
            "/api/circuit-breaker/reset",
            post(circuit_breaker_reset).with_state(state.clone()),
        )
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
            get(pending_status).with_state(state),
        )
}

/// Health/readiness routes -- no auth required (load-balancer probes).
fn health_routes(state: Arc<AppState>) -> Router {
    use axum::routing::get;

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz).with_state(state))
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
    approval_token: &str,
    decision: ResolveDecision,
) -> Result<(), String> {
    let socket = agentpact_socket_path();
    let token = approval_token.to_string();
    tokio::task::spawn_blocking(move || {
        agentpact::send_permission_response(
            &socket,
            "kyrisd-resolve",
            &token,
            decision.as_approval_response(),
            None,
        )
        .map_err(|reason| reason.replace("approval response", "resolution"))
    })
    .await
    .map_err(|e| format!("permission.respond task failed: {e}"))?
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

    if let Err(error) = send_permission_response(&claim.approval_token, decision).await {
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
}

async fn hold_pending(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HoldRequest>,
) -> StatusCode {
    let pending_timeout = state.config.load().mcp.pending_timeout_seconds;
    let pending = state.pending.clone();
    let timeout_id = body.id.clone();
    let _rx = state
        .pending
        .hold(body.id.clone(), body.approval_token, body.server, body.tool);
    let handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(pending_timeout)).await;
        pending.timeout(&timeout_id);
    });
    state.pending.set_timeout_handle(&body.id, handle);
    StatusCode::OK
}

async fn cancel_pending(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> StatusCode {
    if let Some(token) = state.pending.cancel(&id) {
        let _ = send_permission_response(&token, ResolveDecision::Denied).await;
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

#[derive(Serialize)]
struct ReadyzResponse {
    ready: bool,
    providers: usize,
    dropped_events: u64,
    db_writable: bool,
}

async fn readyz(
    State(state): State<Arc<AppState>>,
) -> (axum::http::StatusCode, Json<ReadyzResponse>) {
    let config = state.config.load();
    let dropped = storage::dropped_count();
    let providers = config.providers.len();
    let db_writable = state.db.probe_writable();
    let ready = providers > 0 && dropped == 0 && db_writable;
    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ReadyzResponse {
            ready,
            providers,
            dropped_events: dropped,
            db_writable,
        }),
    )
}

#[derive(Serialize)]
struct HealthzResponse {
    status: &'static str,
}

async fn healthz() -> Json<HealthzResponse> {
    Json(HealthzResponse { status: "ok" })
}

fn provider_configs_match(old: &ProviderConfig, new: &ProviderConfig) -> bool {
    old.name == new.name
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

async fn sighup_reload(state: Arc<AppState>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut hup = signal(SignalKind::hangup()).expect("install SIGHUP handler");
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
    {
        let _ = state;
        // SIGHUP is not available on non-unix platforms.
        std::future::pending::<()>().await;
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let ctrl_c = tokio::signal::ctrl_c();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("ctrl+c received, shutting down");
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl+c handler");
        tracing::info!("shutdown signal received");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::routing::get;
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
            working_dir: None,
        }
    }

    fn make_provider(name: &str, api_key: &str, upstream: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.to_string(),
            api_key: api_key.to_string(),
            upstream: upstream.to_string(),
            models: vec![format!("{name}-model")],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }
    }

    fn make_test_state(config: KyrisdConfig, temp_root: &std::path::Path) -> Arc<AppState> {
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
            agentpact_socket: None,
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
    async fn testHealthzReturnsOk() {
        let app = Router::new().route("/healthz", axum::routing::get(healthz));
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
        assert_eq!(body["status"], "ok");

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn testReadyzWithProviders() {
        let dir = tempfile::tempdir().unwrap();
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.providers = vec![make_provider("openai", "key", "http://localhost")];
        let state = make_test_state(config, dir.path());

        let app = Router::new().route("/readyz", axum::routing::get(readyz).with_state(state));
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
            .get(format!("{addr}/readyz"))
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
    async fn testReadyzWithoutProvidersReturnsUnavailable() {
        let dir = tempfile::tempdir().unwrap();
        let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        let state = make_test_state(config, dir.path());

        let app = Router::new().route("/readyz", axum::routing::get(readyz).with_state(state));
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
            .get(format!("{addr}/readyz"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ready"], false);

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
}
