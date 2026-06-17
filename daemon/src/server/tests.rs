// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
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
        agent: Some("claude-code".to_string()),
    }
}

fn make_provider(name: &str, upstream: &str) -> ProviderConfig {
    let format = match name {
        "anthropic" => ProviderFormat::Anthropic,
        "google" => ProviderFormat::Google,
        _ => ProviderFormat::OpenAI,
    };
    ProviderConfig {
        name: name.to_string(),
        format,
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
        gate: Arc::new(crate::gate::GateRegistry::new()),
        cost_calculator: CostCalculator::new(),
        stats_tx,
        db: Arc::new(storage::DuckDbWriter::open(
            &temp_root.join("kyrisd.duckdb"),
        )),
        provider_clients: ArcSwap::from_pointee(HashMap::new()),
        default_provider_client: build_default_provider_client(),
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
    // `drain_timeout` now bounds the stats-writer flush (it no longer gates a
    // blind pre-sleep), so give the writer a real budget to persist the
    // queued event before the handle is awaited.
    drain_and_flush_stats(stats_tx, writer_handle, Duration::from_secs(5))
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
    initial_config.providers = vec![make_provider("openai", "https://old.example")];
    let initial_clients = build_provider_clients(&initial_config);
    let state = make_test_state(initial_config, dir.path());
    state.provider_clients.store(Arc::new(initial_clients));

    let (reload_tx, reload_rx) = mpsc::channel(1);
    let gate = Arc::new(Notify::new());
    let started = Arc::new(Notify::new());
    let next_config = {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.providers = vec![
            make_provider("openai", "https://new.example"),
            make_provider("anthropic", "https://anth.example"),
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
    assert_eq!(
        state.config.load().providers[0].upstream,
        "https://old.example"
    );

    gate.notify_waiters();
    drop(reload_tx);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let loaded = state.config.load();
            if loaded.providers.len() == 2 && loaded.providers[0].upstream == "https://new.example"
            {
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
    assert_eq!(loaded.providers[0].upstream, "https://new.example");
    let clients = state.provider_clients.load();
    assert!(clients.contains_key("openai"));
    assert!(clients.contains_key("anthropic"));
}

#[tokio::test]
async fn testReloadLoopKeepsCurrentConfigOnLoadFailure() {
    let dir = tempfile::tempdir().unwrap();
    let mut initial_config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    initial_config.providers = vec![make_provider("google", "https://old.example")];
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
    assert_eq!(loaded.providers[0].upstream, "https://old.example");
    let clients = state.provider_clients.load();
    assert_eq!(clients.len(), 1);
    assert!(clients.contains_key("google"));
}

#[tokio::test]
async fn testHealthzReadyWithProviders() {
    let dir = tempfile::tempdir().unwrap();
    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![make_provider("openai", "http://localhost")];
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
        None,
        "test-agent".into(),
        true,
        None,
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
            "tool": "read_file",
            "agent": "test-agent",
            "allow_always": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let held = state.pending.list_held();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].id, "req-ext-1");
    assert_eq!(held[0].agent, "test-agent");

    let _ = shutdown_tx.send(());
    handle.await.unwrap();
}

#[tokio::test]
async fn testHoldPendingEndpointRequiresAgentAndAllowAlways() {
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

    let client = reqwest::Client::new();
    let missing_agent = client
        .post(format!("{addr}/api/pending/hold"))
        .json(&serde_json::json!({
            "id": "req-missing-agent",
            "approval_token": "apt-missing-agent",
            "server": "github",
            "tool": "read_file",
            "allow_always": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_agent.status(), 422);

    let missing_allow_always = client
        .post(format!("{addr}/api/pending/hold"))
        .json(&serde_json::json!({
            "id": "req-missing-aa",
            "approval_token": "apt-missing-aa",
            "server": "github",
            "tool": "read_file",
            "agent": "test-agent"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_allow_always.status(), 422);
    assert!(state.pending.list_held().is_empty());

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
        None,
        "test-agent".into(),
        true,
        None,
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
            "/operator/timeline",
            axum::routing::get(operator_timeline).with_state(state.clone()),
        )
        .route(
            "/operator/stats",
            axum::routing::get(operator_stats).with_state(state.clone()),
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
async fn testOperatorTimelineRejectsMalformedSince() {
    // A non-RFC3339 bound must 400 on every operator read path, rather than
    // returning a misleading partial window (the event reader would keep
    // everything, the record reader would drop everything). Regression for
    // the silent since-divergence found during live verification.
    let dir = tempfile::tempdir().unwrap();
    let config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    let state = make_test_state(config, dir.path());
    let (addr, shutdown_tx, handle) = spawn_operator_app(state).await;
    let client = reqwest::Client::new();

    for path in [
        "/operator/timeline?since=1d",
        "/operator/timeline?until=garbage",
        "/operator/stats?since=7d",
        "/operator/gateway-records?since=not-a-time",
    ] {
        let resp = client.get(format!("{addr}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 400, "expected 400 for {path}");
    }

    // A valid RFC3339 bound is accepted.
    for path in [
        "/operator/timeline?since=2026-01-01T00:00:00Z",
        "/operator/stats?since=2026-01-01T00:00:00%2B00:00",
    ] {
        let resp = client.get(format!("{addr}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "expected 200 for {path}");
    }

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
// simulate a human approving or denying via the popup / tray / app by
// POSTing /api/pending/{id}/resolve from a parallel task.
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
                agent: "test-agent",
                allow_always: true,
                detail: None,
            },
        )
        .await
    });

    // Wait long enough for hold_poll_resolve to POST /api/pending/hold
    // and start polling. POLL_INTERVAL is 1s; we resolve well before the
    // first poll cycle so the request is ready when polling starts.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Simulate a human approving via the popup / app: POST to /api/pending/<id>/resolve.
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
                agent: "test-agent",
                allow_always: true,
                detail: None,
            },
        )
        .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Simulate a human denying via the popup / app.
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
    // Verifies the `GET /api/pending` listing path sees a held request —
    // the tray / app use this to display "what's waiting for approval"
    // before prompting.
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
            "agent": "test-agent",
            "allow_always": true
        }))
        .send()
        .await
        .unwrap();
    assert!(hold_resp.status().is_success());

    // Listing should show the held request — this is what the tray / app
    // display to the user before prompting.
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
    assert_eq!(requests[0]["agent"], "test-agent");
    assert_eq!(requests[0]["state"], "held");

    let _ = shutdown_tx.send(());
    handle.await.unwrap();
}
