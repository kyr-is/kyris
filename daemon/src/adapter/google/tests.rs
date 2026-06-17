// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::post,
};
use bytes::Bytes;
use kyris_core::config::{KyrisdConfig, ProviderConfig, ProviderFormat};
use tokio::sync::{mpsc, oneshot};

use crate::{
    circuit_breaker::CircuitBreaker, cost::CostCalculator, metering::StatsEvent,
    pending::PendingStore, server::AppState, storage::DuckDbWriter,
};

#[test]
fn testExtractTokensFromBody() {
    let body = br#"{"usageMetadata":{"promptTokenCount":300,"candidatesTokenCount":150}}"#;
    let tokens = extract_tokens_from_body(body).unwrap();
    assert_eq!(tokens.input, 300);
    assert_eq!(tokens.output, 150);
}

#[test]
fn testExtractTokensFromBodyInvalid() {
    assert!(extract_tokens_from_body(b"not json").is_none());
}

#[test]
fn testExtractTokensFromBodyNullUsage() {
    let body = br#"{"usageMetadata":null}"#;
    assert!(extract_tokens_from_body(body).is_none());
}

#[test]
fn testParseModelAction() {
    assert_eq!(
        parse_model_action("gemini-2.0-flash:generateContent"),
        Some((
            "gemini-2.0-flash".to_string(),
            GoogleAction::GenerateContent
        ))
    );
    assert_eq!(
        parse_model_action("gemini-2.0-flash:streamGenerateContent"),
        Some((
            "gemini-2.0-flash".to_string(),
            GoogleAction::StreamGenerateContent
        ))
    );
    assert_eq!(parse_model_action("gemini-2.0-flash"), None);
}

#[test]
fn testExtractTokensFromMissingUsage() {
    let body = br#"{"candidates":[]}"#;
    assert!(extract_tokens_from_body(body).is_none());
}

#[test]
fn testExtractTokensFromNDJSONLine() {
    let json = r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":50}}"#;
    let tokens = extract_tokens_from_ndjson_line(json).unwrap();
    assert_eq!(tokens.input, 100);
    assert_eq!(tokens.output, 50);
}

#[test]
fn testExtractTokensFromNDJSONLineNoUsage() {
    let json = r#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#;
    assert!(extract_tokens_from_ndjson_line(json).is_none());
}

#[test]
fn testExtractTokensFromNDJSONLineInvalidJson() {
    assert!(extract_tokens_from_ndjson_line("not json").is_none());
}

#[test]
fn testSplitNDJSONLinesComplete() {
    let buf = "{\"a\":1}\n{\"b\":2}\n";
    let (lines, remainder) = split_ndjson_lines(buf);
    assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}"]);
    assert_eq!(remainder, "");
}

#[test]
fn testSplitNDJSONLinesPartial() {
    let buf = "{\"a\":1}\n{\"partial";
    let (lines, remainder) = split_ndjson_lines(buf);
    assert_eq!(lines, vec!["{\"a\":1}"]);
    assert_eq!(remainder, "{\"partial");
}

#[test]
fn testSplitNDJSONLinesSkipsEmpty() {
    let buf = "{\"a\":1}\n\n{\"b\":2}\n";
    let (lines, remainder) = split_ndjson_lines(buf);
    assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}"]);
    assert_eq!(remainder, "");
}

#[test]
fn testExtractTokensFromNDJSONLineNullUsage() {
    let json = r#"{"candidates":[],"usageMetadata":null}"#;
    assert!(extract_tokens_from_ndjson_line(json).is_none());
}

#[test]
fn testSplitNDJSONLinesSSEFormat() {
    let buf = "data: {\"a\":1}\n\ndata: {\"b\":2}\n";
    let (lines, remainder) = split_ndjson_lines(buf);
    assert_eq!(lines, vec!["data: {\"a\":1}", "data: {\"b\":2}"]);
    assert_eq!(remainder, "");
}

#[tokio::test]
async fn testGoogleRouteForwardsQueryKeyAndEmitsStats() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1beta/models/{model_action}",
            post(record_generate_content_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "google".to_string(),
        format: ProviderFormat::Google,
        upstream: upstream_url.clone(),
        models: vec!["gemini-2.0-flash".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    config.circuit_breaker.max_tokens = 90;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": "hi"}]
        }]
    });

    // The caller supplies its own key as the `?key=` query param; kyrisd
    // forwards exactly that value to the upstream.
    let response = reqwest::Client::new()
        .post(format!(
            "{router_url}/v1beta/models/gemini-2.0-flash:generateContent?key=caller-key"
        ))
        .header("x-kyris-session-id", "sess-google")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let trace_id = response
        .headers()
        .get("x-kyris-trace-id")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert!(!trace_id.is_empty());

    let response_json: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_json["usageMetadata"]["promptTokenCount"], 300);
    assert_eq!(response_json["usageMetadata"]["candidatesTokenCount"], 150);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.provider, "google");
    assert_eq!(event.model, "gemini-2.0-flash");
    assert_eq!(event.tokens.input, 300);
    assert_eq!(event.tokens.output, 150);
    assert_eq!(event.session_id.as_deref(), Some("sess-google"));
    // Output-only no-tool counting (was 450 = input+output).
    assert_eq!(state.circuit_breaker.get_token_count("sess-google"), 150);
    // G-K2: Google has no subscription-OAuth path — every call is API-key
    // billed, so the metering event the route emits always classifies
    // `overage` (asserted at the route level, not just the helper).
    assert_eq!(event.plan_status, kyris_core::record::PlanStatus::Overage);

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(request.model, "gemini-2.0-flash");
    assert_eq!(
        request.query.get("key").map(String::as_str),
        Some("caller-key")
    );
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["contents"][0]["parts"][0]["text"], "hi");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testGoogleStreamRouteRelaysNdjson() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1beta/models/{model_action}",
            post(record_stream_generate_content_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "google".to_string(),
        format: ProviderFormat::Google,
        upstream: upstream_url.clone(),
        models: vec!["gemini-2.0-flash".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": "hi"}]
        }]
    });

    // The caller supplies its own key via the `x-goog-api-key` header;
    // kyrisd forwards exactly that value into the upstream `?key=` query.
    let response = reqwest::Client::new()
        .post(format!(
            "{router_url}/v1beta/models/gemini-2.0-flash:streamGenerateContent"
        ))
        .header("x-kyris-session-id", "sess-google-stream")
        .header("x-goog-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let trace_id = response
        .headers()
        .get("x-kyris-trace-id")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert!(!trace_id.is_empty());

    let streamed_body = response.text().await.unwrap();
    assert!(
        streamed_body.contains("\"text\":\"hello\""),
        "{streamed_body}"
    );
    assert!(
        streamed_body.contains("\"promptTokenCount\":70"),
        "{streamed_body}"
    );
    assert!(
        streamed_body.contains("\"candidatesTokenCount\":30"),
        "{streamed_body}"
    );

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(request.model, "gemini-2.0-flash");
    assert_eq!(
        request.query.get("key").map(String::as_str),
        Some("caller-key")
    );
    assert_eq!(request.query.get("alt").map(String::as_str), Some("sse"));
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["contents"][0]["parts"][0]["text"], "hi");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testGoogleStreamRouteEmitsSseStopEventWhenHumanStopsTrippedSession() {
    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "google".to_string(),
        format: ProviderFormat::Google,
        upstream: "http://127.0.0.1:9".to_string(),
        models: vec!["gemini-2.0-flash".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    // No GUI → prompt unanswered → 0s timeout defaults to Stop, delivered as
    // an in-stream SSE error event (the stream is already a 200).
    config.circuit_breaker.decision_timeout_seconds = 0;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    state
        .circuit_breaker
        .record_tokens("sess-google-tripped", 1, 1);
    let app = routes(state);
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": "hi"}]
        }]
    });

    let response = reqwest::Client::new()
        .post(format!(
            "{router_url}/v1beta/models/gemini-2.0-flash:streamGenerateContent"
        ))
        .header("x-kyris-session-id", "sess-google-tripped")
        .header("x-goog-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("\"RESOURCE_EXHAUSTED\""), "{body}");
    assert!(body.contains("Circuit breaker"), "{body}");

    let _ = router_shutdown.send(());
    router_handle.await.unwrap();
}

#[tokio::test]
async fn testGoogleStreamRouteDoesNotInterruptMidStreamButTripsForNext() {
    // Per-request boundary, not a mid-stream interrupter: a stream that
    // crosses the cap in flight is relayed verbatim, and the session is left
    // tripped so the next request gets gated.
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1beta/models/{model_action}",
            post(record_threshold_stream_generate_content_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "google".to_string(),
        format: ProviderFormat::Google,
        upstream: upstream_url.clone(),
        models: vec!["gemini-2.0-flash".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    // The mock emits 150 output tokens; a 90-token cap is crossed at
    // end-of-stream (not mid-stream).
    config.circuit_breaker.max_tokens = 90;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{"text": "hi"}]
        }]
    });

    let response = reqwest::Client::new()
        .post(format!(
            "{router_url}/v1beta/models/gemini-2.0-flash:streamGenerateContent"
        ))
        .header("x-kyris-session-id", "sess-google-threshold")
        .header("x-goog-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let streamed_body = response.text().await.unwrap();
    // No mid-stream injection: upstream bytes pass through untouched.
    assert!(
        !streamed_body.contains("RESOURCE_EXHAUSTED"),
        "stream must not be interrupted mid-flight: {streamed_body}"
    );
    assert!(streamed_body.contains("hello"), "{streamed_body}");

    // Crossing recorded at the boundary → session tripped, next call gated.
    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.status, "circuit_breaker");
    assert!(state.circuit_breaker.is_tripped("sess-google-threshold"));

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(request.query.get("alt").map(String::as_str), Some("sse"));

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testGoogleRouteFailsFastWhenNoCallerKeyAndDoesNotHitUpstream() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1beta/models/{model_action}",
            post(record_generate_content_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "google".to_string(),
        format: ProviderFormat::Google,
        upstream: upstream_url.clone(),
        models: vec!["gemini-2.0-flash".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    // No `x-goog-api-key` header and no `?key=` query: kyrisd has nothing to
    // forward and must fail fast without hitting the upstream.
    let response = reqwest::Client::new()
        .post(format!(
            "{router_url}/v1beta/models/gemini-2.0-flash:generateContent"
        ))
        .json(&serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.text().await.unwrap();
    assert!(body.contains("no provider credential supplied"), "{body}");
    assert!(recorded.lock().unwrap().is_none(), "upstream was hit");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    model: String,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

async fn record_generate_content_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    Path(model_action): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (model, action) = parse_model_action(&model_action).expect("parse google action");
    assert_eq!(action, GoogleAction::GenerateContent);
    *recorded.lock().unwrap() = Some(RecordedRequest {
        model,
        query,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "hello"}]}
            }],
            "usageMetadata": {
                "promptTokenCount": 300,
                "candidatesTokenCount": 150
            }
        })
        .to_string(),
    )
}

async fn record_stream_generate_content_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    Path(model_action): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (model, action) = parse_model_action(&model_action).expect("parse google action");
    assert_eq!(action, GoogleAction::StreamGenerateContent);
    *recorded.lock().unwrap() = Some(RecordedRequest {
        model,
        query,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        concat!(
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\n",
            "data: {\"usageMetadata\":{\"promptTokenCount\":70,\"candidatesTokenCount\":30}}\n\n"
        ),
    )
}

async fn record_threshold_stream_generate_content_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    Path(model_action): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    _headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let (model, action) = parse_model_action(&model_action).expect("parse google action");
    assert_eq!(action, GoogleAction::StreamGenerateContent);
    *recorded.lock().unwrap() = Some(RecordedRequest {
        model,
        query,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        concat!(
            "data: {\"usageMetadata\":{\"promptTokenCount\":100,\"candidatesTokenCount\":150}}\n\n",
            "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\n"
        ),
    )
}

/// An upstream body that sends `first_chunk` and then never ends. The
/// relay can't reach graceful end-of-stream, so a record can only be
/// emitted through the `StreamRecordGuard` drop path once the client
/// disconnects.
fn held_open_stream_body(first_chunk: &'static [u8]) -> axum::body::Body {
    let keepalives = futures_util::stream::unfold((), |()| async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Some((Ok::<Bytes, std::io::Error>(Bytes::from_static(b"\n")), ()))
    });
    axum::body::Body::from_stream(
        futures_util::stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from_static(
            first_chunk,
        ))])
        .chain(keepalives),
    )
}

/// A streaming client that disconnects after receiving the usage line —
/// without reading to end-of-stream — must still produce a gateway record
/// (hyper drops the body future on disconnect; `StreamRecordGuard` emits
/// from its Drop).
#[tokio::test]
async fn testGoogleStreamClientDisconnectStillEmitsStats() {
    let upstream = Router::new().route(
            "/v1beta/models/{model_action}",
            post(|| async {
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/event-stream")
                    .body(held_open_stream_body(
                        b"data: {\"usageMetadata\":{\"promptTokenCount\":70,\"candidatesTokenCount\":30}}\n\n",
                    ))
                    .unwrap()
            }),
        );
    let (upstream_url, _upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "google".to_string(),
        format: ProviderFormat::Google,
        upstream: upstream_url.clone(),
        models: vec!["gemini-2.0-flash".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, _router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "contents": [{"parts": [{"text": "hi"}]}]
    });

    let response = reqwest::Client::new()
        .post(format!(
            "{router_url}/v1beta/models/gemini-2.0-flash:streamGenerateContent"
        ))
        .header("x-kyris-session-id", "sess-google-disconnect")
        .header("x-goog-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut body_stream = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), body_stream.next())
        .await
        .expect("first chunk within 5s")
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&first)
            .unwrap()
            .contains("usageMetadata"),
        "expected the usage line first"
    );
    drop(body_stream);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .expect("disconnect must still emit the gateway record")
        .unwrap();
    assert_eq!(event.provider, "google");
    assert_eq!(event.tokens.input, 70);
    assert_eq!(event.tokens.output, 30);
    assert_eq!(event.session_id.as_deref(), Some("sess-google-disconnect"));

    router_handle.abort();
    upstream_handle.abort();
}

fn make_test_state(
    config: KyrisdConfig,
    temp_root: &std::path::Path,
) -> (Arc<AppState>, mpsc::Receiver<StatsEvent>) {
    let (stats_tx, stats_rx) = mpsc::channel(8);
    let state = Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(config)),
        circuit_breaker: Arc::new(CircuitBreaker::new()),
        gate: Arc::new(crate::gate::GateRegistry::new()),
        cost_calculator: CostCalculator::new(),
        stats_tx,
        db: Arc::new(DuckDbWriter::open(&temp_root.join("kyrisd.duckdb"))),
        provider_clients: ArcSwap::from_pointee(HashMap::new()),
        default_provider_client: crate::server::build_default_provider_client(),
        pending: Arc::new(PendingStore::new()),
        agentpact_socket: None,
        mcp_annotation_cache: crate::mcp_routing::AnnotationCache::default(),
    });
    (state, stats_rx)
}

async fn spawn_test_server(
    app: Router,
) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    (address, shutdown_tx, handle)
}
