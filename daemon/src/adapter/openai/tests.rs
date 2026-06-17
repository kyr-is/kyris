// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::post};
use kyris_core::config::{KyrisdConfig, ProviderConfig, ProviderFormat};
use tokio::sync::{mpsc, oneshot};

#[test]
fn testResponsesUpstreamRoutesByCredentialType() {
    let provider = ProviderConfig::default_for(ProviderFormat::OpenAI);

    // API-key auth (no ChatGPT-Account-ID) -> the standard OpenAI API.
    let mut api = HeaderMap::new();
    api.insert("authorization", "Bearer sk-abc".parse().unwrap());
    assert_eq!(
        responses_upstream_url(&provider, &api),
        "https://api.openai.com/v1/responses"
    );

    // ChatGPT subscription login (ChatGPT-Account-ID present, normalized
    // lowercase by the http crate) -> the ChatGPT codex backend at /responses.
    let mut sub = HeaderMap::new();
    sub.insert("authorization", "Bearer eyJhbGc".parse().unwrap());
    sub.insert("chatgpt-account-id", "acct-123".parse().unwrap());
    assert_eq!(
        responses_upstream_url(&provider, &sub),
        "https://chatgpt.com/backend-api/codex/responses"
    );
}

#[test]
fn testPlanStatusChatgptSubscriptionIsIncluded() {
    // The OpenAI twin of `anthropic_plan_status`: a ChatGPT subscription
    // login (ChatGPT-Account-ID present — the same signal that picks the
    // chatgpt.com upstream) is plan-covered; API-key auth is billed.
    let mut sub = HeaderMap::new();
    sub.insert("authorization", "Bearer eyJhbGc".parse().unwrap());
    sub.insert("chatgpt-account-id", "acct-123".parse().unwrap());
    assert_eq!(
        openai_plan_status(&sub),
        kyris_core::record::PlanStatus::Included
    );

    let mut api = HeaderMap::new();
    api.insert("authorization", "Bearer sk-abc".parse().unwrap());
    assert_eq!(
        openai_plan_status(&api),
        kyris_core::record::PlanStatus::Overage
    );
}

#[test]
fn testForwardableRequestHeaderFiltersKyrisAndFraming() {
    // kyrisd's own routing headers must never leak upstream (the inbound key
    // especially), and the client recomputes framing/length headers.
    for blocked in [
        "x-kyris-inbound",
        "x-kyris-agent-id",
        "x-kyris-session-id",
        "host",
        "content-length",
        "accept-encoding",
        "connection",
    ] {
        assert!(
            !is_forwardable_request_header(blocked),
            "{blocked} must not be forwarded"
        );
    }
    // The caller's auth + codex routing headers must pass through.
    for ok in [
        "authorization",
        "content-type",
        "chatgpt-account-id",
        "openai-beta",
        "x-codex-turn-state",
        "x-codex-installation-id",
    ] {
        assert!(is_forwardable_request_header(ok), "{ok} must be forwarded");
    }
}

use crate::{
    circuit_breaker::CircuitBreaker, cost::CostCalculator, pending::PendingStore, server::AppState,
    storage::DuckDbWriter,
};

#[test]
fn testExtractTokensFromBody() {
    let body = br#"{"usage":{"prompt_tokens":200,"completion_tokens":100}}"#;
    let tokens = extract_tokens_from_body(body).unwrap();
    assert_eq!(tokens.input, 200);
    assert_eq!(tokens.output, 100);
}

#[test]
fn testExtractTokensFromBodyInvalid() {
    assert!(extract_tokens_from_body(b"not json").is_none());
}

#[test]
fn testExtractTokensFromBodyNoUsage() {
    let body = br#"{"id":"chatcmpl-123"}"#;
    assert!(extract_tokens_from_body(body).is_none());
}

#[test]
fn testExtractTokensFromBodyNullUsage() {
    let body = br#"{"usage":null}"#;
    assert!(extract_tokens_from_body(body).is_none());
}

#[test]
fn testInjectStreamUsage() {
    let mut body = serde_json::json!({"model": "gpt-4o", "stream": true});
    inject_stream_usage(&mut body);
    assert_eq!(body["stream_options"]["include_usage"], true);
}

#[test]
fn testInjectStreamUsagePreservesExisting() {
    let mut body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "stream_options": {"include_usage": false}
    });
    inject_stream_usage(&mut body);
    assert_eq!(body["stream_options"]["include_usage"], false);
}

#[test]
fn testInjectStreamUsageIntoEmptyStreamOptions() {
    let mut body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "stream_options": {}
    });
    inject_stream_usage(&mut body);
    assert_eq!(body["stream_options"]["include_usage"], true);
}

#[test]
fn testInjectStreamUsageIntoStreamOptionsWithOtherKeys() {
    let mut body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "stream_options": {"other_key": "value"}
    });
    inject_stream_usage(&mut body);
    assert_eq!(body["stream_options"]["include_usage"], true);
    assert_eq!(body["stream_options"]["other_key"], "value");
}

#[test]
fn testExtractTokensFromSSEFinalChunk() {
    let json =
        r#"{"id":"chatcmpl-abc","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":30}}"#;
    let tokens = extract_tokens_from_sse_json(json).unwrap();
    assert_eq!(tokens.input, 50);
    assert_eq!(tokens.output, 30);
}

#[test]
fn testExtractTokensFromSSENonFinalChunk() {
    let json = r#"{"id":"chatcmpl-abc","choices":[{"delta":{"content":"hi"}}],"usage":null}"#;
    assert!(extract_tokens_from_sse_json(json).is_none());
}

#[test]
fn testExtractTokensFromSSENoUsageField() {
    let json = r#"{"id":"chatcmpl-abc","choices":[{"delta":{"content":"hi"}}]}"#;
    assert!(extract_tokens_from_sse_json(json).is_none());
}

#[test]
fn testExtractTokensFromSSEInvalidJson() {
    assert!(extract_tokens_from_sse_json("not json").is_none());
}

#[tokio::test]
async fn testOpenAiRouteForwardsRequestAndEmitsStats() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/chat/completions", post(record_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });

    // The caller supplies its own credential; kyrisd forwards exactly that
    // `authorization` header to the upstream.
    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .header("x-kyris-session-id", "sess-123")
        .header("authorization", "Bearer caller-key")
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
    assert_eq!(response_json["usage"]["prompt_tokens"], 200);
    assert_eq!(response_json["usage"]["completion_tokens"], 100);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.provider, "openai");
    assert_eq!(event.model, "gpt-4o");
    assert_eq!(event.tokens.input, 200);
    assert_eq!(event.tokens.output, 100);
    assert_eq!(event.session_id.as_deref(), Some("sess-123"));
    // The runaway breaker counts no-tool OUTPUT tokens only (not input) —
    // this plain-text response made no tool call, so the counter is its 100
    // output tokens, not 300 input+output.
    assert_eq!(state.circuit_breaker.get_token_count("sess-123"), 100);
    // This call authenticated with an API key (no ChatGPT-Account-ID), so
    // the route classifies it `overage`. The subscription path classifies
    // `included` (helper-pinned in testPlanStatusChatgptSubscriptionIsIncluded;
    // not exercisable at route level because that branch targets the real
    // chatgpt.com backend — see CHATGPT_CODEX_UPSTREAM).
    assert_eq!(event.plan_status, kyris_core::record::PlanStatus::Overage);

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer caller-key")
    );
    assert_eq!(
        request.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["model"], "gpt-4o");
    assert_eq!(forwarded_json["messages"][0]["content"], "hi");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testOpenAiStreamRouteInjectsUsageAndEmitsStats() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1/chat/completions",
            post(record_streaming_upstream_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .header("x-kyris-session-id", "sess-stream")
        .header("authorization", "Bearer caller-key")
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
    assert!(streamed_body.contains("hello"), "{streamed_body}");
    assert!(streamed_body.contains("prompt_tokens"), "{streamed_body}");

    let request = recorded.lock().unwrap().clone().unwrap();
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["stream"], true);
    assert_eq!(forwarded_json["stream_options"]["include_usage"], true);

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testBreakerFiresWithoutSessionHeader() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/chat/completions", post(record_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    // Output-only counting: the mock returns 100 output tokens, so a 50-token
    // cap trips after one no-tool response. A 0s decision timeout makes the
    // unanswered runaway prompt default to Stop immediately (no GUI in tests),
    // so the second request gets the stop 429 without a multi-day hold.
    config.circuit_breaker.max_tokens = 50;
    config.circuit_breaker.decision_timeout_seconds = 0;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .header("authorization", "Bearer caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.session_id.as_deref(), Some("__default"));
    assert_eq!(state.circuit_breaker.get_token_count("__default"), 100);
    assert!(state.circuit_breaker.is_tripped("__default"));

    let response2 = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .header("authorization", "Bearer caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response2.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value = response2.json().await.unwrap();
    assert!(
        body["error"]["type"]
            .as_str()
            .unwrap()
            .contains("circuit_breaker")
    );

    // Stop 429s the request but still resets the counter (synchronously,
    // before the 429 returns), so the human's decision isn't re-litigated on
    // every subsequent call.
    assert_eq!(state.circuit_breaker.get_token_count("__default"), 0);
    assert!(!state.circuit_breaker.is_tripped("__default"));

    // The next request therefore proceeds normally (200), not another 429.
    let response3 = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .header("authorization", "Bearer caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response3.status(), StatusCode::OK);

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testOpenAiRouteFailsFastWhenNoAuthorizationAndDoesNotHitUpstream() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/chat/completions", post(record_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    // No `authorization` header: kyrisd has nothing to forward and must fail
    // fast without hitting the upstream.
    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}]
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
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn record_upstream_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    *recorded.lock().unwrap() = Some(RecordedRequest {
        headers,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::json!({
            "id": "chatcmpl-123",
            "choices": [{"message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": 200, "completion_tokens": 100}
        })
        .to_string(),
    )
}

async fn record_streaming_upstream_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    *recorded.lock().unwrap() = Some(RecordedRequest {
        headers,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}],\"usage\":null}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":30}}\n\n"
        ),
    )
}

fn make_test_state(
    config: KyrisdConfig,
    temp_root: &std::path::Path,
) -> (Arc<AppState>, mpsc::Receiver<crate::metering::StatsEvent>) {
    let (stats_tx, stats_rx) = mpsc::channel(8);
    let db = Arc::new(DuckDbWriter::open(&temp_root.join("kyrisd.duckdb")));
    let state = Arc::new(AppState {
        config: Arc::new(ArcSwap::from_pointee(config)),
        circuit_breaker: Arc::new(CircuitBreaker::new()),
        gate: Arc::new(crate::gate::GateRegistry::new()),
        cost_calculator: CostCalculator::new(),
        stats_tx,
        db,
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

#[test]
fn testExtractResponsesTokensFromBody() {
    let body = br#"{"usage":{"input_tokens":150,"output_tokens":80}}"#;
    let tokens = extract_responses_tokens_from_body(body).unwrap();
    assert_eq!(tokens.input, 150);
    assert_eq!(tokens.output, 80);
}

#[test]
fn testExtractResponsesTokensFromBodyNoUsage() {
    let body = br#"{"id":"resp-123"}"#;
    assert!(extract_responses_tokens_from_body(body).is_none());
}

#[test]
fn testExtractResponsesTokensFromBodyNullUsage() {
    let body = br#"{"usage":null}"#;
    assert!(extract_responses_tokens_from_body(body).is_none());
}

#[test]
fn testExtractResponsesTokensFromSSEResponseCompleted() {
    let json = r#"{"type":"response.completed","response":{"id":"resp-abc","usage":{"input_tokens":100,"output_tokens":50}}}"#;
    let tokens = extract_responses_tokens_from_sse_json(json).unwrap();
    assert_eq!(tokens.input, 100);
    assert_eq!(tokens.output, 50);
}

#[test]
fn testExtractResponsesTokensFromSSETopLevelUsage() {
    let json = r#"{"type":"response.done","usage":{"input_tokens":75,"output_tokens":25}}"#;
    let tokens = extract_responses_tokens_from_sse_json(json).unwrap();
    assert_eq!(tokens.input, 75);
    assert_eq!(tokens.output, 25);
}

#[test]
fn testExtractResponsesTokensFromSSENoUsage() {
    let json = r#"{"type":"response.output_item.added","item":{"type":"message"}}"#;
    assert!(extract_responses_tokens_from_sse_json(json).is_none());
}

#[test]
fn testExtractResponsesTokensFromSSENullResponseUsage() {
    let json = r#"{"type":"response.in_progress","response":{"usage":null}}"#;
    assert!(extract_responses_tokens_from_sse_json(json).is_none());
}

#[test]
fn testExtractResponsesTokensFromSSEInvalidJson() {
    assert!(extract_responses_tokens_from_sse_json("not json").is_none());
}

#[tokio::test]
async fn testResponsesRouteForwardsRequestAndEmitsStats() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/responses", post(record_responses_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "stream": false,
        "input": "hello"
    });

    // The caller supplies its own credential; kyrisd forwards exactly that
    // `authorization` header to the upstream.
    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/responses"))
        .header("x-kyris-session-id", "sess-resp-1")
        .header("authorization", "Bearer caller-key")
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
    assert_eq!(response_json["usage"]["input_tokens"], 150);
    assert_eq!(response_json["usage"]["output_tokens"], 80);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.provider, "openai");
    assert_eq!(event.model, "gpt-4o");
    assert_eq!(event.tokens.input, 150);
    assert_eq!(event.tokens.output, 80);
    assert_eq!(event.session_id.as_deref(), Some("sess-resp-1"));
    // Output-only no-tool counting (was 230 = input+output).
    assert_eq!(state.circuit_breaker.get_token_count("sess-resp-1"), 80);
    // API-key credential (no ChatGPT-Account-ID) → billed as overage.
    assert_eq!(event.plan_status, kyris_core::record::PlanStatus::Overage);

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer caller-key")
    );
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["model"], "gpt-4o");
    assert_eq!(forwarded_json["input"], "hello");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testResponsesStreamRouteInjectsUsageAndEmitsStats() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1/responses",
            post(record_responses_streaming_upstream_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "input": "hello"
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/responses"))
        .header("x-kyris-session-id", "sess-resp-stream")
        .header("authorization", "Bearer caller-key")
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

    let streamed_body = response.text().await.unwrap();
    assert!(streamed_body.contains("output_text"), "{streamed_body}");
    assert!(streamed_body.contains("input_tokens"), "{streamed_body}");

    let request = recorded.lock().unwrap().clone().unwrap();
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    // Forwarded as-is — no `include: ["usage"]` injection (the Responses API
    // rejects it; usage arrives natively in the streamed `response.completed`).
    assert!(forwarded_json.get("include").is_none(), "{forwarded_json}");
    assert_eq!(forwarded_json["model"], "gpt-4o");

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.provider, "openai");
    assert_eq!(event.model, "gpt-4o");
    assert_eq!(event.tokens.input, 100);
    assert_eq!(event.tokens.output, 50);
    assert_eq!(event.session_id.as_deref(), Some("sess-resp-stream"));
    // Output-only no-tool counting (was 150 = input+output).
    assert_eq!(
        state.circuit_breaker.get_token_count("sess-resp-stream"),
        50
    );

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

async fn record_responses_upstream_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    *recorded.lock().unwrap() = Some(RecordedRequest {
        headers,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::json!({
            "id": "resp-123",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "hello"}]}],
            "usage": {"input_tokens": 150, "output_tokens": 80}
        })
        .to_string(),
    )
}

async fn record_responses_streaming_upstream_request(
    State(recorded): State<Arc<Mutex<Option<RecordedRequest>>>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    *recorded.lock().unwrap() = Some(RecordedRequest {
        headers,
        body: body.to_vec(),
    });

    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        concat!(
            "event: response.output_item.added\n",
            "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}}\n\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-abc\",\"usage\":{\"input_tokens\":100,\"output_tokens\":50}}}\n\n"
        ),
    )
}

/// An upstream body that sends `first_chunk` and then never ends (endless
/// SSE keepalive comments). The relay can't reach graceful end-of-stream,
/// so a record can only be emitted through the `StreamRecordGuard` drop
/// path once the client disconnects — the next keepalive write surfaces
/// the dead socket to hyper, which drops the response body.
fn held_open_stream_body(first_chunk: &'static [u8]) -> axum::body::Body {
    let keepalives = futures_util::stream::unfold((), |()| async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Some((
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b": keepalive\n\n")),
            (),
        ))
    });
    axum::body::Body::from_stream(
        futures_util::stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from_static(
            first_chunk,
        ))])
        .chain(keepalives),
    )
}

/// Pins the e2e `D/test_01` codex-cli regression: `codex exec` exits — and
/// closes its connection — the moment it sees `response.completed`, without
/// reading to end-of-stream. Hyper then drops the response-body future, and
/// before `StreamRecordGuard` the gateway record was silently lost. The
/// usage already relayed must still land as a `StatsEvent`.
#[tokio::test]
async fn testResponsesStreamClientDisconnectStillEmitsStats() {
    let upstream = Router::new().route(
            "/v1/responses",
            post(|| async {
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/event-stream")
                    .body(held_open_stream_body(
                        b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-abc\",\"usage\":{\"input_tokens\":100,\"output_tokens\":50}}}\n\n",
                    ))
                    .unwrap()
            }),
        );
    let (upstream_url, _upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, _router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "input": "hello"
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/responses"))
        .header("x-kyris-session-id", "sess-resp-disconnect")
        .header("authorization", "Bearer caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Read the completion (with its usage) and disconnect like codex does
    // — without waiting for end-of-stream.
    let mut body_stream = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), body_stream.next())
        .await
        .expect("first chunk within 5s")
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&first)
            .unwrap()
            .contains("response.completed"),
        "expected the completion event first"
    );
    drop(body_stream);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .expect("disconnect must still emit the gateway record")
        .unwrap();
    assert_eq!(event.provider, "openai");
    assert_eq!(event.model, "gpt-4o");
    assert_eq!(event.tokens.input, 100);
    assert_eq!(event.tokens.output, 50);
    assert_eq!(event.session_id.as_deref(), Some("sess-resp-disconnect"));

    router_handle.abort();
    upstream_handle.abort();
}

/// Chat-completions twin of the disconnect regression (separate relay copy,
/// same guard requirement).
#[tokio::test]
async fn testChatStreamClientDisconnectStillEmitsStats() {
    let upstream = Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/event-stream")
                    .body(held_open_stream_body(
                        b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":30}}\n\n",
                    ))
                    .unwrap()
            }),
        );
    let (upstream_url, _upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, _router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/chat/completions"))
        .header("x-kyris-session-id", "sess-chat-disconnect")
        .header("authorization", "Bearer caller-key")
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
        std::str::from_utf8(&first).unwrap().contains("usage"),
        "expected the usage chunk first"
    );
    drop(body_stream);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .expect("disconnect must still emit the gateway record")
        .unwrap();
    assert_eq!(event.tokens.input, 50);
    assert_eq!(event.tokens.output, 30);
    assert_eq!(event.session_id.as_deref(), Some("sess-chat-disconnect"));

    router_handle.abort();
    upstream_handle.abort();
}

/// Buffered (non-streaming) twin: a client that gives up while kyrisd is
/// still waiting on the upstream must not lose the record — the upstream
/// call completes and bills regardless. `RunToCompletionLayer` keeps the
/// handler running after the connection is gone.
#[tokio::test]
async fn testBufferedClientDisconnectStillEmitsStats() {
    let upstream = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                serde_json::json!({
                    "choices": [{"message": {"content": "hello"}}],
                    "usage": {"prompt_tokens": 200, "completion_tokens": 100}
                })
                .to_string(),
            )
        }),
    );
    let (upstream_url, _upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "openai".to_string(),
        format: ProviderFormat::OpenAI,
        upstream: upstream_url.clone(),
        models: vec!["gpt-4o".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, _router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });

    // The client hangs up after 50ms; the upstream answers at 300ms.
    let aborted = tokio::time::timeout(
        Duration::from_millis(50),
        reqwest::Client::new()
            .post(format!("{router_url}/v1/chat/completions"))
            .header("x-kyris-session-id", "sess-buffered-disconnect")
            .header("authorization", "Bearer caller-key")
            .json(&request_body)
            .send(),
    )
    .await;
    assert!(
        aborted.is_err(),
        "client should have disconnected before the upstream responded"
    );

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .expect("disconnect must still emit the gateway record")
        .unwrap();
    assert_eq!(event.tokens.input, 200);
    assert_eq!(event.tokens.output, 100);
    assert_eq!(
        event.session_id.as_deref(),
        Some("sess-buffered-disconnect")
    );

    router_handle.abort();
    upstream_handle.abort();
}
