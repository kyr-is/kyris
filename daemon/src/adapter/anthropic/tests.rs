// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::post};
use bytes::Bytes;
use kyris_core::config::{KyrisdConfig, ProviderConfig, ProviderFormat};
use tokio::sync::{mpsc, oneshot};

#[test]
fn testPlanStatusSubscriptionOauthIsIncluded() {
    let mut h = HeaderMap::new();
    h.insert("authorization", "Bearer sk-ant-oat01-abc".parse().unwrap());
    assert_eq!(anthropic_plan_status(&h), PlanStatus::Included);

    let mut beta = HeaderMap::new();
    beta.insert(
        "anthropic-beta",
        "claude-code-20250219,oauth-2025-04-20".parse().unwrap(),
    );
    assert_eq!(anthropic_plan_status(&beta), PlanStatus::Included);
}

#[test]
fn testPlanStatusApiKeyAndFallbackAreOverage() {
    let mut key = HeaderMap::new();
    key.insert("x-api-key", "sk-ant-api03-xyz".parse().unwrap());
    assert_eq!(anthropic_plan_status(&key), PlanStatus::Overage);
    // No agent credential -> kyrisd substitutes its configured key -> billed.
    assert_eq!(
        anthropic_plan_status(&HeaderMap::new()),
        PlanStatus::Overage
    );
}

use crate::{
    circuit_breaker::CircuitBreaker, cost::CostCalculator, metering::StatsEvent,
    pending::PendingStore, server::AppState, storage::DuckDbWriter,
};

#[test]
fn testExtractUsageFromBody() {
    let body = br#"{"usage":{"input_tokens":100,"output_tokens":50,"cache_creation_input_tokens":20,"cache_read_input_tokens":10}}"#;
    let usage = extract_usage_from_body(body).unwrap();
    assert_eq!(usage.tokens.input, 100);
    assert_eq!(usage.tokens.output, 50);
    assert_eq!(usage.cache_create, 20);
    assert_eq!(usage.cache_read, 10);
}

#[test]
fn testExtractUsageFromInvalidBody() {
    let body = b"not json";
    assert!(extract_usage_from_body(body).is_none());
}

#[test]
fn testExtractUsageFromMissingUsage() {
    let body = br#"{"id":"msg_123"}"#;
    assert!(extract_usage_from_body(body).is_none());
}

#[test]
fn testExtractUsageFromNullUsage() {
    let body = br#"{"usage":null}"#;
    assert!(extract_usage_from_body(body).is_none());
}

#[test]
fn testExtractUsageFromEmptyUsage() {
    let body = br#"{"usage":{}}"#;
    let usage = extract_usage_from_body(body).unwrap();
    assert_eq!(usage.tokens.input, 0);
    assert_eq!(usage.tokens.output, 0);
}

#[test]
fn testExtractSessionId() {
    let mut headers = HeaderMap::new();
    headers.insert("x-kyris-session-id", "sess-123".parse().unwrap());
    assert_eq!(super::super::extract_session_id(&headers), "sess-123");
}

#[test]
fn testExtractSessionIdMissingFallsBackToDefault() {
    let headers = HeaderMap::new();
    assert_eq!(super::super::extract_session_id(&headers), "__default");
}

#[test]
fn testExtractTokensFromSSEMessageStart() {
    let json = r#"{"type":"message_start","message":{"usage":{"input_tokens":150,"cache_creation_input_tokens":50,"cache_read_input_tokens":25}}}"#;
    let result = extract_tokens_from_sse_json(json).unwrap();
    assert_eq!(result.tokens.input, 150);
    assert_eq!(result.tokens.output, 0);
    assert_eq!(result.cache_creation_input, 50);
    assert_eq!(result.cache_read_input, 25);
}

#[test]
fn testExtractTokensFromSSEMessageDelta() {
    let json = r#"{"type":"message_delta","usage":{"output_tokens":42}}"#;
    let result = extract_tokens_from_sse_json(json).unwrap();
    assert_eq!(result.tokens.input, 0);
    assert_eq!(result.tokens.output, 42);
}

#[test]
fn testExtractTokensFromSSEContentDelta() {
    let json = r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}"#;
    assert!(extract_tokens_from_sse_json(json).is_none());
}

#[test]
fn testExtractTokensFromSSEMessageStartNoCacheTokens() {
    let json = r#"{"type":"message_start","message":{"usage":{"input_tokens":100}}}"#;
    let result = extract_tokens_from_sse_json(json).unwrap();
    assert_eq!(result.tokens.input, 100);
    assert_eq!(result.cache_creation_input, 0);
    assert_eq!(result.cache_read_input, 0);
}

#[test]
fn testExtractTokensFromSSEInvalidJson() {
    assert!(extract_tokens_from_sse_json("not json").is_none());
}

#[test]
fn testExtractTokensFromSSENoType() {
    let json = r#"{"message":"hello"}"#;
    assert!(extract_tokens_from_sse_json(json).is_none());
}

#[tokio::test]
async fn testAnthropicRouteForwardsHeadersAndEmitsStats() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/messages", post(record_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    config.circuit_breaker.max_tokens = 100;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "hi"}]
    });

    // The caller supplies its own credential; kyrisd forwards exactly that
    // `x-api-key` value to the upstream.
    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-anthropic")
        .header("x-api-key", "caller-key")
        .header("anthropic-beta", "prompt-caching-2024-07-31")
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
    assert_eq!(response_json["usage"]["input_tokens"], 100);
    assert_eq!(response_json["usage"]["output_tokens"], 50);
    assert_eq!(response_json["usage"]["cache_creation_input_tokens"], 20);
    assert_eq!(response_json["usage"]["cache_read_input_tokens"], 10);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.provider, "anthropic");
    assert_eq!(event.model, "claude-3-5-sonnet-20241022");
    assert_eq!(event.tokens.input, 100);
    assert_eq!(event.tokens.output, 50);
    assert_eq!(event.cache_create, 20);
    assert_eq!(event.cache_read, 10);
    assert_eq!(event.session_id.as_deref(), Some("sess-anthropic"));
    // Output-only no-tool counting (was 150 = input+output).
    assert_eq!(state.circuit_breaker.get_token_count("sess-anthropic"), 50);

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(
        request.headers.get("x-api-key").map(String::as_str),
        Some("caller-key")
    );
    assert_eq!(
        request.headers.get("anthropic-version").map(String::as_str),
        Some("2023-06-01")
    );
    assert_eq!(
        request.headers.get("anthropic-beta").map(String::as_str),
        Some("prompt-caching-2024-07-31")
    );
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["model"], "claude-3-5-sonnet-20241022");
    assert_eq!(forwarded_json["messages"][0]["content"], "hi");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

/// G-K2: the emitted metering event carries the right `plan_status` at the
/// route level (not just the pure `anthropic_plan_status` helper). A
/// subscription OAuth credential classifies `Included`; a plain API key
/// classifies `Overage`. Both drive the full handler against the fake
/// upstream and read the recorded `StatsEvent.plan_status`.
#[tokio::test]
async fn testAnthropicRouteEmitsIncludedForOauthAndOverageForApiKey() {
    use kyris_core::record::PlanStatus;

    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/messages", post(record_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]
    });

    // Subscription OAuth (`sk-ant-oat…` bearer) → Included.
    let included = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-oauth")
        .header("authorization", "Bearer sk-ant-oat01-subscription")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(included.status(), StatusCode::OK);
    let included_event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        included_event.plan_status,
        PlanStatus::Included,
        "OAuth subscription credential must emit plan_status=Included"
    );

    // Plain API key → Overage.
    let overage = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-apikey")
        .header("x-api-key", "sk-ant-api03-billed")
        .json(&request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(overage.status(), StatusCode::OK);
    let overage_event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        overage_event.plan_status,
        PlanStatus::Overage,
        "API-key credential must emit plan_status=Overage"
    );

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

/// G-K5: `content-encoding` is preserved end-to-end through the full proxy.
/// kyrisd buffers the upstream body and rebuilds the caller response, and
/// because its reqwest client is built WITHOUT decompression
/// (`build_default_provider_client`), the body must travel byte-identical
/// with its `content-encoding` intact — the load-bearing half of the
/// relay-response-framing fix. (The complementary hop-by-hop framing strip in
/// `relay_upstream_headers` is unit-tested directly in
/// `testRelayUpstreamHeadersDropsFramingKeepsContent`; it cannot be exercised
/// at this layer because reqwest normalizes `transfer-encoding`/chunked away
/// before kyrisd ever sees the upstream response headers.)
#[tokio::test]
async fn testAnthropicRoutePreservesContentEncodingThroughProxy() {
    let body_bytes = serde_json::json!({
        "id": "msg_123",
        "type": "message",
        "content": [{"type": "text", "text": "hello"}],
        "usage": {"input_tokens": 10, "output_tokens": 5}
    })
    .to_string();
    let body_for_upstream = body_bytes.clone();

    // Fake upstream that advertises a content-encoding. The body is not
    // actually gzipped — kyrisd never decodes it, so byte-identity is what
    // matters (its reqwest client has no decompression feature). We do NOT
    // set `transfer-encoding: chunked` here: hyper owns response framing, so
    // a manual chunked header on a fixed-length body produces a malformed
    // response, and reqwest would normalize it away before kyrisd saw it
    // anyway.
    let upstream = Router::new().route(
        "/v1/messages",
        post(move || {
            let body = body_for_upstream.clone();
            async move {
                (
                    StatusCode::OK,
                    [
                        ("content-type", "application/json"),
                        ("content-encoding", "gzip"),
                    ],
                    body,
                )
            }
        }),
    );
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]
    });

    // reqwest is built without gzip/brotli/deflate features (see Cargo.toml),
    // so it never transparently decodes a response body — the relayed
    // `content-encoding` header and the raw bytes are observed verbatim,
    // which is exactly the property this test relies on.
    let resp = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    // content-encoding survives the proxy (kyrisd does not decompress).
    assert_eq!(
        resp.headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "content-encoding must be relayed: kyrisd does not decompress the body"
    );
    // The relayed response carries kyrisd's own framing (a content-length for
    // the buffered body), never a hop-by-hop transfer-encoding.
    assert!(
        !resp.headers().contains_key("transfer-encoding"),
        "the relayed response must not carry a hop-by-hop transfer-encoding"
    );
    // Body is byte-identical (not decoded/re-encoded).
    let relayed = resp.bytes().await.unwrap();
    assert_eq!(
        relayed.as_ref(),
        body_bytes.as_bytes(),
        "relayed body must be byte-identical to the upstream body"
    );

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testAnthropicStreamRouteRelaysSse() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/messages", post(record_streaming_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "stream": true,
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-anthropic-stream")
        .header("x-api-key", "caller-key")
        .header("anthropic-beta", "prompt-caching-2024-07-31")
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
        streamed_body.contains("\"type\":\"message_start\""),
        "{streamed_body}"
    );
    assert!(
        streamed_body.contains("\"text\":\"hello\""),
        "{streamed_body}"
    );
    assert!(
        streamed_body.contains("\"output_tokens\":40"),
        "{streamed_body}"
    );

    let request = recorded.lock().unwrap().clone().unwrap();
    assert_eq!(
        request.headers.get("x-api-key").map(String::as_str),
        Some("caller-key")
    );
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["stream"], true);
    assert_eq!(forwarded_json["messages"][0]["content"], "hi");

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testAnthropicNonStreamRouteReturns429WhenBreakerTrippedAndHumanStops() {
    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: "http://127.0.0.1:9".to_string(), // unreachable — gate fires first
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    // No GUI in tests, so the runaway prompt is never answered; a 0s decision
    // timeout makes it default to Stop immediately → the 429 below.
    config.circuit_breaker.decision_timeout_seconds = 0;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    state
        .circuit_breaker
        .record_tokens("sess-anthropic-nonstream-tripped", 1, 1);
    let app = routes(state);
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-anthropic-nonstream-tripped")
        .header("x-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "circuit_breaker");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("resume from the Kyris")
    );

    let _ = router_shutdown.send(());
    router_handle.await.unwrap();
}

#[tokio::test]
async fn testAnthropicStreamRouteEmitsSseStopEventWhenHumanStopsTrippedSession() {
    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: "http://127.0.0.1:9".to_string(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    // No GUI → prompt unanswered → 0s timeout defaults to Stop. A stream that
    // has already returned 200 can't become a 429, so Stop arrives as an
    // in-stream `event: error` chunk instead.
    config.circuit_breaker.decision_timeout_seconds = 0;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    state
        .circuit_breaker
        .record_tokens("sess-anthropic-tripped", 1, 1);
    let app = routes(state);
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "stream": true,
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-anthropic-tripped")
        .header("x-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    // Gated streaming response: 200 SSE, with the stop signal delivered as an
    // in-stream error event (not a 429).
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let streamed_body = response.text().await.unwrap();
    assert!(streamed_body.contains("event: error"), "{streamed_body}");
    assert!(
        streamed_body.contains("\"type\":\"circuit_breaker\""),
        "{streamed_body}"
    );
    assert!(
        streamed_body.contains("resume from the Kyris"),
        "{streamed_body}"
    );

    let _ = router_shutdown.send(());
    router_handle.await.unwrap();
}

#[tokio::test]
async fn testAnthropicStreamRouteDoesNotInterruptMidStreamButTripsForNext() {
    // The runaway breaker is a per-request boundary check, NOT a mid-stream
    // interrupter: a stream that crosses the cap while in flight is relayed
    // verbatim (no injected error), and the session is left tripped so the
    // *next* request gets gated.
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route(
            "/v1/messages",
            post(record_threshold_streaming_upstream_request),
        )
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];
    // The mock emits 150 output tokens; a 100-token cap is crossed at
    // end-of-stream (not mid-stream).
    config.circuit_breaker.max_tokens = 100;

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "stream": true,
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-anthropic-threshold")
        .header("x-api-key", "caller-key")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let streamed_body = response.text().await.unwrap();
    // No mid-stream injection: the upstream bytes pass through untouched.
    assert!(
        !streamed_body.contains("circuit_breaker"),
        "stream must not be interrupted mid-flight: {streamed_body}"
    );
    assert!(streamed_body.contains("hello"), "{streamed_body}");

    // The crossing is recorded at the request boundary, so the session is
    // now tripped and the next request would be gated.
    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.status, "circuit_breaker");
    assert!(state.circuit_breaker.is_tripped("sess-anthropic-threshold"));

    let request = recorded.lock().unwrap().clone().unwrap();
    let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(forwarded_json["stream"], true);

    let _ = router_shutdown.send(());
    let _ = upstream_shutdown.send(());
    router_handle.await.unwrap();
    upstream_handle.await.unwrap();
}

#[tokio::test]
async fn testAnthropicRouteFailsFastWhenNoCredentialAndDoesNotHitUpstream() {
    let recorded = Arc::new(Mutex::new(None));
    let upstream = Router::new()
        .route("/v1/messages", post(record_upstream_request))
        .with_state(recorded.clone());
    let (upstream_url, upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, _stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, router_shutdown, router_handle) = spawn_test_server(app).await;

    // No `authorization` and no `x-api-key`: kyrisd has nothing to forward
    // and must fail fast without hitting the upstream.
    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .json(&serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 128,
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
            "id": "msg_123",
            "type": "message",
            "content": [{"type": "text", "text": "hello"}],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_input_tokens": 20,
                "cache_read_input_tokens": 10
            }
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
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":80,\"cache_creation_input_tokens\":20,\"cache_read_input_tokens\":10}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":40}}\n\n"
        ),
    )
}

async fn record_threshold_streaming_upstream_request(
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
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":120}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":150}}\n\n"
        ),
    )
}

/// An upstream body that sends `first_chunk` and then never ends (endless
/// SSE keepalive comments). The relay can't reach graceful end-of-stream,
/// so a record can only be emitted through the `StreamRecordGuard` drop
/// path once the client disconnects.
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

/// A streaming client that disconnects after receiving the usage events —
/// without reading to end-of-stream — must still produce a gateway record
/// (hyper drops the body future on disconnect; `StreamRecordGuard` emits
/// from its Drop).
#[tokio::test]
async fn testAnthropicStreamClientDisconnectStillEmitsStats() {
    let upstream = Router::new().route(
            "/v1/messages",
            post(|| async {
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/event-stream")
                    .body(held_open_stream_body(
                        b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":120}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":40}}\n\n",
                    ))
                    .unwrap()
            }),
        );
    let (upstream_url, _upstream_shutdown, upstream_handle) = spawn_test_server(upstream).await;

    let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    config.providers = vec![ProviderConfig {
        name: "anthropic".to_string(),
        format: ProviderFormat::Anthropic,
        upstream: upstream_url.clone(),
        models: vec!["claude-3-5-sonnet-20241022".to_string()],
        timeout_seconds: 30,
        streaming_timeout_seconds: 300,
    }];

    let temp_dir = tempfile::tempdir().unwrap();
    let (state, mut stats_rx) = make_test_state(config, temp_dir.path());
    let app = routes(state.clone());
    let (router_url, _router_shutdown, router_handle) = spawn_test_server(app).await;

    let request_body = serde_json::json!({
        "model": "claude-3-5-sonnet-20241022",
        "stream": true,
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let response = reqwest::Client::new()
        .post(format!("{router_url}/v1/messages"))
        .header("x-kyris-session-id", "sess-anthropic-disconnect")
        .header("x-api-key", "caller-key")
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
            .contains("message_delta"),
        "expected the usage events first"
    );
    drop(body_stream);

    let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
        .await
        .expect("disconnect must still emit the gateway record")
        .unwrap();
    assert_eq!(event.provider, "anthropic");
    assert_eq!(event.tokens.input, 120);
    assert_eq!(event.tokens.output, 40);
    assert_eq!(
        event.session_id.as_deref(),
        Some("sess-anthropic-disconnect")
    );

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
