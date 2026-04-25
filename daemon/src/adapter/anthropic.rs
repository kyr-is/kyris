// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use bytes::Bytes;
use futures_util::StreamExt;

use crate::metering::{StatsEvent, TokenCounts};
use crate::server::AppState;
use crate::streaming::{self, StreamTokenCounts};

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/messages",
            post(handle_messages).with_state(state.clone()),
        )
        .route(
            "/v1/messages/count_tokens",
            post(handle_count_tokens).with_state(state),
        )
}

async fn handle_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let body_value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let model = body_value
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let is_stream = body_value
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let trace_id = uuid::Uuid::now_v7().to_string();
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);

    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        crate::notify::circuit_breaker_toast(count);
        if is_stream {
            return Ok(circuit_breaker_sse_error(&trace_id, count));
        }
        return Ok(circuit_breaker_error(&trace_id, count).into_response());
    }

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.name == "anthropic")
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let clients = state.provider_clients.load();
    let client = clients
        .get("anthropic")
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!("{}/v1/messages", provider.upstream);

    let timeout_secs = if is_stream {
        provider.streaming_timeout_seconds
    } else {
        provider.timeout_seconds
    };

    let mut req = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .header("x-api-key", &provider.api_key)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(body.to_vec());

    for (key, value) in &headers {
        let name = key.as_str().to_lowercase();
        if name.starts_with("anthropic-") && name != "anthropic-version" {
            req = req.header(key, value);
        }
    }

    let response = req.send().await.map_err(|e| {
        tracing::error!(error = %e, "upstream request failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    if is_stream {
        return relay_sse_stream(
            state,
            response,
            status,
            resp_headers,
            trace_id,
            model,
            session_id,
            trace_token,
            start,
        );
    }

    let resp_body = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let usage = extract_usage_from_body(&resp_body);
    let metering = if usage.is_some() {
        kyris_core::record::Metering::Available
    } else {
        kyris_core::record::Metering::Unavailable
    };
    let (tokens, cache_creation, cache_read) = match usage {
        Some(u) => (u.tokens, u.cache_create, u.cache_read),
        None => (TokenCounts::default(), 0, 0),
    };
    let latency_ms = start.elapsed().as_millis() as i64;

    let cost = state.cost_calculator.calculate(
        &model,
        tokens.input,
        tokens.output,
        if cache_creation > 0 {
            Some(cache_creation)
        } else {
            None
        },
        if cache_read > 0 {
            Some(cache_read)
        } else {
            None
        },
    );

    {
        let config = state.config.load();
        if config.circuit_breaker.enabled {
            let total = tokens.input + tokens.output;
            let max = config.circuit_breaker.max_tokens as i64;
            state.circuit_breaker.record_tokens(&session_id, total, max);
        }
    }

    let working_dir = match trace_token.as_deref() {
        Some(token) => super::relay_trace_attach(&state, token, &trace_id).await,
        None => None,
    };

    let _ = state.stats_tx.try_send(StatsEvent {
        trace_id: trace_id.clone(),
        provider: "anthropic".to_string(),
        model: model.clone(),
        tokens,
        cache_create: cache_creation,
        cache_read,
        cost,
        latency_ms,
        status: if status.is_success() {
            "success".to_string()
        } else {
            "error".to_string()
        },
        session_id: Some(session_id.clone()),
        mcp_server: None,
        mcp_tool: None,
        metering,
        working_dir,
    });

    let mut builder = Response::builder().status(status);
    for (key, value) in &resp_headers {
        builder = builder.header(key, value);
    }
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder
        .body(Body::from(resp_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[allow(clippy::too_many_arguments)]
fn relay_sse_stream(
    state: Arc<AppState>,
    response: reqwest::Response,
    status: StatusCode,
    resp_headers: HeaderMap,
    trace_id: String,
    model: String,
    session_id: String,
    trace_token: Option<String>,
    start: std::time::Instant,
) -> Result<Response, StatusCode> {
    let accumulated = Arc::new(std::sync::Mutex::new(StreamTokenCounts::default()));
    let line_buf = Arc::new(std::sync::Mutex::new(String::new()));
    let breaker_tripped = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Build the relay stream that forwards chunks and extracts tokens
    let relay = {
        let accumulated = accumulated.clone();
        let line_buf = line_buf.clone();
        let breaker_tripped = breaker_tripped.clone();
        let state = state.clone();

        response
            .bytes_stream()
            .map(move |chunk_result| match chunk_result {
                Ok(chunk) => {
                    if let Ok(text) = std::str::from_utf8(&chunk) {
                        let mut buf = line_buf.lock().expect("lock line buffer");
                        buf.push_str(text);
                        let snapshot = buf.clone();
                        let (lines, remainder) = streaming::split_sse_lines(&snapshot);
                        for line in &lines {
                            if let Some(json) = streaming::parse_sse_line(line)
                                && let Some(delta) = extract_tokens_from_sse_json(json)
                            {
                                accumulated
                                    .lock()
                                    .expect("lock accumulated")
                                    .accumulate(&delta);
                            }
                        }
                        *buf = remainder.to_string();
                    }

                    {
                        let acc = accumulated.lock().expect("lock accumulated");
                        let total = acc.tokens.input + acc.tokens.output;
                        let max = state.config.load().circuit_breaker.max_tokens as i64;
                        if total > max {
                            breaker_tripped.store(true, std::sync::atomic::Ordering::Relaxed);
                            crate::notify::circuit_breaker_toast(total);
                            let payload = serde_json::json!({
                                "type": "error",
                                "error": {
                                    "type": "circuit_breaker",
                                    "message": circuit_breaker_message(total),
                                }
                            });
                            let err_chunk = format!("\nevent: error\ndata: {payload}\n\n");
                            let mut combined = chunk.to_vec();
                            combined.extend_from_slice(err_chunk.as_bytes());
                            return Ok::<Bytes, reqwest::Error>(Bytes::from(combined));
                        }
                    }

                    Ok(chunk)
                }
                Err(e) => Err(e),
            })
    };

    let mut relay = Box::pin(relay);
    let mut finalized = false;
    let trace_id_for_stream = trace_id.clone();
    let model_for_stream = model.clone();
    let session_id_for_stream = session_id.clone();
    let full_stream = futures_util::stream::poll_fn(move |cx| {
        use std::task::Poll;

        if finalized {
            return Poll::Ready(None);
        }

        let finalize_stream = |emit_breaker_chunk: bool| {
            let remaining = {
                let mut buf = line_buf.lock().expect("lock line buffer");
                std::mem::take(&mut *buf)
            };
            if !remaining.is_empty() {
                let mut acc = accumulated.lock().expect("lock accumulated");
                for line in remaining.lines() {
                    if let Some(json) = streaming::parse_sse_line(line)
                        && let Some(delta) = extract_tokens_from_sse_json(json)
                    {
                        acc.accumulate(&delta);
                    }
                }
            }

            let stream_tokens = accumulated.lock().expect("lock accumulated").clone();
            let tokens = stream_tokens.tokens.clone();
            let latency_ms = start.elapsed().as_millis() as i64;

            let cache_creation = if stream_tokens.cache_creation_input > 0 {
                Some(stream_tokens.cache_creation_input)
            } else {
                None
            };
            let cache_read = if stream_tokens.cache_read_input > 0 {
                Some(stream_tokens.cache_read_input)
            } else {
                None
            };
            let cost = state.cost_calculator.calculate(
                &model,
                tokens.input,
                tokens.output,
                cache_creation,
                cache_read,
            );

            let mut breaker_chunk = None;
            let mut status = "success";
            {
                let config = state.config.load();
                if config.circuit_breaker.enabled {
                    let total = tokens.input + tokens.output;
                    let max = config.circuit_breaker.max_tokens as i64;
                    if breaker_tripped.load(std::sync::atomic::Ordering::Relaxed) {
                        state.circuit_breaker.record_tokens(&session_id, total, max);
                        status = "circuit_breaker";
                    } else if total > max {
                        state.circuit_breaker.record_tokens(&session_id, total, max);
                        breaker_tripped.store(true, std::sync::atomic::Ordering::Relaxed);
                        status = "circuit_breaker";
                        if emit_breaker_chunk {
                            let payload = serde_json::json!({
                                "type": "error",
                                "error": {
                                    "type": "circuit_breaker",
                                    "message": circuit_breaker_message(total),
                                }
                            });
                            let err_chunk = format!("\nevent: error\ndata: {payload}\n\n");
                            breaker_chunk = Some(Bytes::from(err_chunk));
                        }
                    } else {
                        state.circuit_breaker.record_tokens(&session_id, total, max);
                    }
                }
            }

            let stream_metering = if tokens.input == 0 && tokens.output == 0 {
                kyris_core::record::Metering::Unavailable
            } else {
                kyris_core::record::Metering::Available
            };

            // Sync call — runs inside poll_fn where .await is unavailable.
            // Acceptable: stream is fully received at this point.
            let working_dir = trace_token.as_deref().and_then(|token| {
                super::relay_trace_attach_sync(&state, token, &trace_id_for_stream)
            });

            let _ = state.stats_tx.try_send(StatsEvent {
                trace_id: trace_id_for_stream.clone(),
                provider: "anthropic".to_string(),
                model: model_for_stream.clone(),
                tokens,
                cache_create: stream_tokens.cache_creation_input,
                cache_read: stream_tokens.cache_read_input,
                cost,
                latency_ms,
                status: status.to_string(),
                session_id: Some(session_id_for_stream.clone()),
                mcp_server: None,
                mcp_tool: None,
                metering: stream_metering,
                working_dir,
            });

            breaker_chunk
        };

        if breaker_tripped.load(std::sync::atomic::Ordering::Relaxed) {
            match futures_util::Stream::poll_next(relay.as_mut(), cx) {
                Poll::Ready(Some(_)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    finalized = true;
                    if let Some(chunk) = finalize_stream(false) {
                        return Poll::Ready(Some(Ok(chunk)));
                    }
                    return Poll::Ready(None);
                }
            }
        }

        match futures_util::Stream::poll_next(relay.as_mut(), cx) {
            Poll::Ready(Some(chunk)) => {
                if breaker_tripped.load(std::sync::atomic::Ordering::Relaxed) {
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Some(chunk))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                finalized = true;
                if let Some(chunk) = finalize_stream(true) {
                    Poll::Ready(Some(Ok(chunk)))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    });

    let mut builder = Response::builder().status(status);
    for (key, value) in &resp_headers {
        let name = key.as_str();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(key, value);
    }
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder
        .body(Body::from_stream(full_stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_count_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.name == "anthropic")
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let clients = state.provider_clients.load();
    let client = clients
        .get("anthropic")
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!("{}/v1/messages/count_tokens", provider.upstream);

    let mut req = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(provider.timeout_seconds))
        .header("x-api-key", &provider.api_key)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(body.to_vec());

    for (key, value) in &headers {
        let name = key.as_str().to_lowercase();
        if name.starts_with("anthropic-") && name != "anthropic-version" {
            req = req.header(key, value);
        }
    }

    let response = req.send().await.map_err(|e| {
        tracing::error!(error = %e, "count_tokens upstream failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_body = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(resp_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

struct BodyUsage {
    tokens: TokenCounts,
    cache_create: i64,
    cache_read: i64,
}

fn extract_usage_from_body(body: &[u8]) -> Option<BodyUsage> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(BodyUsage {
        tokens: TokenCounts {
            input: usage["input_tokens"].as_i64().unwrap_or(0),
            output: usage["output_tokens"].as_i64().unwrap_or(0),
        },
        cache_create: usage["cache_creation_input_tokens"].as_i64().unwrap_or(0),
        cache_read: usage["cache_read_input_tokens"].as_i64().unwrap_or(0),
    })
}

/// Extract token information from a single SSE data JSON payload (Anthropic format).
pub fn extract_tokens_from_sse_json(json: &str) -> Option<StreamTokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let event_type = v.get("type")?.as_str()?;

    match event_type {
        "message_start" => {
            let usage = &v["message"]["usage"];
            let input = usage["input_tokens"].as_i64().unwrap_or(0);
            let cache_creation = usage["cache_creation_input_tokens"].as_i64().unwrap_or(0);
            let cache_read = usage["cache_read_input_tokens"].as_i64().unwrap_or(0);
            Some(StreamTokenCounts {
                tokens: TokenCounts { input, output: 0 },
                cache_creation_input: cache_creation,
                cache_read_input: cache_read,
            })
        }
        "message_delta" => {
            let usage = &v["usage"];
            let output = usage["output_tokens"].as_i64().unwrap_or(0);
            Some(StreamTokenCounts {
                tokens: TokenCounts { input: 0, output },
                cache_creation_input: 0,
                cache_read_input: 0,
            })
        }
        _ => None,
    }
}

fn circuit_breaker_message(token_count: i64) -> String {
    format!(
        "Circuit breaker: {token_count} tokens consumed in this session without human input. Run 'kyris continue' to resume."
    )
}

fn circuit_breaker_error(trace_id: &str, token_count: i64) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "type": "error",
        "error": {
            "type": "circuit_breaker",
            "message": circuit_breaker_message(token_count),
        },
        "x-kyris-trace-id": trace_id,
    }))
}

fn circuit_breaker_sse_error(trace_id: &str, token_count: i64) -> Response {
    let payload = serde_json::json!({
        "type": "error",
        "error": {
            "type": "circuit_breaker",
            "message": circuit_breaker_message(token_count),
        },
        "x-kyris-trace-id": trace_id,
    });
    let chunk = format!("event: error\ndata: {payload}\n\n");

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(chunk))
        .expect("build circuit breaker SSE response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::post};
    use bytes::Bytes;
    use kyris_core::config::{KyrisdConfig, ProviderConfig};
    use tokio::sync::{mpsc, oneshot};

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
            api_key: "anthropic-secret".to_string(),
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

        let response = reqwest::Client::new()
            .post(format!("{router_url}/v1/messages"))
            .header("x-kyris-session-id", "sess-anthropic")
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
        assert_eq!(state.circuit_breaker.get_token_count("sess-anthropic"), 150);

        let request = recorded.lock().unwrap().clone().unwrap();
        assert_eq!(
            request.headers.get("x-api-key").map(String::as_str),
            Some("anthropic-secret")
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
            api_key: "anthropic-secret".to_string(),
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
            Some("anthropic-secret")
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
    async fn testAnthropicStreamRouteReturnsSseBreakerErrorWhenSessionIsTripped() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.providers = vec![ProviderConfig {
            name: "anthropic".to_string(),
            api_key: "anthropic-secret".to_string(),
            upstream: "http://127.0.0.1:9".to_string(),
            models: vec!["claude-3-5-sonnet-20241022".to_string()],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }];

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
        assert!(streamed_body.contains("event: error"), "{streamed_body}");
        assert!(
            streamed_body.contains("\"type\":\"circuit_breaker\""),
            "{streamed_body}"
        );

        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }

    #[tokio::test]
    async fn testAnthropicStreamRouteInjectsBreakerErrorWhenUsageCrossesThreshold() {
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
            api_key: "anthropic-secret".to_string(),
            upstream: upstream_url.clone(),
            models: vec!["claude-3-5-sonnet-20241022".to_string()],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }];
        config.circuit_breaker.max_tokens = 100;

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
            .header("x-kyris-session-id", "sess-anthropic-threshold")
            .json(&request_body)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let streamed_body = response.text().await.unwrap();
        assert!(streamed_body.contains("event: error"), "{streamed_body}");
        assert!(
            streamed_body.contains("\"type\":\"circuit_breaker\""),
            "{streamed_body}"
        );

        let request = recorded.lock().unwrap().clone().unwrap();
        let forwarded_json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(forwarded_json["stream"], true);

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
                "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n"
            ),
        )
    }

    fn make_test_state(
        config: KyrisdConfig,
        temp_root: &std::path::Path,
    ) -> (Arc<AppState>, mpsc::Receiver<StatsEvent>) {
        let (stats_tx, stats_rx) = mpsc::channel(8);
        let state = Arc::new(AppState {
            config: Arc::new(ArcSwap::from_pointee(config)),
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            cost_calculator: CostCalculator::new(),
            stats_tx,
            db: Arc::new(DuckDbWriter::open(&temp_root.join("kyrisd.duckdb"))),
            provider_clients: ArcSwap::from_pointee(HashMap::new()),
            pending: Arc::new(PendingStore::new()),
            agentpact_socket: None,
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
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (address, shutdown_tx, handle)
    }
}
