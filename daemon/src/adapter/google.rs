// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use bytes::Bytes;
use futures_util::StreamExt;

use kyris_core::config::ProviderFormat;

use crate::metering::{StatsEvent, TokenCounts};
use crate::server::AppState;

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new().route(
        "/v1beta/models/{model_action}",
        post(handle_model_action).with_state(state),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GoogleAction {
    GenerateContent,
    StreamGenerateContent,
}

async fn handle_model_action(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(model_action): Path<String>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let Some((model, action)) = parse_model_action(&model_action) else {
        return Err(StatusCode::NOT_FOUND);
    };
    match action {
        GoogleAction::GenerateContent => {
            handle_generate_content(state, headers, model, peer_addr, body).await
        }
        GoogleAction::StreamGenerateContent => {
            handle_stream_generate_content(state, headers, model, peer_addr, body).await
        }
    }
}

fn parse_model_action(model_action: &str) -> Option<(String, GoogleAction)> {
    if let Some(model) = model_action.strip_suffix(":generateContent") {
        return Some((model.to_string(), GoogleAction::GenerateContent));
    }
    if let Some(model) = model_action.strip_suffix(":streamGenerateContent") {
        return Some((model.to_string(), GoogleAction::StreamGenerateContent));
    }
    None
}

async fn handle_generate_content(
    state: Arc<AppState>,
    headers: HeaderMap,
    model: String,
    peer_addr: SocketAddr,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let trace_id = uuid::Uuid::now_v7().to_string();
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);

    if let (Some(token), Some(aid)) = (trace_token.as_deref(), agent_id.as_deref()) {
        tracing::debug!(
            agent_id = aid,
            trace_token = token,
            "native protocol observed"
        );
        super::write_native_seen_breadcrumb(aid);
    }

    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        crate::notify::circuit_breaker_toast(count);
        return Ok(circuit_breaker_error(&trace_id, count));
    }

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::Google)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let provider_name = provider.name.clone();

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!(
        "{}/v1beta/models/{}:generateContent?key={}",
        provider.upstream, model, provider.api_key
    );

    let response = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(provider.timeout_seconds))
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "upstream request failed");
            StatusCode::BAD_GATEWAY
        })?;

    let status = response.status();
    let resp_body = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let parsed_tokens = extract_tokens_from_body(&resp_body);
    let metering = if parsed_tokens.is_some() {
        kyris_core::record::Metering::Available
    } else {
        kyris_core::record::Metering::Unavailable
    };
    let tokens = parsed_tokens.unwrap_or_default();
    let latency_ms = start.elapsed().as_millis() as i64;

    let cost = state
        .cost_calculator
        .calculate(&model, tokens.input, tokens.output, None, None);

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
        None => super::resolve_peer_working_dir(peer_addr).await,
    };

    let _ = state.stats_tx.try_send(StatsEvent {
        trace_id: trace_id.clone(),
        provider: provider_name,
        model: model.clone(),
        tokens,
        cache_create: 0,
        cache_read: 0,
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

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", &trace_id)
        .body(Body::from(resp_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_stream_generate_content(
    state: Arc<AppState>,
    headers: HeaderMap,
    model: String,
    peer_addr: SocketAddr,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let trace_id = uuid::Uuid::now_v7().to_string();
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);

    if let (Some(token), Some(aid)) = (trace_token.as_deref(), agent_id.as_deref()) {
        tracing::debug!(
            agent_id = aid,
            trace_token = token,
            "native protocol observed"
        );
        super::write_native_seen_breadcrumb(aid);
    }

    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        crate::notify::circuit_breaker_toast(count);
        return Ok(circuit_breaker_error(&trace_id, count));
    }

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::Google)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let provider_name = provider.name.clone();

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!(
        "{}/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
        provider.upstream, model, provider.api_key
    );

    let response = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(
            provider.streaming_timeout_seconds,
        ))
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "upstream request failed");
            StatusCode::BAD_GATEWAY
        })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    relay_ndjson_stream(
        state,
        response,
        status,
        resp_headers,
        trace_id,
        model,
        provider_name,
        session_id,
        trace_token,
        peer_addr,
        start,
    )
}

#[allow(clippy::too_many_arguments)]
fn relay_ndjson_stream(
    state: Arc<AppState>,
    response: reqwest::Response,
    status: StatusCode,
    resp_headers: HeaderMap,
    trace_id: String,
    model: String,
    provider_name: String,
    session_id: String,
    trace_token: Option<String>,
    peer_addr: SocketAddr,
    start: std::time::Instant,
) -> Result<Response, StatusCode> {
    let accumulated = Arc::new(std::sync::Mutex::new(TokenCounts::default()));
    let line_buf = Arc::new(std::sync::Mutex::new(String::new()));
    let breaker_tripped = Arc::new(std::sync::atomic::AtomicBool::new(false));

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
                        let (lines, remainder) = split_ndjson_lines(&snapshot);
                        for line in &lines {
                            let json_str = line.strip_prefix("data: ").unwrap_or(line);
                            if let Some(tokens) = extract_tokens_from_ndjson_line(json_str) {
                                let mut acc = accumulated.lock().expect("lock accumulated");
                                if tokens.input > acc.input {
                                    acc.input = tokens.input;
                                }
                                if tokens.output > acc.output {
                                    acc.output = tokens.output;
                                }
                            }
                        }
                        *buf = remainder.to_string();
                    }

                    {
                        let acc = accumulated.lock().expect("lock accumulated");
                        let total = acc.input + acc.output;
                        let max = state.config.load().circuit_breaker.max_tokens as i64;
                        if total > max {
                            breaker_tripped.store(true, std::sync::atomic::Ordering::Relaxed);
                            crate::notify::circuit_breaker_toast(total);
                            let payload = serde_json::json!({
                                "error": {
                                    "code": 429,
                                    "message": circuit_breaker_message(total),
                                    "status": "RESOURCE_EXHAUSTED"
                                }
                            });
                            let err_chunk = format!("{payload}\n");
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

    let mut relay = Some(Box::pin(relay));
    let mut finalized = false;
    let trace_id_for_stream = trace_id.clone();
    let model_for_stream = model.clone();
    let provider_name_for_stream = provider_name;
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
                    let json_str = line.strip_prefix("data: ").unwrap_or(line);
                    if let Some(tokens) = extract_tokens_from_ndjson_line(json_str) {
                        if tokens.input > acc.input {
                            acc.input = tokens.input;
                        }
                        if tokens.output > acc.output {
                            acc.output = tokens.output;
                        }
                    }
                }
            }

            let tokens = accumulated.lock().expect("lock accumulated").clone();
            let latency_ms = start.elapsed().as_millis() as i64;
            let cost =
                state
                    .cost_calculator
                    .calculate(&model, tokens.input, tokens.output, None, None);

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
                                "error": {
                                    "code": 429,
                                    "message": circuit_breaker_message(total),
                                    "status": "RESOURCE_EXHAUSTED"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("{payload}\n")));
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

            let working_dir = match trace_token.as_deref() {
                Some(token) => super::relay_trace_attach_sync(&state, token, &trace_id_for_stream),
                None => super::resolve_peer_working_dir_sync(peer_addr),
            };

            let _ = state.stats_tx.try_send(StatsEvent {
                trace_id: trace_id_for_stream.clone(),
                provider: provider_name_for_stream.clone(),
                model: model_for_stream.clone(),
                tokens,
                cache_create: 0,
                cache_read: 0,
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
            drop(relay.take());
            finalized = true;
            if let Some(chunk) = finalize_stream(false) {
                return Poll::Ready(Some(Ok(chunk)));
            }
            return Poll::Ready(None);
        }

        let r = relay.as_mut().expect("relay alive before breaker trip");
        match futures_util::Stream::poll_next(r.as_mut(), cx) {
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

fn circuit_breaker_message(token_count: i64) -> String {
    format!(
        "Circuit breaker: {token_count} tokens consumed in this session without human input. Run 'kyris continue' to resume."
    )
}

fn circuit_breaker_error(trace_id: &str, token_count: i64) -> Response {
    let payload = serde_json::json!({
        "error": {
            "code": 429,
            "message": circuit_breaker_message(token_count),
            "status": "RESOURCE_EXHAUSTED"
        }
    });

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(payload.to_string()))
        .expect("build circuit breaker error response")
}

/// Split NDJSON buffer into complete lines and a trailing partial line.
fn split_ndjson_lines(buf: &str) -> (Vec<&str>, &str) {
    if let Some(last_newline) = buf.rfind('\n') {
        let complete = &buf[..=last_newline];
        let remainder = &buf[last_newline + 1..];
        let lines: Vec<&str> = complete.lines().filter(|l| !l.trim().is_empty()).collect();
        (lines, remainder)
    } else {
        (vec![], buf)
    }
}

fn extract_tokens_from_body(body: &[u8]) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usageMetadata")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["promptTokenCount"].as_i64().unwrap_or(0),
        output: usage["candidatesTokenCount"].as_i64().unwrap_or(0),
    })
}

/// Extract usage metadata from a single NDJSON line (Google format).
fn extract_tokens_from_ndjson_line(json: &str) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let usage = v.get("usageMetadata")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["promptTokenCount"].as_i64().unwrap_or(0),
        output: usage["candidatesTokenCount"].as_i64().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
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
            api_key: "google-key".to_string(),
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

        let response = reqwest::Client::new()
            .post(format!(
                "{router_url}/v1beta/models/gemini-2.0-flash:generateContent"
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
        assert_eq!(state.circuit_breaker.get_token_count("sess-google"), 450);

        let request = recorded.lock().unwrap().clone().unwrap();
        assert_eq!(request.model, "gemini-2.0-flash");
        assert_eq!(
            request.query.get("key").map(String::as_str),
            Some("google-key")
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
            api_key: "google-key".to_string(),
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

        let response = reqwest::Client::new()
            .post(format!(
                "{router_url}/v1beta/models/gemini-2.0-flash:streamGenerateContent"
            ))
            .header("x-kyris-session-id", "sess-google-stream")
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
            Some("google-key")
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
    async fn testGoogleStreamRouteReturnsJsonBreakerErrorWhenSessionIsTripped() {
        let mut config: KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
        config.providers = vec![ProviderConfig {
            name: "google".to_string(),
            format: ProviderFormat::Google,
            api_key: "google-key".to_string(),
            upstream: "http://127.0.0.1:9".to_string(),
            models: vec!["gemini-2.0-flash".to_string()],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }];

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
            .json(&request_body)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = response.text().await.unwrap();
        assert!(body.contains("\"RESOURCE_EXHAUSTED\""), "{body}");
        assert!(body.contains("Circuit breaker"), "{body}");

        let _ = router_shutdown.send(());
        router_handle.await.unwrap();
    }

    #[tokio::test]
    async fn testGoogleStreamRouteInjectsBreakerErrorWhenUsageCrossesThreshold() {
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
            api_key: "google-key".to_string(),
            upstream: upstream_url.clone(),
            models: vec!["gemini-2.0-flash".to_string()],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }];
        config.circuit_breaker.max_tokens = 90;

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

        let response = reqwest::Client::new()
            .post(format!(
                "{router_url}/v1beta/models/gemini-2.0-flash:streamGenerateContent"
            ))
            .header("x-kyris-session-id", "sess-google-threshold")
            .json(&request_body)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let streamed_body = response.text().await.unwrap();
        assert!(
            streamed_body.contains("\"RESOURCE_EXHAUSTED\""),
            "{streamed_body}"
        );
        assert!(streamed_body.contains("Circuit breaker"), "{streamed_body}");

        let request = recorded.lock().unwrap().clone().unwrap();
        assert_eq!(request.query.get("alt").map(String::as_str), Some("sse"));

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
                "data: {\"usageMetadata\":{\"promptTokenCount\":100,\"candidatesTokenCount\":0}}\n\n",
                "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\n"
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
}
