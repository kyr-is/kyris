// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use bytes::Bytes;
use futures_util::StreamExt;

use kyris_core::config::ProviderFormat;

use crate::metering::{StatsEvent, TokenCounts};
use crate::server::AppState;
use crate::streaming;

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/chat/completions",
            post(handle_completions).with_state(state.clone()),
        )
        .route("/v1/responses", post(handle_responses).with_state(state))
}

async fn handle_completions(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let mut body_value: serde_json::Value =
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

    if is_stream {
        inject_stream_usage(&mut body_value);
    }

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::OpenAI)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let provider_name = provider.name.clone();

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!("{}/v1/chat/completions", provider.upstream);

    let outbound_body = serde_json::to_vec(&body_value).map_err(|_| StatusCode::BAD_REQUEST)?;

    let timeout_secs = if is_stream {
        provider.streaming_timeout_seconds
    } else {
        provider.timeout_seconds
    };

    let response = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .header("authorization", format!("Bearer {}", provider.api_key))
        .header("content-type", "application/json")
        .body(outbound_body)
        .send()
        .await
        .map_err(|e| {
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
            provider_name,
            session_id,
            trace_token,
            peer_addr,
            start,
        );
    }

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

    let mut builder = Response::builder().status(status);
    for (key, value) in &resp_headers {
        builder = builder.header(key, value);
    }
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder
        .body(Body::from(resp_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_responses(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let mut body_value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let model = body_value
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let is_stream = body_value
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);

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

    if is_stream {
        inject_responses_stream_usage(&mut body_value);
    }

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::OpenAI)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let provider_name = provider.name.clone();

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(reqwest::Client::new);
    let upstream_url = format!("{}/v1/responses", provider.upstream);

    let outbound_body = serde_json::to_vec(&body_value).map_err(|_| StatusCode::BAD_REQUEST)?;

    let timeout_secs = if is_stream {
        provider.streaming_timeout_seconds
    } else {
        provider.timeout_seconds
    };

    let response = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .header("authorization", format!("Bearer {}", provider.api_key))
        .header("content-type", "application/json")
        .body(outbound_body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "upstream request failed");
            StatusCode::BAD_GATEWAY
        })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    if is_stream {
        return relay_responses_sse_stream(
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
        );
    }

    let resp_body = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let parsed_tokens = extract_responses_tokens_from_body(&resp_body);
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
fn relay_responses_sse_stream(
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
                        let (lines, remainder) = streaming::split_sse_lines(&snapshot);
                        for line in &lines {
                            if let Some(json) = streaming::parse_sse_line(line)
                                && let Some(tokens) = extract_responses_tokens_from_sse_json(json)
                            {
                                let mut acc = accumulated.lock().expect("lock accumulated");
                                acc.input += tokens.input;
                                acc.output += tokens.output;
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
                                    "message": circuit_breaker_message(total),
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            let err_chunk = format!("data: {payload}\n\n");
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
                    if let Some(json) = streaming::parse_sse_line(line)
                        && let Some(tokens) = extract_responses_tokens_from_sse_json(json)
                    {
                        acc.input += tokens.input;
                        acc.output += tokens.output;
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
                        if emit_breaker_chunk {
                            let payload = serde_json::json!({
                                "error": {
                                    "message": "Circuit breaker: token limit exceeded. Run 'kyris continue' to resume.",
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("data: {payload}\n\n")));
                        }
                    } else if total > max {
                        state.circuit_breaker.record_tokens(&session_id, total, max);
                        breaker_tripped.store(true, std::sync::atomic::Ordering::Relaxed);
                        status = "circuit_breaker";
                        if emit_breaker_chunk {
                            let payload = serde_json::json!({
                                "error": {
                                    "message": "Circuit breaker: token limit exceeded. Run 'kyris continue' to resume.",
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("data: {payload}\n\n")));
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

#[allow(clippy::too_many_arguments)]
fn relay_sse_stream(
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
                        let (lines, remainder) = streaming::split_sse_lines(&snapshot);
                        for line in &lines {
                            if let Some(json) = streaming::parse_sse_line(line)
                                && let Some(tokens) = extract_tokens_from_sse_json(json)
                            {
                                let mut acc = accumulated.lock().expect("lock accumulated");
                                acc.input += tokens.input;
                                acc.output += tokens.output;
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
                                    "message": circuit_breaker_message(total),
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            let err_chunk = format!("data: {payload}\n\n");
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
                    if let Some(json) = streaming::parse_sse_line(line)
                        && let Some(tokens) = extract_tokens_from_sse_json(json)
                    {
                        acc.input += tokens.input;
                        acc.output += tokens.output;
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
                        if emit_breaker_chunk {
                            let payload = serde_json::json!({
                                "error": {
                                    "message": "Circuit breaker: token limit exceeded. Run 'kyris continue' to resume.",
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("data: {payload}\n\n")));
                        }
                    } else if total > max {
                        state.circuit_breaker.record_tokens(&session_id, total, max);
                        breaker_tripped.store(true, std::sync::atomic::Ordering::Relaxed);
                        status = "circuit_breaker";
                        if emit_breaker_chunk {
                            let payload = serde_json::json!({
                                "error": {
                                    "message": "Circuit breaker: token limit exceeded. Run 'kyris continue' to resume.",
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("data: {payload}\n\n")));
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
            "message": circuit_breaker_message(token_count),
            "type": "circuit_breaker",
            "code": "circuit_breaker"
        }
    });

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(payload.to_string()))
        .expect("build circuit breaker error response")
}

fn inject_stream_usage(body: &mut serde_json::Value) {
    let explicitly_false = body
        .get("stream_options")
        .and_then(|o| o.get("include_usage"))
        .and_then(serde_json::Value::as_bool)
        == Some(false);
    if !explicitly_false {
        body["stream_options"]["include_usage"] = serde_json::Value::Bool(true);
    }
}

fn extract_tokens_from_body(body: &[u8]) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["prompt_tokens"].as_i64().unwrap_or(0),
        output: usage["completion_tokens"].as_i64().unwrap_or(0),
    })
}

/// Extract tokens from an `OpenAI` SSE chunk's `usage` field.
/// Only the final chunk (with `stream_options.include_usage`) has usage data.
fn extract_tokens_from_sse_json(json: &str) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["prompt_tokens"].as_i64().unwrap_or(0),
        output: usage["completion_tokens"].as_i64().unwrap_or(0),
    })
}

fn inject_responses_stream_usage(body: &mut serde_json::Value) {
    let include = body.get("include").and_then(|v| v.as_array());
    let already_has_usage =
        include.is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("usage")));
    if !already_has_usage {
        let mut arr = body
            .get("include")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        arr.push(serde_json::json!("usage"));
        body["include"] = serde_json::Value::Array(arr);
    }
}

fn extract_responses_tokens_from_body(body: &[u8]) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["input_tokens"].as_i64().unwrap_or(0),
        output: usage["output_tokens"].as_i64().unwrap_or(0),
    })
}

/// Extract tokens from a Responses API SSE event's `response.usage` or top-level `usage`.
/// Usage arrives in the `response.completed` event which contains the full response object.
fn extract_responses_tokens_from_sse_json(json: &str) -> Option<TokenCounts> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let usage = v
        .get("response")
        .and_then(|r| r.get("usage"))
        .or_else(|| v.get("usage"))?;
    if usage.is_null() {
        return None;
    }
    Some(TokenCounts {
        input: usage["input_tokens"].as_i64().unwrap_or(0),
        output: usage["output_tokens"].as_i64().unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::post};
    use kyris_core::config::{KyrisdConfig, ProviderConfig, ProviderFormat};
    use tokio::sync::{mpsc, oneshot};

    use crate::{
        circuit_breaker::CircuitBreaker, cost::CostCalculator, pending::PendingStore,
        server::AppState, storage::DuckDbWriter,
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
        let json = r#"{"id":"chatcmpl-abc","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":30}}"#;
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
            api_key: "upstream-key".to_string(),
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

        let response = reqwest::Client::new()
            .post(format!("{router_url}/v1/chat/completions"))
            .header("x-kyris-session-id", "sess-123")
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
        assert_eq!(state.circuit_breaker.get_token_count("sess-123"), 300);

        let request = recorded.lock().unwrap().clone().unwrap();
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer upstream-key")
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
            api_key: "upstream-key".to_string(),
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
            api_key: "key".to_string(),
            upstream: upstream_url.clone(),
            models: vec!["gpt-4o".to_string()],
            timeout_seconds: 30,
            streaming_timeout_seconds: 300,
        }];
        config.circuit_breaker.max_tokens = 200;

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
        assert_eq!(state.circuit_breaker.get_token_count("__default"), 300);
        assert!(state.circuit_breaker.is_tripped("__default"));

        let response2 = reqwest::Client::new()
            .post(format!("{router_url}/v1/chat/completions"))
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
            cost_calculator: CostCalculator::new(),
            stats_tx,
            db,
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

    #[test]
    fn testInjectResponsesStreamUsage() {
        let mut body = serde_json::json!({"model": "gpt-4o", "input": "hello"});
        inject_responses_stream_usage(&mut body);
        let include = body["include"].as_array().unwrap();
        assert!(include.iter().any(|v| v.as_str() == Some("usage")));
    }

    #[test]
    fn testInjectResponsesStreamUsagePreservesExisting() {
        let mut body = serde_json::json!({"model": "gpt-4o", "include": ["usage", "reasoning"]});
        inject_responses_stream_usage(&mut body);
        let include = body["include"].as_array().unwrap();
        assert_eq!(include.len(), 2);
        assert!(include.iter().any(|v| v.as_str() == Some("usage")));
        assert!(include.iter().any(|v| v.as_str() == Some("reasoning")));
    }

    #[test]
    fn testInjectResponsesStreamUsageAppendsToExistingArray() {
        let mut body = serde_json::json!({"model": "gpt-4o", "include": ["reasoning"]});
        inject_responses_stream_usage(&mut body);
        let include = body["include"].as_array().unwrap();
        assert_eq!(include.len(), 2);
        assert!(include.iter().any(|v| v.as_str() == Some("usage")));
        assert!(include.iter().any(|v| v.as_str() == Some("reasoning")));
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
            api_key: "upstream-key".to_string(),
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

        let response = reqwest::Client::new()
            .post(format!("{router_url}/v1/responses"))
            .header("x-kyris-session-id", "sess-resp-1")
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
        assert_eq!(state.circuit_breaker.get_token_count("sess-resp-1"), 230);

        let request = recorded.lock().unwrap().clone().unwrap();
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer upstream-key")
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
            api_key: "upstream-key".to_string(),
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
            "input": "hello"
        });

        let response = reqwest::Client::new()
            .post(format!("{router_url}/v1/responses"))
            .header("x-kyris-session-id", "sess-resp-stream")
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
        let include = forwarded_json["include"].as_array().unwrap();
        assert!(include.iter().any(|v| v.as_str() == Some("usage")));

        let event = tokio::time::timeout(Duration::from_secs(5), stats_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.provider, "openai");
        assert_eq!(event.model, "gpt-4o");
        assert_eq!(event.tokens.input, 100);
        assert_eq!(event.tokens.output, 50);
        assert_eq!(event.session_id.as_deref(), Some("sess-resp-stream"));
        assert_eq!(
            state.circuit_breaker.get_token_count("sess-resp-stream"),
            150
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
}
