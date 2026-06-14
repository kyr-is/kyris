// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, RawQuery, State},
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
    Router::new()
        .route(
            "/v1beta/models/{model_action}",
            post(handle_model_action).with_state(state),
        )
        // Run handlers to completion even if the client disconnects — the
        // gateway record must not depend on the downstream connection's fate.
        .layer(super::RunToCompletionLayer)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GoogleAction {
    GenerateContent,
    StreamGenerateContent,
}

async fn handle_model_action(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    trace_id_ext: Option<axum::Extension<crate::trace_id::TraceId>>,
    headers: HeaderMap,
    Path(model_action): Path<String>,
    RawQuery(raw_query): RawQuery,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let Some((model, action)) = parse_model_action(&model_action) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let trace_id = trace_id_ext.map_or_else(
        || uuid::Uuid::now_v7().to_string(),
        |axum::Extension(t)| t.as_str().to_string(),
    );
    // Pure passthrough: kyrisd holds no provider credential. The caller's key
    // arrives either as the `x-goog-api-key` header or the `?key=` query param;
    // we forward whichever is present, and fail fast if neither is.
    let caller_key = caller_api_key(&headers, raw_query.as_deref());
    match action {
        GoogleAction::GenerateContent => {
            handle_generate_content(state, headers, model, peer_addr, body, trace_id, caller_key)
                .await
        }
        GoogleAction::StreamGenerateContent => {
            handle_stream_generate_content(
                state, headers, model, peer_addr, body, trace_id, caller_key,
            )
            .await
        }
    }
}

/// Extract the caller's Google API key: prefer the `x-goog-api-key` header,
/// otherwise the `key` query parameter. Returns `None` if neither is present
/// (or present but empty), which triggers a fail-fast response.
fn caller_api_key(headers: &HeaderMap, raw_query: Option<&str>) -> Option<String> {
    if let Some(v) = headers
        .get("x-goog-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Some(v.to_string());
    }
    let query = raw_query?;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("key=")
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

/// Which side of the request the forwarded key came from, for diagnostic tracing
/// on an upstream rejection. Mirrors [`caller_api_key`]'s precedence (header
/// first), so it names the source that was actually used.
fn caller_key_source(headers: &HeaderMap) -> &'static str {
    if headers.contains_key("x-goog-api-key") {
        "header:x-goog-api-key"
    } else {
        "query:key"
    }
}

/// A non-reversible fingerprint of a credential for diagnostic logs: its length
/// plus the first/last 4 characters. NEVER logs the full secret — enough to tell
/// "the right key, intact" from "empty / truncated / a different key" when an
/// upstream rejects it, without leaking the credential into the log.
fn credential_fingerprint(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return format!("len={n} <too-short-to-fingerprint>");
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("len={n} {head}…{tail}")
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
    trace_id: String,
    caller_key: Option<String>,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);

    super::record_agent_traffic(agent_id.as_deref(), trace_token.as_deref());

    // Resolve attribution now, while the peer socket still maps to a live
    // process — the record is written at handler end, by which time the agent
    // may have disconnected and exited, and a record without `working_dir`
    // never becomes sync-eligible.
    let (working_dir, peer_agent) = if let Some(token) = trace_token.as_deref() {
        (
            super::relay_trace_attach(&state, token, &trace_id).await,
            None,
        )
    } else {
        let attr = super::resolve_peer_attribution(&state, peer_addr, agent_id.is_none()).await;
        (attr.working_dir, attr.agent)
    };
    let agent = agent_id.or(peer_agent);

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::Google)
        .cloned()
        .unwrap_or_else(|| {
            // Fresh-install passthrough: no `providers[]` configured -> route to
            // the canonical Google upstream.
            kyris_core::config::ProviderConfig::default_for(ProviderFormat::Google)
        });
    let provider_name = provider.name.clone();

    // Pure passthrough: forward the caller's key or fail fast.
    let Some(caller_key) = caller_key else {
        return Ok(no_credential_error(&trace_id));
    };

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone());
    let upstream_url = format!(
        "{}/v1beta/models/{}:generateContent?key={}",
        provider.upstream, model, caller_key
    );

    // Runaway gate (see openai::handle_completions): hold a tripped session's
    // request on a human "continue or stop?" decision instead of sending.
    // generateContent is non-streaming, so a true 429 on Stop is fine.
    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        match super::await_token_gate(state.clone(), session_id.clone(), agent.clone(), count).await
        {
            super::GateDecision::Stop => return Ok(circuit_breaker_error(&trace_id, count)),
            super::GateDecision::Continue => {}
        }
    }

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
    let resp_body = response.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read Google generateContent upstream response body");
        StatusCode::BAD_GATEWAY
    })?;
    // Diagnostic: on an upstream rejection, record HOW the credential was
    // presented (source + redacted fingerprint) alongside the upstream status
    // and error body. This is the evidence that distinguishes a kyrisd
    // forwarding defect (empty/truncated/wrong key) from a genuine upstream 4xx
    // (the right key, intact, rejected by Google). Never logs the full key.
    if !status.is_success() {
        tracing::warn!(
            trace_id = %trace_id,
            provider = "google",
            method = "generateContent",
            model = %model,
            upstream_status = status.as_u16(),
            key_source = caller_key_source(&headers),
            key_fp = %credential_fingerprint(&caller_key),
            upstream_body = %String::from_utf8_lossy(&resp_body).chars().take(300).collect::<String>(),
            "google upstream returned non-2xx — forwarded credential shown by source + redacted fingerprint"
        );
    }
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

    let had_tool_call = google_body_has_tool_call(&resp_body);
    let breaker_crossed = {
        let config = state.config.load();
        if config.circuit_breaker.enabled {
            let max = config.circuit_breaker.max_tokens as i64;
            state
                .circuit_breaker
                .record(&session_id, tokens.output, had_tool_call, max)
        } else {
            false
        }
    };

    if state
        .stats_tx
        .try_send(StatsEvent {
            trace_id: trace_id.clone(),
            provider: provider_name,
            model: model.clone(),
            tokens,
            cache_create: 0,
            cache_read: 0,
            cost,
            latency_ms,
            status: if !status.is_success() {
                "error".to_string()
            } else if breaker_crossed {
                "circuit_breaker".to_string()
            } else {
                "success".to_string()
            },
            session_id: Some(session_id.clone()),
            mcp_server: None,
            mcp_tool: None,
            metering,
            plan_status: kyris_core::record::PlanStatus::Overage,
            working_dir,
            agent,
        })
        .is_err()
    {
        crate::storage::record_dropped(1);
    }

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", &trace_id)
        .body(Body::from(resp_body))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build Google generateContent response");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn handle_stream_generate_content(
    state: Arc<AppState>,
    headers: HeaderMap,
    model: String,
    peer_addr: SocketAddr,
    body: Bytes,
    trace_id: String,
    caller_key: Option<String>,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);

    super::record_agent_traffic(agent_id.as_deref(), trace_token.as_deref());

    // Resolve attribution now, while the peer socket still maps to a live
    // process — the record is written at stream end, by which time the agent
    // may have disconnected and exited, and a record without `working_dir`
    // never becomes sync-eligible.
    let (working_dir, peer_agent) = if let Some(token) = trace_token.as_deref() {
        (
            super::relay_trace_attach(&state, token, &trace_id).await,
            None,
        )
    } else {
        let attr = super::resolve_peer_attribution(&state, peer_addr, agent_id.is_none()).await;
        (attr.working_dir, attr.agent)
    };
    let agent = agent_id.or(peer_agent);

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::Google)
        .cloned()
        .unwrap_or_else(|| {
            // Fresh-install passthrough: no `providers[]` configured -> route to
            // the canonical Google upstream.
            kyris_core::config::ProviderConfig::default_for(ProviderFormat::Google)
        });
    let provider_name = provider.name.clone();

    // Pure passthrough: forward the caller's key or fail fast.
    let Some(caller_key) = caller_key else {
        return Ok(no_credential_error(&trace_id));
    };

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone());
    let upstream_url = format!(
        "{}/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
        provider.upstream, model, caller_key
    );

    let req_builder = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(
            provider.streaming_timeout_seconds,
        ))
        .header("content-type", "application/json")
        .body(body.to_vec());

    // Runaway gate (see openai::handle_completions): hold a tripped session's
    // request on a human "continue or stop?" decision instead of sending.
    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        return Ok(super::gated_streaming_response(
            state.clone(),
            session_id.clone(),
            agent.clone(),
            count,
            trace_id.clone(),
            google_stop_chunk(count),
            move || {
                Box::pin(async move {
                    let response = req_builder.send().await.map_err(|e| {
                        tracing::error!(error = %e, "upstream request failed (after continue)");
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
                        working_dir,
                        agent,
                        start,
                    )
                })
            },
        ));
    }

    let response = req_builder.send().await.map_err(|e| {
        tracing::error!(error = %e, "upstream request failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();
    // Same upstream-rejection diagnostic as the non-streaming path. The error
    // body is consumed downstream by the stream relay, so we log source + status
    // + redacted key fingerprint here (enough to tell a forwarding defect from a
    // genuine upstream 4xx); never logs the full key.
    if !status.is_success() {
        tracing::warn!(
            trace_id = %trace_id,
            provider = "google",
            method = "streamGenerateContent",
            model = %model,
            upstream_status = status.as_u16(),
            key_source = caller_key_source(&headers),
            key_fp = %credential_fingerprint(&caller_key),
            "google streaming upstream returned non-2xx — forwarded credential shown by source + redacted fingerprint"
        );
    }

    relay_ndjson_stream(
        state,
        response,
        status,
        resp_headers,
        trace_id,
        model,
        provider_name,
        session_id,
        working_dir,
        agent,
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
    working_dir: Option<String>,
    agent: Option<String>,
    start: std::time::Instant,
) -> Result<Response, StatusCode> {
    let accumulated = Arc::new(std::sync::Mutex::new(TokenCounts::default()));
    let line_buf = Arc::new(std::sync::Mutex::new(String::new()));
    // Whether any response in this stream emitted a `functionCall` part (resets
    // the runaway counter; only no-tool output accumulates toward the cap).
    let had_tool_call = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let relay = {
        let accumulated = accumulated.clone();
        let line_buf = line_buf.clone();
        let had_tool_call = had_tool_call.clone();

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
                            if google_json_has_tool_call(json_str) {
                                had_tool_call.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        *buf = remainder.to_string();
                    }
                    Ok::<Bytes, reqwest::Error>(chunk)
                }
                Err(e) => Err(e),
            })
    };

    let mut relay = Box::pin(relay);
    // The finalize owns (clones of) everything the record needs so it can run
    // from the guard's Drop as well as from the poll path — a client that
    // disconnects before end-of-stream must still produce a gateway record
    // (see `StreamRecordGuard`).
    let finalize_stream = {
        let accumulated = accumulated.clone();
        let line_buf = line_buf.clone();
        let had_tool_call = had_tool_call.clone();
        let state = state.clone();
        let trace_id = trace_id.clone();
        let model = model.clone();
        let session_id = session_id.clone();
        move |_emit_breaker_chunk: bool| {
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
                    if google_json_has_tool_call(json_str) {
                        had_tool_call.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            let tokens = accumulated.lock().expect("lock accumulated").clone();
            let latency_ms = start.elapsed().as_millis() as i64;
            let cost =
                state
                    .cost_calculator
                    .calculate(&model, tokens.input, tokens.output, None, None);

            let tool = had_tool_call.load(std::sync::atomic::Ordering::Relaxed);
            let crossed = {
                let config = state.config.load();
                if config.circuit_breaker.enabled {
                    let max = config.circuit_breaker.max_tokens as i64;
                    state
                        .circuit_breaker
                        .record(&session_id, tokens.output, tool, max)
                } else {
                    false
                }
            };

            let stream_metering = if tokens.input == 0 && tokens.output == 0 {
                kyris_core::record::Metering::Unavailable
            } else {
                kyris_core::record::Metering::Available
            };

            if state
                .stats_tx
                .try_send(StatsEvent {
                    trace_id: trace_id.clone(),
                    provider: provider_name.clone(),
                    model: model.clone(),
                    tokens,
                    cache_create: 0,
                    cache_read: 0,
                    cost,
                    latency_ms,
                    status: if crossed {
                        "circuit_breaker"
                    } else {
                        "success"
                    }
                    .to_string(),
                    session_id: Some(session_id.clone()),
                    mcp_server: None,
                    mcp_tool: None,
                    metering: stream_metering,
                    plan_status: kyris_core::record::PlanStatus::Overage,
                    working_dir: working_dir.clone(),
                    agent: agent.clone(),
                })
                .is_err()
            {
                crate::storage::record_dropped(1);
            }

            None
        }
    };
    let mut record_guard = super::StreamRecordGuard::new(finalize_stream);
    let full_stream = futures_util::stream::poll_fn(move |cx| {
        use std::task::Poll;

        if record_guard.is_done() {
            return Poll::Ready(None);
        }

        match futures_util::Stream::poll_next(relay.as_mut(), cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(chunk)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                record_guard.finalize(false);
                Poll::Ready(None)
            }
        }
    });

    let mut builder =
        super::relay_upstream_headers(Response::builder().status(status), &resp_headers);
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder
        .body(Body::from_stream(full_stream))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build Google streamGenerateContent SSE stream response");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

fn circuit_breaker_message(token_count: i64) -> String {
    format!(
        "Circuit breaker: {token_count} tokens generated without a tool call. The human chose to stop; run 'kyris continue' to resume."
    )
}

/// The SSE "stop" event for a Google stream gated then stopped by the human. A
/// true 429 is impossible once a 200 SSE response has begun, so the agent is
/// halted with an in-stream error event (`alt=sse`, so `data:`-framed).
fn google_stop_chunk(token_count: i64) -> Bytes {
    let payload = serde_json::json!({
        "error": {
            "code": 429,
            "message": circuit_breaker_message(token_count),
            "status": "RESOURCE_EXHAUSTED"
        }
    });
    Bytes::from(format!("data: {payload}\n\n"))
}

/// Whether a Gemini `GenerateContentResponse` value contains a `functionCall`
/// part — the model invoked a tool, so the runaway counter resets (see
/// [`crate::circuit_breaker`]).
fn google_value_has_tool_call(v: &serde_json::Value) -> bool {
    v.get("candidates")
        .and_then(|c| c.as_array())
        .is_some_and(|cands| {
            cands.iter().any(|c| {
                c.get("content")
                    .and_then(|content| content.get("parts"))
                    .and_then(|parts| parts.as_array())
                    .is_some_and(|parts| {
                        parts
                            .iter()
                            .any(|p| p.get("functionCall").is_some_and(|f| !f.is_null()))
                    })
            })
        })
}

fn google_body_has_tool_call(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| google_value_has_tool_call(&v))
}

fn google_json_has_tool_call(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json).is_ok_and(|v| google_value_has_tool_call(&v))
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

/// Fail-fast response (401) when the caller supplied no Google API key (neither
/// `x-goog-api-key` header nor `?key=` query). kyrisd is a pure passthrough —
/// it forwards the caller's credential and stores none.
fn no_credential_error(trace_id: &str) -> Response {
    let payload = serde_json::json!({
        "error": "no provider credential supplied; kyrisd forwards your agent's credential and stores none"
    });

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(payload.to_string()))
        .expect("build no-credential error response")
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
}
