// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use bytes::Bytes;
use futures_util::StreamExt;

use kyris_core::config::ProviderFormat;
use kyris_core::record::PlanStatus;

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
        // Run handlers to completion even if the client disconnects — the
        // gateway record must not depend on the downstream connection's fate.
        .layer(super::RunToCompletionLayer)
}

/// Classify the cost-coverage of a request from the agent's inbound credential.
/// A subscription OAuth credential (Anthropic `sk-ant-oat…` bearer, or an
/// `oauth-` beta) is plan-covered (Included); anything else is billed (Overage).
fn anthropic_plan_status(headers: &HeaderMap) -> PlanStatus {
    let beta = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let authz = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if beta.contains("oauth") || authz.contains("sk-ant-oat") {
        PlanStatus::Included
    } else {
        PlanStatus::Overage
    }
}

async fn handle_messages(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    trace_id_ext: Option<axum::Extension<crate::trace_id::TraceId>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let body_value: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!(error = %e, "failed to parse Anthropic messages request body");
        StatusCode::BAD_REQUEST
    })?;

    let model = body_value
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let is_stream = body_value
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    // Unified trace_id: prefer the one stamped by the outer
    // trace_id_middleware (production path) so this id matches what
    // request_log_middleware logs, what we echo as x-kyris-trace-id,
    // and what the gateway record stores. Mint a fresh one only for
    // direct-handler unit tests that bypass the middleware.
    let trace_id = trace_id_ext.map_or_else(
        || uuid::Uuid::now_v7().to_string(),
        |axum::Extension(t)| t.as_str().to_string(),
    );
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);

    super::record_agent_traffic(agent_id.as_deref(), trace_token.as_deref());

    // Resolve attribution now, while the peer socket still maps to a live
    // process — the record is written at stream/handler end, by which time the
    // agent may have disconnected and exited, and a record without
    // `working_dir` never becomes sync-eligible.
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
        .find(|p| p.format == ProviderFormat::Anthropic)
        .cloned()
        .unwrap_or_else(|| {
            // Fresh-install passthrough: no `providers[]` configured -> route to
            // the canonical Anthropic upstream with an empty fallback key. The
            // agent's own credential (OAuth or API key) is what gets forwarded.
            kyris_core::config::ProviderConfig::default_for(ProviderFormat::Anthropic)
        });
    let provider_name = provider.name.clone();

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone());
    let upstream_url = match raw_query.as_deref() {
        Some(q) if !q.is_empty() => format!("{}/v1/messages?{q}", provider.upstream),
        _ => format!("{}/v1/messages", provider.upstream),
    };

    let timeout_secs = if is_stream {
        provider.streaming_timeout_seconds
    } else {
        provider.timeout_seconds
    };

    // kyrisd is a pure passthrough: it forwards the caller's own credential
    // (subscription OAuth or its own API key) and holds none of its own. If the
    // caller sent neither `authorization` nor `x-api-key`, fail fast — there is
    // nothing to forward. The cost class follows the auth mode (OAuth ->
    // Included, else Overage).
    let plan_status = anthropic_plan_status(&headers);
    if !headers.contains_key("authorization") && !headers.contains_key("x-api-key") {
        return Ok(no_credential_response(&trace_id));
    }

    // Spine event 1/3: provider selection. Answers "did we route to the
    // right upstream?" without anyone having to instrument that decision
    // point by hand. kyrisd always forwards the caller's credential.
    tracing::debug!(
        provider = %provider_name,
        upstream = %provider.upstream,
        model = %model,
        is_stream,
        credential_mode = "passthrough",
        plan_status = ?plan_status,
        "provider_selected"
    );

    let mut req = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(body.to_vec());

    if let Some(v) = headers.get("authorization") {
        req = req.header("authorization", v);
    }
    if let Some(v) = headers.get("x-api-key") {
        req = req.header("x-api-key", v);
    }

    for (key, value) in &headers {
        let name = key.as_str().to_lowercase();
        if (name.starts_with("anthropic-") && name != "anthropic-version") || name == "user-agent" {
            req = req.header(key, value);
        }
    }

    // Runaway gate (see openai::handle_completions): hold a tripped session's
    // request on a human "continue or stop?" decision instead of sending.
    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        if is_stream {
            return Ok(super::gated_streaming_response(
                state.clone(),
                session_id.clone(),
                agent.clone(),
                count,
                trace_id.clone(),
                anthropic_stop_chunk(count),
                move || {
                    Box::pin(async move {
                        let response = req.send().await.map_err(|e| {
                            tracing::error!(error = %e, "upstream_request_failed (after continue)");
                            StatusCode::BAD_GATEWAY
                        })?;
                        let status = response.status();
                        let resp_headers = response.headers().clone();
                        relay_sse_stream(
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
                            plan_status,
                        )
                    })
                },
            ));
        }
        match super::await_token_gate(state.clone(), session_id.clone(), agent.clone(), count).await
        {
            super::GateDecision::Stop => return Ok(circuit_breaker_response(&trace_id, count)),
            super::GateDecision::Continue => {}
        }
    }

    let response = req.send().await.map_err(|e| {
        tracing::error!(
            upstream = %provider.upstream,
            error = %e,
            "upstream_request_failed"
        );
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    // Spine event 2/3: upstream framing. The five fields below are
    // exactly what a "why did this response not reach the client?"
    // investigation needs — they pin the framing-conflict failure
    // mode (e.g. `transfer-encoding: chunked` from the upstream
    // copied verbatim onto our own collected-Bytes body) to a
    // single log line instead of requiring a packet capture.
    tracing::debug!(
        upstream_status = status.as_u16(),
        content_length = ?resp_headers.get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        content_encoding = ?resp_headers.get(axum::http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        transfer_encoding = ?resp_headers.get(axum::http::header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok()),
        content_type = ?resp_headers.get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        is_stream,
        "upstream_response"
    );

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
            working_dir,
            agent,
            start,
            plan_status,
        );
    }

    let resp_body = response.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read Anthropic messages upstream response body");
        StatusCode::BAD_GATEWAY
    })?;
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

    let had_tool_call = anthropic_body_has_tool_call(&resp_body);
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
            cache_create: cache_creation,
            cache_read,
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
            plan_status,
            working_dir,
            agent,
        })
        .is_err()
    {
        crate::storage::record_dropped(1);
    }

    let mut builder =
        super::relay_upstream_headers(Response::builder().status(status), &resp_headers);
    builder = builder.header("x-kyris-trace-id", &trace_id);

    // Spine event 3/3: response we're about to hand hyper. Header
    // names (not values — values can carry secrets) + body byte
    // count make the framing situation observable: if upstream sent
    // `transfer-encoding: chunked` and we're emitting a fixed-size
    // body, both names appear here AND the response_framing_check
    // middleware will ERROR with the exact reason.
    let response_body_bytes = resp_body.len();
    let header_names: Vec<&str> = resp_headers
        .keys()
        .map(axum::http::HeaderName::as_str)
        .collect();
    tracing::debug!(
        response_status = status.as_u16(),
        response_body_bytes,
        header_names = ?header_names,
        "response_built"
    );

    builder.body(Body::from(resp_body)).map_err(|e| {
        tracing::error!(error = %e, "failed to build Anthropic messages response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
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
    working_dir: Option<String>,
    agent: Option<String>,
    start: std::time::Instant,
    plan_status: PlanStatus,
) -> Result<Response, StatusCode> {
    let accumulated = Arc::new(std::sync::Mutex::new(StreamTokenCounts::default()));
    let line_buf = Arc::new(std::sync::Mutex::new(String::new()));
    // Whether any response in this stream emitted a `tool_use` block (resets the
    // runaway counter; only no-tool output accumulates toward the cap).
    let had_tool_call = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Build the relay stream that forwards chunks and extracts tokens
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
                        let (lines, remainder) = streaming::split_sse_lines(&snapshot);
                        for line in &lines {
                            if let Some(json) = streaming::parse_sse_line(line) {
                                if let Some(delta) = extract_tokens_from_sse_json(json) {
                                    accumulated
                                        .lock()
                                        .expect("lock accumulated")
                                        .accumulate(&delta);
                                }
                                if anthropic_sse_has_tool_call(json) {
                                    had_tool_call.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
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
                    if let Some(json) = streaming::parse_sse_line(line) {
                        if let Some(delta) = extract_tokens_from_sse_json(json) {
                            acc.accumulate(&delta);
                        }
                        if anthropic_sse_has_tool_call(json) {
                            had_tool_call.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
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
                    cache_create: stream_tokens.cache_creation_input,
                    cache_read: stream_tokens.cache_read_input,
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
                    plan_status,
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

    builder.body(Body::from_stream(full_stream)).map_err(|e| {
        tracing::error!(error = %e, "failed to build Anthropic messages SSE stream response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
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
        .find(|p| p.format == ProviderFormat::Anthropic)
        .cloned()
        .unwrap_or_else(|| {
            // Fresh-install passthrough: no `providers[]` configured -> route to
            // the canonical Anthropic upstream. The agent's own credential
            // (OAuth or API key) is what gets forwarded.
            kyris_core::config::ProviderConfig::default_for(ProviderFormat::Anthropic)
        });

    // Pure passthrough: forward the caller's credential or fail fast.
    if !headers.contains_key("authorization") && !headers.contains_key("x-api-key") {
        return Ok(no_credential_response(&uuid::Uuid::now_v7().to_string()));
    }

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider.name)
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone());
    let upstream_url = format!("{}/v1/messages/count_tokens", provider.upstream);

    let mut req = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(provider.timeout_seconds))
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(body.to_vec());

    if let Some(v) = headers.get("authorization") {
        req = req.header("authorization", v);
    }
    if let Some(v) = headers.get("x-api-key") {
        req = req.header("x-api-key", v);
    }

    for (key, value) in &headers {
        let name = key.as_str().to_lowercase();
        if (name.starts_with("anthropic-") && name != "anthropic-version") || name == "user-agent" {
            req = req.header(key, value);
        }
    }

    let response = req.send().await.map_err(|e| {
        tracing::error!(error = %e, "count_tokens upstream failed");
        StatusCode::BAD_GATEWAY
    })?;

    let status = response.status();
    let resp_body = response.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read Anthropic count_tokens upstream response body");
        StatusCode::BAD_GATEWAY
    })?;

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(resp_body))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build Anthropic count_tokens response");
            StatusCode::INTERNAL_SERVER_ERROR
        })
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
        "Circuit breaker: {token_count} tokens generated without a tool call. The run was stopped — resume from the Kyris dialog, tray, or app."
    )
}

/// The SSE "stop" event for an Anthropic stream gated then stopped by the
/// human. A true 429 is impossible once a 200 SSE response has begun, so the
/// agent is halted with an in-stream `error` event.
fn anthropic_stop_chunk(token_count: i64) -> Bytes {
    let payload = serde_json::json!({
        "type": "error",
        "error": {
            "type": "circuit_breaker",
            "message": circuit_breaker_message(token_count),
        }
    });
    Bytes::from(format!("event: error\ndata: {payload}\n\n"))
}

/// Whether a Messages response object contains a `tool_use` content block (or a
/// `stop_reason` of `tool_use`) — the agent took an action, so the runaway
/// counter resets (see [`crate::circuit_breaker`]).
fn anthropic_body_has_tool_call(body: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    if v.get("stop_reason").and_then(|s| s.as_str()) == Some("tool_use") {
        return true;
    }
    v.get("content")
        .and_then(|c| c.as_array())
        .is_some_and(|blocks| {
            blocks
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
        })
}

/// Tool-call detection for a single Messages SSE event: a `content_block_start`
/// whose block is a `tool_use`, or a `message_delta` reporting
/// `stop_reason: tool_use`.
fn anthropic_sse_has_tool_call(json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    if v.get("content_block")
        .and_then(|b| b.get("type"))
        .and_then(|t| t.as_str())
        == Some("tool_use")
    {
        return true;
    }
    v.get("delta")
        .and_then(|d| d.get("stop_reason"))
        .and_then(|s| s.as_str())
        == Some("tool_use")
}

/// Pre-request circuit breaker response (429). Used for both streaming and
/// non-streaming requests: the SSE connection has not been established yet,
/// so a plain HTTP 429 is the correct response regardless of stream mode.
/// Mid-stream circuit breaker injection (once SSE is active) remains 200.
fn circuit_breaker_response(trace_id: &str, token_count: i64) -> Response {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(
            serde_json::json!({
                "type": "error",
                "error": {
                    "type": "circuit_breaker",
                    "message": circuit_breaker_message(token_count),
                },
            })
            .to_string(),
        ))
        .expect("build circuit breaker response")
}

/// Fail-fast response (401) when the caller supplied no provider credential.
/// kyrisd is a pure passthrough — it forwards the caller's credential and
/// stores none — so there is nothing to send upstream.
fn no_credential_response(trace_id: &str) -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .header("x-kyris-trace-id", trace_id)
        .body(Body::from(
            serde_json::json!({
                "error": "no provider credential supplied; kyrisd forwards your agent's credential and stores none"
            })
            .to_string(),
        ))
        .expect("build no-credential response")
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
}
