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

/// `ChatGPT` subscription (login) tokens are only valid at `OpenAI`'s `ChatGPT` codex
/// backend — NOT api.openai.com, which rejects them ("missing scopes:
/// api.responses.write"). codex signals subscription auth by attaching a
/// `ChatGPT-Account-ID` header (api-key auth omits it) and natively sends such
/// requests to this base URL; kyrisd mirrors that choice. (api.openai.com is the
/// default for api-key auth — see `ProviderConfig::default_for`.)
const CHATGPT_CODEX_UPSTREAM: &str = "https://chatgpt.com/backend-api/codex";

/// Pick the Responses upstream from the caller's credential type. A `ChatGPT`
/// subscription login (signalled by `ChatGPT-Account-ID`) routes to the `ChatGPT`
/// codex backend at `/responses`; an API key routes to `{upstream}/v1/responses`.
fn responses_upstream_url(
    provider: &kyris_core::config::ProviderConfig,
    headers: &HeaderMap,
) -> String {
    if headers.contains_key("chatgpt-account-id") {
        format!("{CHATGPT_CODEX_UPSTREAM}/responses")
    } else {
        format!("{}/v1/responses", provider.upstream)
    }
}

/// Classify the cost-coverage of a request from the caller's credential type —
/// the `OpenAI` twin of `anthropic_plan_status`. A `ChatGPT` subscription login
/// attaches `ChatGPT-Account-ID` (the same signal `responses_upstream_url`
/// trusts to pick the subscription backend); API-key auth omits it.
/// Subscription → `Included` (plan-covered), API key → `Overage` (billed).
fn openai_plan_status(headers: &HeaderMap) -> kyris_core::record::PlanStatus {
    if headers.contains_key("chatgpt-account-id") {
        kyris_core::record::PlanStatus::Included
    } else {
        kyris_core::record::PlanStatus::Overage
    }
}

/// Whether a caller request header should be forwarded upstream. kyrisd must NOT
/// leak its own routing headers (`x-kyris-*`, the inbound key above all) and must
/// let the HTTP client recompute framing/length headers. Everything else the
/// caller sent — authorization, content-type, `ChatGPT-Account-ID`, `OpenAI-Beta`,
/// the `x-codex-*` session/turn headers — is forwarded so the upstream sees a
/// faithful request (the `ChatGPT` backend in particular requires these).
fn is_forwardable_request_header(name: &str) -> bool {
    !name.starts_with("x-kyris-")
        && !matches!(
            name,
            "host"
                | "content-length"
                | "accept-encoding"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-authorization"
                | "proxy-authenticate"
        )
}

pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/chat/completions",
            post(handle_completions).with_state(state.clone()),
        )
        .route("/v1/responses", post(handle_responses).with_state(state))
        // Run handlers to completion even if the client disconnects — the
        // gateway record must not depend on the downstream connection's fate.
        .layer(super::RunToCompletionLayer)
}

async fn handle_completions(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    trace_id_ext: Option<axum::Extension<crate::trace_id::TraceId>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let mut body_value: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!(error = %e, "failed to parse OpenAI chat completions request body");
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

    let trace_id = trace_id_ext.map_or_else(
        || uuid::Uuid::now_v7().to_string(),
        |axum::Extension(t)| t.as_str().to_string(),
    );
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);
    // Cost-coverage from the caller's credential type (ChatGPT subscription →
    // Included, API key → Overage).
    let plan_status = openai_plan_status(&headers);

    super::record_agent_traffic(agent_id.as_deref(), trace_token.as_deref());

    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        crate::notify::circuit_breaker_toast(count);
        return Ok(circuit_breaker_error(&trace_id, count));
    }

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

    if is_stream {
        inject_stream_usage(&mut body_value);
    }

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::OpenAI)
        .cloned()
        .unwrap_or_else(|| {
            // Fresh-install passthrough: no `providers[]` configured -> route to
            // the canonical OpenAI upstream.
            kyris_core::config::ProviderConfig::default_for(ProviderFormat::OpenAI)
        });
    let provider_name = provider.name.clone();

    // Pure passthrough: forward the caller's `authorization` header or fail
    // fast. kyrisd holds no provider credential of its own.
    let Some(authorization) = headers.get("authorization").cloned() else {
        return Ok(no_credential_error(&trace_id));
    };

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone());
    let upstream_url = format!("{}/v1/chat/completions", provider.upstream);

    let outbound_body = serde_json::to_vec(&body_value).map_err(|e| {
        tracing::warn!(error = %e, "failed to serialize OpenAI chat completions outbound body");
        StatusCode::BAD_REQUEST
    })?;

    let timeout_secs = if is_stream {
        provider.streaming_timeout_seconds
    } else {
        provider.timeout_seconds
    };

    // Spine event 1/3: provider selection. kyrisd always forwards the
    // caller's `authorization` credential.
    tracing::debug!(
        provider = %provider_name,
        upstream = %provider.upstream,
        model = %model,
        is_stream,
        credential_mode = "passthrough",
        "provider_selected"
    );

    let response = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .header("authorization", &authorization)
        .header("content-type", "application/json")
        .body(outbound_body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                upstream = %provider.upstream,
                error = %e,
                "upstream_request_failed"
            );
            StatusCode::BAD_GATEWAY
        })?;

    let status = response.status();
    let resp_headers = response.headers().clone();
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
            plan_status,
            start,
        );
    }

    let resp_body = response
        .bytes()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to read OpenAI chat completions upstream response body");
            StatusCode::BAD_GATEWAY
        })?;

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

    let breaker_crossed = {
        let config = state.config.load();
        if config.circuit_breaker.enabled {
            let total = tokens.input + tokens.output;
            let max = config.circuit_breaker.max_tokens as i64;
            state
                .circuit_breaker
                .record_and_is_tripped(&session_id, total, max)
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
        tracing::error!(error = %e, "failed to build OpenAI chat completions response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

async fn handle_responses(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    trace_id_ext: Option<axum::Extension<crate::trace_id::TraceId>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();
    let body_value: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!(error = %e, "failed to parse OpenAI responses request body");
        StatusCode::BAD_REQUEST
    })?;

    let model = body_value
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // OpenAI's Responses API defaults `stream` to false; honor that. Defaulting
    // to streaming made a plain (non-stream) request take the SSE path.
    let is_stream = body_value
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let trace_id = trace_id_ext.map_or_else(
        || uuid::Uuid::now_v7().to_string(),
        |axum::Extension(t)| t.as_str().to_string(),
    );
    let session_id = super::extract_session_id(&headers);
    let trace_token = super::extract_trace_token(&headers);
    let agent_id = super::extract_agent_id(&headers);
    // Cost-coverage from the caller's credential type (ChatGPT subscription →
    // Included, API key → Overage) — the same header that picks the upstream.
    let plan_status = openai_plan_status(&headers);

    super::record_agent_traffic(agent_id.as_deref(), trace_token.as_deref());

    if state.config.load().circuit_breaker.enabled && state.circuit_breaker.is_tripped(&session_id)
    {
        let count = state.circuit_breaker.get_token_count(&session_id);
        crate::notify::circuit_breaker_toast(count);
        return Ok(circuit_breaker_error(&trace_id, count));
    }

    // Resolve attribution now, while the peer socket still maps to a live
    // process — the record is written at stream/handler end, by which time the
    // agent may have disconnected and exited (codex exec quits on
    // `response.completed`), and a record without `working_dir` never becomes
    // sync-eligible.
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

    // No body rewriting: the Responses API returns token usage natively (in the
    // response object / the streaming `response.completed` event), so kyrisd
    // forwards the request as-is. (The old `include: ["usage"]` injection is an
    // invalid `include` value the API rejects with 400.)

    let config = state.config.load();
    let provider = config
        .providers
        .iter()
        .find(|p| p.format == ProviderFormat::OpenAI)
        .cloned()
        .unwrap_or_else(|| {
            // Fresh-install passthrough: no `providers[]` configured -> route to
            // the canonical OpenAI upstream.
            kyris_core::config::ProviderConfig::default_for(ProviderFormat::OpenAI)
        });
    let provider_name = provider.name.clone();

    // Pure passthrough: the caller's `authorization` (their own credential) is
    // forwarded with the rest of their headers below. Fail fast if absent —
    // kyrisd holds no provider credential of its own.
    if !headers.contains_key("authorization") {
        return Ok(no_credential_error(&trace_id));
    }

    let clients = state.provider_clients.load();
    let client = clients
        .get(&provider_name)
        .cloned()
        .unwrap_or_else(|| state.default_provider_client.clone());
    // Route by credential type: a ChatGPT subscription login goes to the ChatGPT
    // codex backend, an API key to api.openai.com (see `responses_upstream_url`).
    let upstream_url = responses_upstream_url(&provider, &headers);

    let outbound_body = serde_json::to_vec(&body_value).map_err(|e| {
        tracing::warn!(error = %e, "failed to serialize OpenAI responses outbound body");
        StatusCode::BAD_REQUEST
    })?;

    let timeout_secs = if is_stream {
        provider.streaming_timeout_seconds
    } else {
        provider.timeout_seconds
    };

    let mut request = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .body(outbound_body);
    // Forward the caller's headers faithfully (codex's ChatGPT-Account-ID,
    // OpenAI-Beta, x-codex-* session/turn headers, content-type, authorization),
    // minus kyrisd's own x-kyris-* routing headers and framing/length headers.
    for (name, value) in &headers {
        if is_forwardable_request_header(name.as_str()) {
            request = request.header(name, value);
        }
    }
    let response = request.send().await.map_err(|e| {
        tracing::error!(error = %e, "OpenAI responses upstream request failed");
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
            working_dir,
            agent,
            plan_status,
            start,
        );
    }

    let resp_body = response.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "failed to read OpenAI responses upstream response body");
        StatusCode::BAD_GATEWAY
    })?;

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

    let breaker_crossed = {
        let config = state.config.load();
        if config.circuit_breaker.enabled {
            let total = tokens.input + tokens.output;
            let max = config.circuit_breaker.max_tokens as i64;
            state
                .circuit_breaker
                .record_and_is_tripped(&session_id, total, max)
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

    builder.body(Body::from(resp_body)).map_err(|e| {
        tracing::error!(error = %e, "failed to build OpenAI responses response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
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
    working_dir: Option<String>,
    agent: Option<String>,
    plan_status: kyris_core::record::PlanStatus,
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
    // The finalize owns (clones of) everything the record needs so it can run
    // from the guard's Drop as well as from the poll path — a client that
    // disconnects before end-of-stream must still produce a gateway record
    // (see `StreamRecordGuard`). `codex exec` exits the moment it sees
    // `response.completed`, so its last turn routinely races the final poll.
    let finalize_stream = {
        let accumulated = accumulated.clone();
        let line_buf = line_buf.clone();
        let breaker_tripped = breaker_tripped.clone();
        let state = state.clone();
        let trace_id = trace_id.clone();
        let model = model.clone();
        let session_id = session_id.clone();
        move |emit_breaker_chunk: bool| {
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
                    let already = breaker_tripped.load(std::sync::atomic::Ordering::Relaxed);
                    if state
                        .circuit_breaker
                        .record_and_is_tripped(&session_id, total, max)
                    {
                        status = "circuit_breaker";
                        // The mid-stream relay already injects the breaker chunk
                        // when the cap is crossed during the stream; only append
                        // one here on a natural end-of-stream crossing that
                        // wasn't already signalled.
                        if emit_breaker_chunk && !already {
                            let payload = serde_json::json!({
                                "error": {
                                    "message": "Circuit breaker: token limit exceeded. Run 'kyris continue' to resume.",
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("data: {payload}\n\n")));
                        }
                    }
                }
            }

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
                    status: status.to_string(),
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

            breaker_chunk
        }
    };
    let mut record_guard = super::StreamRecordGuard::new(finalize_stream);
    let full_stream = futures_util::stream::poll_fn(move |cx| {
        use std::task::Poll;

        if record_guard.is_done() {
            return Poll::Ready(None);
        }

        if breaker_tripped.load(std::sync::atomic::Ordering::Relaxed) {
            drop(relay.take());
            if let Some(chunk) = record_guard.finalize(false) {
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
                if let Some(chunk) = record_guard.finalize(true) {
                    Poll::Ready(Some(Ok(chunk)))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    });

    let mut builder =
        super::relay_upstream_headers(Response::builder().status(status), &resp_headers);
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder.body(Body::from_stream(full_stream)).map_err(|e| {
        tracing::error!(error = %e, "failed to build OpenAI responses SSE stream response");
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
    plan_status: kyris_core::record::PlanStatus,
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
    // The finalize owns (clones of) everything the record needs so it can run
    // from the guard's Drop as well as from the poll path — a client that
    // disconnects before end-of-stream must still produce a gateway record
    // (see `StreamRecordGuard`).
    let finalize_stream = {
        let accumulated = accumulated.clone();
        let line_buf = line_buf.clone();
        let breaker_tripped = breaker_tripped.clone();
        let state = state.clone();
        let trace_id = trace_id.clone();
        let model = model.clone();
        let session_id = session_id.clone();
        move |emit_breaker_chunk: bool| {
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
                    let already = breaker_tripped.load(std::sync::atomic::Ordering::Relaxed);
                    if state
                        .circuit_breaker
                        .record_and_is_tripped(&session_id, total, max)
                    {
                        status = "circuit_breaker";
                        // The mid-stream relay already injects the breaker chunk
                        // when the cap is crossed during the stream; only append
                        // one here on a natural end-of-stream crossing that
                        // wasn't already signalled.
                        if emit_breaker_chunk && !already {
                            let payload = serde_json::json!({
                                "error": {
                                    "message": "Circuit breaker: token limit exceeded. Run 'kyris continue' to resume.",
                                    "type": "circuit_breaker",
                                    "code": "circuit_breaker"
                                }
                            });
                            breaker_chunk = Some(Bytes::from(format!("data: {payload}\n\n")));
                        }
                    }
                }
            }

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
                    status: status.to_string(),
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

            breaker_chunk
        }
    };
    let mut record_guard = super::StreamRecordGuard::new(finalize_stream);
    let full_stream = futures_util::stream::poll_fn(move |cx| {
        use std::task::Poll;

        if record_guard.is_done() {
            return Poll::Ready(None);
        }

        if breaker_tripped.load(std::sync::atomic::Ordering::Relaxed) {
            drop(relay.take());
            if let Some(chunk) = record_guard.finalize(false) {
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
                if let Some(chunk) = record_guard.finalize(true) {
                    Poll::Ready(Some(Ok(chunk)))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    });

    let mut builder =
        super::relay_upstream_headers(Response::builder().status(status), &resp_headers);
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder.body(Body::from_stream(full_stream)).map_err(|e| {
        tracing::error!(error = %e, "failed to build OpenAI chat completions SSE stream response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
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

/// Fail-fast response (401) when the caller supplied no `authorization`
/// credential. kyrisd is a pure passthrough — it forwards the caller's
/// credential and stores none — so there is nothing to send upstream.
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
        assert_eq!(state.circuit_breaker.get_token_count("sess-123"), 300);
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
        assert_eq!(state.circuit_breaker.get_token_count("__default"), 300);
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
        assert_eq!(state.circuit_breaker.get_token_count("sess-resp-1"), 230);
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
}
