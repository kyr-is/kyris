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

    let req_builder = client
        .post(&upstream_url)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .header("authorization", &authorization)
        .header("content-type", "application/json")
        .body(outbound_body);

    // Runaway gate: if this session crossed the no-action token cap, hold the
    // request on a human "continue or stop?" decision rather than sending. On
    // Continue the breaker is reset and the request proceeds; on Stop the agent
    // is halted (a 429 for non-stream, an in-stream error for streaming).
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
                openai_stop_chunk(count),
                move || {
                    Box::pin(async move {
                        let response = req_builder.send().await.map_err(|e| {
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
                            plan_status,
                            start,
                        )
                    })
                },
            ));
        }
        match super::await_token_gate(state.clone(), session_id.clone(), agent.clone(), count).await
        {
            super::GateDecision::Stop => return Ok(circuit_breaker_error(&trace_id, count)),
            super::GateDecision::Continue => {}
        }
    }

    let response = req_builder.send().await.map_err(|e| {
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

    let had_tool_call = chat_body_has_tool_call(&resp_body);
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
    // Runaway gate (see handle_completions): hold a tripped session's request
    // on a human "continue or stop?" decision instead of sending.
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
                openai_stop_chunk(count),
                move || {
                    Box::pin(async move {
                        let response = request.send().await.map_err(|e| {
                            tracing::error!(error = %e, "OpenAI responses upstream request failed (after continue)");
                            StatusCode::BAD_GATEWAY
                        })?;
                        let status = response.status();
                        let resp_headers = response.headers().clone();
                        relay_responses_sse_stream(
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
                        )
                    })
                },
            ));
        }
        match super::await_token_gate(state.clone(), session_id.clone(), agent.clone(), count).await
        {
            super::GateDecision::Stop => return Ok(circuit_breaker_error(&trace_id, count)),
            super::GateDecision::Continue => {}
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

    let had_tool_call = responses_body_has_tool_call(&resp_body);
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

mod breaker;
mod stream;
mod usage;

use breaker::{
    chat_body_has_tool_call, chat_sse_has_tool_call, circuit_breaker_error, no_credential_error,
    openai_stop_chunk, responses_body_has_tool_call, responses_sse_has_tool_call,
};
use stream::{inject_stream_usage, relay_responses_sse_stream, relay_sse_stream};
use usage::{
    extract_responses_tokens_from_body, extract_responses_tokens_from_sse_json,
    extract_tokens_from_body, extract_tokens_from_sse_json,
};

#[cfg(test)]
mod tests;
