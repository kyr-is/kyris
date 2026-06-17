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

mod breaker;
mod stream;
mod usage;

use breaker::{
    anthropic_body_has_tool_call, anthropic_sse_has_tool_call, anthropic_stop_chunk,
    circuit_breaker_response, no_credential_response,
};
use stream::relay_sse_stream;
use usage::extract_usage_from_body;
// `extract_tokens_from_sse_json` is part of the crate's public adapter surface;
// re-export it path-compatibly so `adapter::anthropic::extract_tokens_from_sse_json`
// keeps resolving after the move into the `usage` submodule.
pub use usage::extract_tokens_from_sse_json;

#[cfg(test)]
mod tests;
