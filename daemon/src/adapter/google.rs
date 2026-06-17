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

mod breaker;
mod stream;
mod usage;

use breaker::{
    circuit_breaker_error, google_body_has_tool_call, google_json_has_tool_call, google_stop_chunk,
    no_credential_error,
};
use stream::relay_ndjson_stream;
// Only the test module references `split_ndjson_lines` from the parent scope.
#[cfg(test)]
use stream::split_ndjson_lines;
use usage::{extract_tokens_from_body, extract_tokens_from_ndjson_line};

#[cfg(test)]
mod tests;
