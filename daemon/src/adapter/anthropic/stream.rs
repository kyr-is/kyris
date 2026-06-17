// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use super::{
    AppState, Arc, Body, Bytes, HeaderMap, PlanStatus, Response, StatsEvent, StatusCode, StreamExt,
    StreamTokenCounts, anthropic_sse_has_tool_call, extract_tokens_from_sse_json, streaming,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn relay_sse_stream(
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
    let mut record_guard = super::super::StreamRecordGuard::new(finalize_stream);
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
        super::super::relay_upstream_headers(Response::builder().status(status), &resp_headers);
    builder = builder.header("x-kyris-trace-id", &trace_id);

    builder.body(Body::from_stream(full_stream)).map_err(|e| {
        tracing::error!(error = %e, "failed to build Anthropic messages SSE stream response");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
