// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Pluggable LLM provider adapters. Each adapter translates between `kyrisd`'s
//! internal routing and a provider's API (Anthropic, Google, `OpenAI`), handling
//! auth header forwarding, streaming SSE relay, and session extraction.
pub mod anthropic;
pub mod google;
pub mod openai;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use crate::gate::GateDecision;
use crate::server::AppState;

/// Runs a streaming relay's record-finalize exactly once, no matter how the
/// response body ends.
///
/// Hyper drops a response-body future the moment the downstream peer goes
/// away. A relay that only finalizes (emits its gateway `StatsEvent`) when the
/// body is polled to graceful end-of-stream therefore silently loses the
/// record whenever the client closes first — `codex exec`, for instance, exits
/// as soon as it sees `response.completed`, racing the final poll, and the
/// tokens it burned vanish from metering. The guard closes that hole: the
/// poll path calls [`finalize`](Self::finalize) on natural end-of-stream or a
/// breaker trip (and may get a trailing chunk to deliver), and `Drop` runs the
/// same finalize when the stream is torn down early. By then the usage event
/// has usually already been relayed and accumulated, so the record carries
/// real token counts; a mid-generation abort records whatever had arrived,
/// which still beats no record for a request the upstream billed.
pub(crate) struct StreamRecordGuard<F: FnMut(bool) -> Option<bytes::Bytes>> {
    finalize: F,
    done: bool,
}

impl<F: FnMut(bool) -> Option<bytes::Bytes>> StreamRecordGuard<F> {
    pub fn new(finalize: F) -> Self {
        Self {
            finalize,
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Emit the record now (idempotent) and return the optional trailing
    /// chunk (e.g. a circuit-breaker error event) to append to the stream.
    pub fn finalize(&mut self, emit_breaker_chunk: bool) -> Option<bytes::Bytes> {
        if self.done {
            return None;
        }
        self.done = true;
        (self.finalize)(emit_breaker_chunk)
    }
}

impl<F: FnMut(bool) -> Option<bytes::Bytes>> Drop for StreamRecordGuard<F> {
    fn drop(&mut self) {
        // Skip during a panic unwind: the finalize closure locks the shared
        // token accumulators, and a poisoned lock here would turn a task panic
        // into a process abort (panic-in-drop).
        if self.done || std::thread::panicking() {
            return;
        }
        // Client disconnected before end-of-stream; no chunk can be delivered,
        // but the record must still be persisted.
        let _ = self.finalize(false);
    }
}

/// Tower layer that spawns each adapter request's handler future onto the
/// runtime so it runs to completion even if the client disconnects mid-flight.
///
/// Hyper drops a connection's service future when the peer goes away. For the
/// buffered (non-streaming) handlers the gateway `StatsEvent` is emitted only
/// after `send()`/`bytes()` complete — exactly the window in which a client
/// timeout or Ctrl-C would otherwise cancel the future, losing the record for
/// an upstream call that completed and billed. Spawning decouples the
/// handler's lifetime from the connection's: the response is discarded if
/// nobody is left to read it, but the bookkeeping always runs with the real
/// usage. (Streaming response BODIES outlive their handler and are protected
/// separately — see [`StreamRecordGuard`].)
#[derive(Clone)]
pub struct RunToCompletionLayer;

impl<S> tower::Layer<S> for RunToCompletionLayer {
    type Service = RunToCompletion<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RunToCompletion(inner)
    }
}

#[derive(Clone)]
pub struct RunToCompletion<S>(S);

impl<S, B> tower::Service<axum::http::Request<B>> for RunToCompletion<S>
where
    S: tower::Service<axum::http::Request<B>, Response = axum::response::Response>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<B>) -> Self::Future {
        use axum::response::IntoResponse as _;
        use tracing::Instrument as _;

        // Keep the request's tracing span: tokio::spawn would otherwise detach
        // the handler's logs from the request that caused them.
        let fut = tokio::spawn(self.0.call(req).instrument(tracing::Span::current()));
        Box::pin(async move {
            match fut.await {
                Ok(result) => result,
                Err(join_error) => {
                    tracing::error!(error = %join_error, "adapter handler task failed");
                    Ok(axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
            }
        })
    }
}

pub fn extract_session_id(headers: &HeaderMap) -> String {
    headers
        .get("x-kyris-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map_or_else(|| "__default".to_string(), String::from)
}

pub fn extract_trace_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-kyris-trace-token")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

pub fn extract_agent_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-kyris-agent-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Connection-level + body-framing headers that describe the UPSTREAM hop and
/// must never be relayed verbatim. kyrisd buffers the body and re-serves it over
/// its own connection, so hyper recomputes content-length/framing for the bytes
/// it actually writes; relaying these makes the declared framing contradict the
/// re-served body and hyper resets the connection (client sees `RemoteDisconnected`).
/// Hop-by-hop set per RFC 7230 §6.1.
///
/// `content-encoding` is intentionally NOT here: kyrisd's reqwest is built
/// WITHOUT gzip/brotli/deflate, so the body is byte-identical to upstream and its
/// content-encoding stays valid. If client-side decompression is ever enabled,
/// add `content-encoding` (the body would then be decoded plaintext).
const NON_RELAYABLE_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Relay `upstream` response headers onto `builder`, dropping the connection /
/// body-framing headers ([`NON_RELAYABLE_HEADERS`]) plus any header named in the
/// upstream `Connection` header (RFC 7230 §6.1). Everything else (`content-type`,
/// `content-encoding`, rate-limit / request-id / app headers) is relayed verbatim.
/// Used by every adapter relay path so a buffered upstream response is re-framed
/// correctly instead of resetting the client connection.
#[must_use]
pub fn relay_upstream_headers(
    mut builder: axum::http::response::Builder,
    upstream: &HeaderMap,
) -> axum::http::response::Builder {
    let connection_listed: Vec<String> = upstream
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    for (key, value) in upstream {
        let name = key.as_str().to_ascii_lowercase();
        if NON_RELAYABLE_HEADERS.contains(&name.as_str())
            || connection_listed.iter().any(|c| c == &name)
        {
            continue;
        }
        builder = builder.header(key, value);
    }
    builder
}

pub fn relay_trace_attach_sync(
    state: &AppState,
    trace_token: &str,
    trace_id: &str,
) -> Option<String> {
    let socket_path = state.resolve_agentpact_socket()?;
    let socket = socket_path.display().to_string();
    match kyris_agentpact_client::send_trace_attach(
        &socket,
        trace_token,
        trace_id,
        Some(std::time::Duration::from_secs(2)),
    ) {
        Ok(working_dir) => working_dir,
        Err(e) => {
            tracing::warn!(error = %e, "trace.attach relay failed");
            None
        }
    }
}

pub async fn relay_trace_attach(
    state: &AppState,
    trace_token: &str,
    trace_id: &str,
) -> Option<String> {
    let socket_path = state.resolve_agentpact_socket()?;
    let socket = socket_path.display().to_string();
    let token = trace_token.to_string();
    let id = trace_id.to_string();
    match tokio::task::spawn_blocking(move || {
        kyris_agentpact_client::send_trace_attach(
            &socket,
            &token,
            &id,
            Some(std::time::Duration::from_secs(2)),
        )
    })
    .await
    {
        Ok(Ok(working_dir)) => working_dir,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "trace.attach relay failed");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "trace.attach spawn_blocking failed");
            None
        }
    }
}

pub fn write_native_seen_breadcrumb(agent_id: &str) {
    let dir = kyris_core::paths::agents_dir().join(".native-seen");
    // The header carries the canonical `vendor/product` id; reconcile reads the
    // bare registry handle (and a slash would nest the path into an uncreated
    // subdirectory, silently dropping the breadcrumb).
    let path = dir.join(kyris_core::live_evidence::bare_agent_id(agent_id));
    if path.exists() {
        return;
    }
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&path, chrono::Utc::now().to_rfc3339());
}

/// One call per provider-adapter request, after header extraction: any request
/// carrying `x-kyris-agent-id` proves the burn-control surface live (the
/// adapted env/config routing delivered the agent's traffic here), and one
/// also carrying a trace token is native-protocol evidence.
pub fn record_agent_traffic(agent_id: Option<&str>, trace_token: Option<&str>) {
    let Some(aid) = agent_id else { return };
    kyris_core::live_evidence::record(aid, kyris_core::live_evidence::SURFACE_BURN_CONTROL);
    if let Some(token) = trace_token {
        tracing::debug!(
            agent_id = aid,
            trace_token = token,
            "native protocol observed"
        );
        write_native_seen_breadcrumb(aid);
    }
}

/// Hold a tripped session's request until the human answers the runaway prompt
/// ("Agent X burned N tokens without a tool call — continue running?"), then
/// return their decision. The prompt is surfaced once (the first waiter fires
/// the desktop dialog + toast); concurrent requests for the same session share
/// the answer. The decision can also arrive from the tray or the app's
/// Stop/Continue control (the reset/stop endpoint) via [`crate::gate`].
///
/// On `Continue` the session's no-action counter is reset so the request can
/// proceed. The wait has a multi-day backstop timeout (see
/// `circuit_breaker.decision_timeout_seconds`) — by design the agent waits for
/// a human rather than getting a surprising 429; the timeout only exists so an
/// unattended, never-answered prompt cannot pin a connection forever.
pub async fn await_token_gate(
    state: Arc<AppState>,
    session_id: String,
    agent: Option<String>,
    token_count: i64,
) -> GateDecision {
    let (mut rx, first) = state.gate.subscribe(&session_id);
    // User-facing event: this request is HELD on a human continue/stop decision
    // because the session crossed its no-tool token cap. At `info` so it shows in
    // the default log — the answer to "why did my call hang/429?".
    tracing::info!(
        session_id,
        token_count,
        max_tokens = state.config.load().circuit_breaker.max_tokens,
        shared = !first,
        "circuit_breaker gating request on human decision"
    );
    if first {
        let agent_label = agent.unwrap_or_else(|| "An agent".to_string());
        crate::notify::token_gate_toast(&agent_label, token_count);
        // The modal continue/stop dialog only exists in tray builds; without it
        // the toast above plus the tray / app (the reset/stop endpoint) are how
        // the human answers (otherwise the decision_timeout backstop applies).
        #[cfg(feature = "tray")]
        {
            let body = format!(
                "{agent_label} burned {token_count} tokens without a tool call. Continue running?"
            );
            let state2 = state.clone();
            let session2 = session_id.clone();
            tokio::spawn(async move {
                let outcome =
                    crate::notify::ask_approval("Kyris: token limit", &body, None, false).await;
                match outcome {
                    crate::notify::ApprovalOutcome::Yes
                    | crate::notify::ApprovalOutcome::Always => {
                        state2.gate.resolve(&session2, GateDecision::Continue);
                    }
                    crate::notify::ApprovalOutcome::No => {
                        state2.gate.resolve(&session2, GateDecision::Stop);
                    }
                    // Dialog could not be shown (fullscreen app, etc.). Leave the
                    // prompt open for the tray / the app to resolve.
                    crate::notify::ApprovalOutcome::CouldNotShow => {}
                }
            });
        }
    }

    let timeout = std::time::Duration::from_secs(
        state.config.load().circuit_breaker.decision_timeout_seconds,
    );
    let decision = tokio::time::timeout(timeout, async {
        loop {
            if let Some(d) = *rx.borrow() {
                return d;
            }
            if rx.changed().await.is_err() {
                // Channel dropped without a decision (cleared from under us).
                return GateDecision::Stop;
            }
        }
    })
    .await
    .unwrap_or(GateDecision::Stop);

    // Either answer clears the no-action counter. Continue proceeds with this
    // request; Stop 429s THIS request but still resets, so the agent's next
    // request starts from zero and isn't immediately re-prompted — the human
    // already made a decision about this burst.
    state.circuit_breaker.reset(&session_id);
    state.gate.clear(&session_id);
    decision
}

/// A deferred upstream call: built but not yet sent, run only if the human
/// chooses Continue. Returns the relayed streaming [`Response`].
pub type Continuation =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>;

/// Streaming counterpart of [`await_token_gate`]. Returns an SSE response
/// immediately (so the agent's HTTP client doesn't time out waiting on
/// headers), emits keep-alive comments while the human decides, then either
/// streams the real upstream answer (`Continue`, via `on_continue`) or emits a
/// provider-shaped stop event (`Stop`). `stop_chunk` is the provider's SSE
/// framing for the stop signal — a true 429 is impossible once a 200 SSE
/// response has begun, so the agent is halted with an in-stream error instead.
pub fn gated_streaming_response<F>(
    state: Arc<AppState>,
    session_id: String,
    agent: Option<String>,
    token_count: i64,
    trace_id: String,
    stop_chunk: bytes::Bytes,
    on_continue: F,
) -> Response
where
    F: FnOnce() -> Continuation + Send + 'static,
{
    use futures_util::StreamExt as _;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let mut decision_fut = Box::pin(await_token_gate(state, session_id, agent, token_count));
        // A bare `:` line is a content-free SSE comment — it keeps the
        // connection alive without polluting the stream the agent parses.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        ticker.tick().await; // first tick fires immediately; skip it
        let decision = loop {
            tokio::select! {
                d = &mut decision_fut => break d,
                _ = ticker.tick() => {
                    if tx
                        .send(Ok(bytes::Bytes::from_static(b": kyris awaiting approval\n\n")))
                        .await
                        .is_err()
                    {
                        // Client hung up; still resolve the prompt so it doesn't
                        // linger, then stop relaying.
                        break decision_fut.await;
                    }
                }
            }
        };

        match decision {
            GateDecision::Stop => {
                let _ = tx.send(Ok(stop_chunk)).await;
            }
            GateDecision::Continue => match on_continue().await {
                Ok(resp) => {
                    let mut body = resp.into_body().into_data_stream();
                    while let Some(item) = body.next().await {
                        let sent = match item {
                            Ok(b) => tx.send(Ok(b)).await,
                            Err(e) => tx.send(Err(std::io::Error::other(e))).await,
                        };
                        if sent.is_err() {
                            // Client gone — the relay's own StreamRecordGuard
                            // still finalizes the metering record on drop.
                            break;
                        }
                    }
                }
                Err(code) => {
                    let payload = format!(
                        "data: {{\"error\":{{\"message\":\"kyrisd upstream error after continue: {}\",\"type\":\"upstream_error\"}}}}\n\n",
                        code.as_u16()
                    );
                    let _ = tx.send(Ok(bytes::Bytes::from(payload))).await;
                }
            },
        }
    });

    let body_stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("x-kyris-trace-id", &trace_id)
        .body(Body::from_stream(body_stream))
        .expect("build gated streaming response")
}

/// CWD and agent attribution for the process owning a peer connection, resolved
/// from a single OS PID scan. Used on the non-conformant path (no
/// `x-kyris-trace-token`): the CWD seeds `working_dir`, and — only when the
/// agent did not send an `x-kyris-agent-id` header (`need_agent`) — `kyrisd`
/// asks `agentpactd` to attribute the owning agent from the PID. The header is
/// authoritative when present (Claude Code), so we skip the daemon round-trip
/// for it. Both fields are best-effort and independently `None`.
pub struct PeerAttribution {
    pub working_dir: Option<String>,
    pub agent: Option<String>,
}

fn resolve_peer_attribution_blocking(
    socket: Option<String>,
    peer_addr: SocketAddr,
    need_agent: bool,
) -> PeerAttribution {
    let Some((pid, working_dir)) = kyris_peer_cwd::resolve_with_pid(peer_addr) else {
        return PeerAttribution {
            working_dir: None,
            agent: None,
        };
    };
    let agent = if need_agent {
        socket.and_then(|socket| {
            let pid = u32::try_from(pid).ok()?;
            kyris_agentpact_client::resolve_agent(
                &socket,
                pid,
                Some(std::time::Duration::from_secs(2)),
            )
        })
    } else {
        None
    };
    PeerAttribution { working_dir, agent }
}

pub async fn resolve_peer_attribution(
    state: &AppState,
    peer_addr: SocketAddr,
    need_agent: bool,
) -> PeerAttribution {
    let socket = state
        .resolve_agentpact_socket()
        .map(|p| p.display().to_string());
    tokio::task::spawn_blocking(move || {
        resolve_peer_attribution_blocking(socket, peer_addr, need_agent)
    })
    .await
    .unwrap_or(PeerAttribution {
        working_dir: None,
        agent: None,
    })
}

pub fn resolve_peer_attribution_sync(
    state: &AppState,
    peer_addr: SocketAddr,
    need_agent: bool,
) -> PeerAttribution {
    let socket = state
        .resolve_agentpact_socket()
        .map(|p| p.display().to_string());
    resolve_peer_attribution_blocking(socket, peer_addr, need_agent)
}

// NB: `RunToCompletionLayer` is applied inside each adapter's own `routes()`
// (not here) so the protection travels with the adapter router — including
// when one is mounted directly, as the adapters' unit tests do.
pub fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(anthropic::routes(state.clone()))
        .merge(openai::routes(state.clone()))
        .merge(google::routes(state.clone()))
        .merge(models_route(state))
}

fn models_route(state: Arc<AppState>) -> Router {
    use axum::routing::get;

    Router::new().route("/v1/models", get(list_models).with_state(state))
}

async fn list_models(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let config = state.config.load();
    let mut models = Vec::new();

    for provider in &config.providers {
        for model in &provider.models {
            models.push(serde_json::json!({
                "id": model,
                "object": "model",
                "owned_by": provider.name,
            }));
        }
    }

    axum::Json(serde_json::json!({
        "object": "list",
        "data": models,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn testExtractSessionIdPresent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-kyris-session-id",
            HeaderValue::from_static("sess-abc-123"),
        );
        assert_eq!(extract_session_id(&headers), "sess-abc-123");
    }

    #[test]
    fn testExtractSessionIdMissingFallsBackToDefault() {
        let headers = HeaderMap::new();
        assert_eq!(extract_session_id(&headers), "__default");
    }

    #[test]
    fn testExtractSessionIdEmptyFallsBackToDefault() {
        let mut headers = HeaderMap::new();
        headers.insert("x-kyris-session-id", HeaderValue::from_static(""));
        assert_eq!(extract_session_id(&headers), "__default");
    }

    #[test]
    fn testExtractTraceTokenPresent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-kyris-trace-token",
            HeaderValue::from_static("tok-abc-123"),
        );
        assert_eq!(
            extract_trace_token(&headers),
            Some("tok-abc-123".to_string())
        );
    }

    #[test]
    fn testExtractTraceTokenMissing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_trace_token(&headers), None);
    }

    #[test]
    fn testExtractTraceTokenEmpty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-kyris-trace-token", HeaderValue::from_static(""));
        assert_eq!(extract_trace_token(&headers), None);
    }

    #[test]
    fn testExtractAgentIdPresent() {
        let mut headers = HeaderMap::new();
        headers.insert("x-kyris-agent-id", HeaderValue::from_static("claude-code"));
        assert_eq!(extract_agent_id(&headers), Some("claude-code".to_string()));
    }

    #[test]
    fn testExtractAgentIdMissing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_agent_id(&headers), None);
    }

    #[test]
    fn testExtractAgentIdEmpty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-kyris-agent-id", HeaderValue::from_static(""));
        assert_eq!(extract_agent_id(&headers), None);
    }

    #[test]
    fn testRelayUpstreamHeadersDropsFramingKeepsContent() {
        use axum::http::Response;

        let mut upstream = HeaderMap::new();
        upstream.insert("content-length", HeaderValue::from_static("123"));
        upstream.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        upstream.insert("connection", HeaderValue::from_static("keep-alive"));
        upstream.insert("content-type", HeaderValue::from_static("application/json"));
        upstream.insert("content-encoding", HeaderValue::from_static("gzip"));

        let builder = relay_upstream_headers(Response::builder().status(200), &upstream);
        let response = builder.body(()).expect("build response");
        let out = response.headers();

        assert_eq!(
            out.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            out.get("content-encoding").and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        assert!(!out.contains_key("content-length"));
        assert!(!out.contains_key("transfer-encoding"));
        assert!(!out.contains_key("connection"));
    }

    #[test]
    fn testRelayUpstreamHeadersDropsConnectionListed() {
        use axum::http::Response;

        let mut upstream = HeaderMap::new();
        upstream.insert("connection", HeaderValue::from_static("x-custom-hop"));
        upstream.insert("x-custom-hop", HeaderValue::from_static("drop-me"));
        upstream.insert("x-keep", HeaderValue::from_static("keep-me"));

        let builder = relay_upstream_headers(Response::builder().status(200), &upstream);
        let response = builder.body(()).expect("build response");
        let out = response.headers();

        assert!(!out.contains_key("x-custom-hop"));
        assert_eq!(
            out.get("x-keep").and_then(|v| v.to_str().ok()),
            Some("keep-me")
        );
    }

    #[test]
    fn testWriteNativeSeenBreadcrumb() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::remove_var("KYRIS_HOME");
        }
        let dir = temp
            .path()
            .join(".kyris")
            .join("agents")
            .join(".native-seen");

        write_native_seen_breadcrumb("claude-code");

        let path = dir.join("claude-code");
        assert!(path.exists());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains('T'),
            "expected ISO-8601 timestamp: {contents}"
        );

        // Idempotent: second call doesn't overwrite
        let first_contents = contents;
        write_native_seen_breadcrumb("claude-code");
        let second_contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first_contents, second_contents);
    }
}
