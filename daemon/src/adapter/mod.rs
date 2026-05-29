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
use axum::http::HeaderMap;

use crate::server::AppState;

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
    let path = dir.join(agent_id);
    if path.exists() {
        return;
    }
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&path, chrono::Utc::now().to_rfc3339());
}

pub async fn resolve_peer_working_dir(peer_addr: SocketAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || kyris_peer_cwd::resolve(peer_addr))
        .await
        .ok()
        .flatten()
}

pub fn resolve_peer_working_dir_sync(peer_addr: SocketAddr) -> Option<String> {
    kyris_peer_cwd::resolve(peer_addr)
}

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
