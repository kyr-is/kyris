// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0

/// Per-request access log. Logs every request the daemon sees at
/// `INFO` (4xx → WARN, 5xx → ERROR), with method / path / status /
/// `latency_ms` / body sizes / `trace_id`. Runs inside the request span
/// opened by [`crate::trace_id::trace_id_middleware`], so the same
/// `trace_id` field appears on this line and every nested handler
/// log — making `kyris logs trace <id>` a single coherent view.
pub(super) async fn request_log_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Cheap body-size telemetry: read Content-Length from the request
    // and response headers without consuming the bodies. Streamed or
    // chunked responses come through as `None`; that itself is
    // diagnostic information (LLM streaming responses look that way).
    let req_bytes = content_length(req.headers());
    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    let resp_bytes = content_length(response.headers());
    #[allow(clippy::cast_possible_truncation)]
    let latency_ms = start.elapsed().as_millis() as u64;
    if status >= 500 {
        tracing::error!(
            method = %method,
            path = %path,
            status,
            latency_ms,
            req_bytes = ?req_bytes,
            resp_bytes = ?resp_bytes,
            "request"
        );
    } else if status >= 400 {
        tracing::warn!(
            method = %method,
            path = %path,
            status,
            latency_ms,
            req_bytes = ?req_bytes,
            resp_bytes = ?resp_bytes,
            "request"
        );
    } else {
        tracing::info!(
            method = %method,
            path = %path,
            status,
            latency_ms,
            req_bytes = ?req_bytes,
            resp_bytes = ?resp_bytes,
            "request"
        );
    }
    response
}

/// Sanity check on the response before it goes to hyper. Catches the
/// "framing conflict" silent failure: when a handler builds a
/// response carrying header combinations hyper rejects, hyper resets
/// the TCP connection and writes nothing — the client sees
/// `RemoteDisconnected`, our `request_log_middleware` logged status
/// 401/200/whatever (because the response object was built), and
/// nothing in the log says WHY the bytes never landed.
///
/// We surface the conflict at ERROR here so the log answers the
/// question without anyone having to attach hyper at DEBUG. We do
/// NOT auto-fix the response — adapter-level filtering is the right
/// fix point, and we want the bug to remain visible until that
/// filter lands.
pub(super) async fn response_framing_check_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let response = next.run(req).await;
    if let Some(reason) = response_framing_violation(&response) {
        let status = response.status().as_u16();
        let header_names: Vec<&str> = response
            .headers()
            .keys()
            .map(axum::http::HeaderName::as_str)
            .collect();
        tracing::error!(
            status,
            reason = %reason,
            header_names = ?header_names,
            "response_framing_conflict: hyper will reset this connection \
             and the client will see RemoteDisconnected / Empty reply; \
             the response was built but the framing headers contradict \
             the body the response will be serialized with"
        );
    }
    response
}

/// Detect response header combinations hyper rejects at serialize
/// time. Returns `Some(reason)` if a known conflict is present.
///
/// Known conflicts (RFC 7230 §3.3.3 + RFC 7230 §4):
/// - `transfer-encoding` AND `content-length` together: hyper
///   refuses to choose between them and resets the connection.
/// - Hop-by-hop headers (`connection`, `keep-alive`, `te`,
///   `trailer`, `upgrade`, `proxy-*`) survive past a proxy: hyper
///   strips some and errors on others depending on version.
fn response_framing_violation(response: &axum::response::Response) -> Option<String> {
    // True hop-by-hop headers (RFC 7230 §6.1) must never survive past a
    // proxy. `content-length`/`transfer-encoding` are legitimate on their
    // own and are NOT flagged here; only the connection-scoped set is.
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-authenticate",
        "proxy-authorization",
    ];
    let headers = response.headers();
    let has_te = headers.contains_key("transfer-encoding");
    let has_cl = headers.contains_key("content-length");
    if has_te && has_cl {
        return Some(
            "both transfer-encoding and content-length headers are set \
             on the response (hyper requires exactly one)"
                .to_string(),
        );
    }
    for name in HOP_BY_HOP {
        if headers.contains_key(*name) {
            return Some(format!(
                "hop-by-hop header `{name}` is set on the response (RFC 7230 \
                 §6.1 forbids relaying connection-scoped headers past a proxy)"
            ));
        }
    }
    None
}

/// Read `Content-Length` from a header map as `u64`. None when the
/// header is absent or unparseable (streamed/chunked responses, or
/// requests with no body).
fn content_length(headers: &axum::http::HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}
