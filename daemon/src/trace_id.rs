// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Request `trace_id`: minted at the outermost middleware, attached to
//! request extensions + the request `tracing::Span`, echoed back as
//! `x-kyris-trace-id`. The unified id powers log correlation
//! (`kyris logs trace <id>`), the gateway record's `trace_id` field
//! (so the routing trace and the operational trace are the same
//! value), and any downstream agentpactd UDS call that wants to
//! propagate it via the protocol's `trace_id` field.
//!
//! Callers MUST install [`trace_id_middleware`] as the outermost
//! axum layer so every request — including ones the auth or
//! body-limit middleware rejects — has a `trace_id` before any other
//! middleware runs.

use std::sync::Arc;

use axum::http::header::HeaderName;
use axum::http::{HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// Newtype carried in `request.extensions()`. Cheap to clone — the
/// inner `Arc<str>` makes propagation into spawned tasks free.
#[derive(Clone, Debug)]
pub struct TraceId(pub Arc<str>);

impl TraceId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inbound header an external caller can use to set the `trace_id`
/// (otherwise we mint a `UUIDv7`). Mirrors the `OpenTelemetry` / W3C
/// convention.
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
/// Response header the caller sees with the `trace_id` we used —
/// suitable for pasting into `kyris logs trace <id>`. Matches the
/// existing header kyrisd was already emitting per-adapter.
const X_KYRIS_TRACE_ID: HeaderName = HeaderName::from_static("x-kyris-trace-id");

/// Outermost middleware. Mints (or accepts) a `trace_id`, attaches it
/// to request extensions and the request span, and stamps it onto
/// the response on the way out.
pub async fn trace_id_middleware(mut req: Request<axum::body::Body>, next: Next) -> Response {
    let trace_id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_inbound_id(s))
        .map_or_else(mint_trace_id, Arc::<str>::from);

    req.extensions_mut().insert(TraceId(trace_id.clone()));

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // One span per request; every nested `tracing::debug!` / `info!`
    // emitted inside `next.run(...)` inherits `trace_id` as a field
    // without manual threading.
    let span = tracing::info_span!(
        "request",
        trace_id = %trace_id,
        method = %method,
        path = %path,
    );

    let mut response = next.run(req).instrument(span).await;

    if let Ok(value) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert(&X_KYRIS_TRACE_ID, value);
    }
    response
}

/// Mint a fresh `UUIDv7`. Time-sortable + cryptographically random
/// tail = collision-safe and naturally ordered when grep'd by ts.
fn mint_trace_id() -> Arc<str> {
    Arc::<str>::from(uuid::Uuid::now_v7().to_string())
}

/// Reject obviously-malformed inbound ids so we don't propagate junk
/// into logs. Permissive: any printable ASCII, ≤128 chars, no spaces.
fn is_valid_inbound_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic() && b != b' ')
}

/// Read the `trace_id` off a request's extensions. Returns a borrowed
/// `&str` valid for the lifetime of the request. Caller should clone
/// only if it needs to outlive the request (e.g. spawning a task).
#[must_use]
pub fn from_request<B>(req: &Request<B>) -> Option<&str> {
    req.extensions().get::<TraceId>().map(TraceId::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn echo_trace_id_from_extension(req: Request<Body>) -> impl IntoResponse {
        let id = req
            .extensions()
            .get::<TraceId>()
            .map_or_else(|| "missing".to_string(), |t| t.as_str().to_string());
        (StatusCode::OK, id)
    }

    fn router() -> Router {
        Router::new()
            .route("/", get(echo_trace_id_from_extension))
            .layer(from_fn(trace_id_middleware))
    }

    #[tokio::test]
    async fn testMintsFreshIdWhenInboundAbsent() {
        let app = router();
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let header = response
            .headers()
            .get("x-kyris-trace-id")
            .expect("response carries trace id")
            .to_str()
            .unwrap()
            .to_string();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body_id = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(
            header, body_id,
            "extension trace_id must match response header"
        );
        assert!(header.len() >= 32, "UUIDv7 string is at least 32 chars");
    }

    #[tokio::test]
    async fn testAcceptsInboundXRequestId() {
        let app = router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-request-id", "caller-supplied-id-abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("x-kyris-trace-id").unwrap(),
            "caller-supplied-id-abc123"
        );
    }

    #[tokio::test]
    async fn testRejectsInboundIdWithSpaces() {
        let app = router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-request-id", "has spaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Junk inbound → minted ours, not the inbound. Verify by
        // shape (UUIDv7 contains hyphens, no space).
        let header = response
            .headers()
            .get("x-kyris-trace-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!header.contains(' '));
        assert!(header.contains('-'));
    }

    #[tokio::test]
    async fn testRejectsOverlongInboundId() {
        let app = router();
        let too_long = "x".repeat(129);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-request-id", &too_long)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let header = response
            .headers()
            .get("x-kyris-trace-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(header, too_long);
        assert!(header.len() <= 128);
    }

    #[test]
    fn testValidInboundId() {
        assert!(is_valid_inbound_id("abc-123"));
        assert!(is_valid_inbound_id("01HZAB7QY8M2NB7QY8M2NB7QY8"));
        assert!(!is_valid_inbound_id(""));
        assert!(!is_valid_inbound_id("with space"));
        assert!(!is_valid_inbound_id(&"x".repeat(129)));
    }
}
