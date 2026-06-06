// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use kyris_core::config::KyrisdConfig;

pub enum AuthResult {
    Ok,
    Rejected,
    Misconfigured,
}

pub fn validate_key(headers: &HeaderMap, expected: &str) -> AuthResult {
    if expected.is_empty() {
        return AuthResult::Misconfigured;
    }

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()));

    match provided {
        Some(key) if constant_time_eq(key.as_bytes(), expected.as_bytes()) => AuthResult::Ok,
        _ => AuthResult::Rejected,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Inbound (adapter-route) auth. The gate secret is accepted from a dedicated
/// `x-kyris-inbound` header so the agent's own credential (subscription OAuth or
/// its own API key) can ride in `authorization`/`x-api-key` untouched and be
/// forwarded upstream. Falls back to the native auth header for API-key-mode
/// setups that carry the inbound key there. The gate itself is unchanged — a
/// caller without the secret is still rejected.
pub fn validate_inbound_key(headers: &HeaderMap, expected: &str) -> AuthResult {
    if expected.is_empty() {
        return AuthResult::Misconfigured;
    }
    if let Some(v) = headers.get("x-kyris-inbound").and_then(|v| v.to_str().ok())
        && constant_time_eq(v.as_bytes(), expected.as_bytes())
    {
        return AuthResult::Ok;
    }
    validate_key(headers, expected)
}

pub async fn inbound_auth_middleware(
    State(config): State<Arc<ArcSwap<KyrisdConfig>>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let loaded = config.load();
    let inbound_key = &loaded.server.inbound_key;

    match validate_inbound_key(request.headers(), inbound_key) {
        AuthResult::Ok => Ok(next.run(request).await),
        AuthResult::Rejected => {
            drain_request_body(request).await;
            Err(StatusCode::UNAUTHORIZED)
        }
        AuthResult::Misconfigured => {
            drain_request_body(request).await;
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn operator_auth_middleware(
    State(config): State<Arc<ArcSwap<KyrisdConfig>>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let loaded = config.load();
    let operator_key = &loaded.server.operator_key;

    match validate_key(request.headers(), operator_key) {
        AuthResult::Ok => Ok(next.run(request).await),
        AuthResult::Rejected => {
            drain_request_body(request).await;
            Err(StatusCode::UNAUTHORIZED)
        }
        AuthResult::Misconfigured => {
            drain_request_body(request).await;
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Drain the request body before returning an error response. If we drop the
/// request with the body unread, hyper RSTs the connection (the HTTP/1.1
/// protocol state is undefined with an unconsumed body), and the client sees
/// `RemoteDisconnected` instead of the actual status we returned. Draining
/// lets hyper deliver the response cleanly. The body is already capped by the
/// outer `RequestBodyLimitLayer`, so `usize::MAX` here just means "all of it".
async fn drain_request_body(request: Request<Body>) {
    let _ = axum::body::to_bytes(request.into_body(), usize::MAX).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn testValidateBearerToken() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer sk-kyris-test"),
        );
        assert!(matches!(
            validate_key(&headers, "sk-kyris-test"),
            AuthResult::Ok
        ));
    }

    #[test]
    fn testInboundKeyFromDedicatedHeader() {
        // Subscription/passthrough: gate secret in x-kyris-inbound, the agent's
        // own OAuth in authorization (which must NOT need to match the secret).
        let mut headers = HeaderMap::new();
        headers.insert("x-kyris-inbound", HeaderValue::from_static("secret"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer sk-ant-oat01-xyz"),
        );
        assert!(matches!(
            validate_inbound_key(&headers, "secret"),
            AuthResult::Ok
        ));
    }

    #[test]
    fn testInboundKeyRejectedWithoutSecret() {
        // The agent's OAuth alone (no gate secret) is still rejected — the gate
        // is intact, so a drive-by localhost caller can't get through.
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer sk-ant-oat01-xyz"),
        );
        assert!(matches!(
            validate_inbound_key(&headers, "secret"),
            AuthResult::Rejected
        ));
    }

    #[test]
    fn testInboundKeyFallbackNativeHeader() {
        // API-key-mode setups that carry the inbound key in the native header
        // still pass.
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("secret"));
        assert!(matches!(
            validate_inbound_key(&headers, "secret"),
            AuthResult::Ok
        ));
    }

    #[test]
    fn testValidateXApiKey() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("sk-kyris-test"));
        assert!(matches!(
            validate_key(&headers, "sk-kyris-test"),
            AuthResult::Ok
        ));
    }

    #[test]
    fn testValidateWrongKey() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer wrong-key"),
        );
        assert!(matches!(
            validate_key(&headers, "sk-kyris-test"),
            AuthResult::Rejected
        ));
    }

    #[test]
    fn testValidateNoHeader() {
        let headers = HeaderMap::new();
        assert!(matches!(
            validate_key(&headers, "sk-kyris-test"),
            AuthResult::Rejected
        ));
    }

    #[test]
    fn testValidateEmptyExpectedIsMisconfigured() {
        let headers = HeaderMap::new();
        assert!(matches!(
            validate_key(&headers, ""),
            AuthResult::Misconfigured
        ));
    }

    #[test]
    fn testValidateEmptyExpectedMisconfiguredEvenWithKey() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer some-key"));
        assert!(matches!(
            validate_key(&headers, ""),
            AuthResult::Misconfigured
        ));
    }

    #[test]
    fn testConstantTimeEqMatching() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn testConstantTimeEqMismatch() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn testConstantTimeEqDifferentLength() {
        assert!(!constant_time_eq(b"short", b"longer-string"));
    }

    #[test]
    fn testConstantTimeEqEmpty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn testValidateBearerWithoutPrefix() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("sk-kyris-test"));
        assert!(matches!(
            validate_key(&headers, "sk-kyris-test"),
            AuthResult::Rejected
        ));
    }
}
