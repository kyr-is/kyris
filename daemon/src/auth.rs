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

pub fn validate_key(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return true;
    }

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()));

    match provided {
        Some(key) => constant_time_eq(key.as_bytes(), expected.as_bytes()),
        None => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

pub async fn inbound_auth_middleware(
    State(config): State<Arc<ArcSwap<KyrisdConfig>>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let loaded = config.load();
    let inbound_key = &loaded.server.inbound_key;

    if !validate_key(request.headers(), inbound_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

pub async fn operator_auth_middleware(
    State(config): State<Arc<ArcSwap<KyrisdConfig>>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let loaded = config.load();
    let operator_key = &loaded.server.operator_key;

    if !validate_key(request.headers(), operator_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
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
        assert!(validate_key(&headers, "sk-kyris-test"));
    }

    #[test]
    fn testValidateXApiKey() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("sk-kyris-test"));
        assert!(validate_key(&headers, "sk-kyris-test"));
    }

    #[test]
    fn testValidateWrongKey() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer wrong-key"),
        );
        assert!(!validate_key(&headers, "sk-kyris-test"));
    }

    #[test]
    fn testValidateNoHeader() {
        let headers = HeaderMap::new();
        assert!(!validate_key(&headers, "sk-kyris-test"));
    }

    #[test]
    fn testValidateEmptyExpected() {
        let headers = HeaderMap::new();
        assert!(validate_key(&headers, ""));
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
        assert!(!validate_key(&headers, "sk-kyris-test"));
    }
}
