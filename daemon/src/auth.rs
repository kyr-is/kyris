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

pub async fn inbound_auth_middleware(
    State(config): State<Arc<ArcSwap<KyrisdConfig>>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let loaded = config.load();
    let inbound_key = &loaded.server.inbound_key;

    match validate_key(request.headers(), inbound_key) {
        AuthResult::Ok => Ok(next.run(request).await),
        AuthResult::Rejected => Err(StatusCode::UNAUTHORIZED),
        AuthResult::Misconfigured => Err(StatusCode::INTERNAL_SERVER_ERROR),
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
        AuthResult::Rejected => Err(StatusCode::UNAUTHORIZED),
        AuthResult::Misconfigured => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
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
