// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use kyrisd::auth::validate_key;
use kyrisd::circuit_breaker::CircuitBreaker;

fn bench_validate_key(c: &mut Criterion) {
    use axum::http::{HeaderMap, HeaderValue};

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static(
            "Bearer sk-kyris-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
    );
    let expected = "sk-kyris-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    c.bench_function("validate_key_bearer", |b| {
        b.iter(|| validate_key(black_box(&headers), black_box(expected)));
    });
}

fn bench_circuit_breaker_lookup(c: &mut Criterion) {
    let cb = CircuitBreaker::new();
    for i in 0..100 {
        cb.record_tokens(&format!("sess-{i}"), 1000, 200_000);
    }

    c.bench_function("circuit_breaker_is_tripped", |b| {
        b.iter(|| cb.is_tripped(black_box("sess-50")));
    });
}

fn bench_extract_session_id(c: &mut Criterion) {
    use axum::http::{HeaderMap, HeaderValue};

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-kyris-session-id",
        HeaderValue::from_static("sess-01936b4e-7c3a-7000-8000-000000000001"),
    );

    c.bench_function("extract_session_id", |b| {
        b.iter(|| kyrisd::adapter::extract_session_id(black_box(&headers)));
    });
}

criterion_group!(
    benches,
    bench_validate_key,
    bench_circuit_breaker_lookup,
    bench_extract_session_id,
);
criterion_main!(benches);
