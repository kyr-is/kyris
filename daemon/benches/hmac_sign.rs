// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use kyrisd::sync::event_sync::compute_hmac_signature;

fn bench_hmac_sign(c: &mut Criterion) {
    let key = b"sk-kyris-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let small_body = b"hello world";
    let medium_body = vec![0x42u8; 4096];
    let large_body = vec![0x42u8; 65536];

    c.bench_function("hmac_sign_11B", |b| {
        b.iter(|| compute_hmac_signature(black_box(key), black_box(small_body)));
    });

    c.bench_function("hmac_sign_4KB", |b| {
        b.iter(|| compute_hmac_signature(black_box(key), black_box(&medium_body)));
    });

    c.bench_function("hmac_sign_64KB", |b| {
        b.iter(|| compute_hmac_signature(black_box(key), black_box(&large_body)));
    });
}

criterion_group!(benches, bench_hmac_sign);
criterion_main!(benches);
