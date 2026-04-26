// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use kyrisd::metering::TokenCounts;
use kyrisd::streaming::StreamTokenCounts;

fn bench_accumulate(c: &mut Criterion) {
    let delta = StreamTokenCounts {
        tokens: TokenCounts {
            input: 15,
            output: 3,
        },
        cache_creation_input: 1,
        cache_read_input: 10,
    };

    c.bench_function("stream_token_accumulate_single", |b| {
        b.iter(|| {
            let mut total = StreamTokenCounts::default();
            total.accumulate(black_box(&delta));
            total
        });
    });

    c.bench_function("stream_token_accumulate_1000", |b| {
        b.iter(|| {
            let mut total = StreamTokenCounts::default();
            for _ in 0..1000 {
                total.accumulate(black_box(&delta));
            }
            total
        });
    });
}

criterion_group!(benches, bench_accumulate);
criterion_main!(benches);
