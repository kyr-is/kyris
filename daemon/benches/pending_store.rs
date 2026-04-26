// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use kyrisd::pending::PendingStore;

fn bench_hold(c: &mut Criterion) {
    c.bench_function("pending_hold", |b| {
        let store = PendingStore::new();
        let mut i = 0u64;
        b.iter(|| {
            let _rx = store.hold(
                format!("req-{i}"),
                format!("tok-{i}"),
                "github".into(),
                Some("read_file".into()),
            );
            i += 1;
        });
    });
}

fn bench_claim_complete(c: &mut Criterion) {
    c.bench_function("pending_hold_claim_complete", |b| {
        let store = PendingStore::new();
        let mut i = 0u64;
        b.iter(|| {
            let id = format!("req-{i}");
            let _rx = store.hold(id.clone(), format!("tok-{i}"), "github".into(), None);
            let claim = store.claim(black_box(&id)).unwrap();
            store.complete_claim(claim, true);
            i += 1;
        });
    });
}

fn bench_prune(c: &mut Criterion) {
    c.bench_function("pending_prune_100_resolved", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let store = PendingStore::new();
                for j in 0..100u64 {
                    let id = format!("req-{j}");
                    let _rx = store.hold(id.clone(), format!("tok-{j}"), "github".into(), None);
                    let claim = store.claim(&id).unwrap();
                    store.complete_claim(claim, true);
                }
                let start = std::time::Instant::now();
                store.prune_resolved();
                total += start.elapsed();
            }
            total
        });
    });
}

fn bench_list_held(c: &mut Criterion) {
    let store = PendingStore::new();
    let mut receivers = Vec::new();
    for i in 0..50u64 {
        let rx = store.hold(
            format!("req-{i}"),
            format!("tok-{i}"),
            "github".into(),
            Some("read_file".into()),
        );
        receivers.push(rx);
    }
    for i in 50..100u64 {
        let id = format!("req-{i}");
        let _rx = store.hold(id.clone(), format!("tok-{i}"), "github".into(), None);
        let claim = store.claim(&id).unwrap();
        store.complete_claim(claim, true);
    }

    c.bench_function("pending_list_held_100_entries", |b| {
        b.iter(|| store.list_held());
    });
}

criterion_group!(
    benches,
    bench_hold,
    bench_claim_complete,
    bench_prune,
    bench_list_held
);
criterion_main!(benches);
