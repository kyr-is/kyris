// SPDX-License-Identifier: Apache-2.0
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use kyrisd::config::resolve_effective_config;

fn bench_resolve_no_working_dir(c: &mut Criterion) {
    let global: kyris_core::config::KyrisdConfig = serde_saphyr::from_str("{}").unwrap();

    c.bench_function("resolve_config_no_working_dir", |b| {
        b.iter(|| resolve_effective_config(black_box(&global), None));
    });
}

fn bench_resolve_no_project_file(c: &mut Criterion) {
    let global: kyris_core::config::KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();

    c.bench_function("resolve_config_no_project_file", |b| {
        b.iter(|| resolve_effective_config(black_box(&global), Some(black_box(&path))));
    });
}

fn bench_resolve_with_project_file(c: &mut Criterion) {
    let global: kyris_core::config::KyrisdConfig = serde_saphyr::from_str("{}").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project").join("deep");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(
        dir.path().join("project").join(".kyris.yaml"),
        "circuit_breaker:\n  max_tokens: 50000\n",
    )
    .unwrap();
    let path = project_dir.to_str().unwrap().to_string();

    c.bench_function("resolve_config_with_project_file", |b| {
        b.iter(|| resolve_effective_config(black_box(&global), Some(black_box(&path))));
    });
}

criterion_group!(
    benches,
    bench_resolve_no_working_dir,
    bench_resolve_no_project_file,
    bench_resolve_with_project_file,
);
criterion_main!(benches);
