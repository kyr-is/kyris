// SPDX-License-Identifier: Apache-2.0
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use kyrisd::streaming::{parse_sse_line, split_sse_lines};

fn bench_parse_sse_line(c: &mut Criterion) {
    let line = r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#;

    c.bench_function("parse_sse_line_json", |b| {
        b.iter(|| parse_sse_line(black_box(line)));
    });

    c.bench_function("parse_sse_line_done", |b| {
        b.iter(|| parse_sse_line(black_box("data: [DONE]")));
    });

    c.bench_function("parse_sse_line_comment", |b| {
        b.iter(|| parse_sse_line(black_box(": keepalive")));
    });
}

fn bench_split_sse_lines(c: &mut Criterion) {
    let small_buf = "data: {\"a\":1}\n\ndata: {\"b\":2}\n";

    let mut large_buf = String::new();
    for i in 0..100 {
        large_buf.push_str(&format!(
            "data: {{\"type\":\"content_block_delta\",\"index\":{i},\"delta\":{{\"text\":\"word \"}}}}\n\n"
        ));
    }

    c.bench_function("split_sse_lines_small", |b| {
        b.iter(|| split_sse_lines(black_box(small_buf)));
    });

    c.bench_function("split_sse_lines_100_events", |b| {
        b.iter(|| split_sse_lines(black_box(&large_buf)));
    });
}

criterion_group!(benches, bench_parse_sse_line, bench_split_sse_lines);
criterion_main!(benches);
