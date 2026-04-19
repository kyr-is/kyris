// SPDX-License-Identifier: Apache-2.0
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn is_tools_call(message: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(String::from))
        .is_some_and(|m| m == "tools/call")
}

fn bench_is_tools_call(c: &mut Criterion) {
    let tools_call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}"#;
    let ping = br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
    let not_json = b"this is not json at all";

    c.bench_function("is_tools_call_match", |b| {
        b.iter(|| is_tools_call(black_box(tools_call)));
    });

    c.bench_function("is_tools_call_no_match", |b| {
        b.iter(|| is_tools_call(black_box(ping)));
    });

    c.bench_function("is_tools_call_invalid_json", |b| {
        b.iter(|| is_tools_call(black_box(not_json)));
    });
}

criterion_group!(benches, bench_is_tools_call);
criterion_main!(benches);
