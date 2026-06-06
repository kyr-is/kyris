// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Shared fake-agentpactd UDS harness for client round-trip tests.
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

/// A minimal stand-in for `agentpactd`: binds a UDS, serves one canned JSON
/// response per accepted connection (matching the client's JSON + newline
/// framing — read to EOF, write response, close), and records every request it
/// received so a test can assert the wire shape the client sent.
///
/// One connection is served per element of `responses`, so a test must make
/// exactly that many client calls or `finish()` will block on the unmatched
/// `accept()`.
pub struct FakeDaemon {
    requests: Arc<Mutex<Vec<serde_json::Value>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeDaemon {
    pub fn start(socket_path: &Path, responses: Vec<serde_json::Value>) -> Self {
        if socket_path.exists() {
            std::fs::remove_file(socket_path).expect("remove stale socket");
        }
        let listener = UnixListener::bind(socket_path).expect("bind fake daemon socket");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept fake daemon connection");
                let mut buf = Vec::new();
                stream
                    .read_to_end(&mut buf)
                    .expect("read fake daemon request");
                let request: serde_json::Value =
                    serde_json::from_slice(&buf).expect("parse fake daemon request");
                requests_clone.lock().expect("lock requests").push(request);
                let payload = serde_json::to_vec(&response).expect("serialize response");
                stream
                    .write_all(&payload)
                    .expect("write fake daemon response");
                // `stream` drops at the end of the iteration → EOF for the
                // client's read-to-EOF.
            }
        });
        Self {
            requests,
            handle: Some(handle),
        }
    }

    /// Join the server thread (all responses consumed) and return the recorded
    /// requests.
    pub fn finish(mut self) -> Vec<serde_json::Value> {
        if let Some(handle) = self.handle.take() {
            handle.join().expect("join fake daemon thread");
        }
        self.requests.lock().expect("lock requests").clone()
    }
}
