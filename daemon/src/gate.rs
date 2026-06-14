// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Human "continue or stop?" gate for runaway sessions.
//!
//! When a session crosses the circuit breaker's no-action token cap (see
//! [`crate::circuit_breaker`]), kyrisd does NOT silently kill the agent with a
//! 429. It holds the agent's next request and asks the human: *"Agent X burned
//! N tokens without a tool call. Continue running?"* The human's answer arrives
//! from any surface — the desktop dialog, `kyris continue` (the reset
//! endpoint), the tray, or the app's Stop control — and is delivered to every
//! request waiting on that session through this registry.
//!
//! A `watch` channel per session lets multiple concurrent requests for the same
//! session all observe one decision: the first waiter creates the channel and
//! fires the dialog; the rest just await the same value.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::watch;

/// The human's answer to a runaway prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Keep going — reset the session's no-action counter and forward the
    /// request upstream. This is what `kyris continue` signals.
    Continue,
    /// Halt the agent — return the 429 / stop event for this request.
    Stop,
}

/// Per-session decision channels. A tripped session gets one `watch` sender;
/// every request that arrives while the prompt is open subscribes to it, so a
/// single human answer releases all of them.
#[derive(Default)]
pub struct GateRegistry {
    waiters: Mutex<HashMap<String, watch::Sender<Option<GateDecision>>>>,
}

impl GateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to a session's decision. Returns the receiver plus whether
    /// this call *created* the channel — the creator is responsible for
    /// surfacing the prompt (firing the desktop dialog / toast) exactly once.
    pub fn subscribe(&self, session_id: &str) -> (watch::Receiver<Option<GateDecision>>, bool) {
        let mut waiters = self.waiters.lock().expect("lock gate waiters");
        if let Some(tx) = waiters.get(session_id) {
            (tx.subscribe(), false)
        } else {
            let (tx, rx) = watch::channel(None);
            waiters.insert(session_id.to_string(), tx);
            (rx, true)
        }
    }

    /// Deliver a decision to every request waiting on this session. No-op if
    /// nothing is waiting (e.g. `kyris continue` for a session with no open
    /// prompt — the plain breaker reset still happens at the call site).
    pub fn resolve(&self, session_id: &str, decision: GateDecision) {
        if let Some(tx) = self
            .waiters
            .lock()
            .expect("lock gate waiters")
            .get(session_id)
        {
            let _ = tx.send(Some(decision));
        }
    }

    /// Resolve every open prompt with the same decision (e.g. `kyris continue`
    /// with no session arg → Continue all). Returns the resolved session IDs.
    pub fn resolve_all(&self, decision: GateDecision) -> Vec<String> {
        let waiters = self.waiters.lock().expect("lock gate waiters");
        let ids: Vec<String> = waiters.keys().cloned().collect();
        for tx in waiters.values() {
            let _ = tx.send(Some(decision));
        }
        ids
    }

    /// Drop a session's channel once its prompt has been resolved and consumed,
    /// so the next trip starts a fresh prompt.
    pub fn clear(&self, session_id: &str) {
        self.waiters
            .lock()
            .expect("lock gate waiters")
            .remove(session_id);
    }

    /// Whether a prompt is currently open for this session.
    pub fn is_pending(&self, session_id: &str) -> bool {
        self.waiters
            .lock()
            .expect("lock gate waiters")
            .contains_key(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn testFirstSubscriberCreatesChannel() {
        let reg = GateRegistry::new();
        let (_rx1, first1) = reg.subscribe("sess-1");
        assert!(first1, "first subscriber should create the channel");
        let (_rx2, first2) = reg.subscribe("sess-1");
        assert!(!first2, "second subscriber should reuse the channel");
    }

    #[tokio::test]
    async fn testResolveReleasesAllWaiters() {
        let reg = GateRegistry::new();
        let (mut rx1, _) = reg.subscribe("sess-1");
        let (mut rx2, _) = reg.subscribe("sess-1");
        reg.resolve("sess-1", GateDecision::Continue);
        rx1.changed().await.unwrap();
        rx2.changed().await.unwrap();
        assert_eq!(*rx1.borrow(), Some(GateDecision::Continue));
        assert_eq!(*rx2.borrow(), Some(GateDecision::Continue));
    }

    #[tokio::test]
    async fn testResolveUnknownSessionIsNoop() {
        let reg = GateRegistry::new();
        reg.resolve("nope", GateDecision::Stop); // must not panic
        assert!(!reg.is_pending("nope"));
    }

    #[tokio::test]
    async fn testClearRemovesChannel() {
        let reg = GateRegistry::new();
        let (_rx, _) = reg.subscribe("sess-1");
        assert!(reg.is_pending("sess-1"));
        reg.clear("sess-1");
        assert!(!reg.is_pending("sess-1"));
    }
}
