// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    Held,
    Approved,
    Denied,
    TimedOut,
    Cancelled,
}

#[derive(Serialize)]
pub struct PendingInfo {
    pub id: String,
    pub server: String,
    pub tool: Option<String>,
    pub state: PendingState,
    pub held_since_ms: u64,
    /// Whether answering "Always" would persist a standing override (the
    /// daemon's authoritative signal). `kyris pending` offers "always" only
    /// when this is true.
    pub allow_always: bool,
}

struct PendingEntry {
    approval_token: String,
    server: String,
    tool: Option<String>,
    state: PendingState,
    created: Instant,
    allow_always: bool,
    resolver: Option<oneshot::Sender<Resolution>>,
    timeout_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct Resolution {
    pub approved: bool,
}

pub struct PendingStore {
    entries: Mutex<HashMap<String, PendingEntry>>,
}

impl Default for PendingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn hold(
        &self,
        id: String,
        approval_token: String,
        server: String,
        tool: Option<String>,
        allow_always: bool,
    ) -> oneshot::Receiver<Resolution> {
        let (tx, rx) = oneshot::channel();
        let entry = PendingEntry {
            approval_token,
            server,
            tool,
            state: PendingState::Held,
            created: Instant::now(),
            allow_always,
            resolver: Some(tx),
            timeout_handle: None,
        };
        let mut entries = self.entries.lock().expect("lock pending");
        if let Some(old) = entries.remove(&id)
            && let Some(handle) = old.timeout_handle
        {
            handle.abort();
        }
        entries.insert(id, entry);
        rx
    }

    pub fn set_timeout_handle(&self, id: &str, handle: tokio::task::JoinHandle<()>) {
        let mut entries = self.entries.lock().expect("lock pending");
        if let Some(entry) = entries.get_mut(id) {
            entry.timeout_handle = Some(handle);
        }
    }

    pub fn claim(&self, id: &str) -> Result<Claim, ResolveError> {
        let mut entries = self.entries.lock().expect("lock pending");
        let entry = entries.get_mut(id).ok_or(ResolveError::NotFound)?;
        if entry.state != PendingState::Held {
            return match entry.state {
                PendingState::TimedOut | PendingState::Cancelled => {
                    Err(ResolveError::NoLongerResolvable(entry.state))
                }
                _ => Err(ResolveError::AlreadyResolved(entry.state)),
            };
        }
        if entry.resolver.is_none() {
            return Err(ResolveError::AlreadyResolved(PendingState::Held));
        }
        if let Some(handle) = entry.timeout_handle.take() {
            handle.abort();
        }
        let token = entry.approval_token.clone();
        let resolver = entry.resolver.take();
        Ok(Claim {
            id: id.to_string(),
            approval_token: token,
            resolver,
            completed: false,
        })
    }

    pub fn complete_claim(&self, mut claim: Claim, approved: bool) {
        claim.completed = true;
        if let Some(tx) = claim.resolver.take() {
            let _ = tx.send(Resolution { approved });
        }
        let mut entries = self.entries.lock().expect("lock pending");
        if let Some(entry) = entries.get_mut(&claim.id)
            && matches!(entry.state, PendingState::Held)
        {
            entry.state = if approved {
                PendingState::Approved
            } else {
                PendingState::Denied
            };
            if let Some(handle) = entry.timeout_handle.take() {
                handle.abort();
            }
        }
    }

    pub fn abandon_claim(&self, mut claim: Claim) {
        claim.completed = true;
        let mut entries = self.entries.lock().expect("lock pending");
        if let Some(entry) = entries.get_mut(&claim.id) {
            entry.resolver = claim.resolver.take();
        }
    }

    pub fn timeout(&self, id: &str) {
        let mut entries = self.entries.lock().expect("lock pending");
        if let Some(entry) = entries.get_mut(id)
            && entry.state == PendingState::Held
        {
            entry.state = PendingState::TimedOut;
            drop(entry.resolver.take());
            drop(entry.timeout_handle.take());
        }
    }

    pub fn cancel(&self, id: &str) -> Option<String> {
        let mut entries = self.entries.lock().expect("lock pending");
        if let Some(entry) = entries.get_mut(id)
            && entry.state == PendingState::Held
        {
            let token = entry.approval_token.clone();
            entry.state = PendingState::Cancelled;
            drop(entry.resolver.take());
            if let Some(handle) = entry.timeout_handle.take() {
                handle.abort();
            }
            Some(token)
        } else {
            None
        }
    }

    pub fn list(&self) -> Vec<PendingInfo> {
        let entries = self.entries.lock().expect("lock pending");
        entries
            .iter()
            .map(|(id, entry)| PendingInfo {
                id: id.clone(),
                server: entry.server.clone(),
                tool: entry.tool.clone(),
                state: entry.state,
                held_since_ms: entry.created.elapsed().as_millis() as u64,
                allow_always: entry.allow_always,
            })
            .collect()
    }

    pub fn get_state(&self, id: &str) -> Option<PendingState> {
        self.entries
            .lock()
            .expect("lock pending")
            .get(id)
            .map(|e| e.state)
    }

    pub fn list_held(&self) -> Vec<PendingInfo> {
        self.list()
            .into_iter()
            .filter(|p| p.state == PendingState::Held)
            .collect()
    }

    pub fn prune_resolved(&self) {
        let mut entries = self.entries.lock().expect("lock pending");
        entries.retain(|_, entry| entry.state == PendingState::Held);
    }
}

pub struct Claim {
    id: String,
    pub approval_token: String,
    resolver: Option<oneshot::Sender<Resolution>>,
    completed: bool,
}

impl Drop for Claim {
    fn drop(&mut self) {
        if !self.completed
            && let Some(tx) = self.resolver.take()
        {
            let _ = tx.send(Resolution { approved: false });
        }
    }
}

#[derive(Debug)]
pub enum ResolveError {
    NotFound,
    AlreadyResolved(PendingState),
    NoLongerResolvable(PendingState),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testHoldAndClaimApproved() {
        let store = PendingStore::new();
        let _rx = store.hold(
            "req-1".into(),
            "tok-1".into(),
            "github".into(),
            Some("read_file".into()),
            true,
        );

        assert_eq!(store.list_held().len(), 1);
        let claim = store.claim("req-1").unwrap();
        assert_eq!(claim.approval_token, "tok-1");
        store.complete_claim(claim, true);
        assert_eq!(store.list_held().len(), 0);

        let info = &store.list()[0];
        assert_eq!(info.state, PendingState::Approved);
    }

    #[test]
    fn testHoldAndClaimDenied() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        store.complete_claim(claim, false);
        let info = &store.list()[0];
        assert_eq!(info.state, PendingState::Denied);
    }

    #[test]
    fn testClaimNotFound() {
        let store = PendingStore::new();
        assert!(matches!(
            store.claim("nonexistent"),
            Err(ResolveError::NotFound)
        ));
    }

    #[test]
    fn testDoubleClaimFails() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        assert!(store.claim("req-1").is_err());
        store.complete_claim(claim, true);
    }

    #[test]
    fn testAbandonClaimRestoresHeld() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        store.abandon_claim(claim);

        assert_eq!(store.list_held().len(), 1);
        let retry = store.claim("req-1").unwrap();
        assert_eq!(retry.approval_token, "tok-1");
        store.complete_claim(retry, true);
    }

    #[test]
    fn testTimeout() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        store.timeout("req-1");
        assert_eq!(store.list_held().len(), 0);
        assert_eq!(store.list()[0].state, PendingState::TimedOut);
    }

    #[test]
    fn testCancel() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        store.cancel("req-1");
        assert_eq!(store.list_held().len(), 0);
        assert_eq!(store.list()[0].state, PendingState::Cancelled);
    }

    #[test]
    fn testClaimAfterTimeoutFails() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        store.timeout("req-1");
        assert!(matches!(
            store.claim("req-1"),
            Err(ResolveError::NoLongerResolvable(PendingState::TimedOut))
        ));
    }

    #[test]
    fn testPruneResolved() {
        let store = PendingStore::new();
        let _rx1 = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);
        let _rx2 = store.hold("req-2".into(), "tok-2".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        store.complete_claim(claim, true);
        store.prune_resolved();

        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].id, "req-2");
    }

    #[tokio::test]
    async fn testClaimChannelReceivesApproval() {
        let store = PendingStore::new();
        let rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        store.complete_claim(claim, true);
        let resolution = rx.await.unwrap();
        assert!(resolution.approved);
    }

    #[tokio::test]
    async fn testClaimChannelReceivesDenial() {
        let store = PendingStore::new();
        let rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        store.complete_claim(claim, false);
        let resolution = rx.await.unwrap();
        assert!(!resolution.approved);
    }

    #[tokio::test]
    async fn testTimeoutDropsChannel() {
        let store = PendingStore::new();
        let rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        store.timeout("req-1");
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn testCancelDropsChannel() {
        let store = PendingStore::new();
        let rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        store.cancel("req-1");
        assert!(rx.await.is_err());
    }

    #[test]
    fn testGetStateReturnsHeldThenApproved() {
        let store = PendingStore::new();
        assert!(store.get_state("req-1").is_none());

        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);
        assert_eq!(store.get_state("req-1"), Some(PendingState::Held));

        let claim = store.claim("req-1").unwrap();
        store.complete_claim(claim, true);
        assert_eq!(store.get_state("req-1"), Some(PendingState::Approved));
    }

    #[test]
    fn testGetStateReturnsDenied() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        let claim = store.claim("req-1").unwrap();
        store.complete_claim(claim, false);
        assert_eq!(store.get_state("req-1"), Some(PendingState::Denied));
    }

    #[test]
    fn testCompleteClaimRefusesToOverwriteTerminalState() {
        let store = PendingStore::new();
        let _rx = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);

        store.timeout("req-1");
        assert_eq!(store.get_state("req-1"), Some(PendingState::TimedOut));

        let (tx, _rx2) = oneshot::channel();
        let claim = Claim {
            id: "req-1".into(),
            approval_token: "tok-1".into(),
            resolver: Some(tx),
            completed: false,
        };
        store.complete_claim(claim, true);
        assert_eq!(store.get_state("req-1"), Some(PendingState::TimedOut));
    }

    #[test]
    fn testHoldDuplicateIdReplacesEntry() {
        let store = PendingStore::new();
        let _rx1 = store.hold("req-1".into(), "tok-1".into(), "github".into(), None, true);
        let _rx2 = store.hold("req-1".into(), "tok-2".into(), "gitlab".into(), None, true);

        assert_eq!(store.list().len(), 1);
        let claim = store.claim("req-1").unwrap();
        assert_eq!(claim.approval_token, "tok-2");
        store.complete_claim(claim, true);
    }
}
