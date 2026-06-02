// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

pub struct CircuitBreaker {
    sessions: RwLock<HashMap<String, SessionState>>,
}

struct SessionState {
    total_tokens: i64,
    max_tokens: i64,
    last_activity: Instant,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn record_tokens(&self, session_id: &str, tokens: i64, max_tokens: i64) {
        let mut sessions = self.sessions.write().expect("lock sessions");
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert(SessionState {
                total_tokens: 0,
                max_tokens,
                last_activity: Instant::now(),
            });
        entry.total_tokens += tokens;
        entry.max_tokens = max_tokens;
        entry.last_activity = Instant::now();
    }

    /// Record a completed call's tokens against its session and report whether
    /// that pushed the session to/over its cap. Because already-tripped
    /// sessions are rejected pre-flight (they never reach a record path), a
    /// `true` here marks the *crossing* call — the single call recorded as
    /// `circuit_breaker`. Subsequent calls are 429'd pre-flight and unrecorded.
    pub fn record_and_is_tripped(&self, session_id: &str, tokens: i64, max_tokens: i64) -> bool {
        self.record_tokens(session_id, tokens, max_tokens);
        self.is_tripped(session_id)
    }

    pub fn is_tripped(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().expect("lock sessions");
        sessions
            .get(session_id)
            .is_some_and(|s| s.total_tokens >= s.max_tokens)
    }

    pub fn reset(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().expect("lock sessions");
        if let Some(state) = sessions.get_mut(session_id) {
            state.total_tokens = 0;
            state.last_activity = Instant::now();
            true
        } else {
            false
        }
    }

    /// Clear every session that's at or above its token cap. Returns
    /// the IDs that were actually tripped (and are now reset) so the
    /// caller can report which sessions resumed.
    pub fn reset_all_tripped(&self) -> Vec<String> {
        let mut sessions = self.sessions.write().expect("lock sessions");
        let now = Instant::now();
        let mut cleared = Vec::new();
        for (id, state) in sessions.iter_mut() {
            if state.total_tokens >= state.max_tokens {
                state.total_tokens = 0;
                state.last_activity = now;
                cleared.push(id.clone());
            }
        }
        cleared
    }

    pub fn prune_idle(&self, idle_timeout: std::time::Duration) {
        let mut sessions = self.sessions.write().expect("lock sessions");
        sessions.retain(|_, state| state.last_activity.elapsed() < idle_timeout);
    }

    pub fn get_token_count(&self, session_id: &str) -> i64 {
        let sessions = self.sessions.read().expect("lock sessions");
        sessions.get(session_id).map_or(0, |s| s.total_tokens)
    }

    pub fn rebuild_from(&self, stored: &[(String, i64, std::time::Duration)], max_tokens: i64) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().expect("lock sessions");
        for (session_id, total_tokens, elapsed) in stored {
            sessions.insert(
                session_id.clone(),
                SessionState {
                    total_tokens: *total_tokens,
                    max_tokens,
                    last_activity: now.checked_sub(*elapsed).unwrap_or(now),
                },
            );
        }
    }

    pub fn session_totals(&self) -> Vec<(String, i64)> {
        let sessions = self.sessions.read().expect("lock sessions");
        sessions
            .iter()
            .map(|(id, state)| (id.clone(), state.total_tokens))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn testCircuitBreakerRecordAndTrip() {
        let cb = CircuitBreaker::new();
        cb.record_tokens("sess-1", 100_000, 200_000);
        assert!(!cb.is_tripped("sess-1"));
        cb.record_tokens("sess-1", 100_000, 200_000);
        assert!(cb.is_tripped("sess-1"));
    }

    #[test]
    fn testCircuitBreakerReset() {
        let cb = CircuitBreaker::new();
        cb.record_tokens("sess-1", 200_000, 200_000);
        assert!(cb.is_tripped("sess-1"));
        cb.reset("sess-1");
        assert!(!cb.is_tripped("sess-1"));
        assert_eq!(cb.get_token_count("sess-1"), 0);
    }

    #[test]
    fn testCircuitBreakerUnknownSession() {
        let cb = CircuitBreaker::new();
        assert!(!cb.is_tripped("nonexistent"));
        assert_eq!(cb.get_token_count("nonexistent"), 0);
    }

    #[test]
    fn testCircuitBreakerPruneIdle() {
        let cb = CircuitBreaker::new();
        cb.record_tokens("sess-1", 100, 200_000);
        cb.prune_idle(Duration::from_secs(0));
        assert_eq!(cb.get_token_count("sess-1"), 0);
    }

    #[test]
    fn testCircuitBreakerRebuildFrom() {
        let cb = CircuitBreaker::new();
        let stored = vec![
            ("sess-1".to_string(), 200_000i64, Duration::from_mins(1)),
            ("sess-2".to_string(), 100i64, Duration::from_mins(5)),
        ];
        cb.rebuild_from(&stored, 200_000);
        assert!(cb.is_tripped("sess-1"));
        assert!(!cb.is_tripped("sess-2"));
        assert_eq!(cb.get_token_count("sess-1"), 200_000);
        assert_eq!(cb.get_token_count("sess-2"), 100);
    }

    #[test]
    fn testRebuildFromPreservesElapsedTime() {
        let cb = CircuitBreaker::new();
        let stored = vec![("sess-old".to_string(), 100i64, Duration::from_mins(30))];
        cb.rebuild_from(&stored, 200_000);
        cb.prune_idle(Duration::from_mins(30));
        assert_eq!(
            cb.get_token_count("sess-old"),
            0,
            "session idle for exactly the timeout should be pruned"
        );
    }

    #[test]
    fn testRebuildFromRecentSessionSurvivesPrune() {
        let cb = CircuitBreaker::new();
        let stored = vec![("sess-recent".to_string(), 100i64, Duration::from_secs(10))];
        cb.rebuild_from(&stored, 200_000);
        cb.prune_idle(Duration::from_mins(30));
        assert_eq!(
            cb.get_token_count("sess-recent"),
            100,
            "recently active session should survive prune"
        );
    }

    #[test]
    fn testCircuitBreakerSessionTotals() {
        let cb = CircuitBreaker::new();
        cb.record_tokens("sess-1", 100, 200_000);
        cb.record_tokens("sess-2", 200, 200_000);
        let totals = cb.session_totals();
        assert_eq!(totals.len(), 2);
    }

    #[test]
    fn testCircuitBreakerMultipleSessions() {
        let cb = CircuitBreaker::new();
        cb.record_tokens("sess-1", 200_000, 200_000);
        cb.record_tokens("sess-2", 100, 200_000);
        assert!(cb.is_tripped("sess-1"));
        assert!(!cb.is_tripped("sess-2"));
    }
}
