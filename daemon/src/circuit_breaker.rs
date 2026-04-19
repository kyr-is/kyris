// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct CircuitBreaker {
    sessions: Mutex<HashMap<String, SessionState>>,
}

struct SessionState {
    total_tokens: i64,
    max_tokens: i64,
    last_activity: Instant,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_tokens(&self, session_id: &str, tokens: i64, max_tokens: i64) {
        let mut sessions = self.sessions.lock().expect("lock sessions");
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

    pub fn is_tripped(&self, session_id: &str) -> bool {
        let sessions = self.sessions.lock().expect("lock sessions");
        sessions
            .get(session_id)
            .is_some_and(|s| s.total_tokens >= s.max_tokens)
    }

    pub fn reset(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().expect("lock sessions");
        if let Some(state) = sessions.get_mut(session_id) {
            state.total_tokens = 0;
            state.last_activity = Instant::now();
        }
    }

    pub fn prune_idle(&self, idle_timeout: std::time::Duration) {
        let mut sessions = self.sessions.lock().expect("lock sessions");
        sessions.retain(|_, state| state.last_activity.elapsed() < idle_timeout);
    }

    pub fn get_token_count(&self, session_id: &str) -> i64 {
        let sessions = self.sessions.lock().expect("lock sessions");
        sessions.get(session_id).map_or(0, |s| s.total_tokens)
    }

    pub fn rebuild_from(&self, stored: &[(String, i64)], max_tokens: i64) {
        let mut sessions = self.sessions.lock().expect("lock sessions");
        for (session_id, total_tokens) in stored {
            sessions.insert(
                session_id.clone(),
                SessionState {
                    total_tokens: *total_tokens,
                    max_tokens,
                    last_activity: Instant::now(),
                },
            );
        }
    }

    pub fn session_totals(&self) -> Vec<(String, i64)> {
        let sessions = self.sessions.lock().expect("lock sessions");
        sessions
            .iter()
            .map(|(id, state)| (id.clone(), state.total_tokens))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        cb.prune_idle(std::time::Duration::from_secs(0));
        assert_eq!(cb.get_token_count("sess-1"), 0);
    }

    #[test]
    fn testCircuitBreakerRebuildFrom() {
        let cb = CircuitBreaker::new();
        let stored = vec![
            ("sess-1".to_string(), 200_000i64),
            ("sess-2".to_string(), 100i64),
        ];
        cb.rebuild_from(&stored, 200_000);
        assert!(cb.is_tripped("sess-1"));
        assert!(!cb.is_tripped("sess-2"));
        assert_eq!(cb.get_token_count("sess-1"), 200_000);
        assert_eq!(cb.get_token_count("sess-2"), 100);
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
