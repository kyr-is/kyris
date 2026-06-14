// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Runaway guard. Tracks, per session, the model output tokens burned **since
/// the last tool/shell/MCP call**. A response that takes any action (a tool
/// call) resets the counter to zero, so a working agent — which calls a tool on
/// most turns — never accumulates. Only genuine no-action token burning (a
/// reasoning/text loop going nowhere, never invoking a tool) climbs toward the
/// cap. Crossing the cap doesn't kill the agent; it gates the *next* request on
/// a human "continue or stop?" decision (see `adapter::await_token_gate`).
///
/// History: this used to sum `input + output` of every request cumulatively,
/// which N-counted the re-sent context each turn and tripped productive agents
/// (codex hit it within a handful of turns). Counting only no-tool *output*
/// fixed that.
pub struct CircuitBreaker {
    sessions: RwLock<HashMap<String, SessionState>>,
}

struct SessionState {
    /// Output tokens accumulated since the last tool/shell/MCP call.
    idle_output_tokens: i64,
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

    /// Record a completed response against its session: a response that made any
    /// tool/shell/MCP call resets the no-action counter to zero (the agent is
    /// making progress); otherwise its output tokens add to the counter.
    /// Returns whether the session is now at/over its cap (i.e. the *next*
    /// request should be gated on a human decision).
    pub fn record(
        &self,
        session_id: &str,
        output_tokens: i64,
        had_tool_call: bool,
        max_tokens: i64,
    ) -> bool {
        let mut sessions = self.sessions.write().expect("lock sessions");
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert(SessionState {
                idle_output_tokens: 0,
                max_tokens,
                last_activity: Instant::now(),
            });
        if had_tool_call {
            entry.idle_output_tokens = 0;
        } else {
            entry.idle_output_tokens += output_tokens;
        }
        entry.max_tokens = max_tokens;
        entry.last_activity = Instant::now();
        entry.idle_output_tokens >= entry.max_tokens
    }

    /// Add no-action output tokens to a session (a response with no tool call).
    /// Convenience used by tests; the adapters use [`record`](Self::record).
    pub fn record_tokens(&self, session_id: &str, output_tokens: i64, max_tokens: i64) {
        self.record(session_id, output_tokens, false, max_tokens);
    }

    pub fn is_tripped(&self, session_id: &str) -> bool {
        let sessions = self.sessions.read().expect("lock sessions");
        sessions
            .get(session_id)
            .is_some_and(|s| s.idle_output_tokens >= s.max_tokens)
    }

    pub fn reset(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().expect("lock sessions");
        if let Some(state) = sessions.get_mut(session_id) {
            state.idle_output_tokens = 0;
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
            if state.idle_output_tokens >= state.max_tokens {
                state.idle_output_tokens = 0;
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
        sessions.get(session_id).map_or(0, |s| s.idle_output_tokens)
    }

    pub fn rebuild_from(&self, stored: &[(String, i64, std::time::Duration)], max_tokens: i64) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().expect("lock sessions");
        for (session_id, idle_output_tokens, elapsed) in stored {
            sessions.insert(
                session_id.clone(),
                SessionState {
                    idle_output_tokens: *idle_output_tokens,
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
            .map(|(id, state)| (id.clone(), state.idle_output_tokens))
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
    fn testToolCallResetsIdleCounter() {
        // No-tool output accumulates toward the cap...
        let cb = CircuitBreaker::new();
        assert!(!cb.record("sess-1", 150_000, false, 200_000));
        assert_eq!(cb.get_token_count("sess-1"), 150_000);
        // ...but a response that makes a tool call resets it to zero, so a
        // working agent never trips. Output on the tool-call turn is ignored.
        assert!(!cb.record("sess-1", 50_000, true, 200_000));
        assert_eq!(cb.get_token_count("sess-1"), 0);
        assert!(!cb.is_tripped("sess-1"));
        // After the reset the counter must climb again from zero.
        assert!(!cb.record("sess-1", 150_000, false, 200_000));
        assert!(!cb.is_tripped("sess-1"));
    }

    #[test]
    fn testRecordReturnsTrueOnCrossing() {
        // record() returns whether the session is now at/over the cap — the
        // signal that the *next* request must be gated on a human decision.
        let cb = CircuitBreaker::new();
        assert!(!cb.record("sess-1", 100_000, false, 200_000));
        assert!(cb.record("sess-1", 100_000, false, 200_000));
        assert!(cb.is_tripped("sess-1"));
    }

    #[test]
    fn testToolCallClearsAnAlreadyTrippedSession() {
        // A genuine runaway trips; the next turn happening to call a tool
        // clears it (progress resumed) without needing a human resume.
        let cb = CircuitBreaker::new();
        assert!(cb.record("sess-1", 200_000, false, 200_000));
        assert!(cb.is_tripped("sess-1"));
        assert!(!cb.record("sess-1", 0, true, 200_000));
        assert!(!cb.is_tripped("sess-1"));
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
