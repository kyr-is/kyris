# Owed tests surfaced by the kyris-internal e2e suite

Notes filed while building the category-A (agentpact + kyris) e2e seams in
`kyris-internal/tests/`. These are kyris-side behaviors better covered by
unit/integration tests **here** than by the Python e2e (which can't drive them
cleanly), plus prereq-gated cases the e2e leaves as `--setup` stubs.

## Status (2026-06-01)

- ✅ **`send_trace_attach` + `send_permission_response`** — implemented in
  `agentpact-client/tests/daemon_round_trip.rs` against a `FakeDaemon` UDS
  harness (`tests/common/mod.rs`): trace-attach success/empty-wd/rejection/
  malformed, and permission-respond approved/persist-warning/denied-on-PACT_DENIED/
  rejection/unexpected-ask. Added `tempfile` dev-dep.
- ✅ **`check_protocol_compatibility` / version handshake** — pure-fn cases plus
  a real on-disk `daemon.state` path: `check_protocol_compatibility_at(path)` is
  split out (so `read_daemon_state_at` is exercised against a temp file, no env)
  with `testCheckProtocolCompatibilityAt{MatchingVersionFile,NewerVersionFileErrs,
  MissingFileIsOk,MalformedFileIsOk}`.
- ✅ **retry + `launchctl kickstart` restart** — the retry/backoff/restart
  sequence is extracted into a pure `drive_retry(backoffs, attempt, recover)`;
  `send_daemon_request_with_retry` passes the real send + a `recover` closure that
  restarts agentpactd and sleeps. `testDriveRetry{SucceedsAfterTransientFailures,
  ExhaustsBackoffsThenReturnsLastError,NoRestartWhenFirstAttemptSucceeds}` assert
  the [50,100,250]ms sequence + restart count without touching launchctl or the
  clock. (`restart_agentpactd` itself stays a thin launchctl shell-out.)

## `kyris-agentpact-client` internals (unit/integration in this repo)

The happy-path request→decision→event round-trip and the daemon-unavailable
(fail-closed) path are covered by the e2e (`test_agent_hook_to_agentpact`,
`test_kyris_client_to_agentpact`). The rest of the client is internal and untested
against a real daemon:

- **`send_trace_attach(trace_token, trace_id)`** — kyrisd binds a usage report to
  a gateway record. No test drives this against a real agentpactd. Add an
  integration test: real trace_token → `trace.attach` accepted; invalid/missing
  token → error with recovery hint.
- **`send_permission_response(approval_token, decision)`** — the approval delivery
  path when a `kyris pending` resolution returns to agentpactd. Untested
  end-to-end. Assert decision applied + (for `Always`) the persisted override is
  written in the form the decision path matches — see the BUG in
  `agentpact/OWED-TESTS.md` (the always-grant write path is the prime suspect).
- **`check_protocol_compatibility()` / version handshake** — pure-fn tested; add
  an integration check against a real `daemon.state` (match → ok; mismatch →
  upgrade hint).
- **retry + `launchctl kickstart` restart** — on socket error the client retries
  `[50,100,250]ms` then restarts agentpactd. The restart branch is untested.
- **oversized-command ceiling** — already unit-tested; no e2e owed.

## Prereq-gated e2e cases left as `--setup` stubs

These live in the e2e but skip without `--setup`/keys; the real implementations
belong as `--setup` integration tests:

- **`kyris agents setup <agent>` config acceptance** (per agent) — after setup,
  the real agent CLI starts with the written config (exit 0); `undo` reverses it;
  setting up one agent doesn't arm another's hooks. Mutates `~/.claude` etc. →
  snapshot/restore. (e2e: `tests/seams/test_agent_cli_setup.py`, read-only env-file
  assertions are already implemented + green.)
- **install / uninstall / reinstall lifecycle** — plist written, idempotent,
  XDG-preserving across uninstall→reinstall. Mutates the real install → `--setup`.
  (e2e: `tests/seams/test_install_lifecycle.py`.)
- **kyrisd → provider, API-key mode** (anthropic/openai/google non-streaming +
  streaming + upstream-error relay) — needs a real provider key AND a configured
  `providers:` entry (kyrisd ships `providers: 0`). Subscription-passthrough →
  `included` is already covered + green. (e2e: `tests/seams/test_kyrisd_to_provider.py`.)
- **circuit breaker** — token-cap → 429 / SSE error → reset. Needs a lowered
  `circuit_breaker.max_tokens` (config → `--setup`) and real provider calls.
  (e2e: `tests/scenarios/test_circuit_breaker.py`.)
