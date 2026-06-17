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

## Prereq-gated e2e cases — the pre-release gate

These seams need a real environment GitHub Actions can't provide (installed
launchd daemons, real agent CLIs, live provider keys), so they're not in normal
CI. They are tagged `@pytest.mark.pre_release` in `kyris-internal` and run as one
named gate before a release:

```
kyris-internal/scripts/pre-release-gate.sh        # full agent matrix
```

The runner pre-flights the prerequisites and, via `KYRIS_CI_TIER=pre-release`,
**fails** (never silently skips) if a required agent is missing — so the gate
can't pass while omitting a seam. The tests (now in the dir-based `tests/A`
layout, not the old `tests/seams/`):

- **`kyris agent setup <agent>` config acceptance** (per agent) — after setup,
  the real agent CLI starts with the written config (exit 0); setting up one
  agent doesn't arm another's hooks. Snapshot/restores real agent config.
  → `tests/A/test_04_agent_cli_setup.py::test_real_agent_cli_accepts_written_config`
  (the read-only env-file assertions in the same file are unmarked — they run in
  the normal lane). Codex setup↔disconnect round-trip:
  `tests/A/test_10_codex_setup_roundtrip.py::test_codex_setup_undo_restores_config`.
- **kyrisd → provider, API-key mode** (anthropic/openai/google non-streaming +
  streaming + upstream-error relay) — needs a real provider key. Subscription
  passthrough → `included` is also here (marked `subscription_only`).
  → `tests/A/test_03_kyrisd_to_provider.py`.
- **circuit breaker with real provider calls** — tool-call reset + the human
  continue/stop gate (token-cap → 429 / SSE error → reset). Lowers
  `circuit_breaker.max_tokens` via a fixture that edits + restores installed
  config. → `tests/A/test_07_circuit_breaker.py`.

**Still owed (not yet covered by any test):**

- **install / uninstall / reinstall lifecycle** — plist written, idempotent,
  XDG-preserving across uninstall→reinstall. No e2e test exists yet (it mutates
  the real install, which the suite avoids); the pre-release gate notes this and
  it must be verified by hand until a `--setup`-style test lands. When added,
  tag it `pre_release` so the gate picks it up.
