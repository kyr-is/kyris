# AGENTS.md

## Rules
These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

### Rule 1 — Think Before Coding
State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

### Rule 2 — Research First
Prioritize research over trial and error. Consult documentation rather than guessing. If a solution fails twice, stop and investigate further before attempting another fix.

### Rule 3 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

### Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

## Build & Test

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo bench -p kyrisd -- --test
```

MSRV is 1.95. The toolchain is pinned in `rust-toolchain.toml`.

## Workspace Layout

Cargo workspace with nine crates producing four installable binaries (plus a build helper).

### Libraries

| Crate | Path | Purpose |
|-------|------|---------|
| `kyris-types` | `types/` | Shared types: events, pricing tiers, records, config schema, sync protocol. Pure schema — no I/O. |
| `kyris-core` | `core/` | Shared logic: AgentPact wire helpers, config loading, coverage derivation, fail-open log, pending-approval client (feature-gated). Re-exports `kyris-types`. |
| `kyris-agentpact-client` | `agentpact-client/` | UDS client for `agentpactd`: permission requests, trace attachment, approval responses, with retry + graceful degradation. |
| `kyris-peer-cwd` | `peer-cwd/` | Resolve the CWD of the process owning a localhost TCP connection. Used by `kyrisd` for non-conformant-agent attribution (per `design/kyris.md` §5.14). |

### Binaries

| Crate | Binary | Purpose |
|-------|--------|---------|
| `kyrisd` | `kyrisd` | Local LLM routing proxy. Intercepts agent-to-model traffic, enforces policy, meters usage, writes events to DuckDB. Runs as a `launchd` daemon. |
| `kyris` (cli) | `kyris` | CLI for queries (`timeline`, `replay`, `stats`, `history`), setup (`install`, `enroll`, `agents setup`), policy compilation, lifecycle management, agent hook delegation (`hook check`), always-allow management (`always`), post-install verification (`verify`). |
| `kyris-mcp` | `kyris-mcp` | MCP server wrapper. Wraps an MCP server command, routing tool calls through `agentpactd` for permission checks. |
| `kyris-hook` | `kyris-hook` | Shell hook helper (`hooks/helper/`). Lightweight stdlib-only binary invoked by shell preexec hooks to check/respond to `agentpactd` permission requests. |

### Build helpers (not installed)

| Crate | Binary | Purpose |
|-------|--------|---------|
| `xtask` | `xtask` | Development tasks (e.g., dump `kyrisd.yaml` JSON Schema). Invoked via `cargo xtask <task>`. |

## Key Directories

| Path | Contents |
|------|----------|
| `config/` | Default config template (`default.yaml`), example config, pricing tiers. |
| `service/` | `launchd` plist for `kyrisd` and the `Info.plist.template` used by `scripts/build-app-bundle.sh`. |
| `integrations/` | Compiled-policy templates. `compiled-policy/cline/template.json` is the only static template — adapters for OpenCode, Codex CLI, and Gemini CLI are generated at runtime by `kyris compile-policy`. Live hook adapters (Claude Code, Codex CLI, Gemini CLI) are generated at agent-setup time by `cli/src/agents/configure.rs`. |
| `hooks/` | Shell preexec hooks (`zsh_hook.sh`, `zshenv_hook.sh`, `bash_hook.sh`, `bash_env.sh`) and the `kyris-hook` helper crate (`hooks/helper/`). |
| `scripts/` | Local release helpers: `release-local.sh`, `build-app-bundle.sh`, `build-tar.sh`, `sign-and-notarize.sh`. |
| `install.sh` | Standalone bash installer (the brew-detecting front door — see `forest/design/kyris.md` §6.5). |

## Conventions

- `#![forbid(unsafe_code)]` on all crates (daemon and hook use `cfg_attr(not(test), forbid(...))` for test-only exceptions).
- `#![cfg_attr(test, allow(non_snake_case))]` permits descriptive test names.
- All clippy lints are deny-level in CI (`-D warnings`).
- `cargo deny` enforces license allowlist and advisory audits (see `deny.toml`).
- License header `// SPDX-License-Identifier: Apache-2.0` on every `.rs` file.

## Runtime Paths

File-system layout follows XDG Base Directory. The runtime dir holds only
install-managed scaffolding; user data lives under XDG dirs so uninstall +
reinstall (i.e. upgrade) can wipe the runtime freely without touching keys,
credentials, or event-log history. See `kyris-core/src/paths.rs` for the
single source of truth; honors `KYRIS_HOME`, `XDG_CONFIG_HOME`,
`XDG_DATA_HOME`, and `XDG_STATE_HOME`.

- `127.0.0.1:4710`: `kyrisd` default listen address (HTTP, localhost only)
- `~/.kyris/`: install-managed runtime (manifest, hooks, agents, env,
  backups, installer cache); wiped by `uninstall`
- `~/.kyris/kyrisd.pid`: daemon PID file (runtime ephemera)
- `~/.config/kyris/kyrisd.yaml`: daemon config (user-editable, survives uninstall)
- `~/.local/share/kyris/kyrisd.duckdb`: DuckDB event store (audit history; survives uninstall)
- `~/.local/share/kyris/credentials.json`: sync credentials (survives uninstall)
- `~/.local/state/kyris/log/kyris.log`: daemon's in-process log
- `~/.local/state/kyris/log/kyrisd.stdout.log`: `launchd` stdout
- `~/.local/state/kyris/log/kyrisd.stderr.log`: `launchd` stderr
- `~/.local/state/kyris/crash/`: panic reports
- `~/.local/state/kyris/diagnostics/`: SIGUSR1 JSON dumps
- `~/.local/state/kyris/fail-open.jsonl`: shell-hook spool when daemon unreachable

`install.sh --uninstall` preserves the three XDG dirs by default; pass
`--reset-data` (or `brew uninstall --cask --zap`) to wipe them too.

## Dependencies

Kyris depends on the `agentpact` crate (pinned git dependency at `v0.1.2`) for catalog lookups, policy loading, and protocol types. The `kyris-agentpact-client` crate provides the UDS client for communicating with `agentpactd`; `kyris-peer-cwd` provides OS-level process-CWD resolution for non-conformant-agent attribution. See `forest/design/kyris.md` §3.2 for the full per-crate dependency table.
