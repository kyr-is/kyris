# AGENTS.md

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

Cargo workspace with six crates producing four binaries and two libraries.

### Libraries

| Crate | Path | Purpose |
|-------|------|---------|
| `kyris-types` | `types/` | Shared types: events, pricing tiers, records, config schema, sync protocol |
| `kyris-core` | `core/` | Shared logic: AgentPact client helpers, config loading, coverage derivation. Re-exports `kyris-types` |
| `kyris-agentpact-client` | `agentpact-client/` | UDS client for `agentpactd`: permission requests, trace attachment, approval responses |

### Binaries

| Crate | Binary | Purpose |
|-------|--------|---------|
| `kyrisd` | `kyrisd` | Local LLM routing proxy. Intercepts agent-to-model traffic, enforces policy, meters usage, writes events to DuckDB. Runs as a `launchd` daemon |
| `kyris` (cli) | `kyris` | CLI for queries (`timeline`, `replay`, `stats`, `history`), setup (`install`, `enroll`, `setup`), policy compilation, lifecycle management |
| `kyris-mcp` | `kyris-mcp` | MCP server wrapper. Wraps an MCP server command, routing tool calls through `agentpactd` for permission checks |
| `kyris-hook` | `kyris-hook` | Shell hook helper. Lightweight binary invoked by agent hooks to check/respond to `agentpactd` permission requests |

## Key Directories

| Path | Contents |
|------|----------|
| `config/` | Default config template (`default.yaml`), example config, pricing tiers |
| `service/` | `launchd` plist for `kyrisd` |
| `integrations/` | Agent integration configs: compiled policies (Cline) and live hooks (Claude Code, Codex CLI, Gemini CLI) |
| `docs/` | Integration documentation |

## Conventions

- `#![forbid(unsafe_code)]` on all crates (daemon and hook use `cfg_attr(not(test), forbid(...))` for test-only exceptions).
- `#![cfg_attr(test, allow(non_snake_case))]` permits descriptive test names.
- All clippy lints are deny-level in CI (`-D warnings`).
- `cargo deny` enforces license allowlist and advisory audits (see `deny.toml`).
- License header `// SPDX-License-Identifier: Apache-2.0` on every `.rs` file.

## Runtime Paths

- `127.0.0.1:4710`: `kyrisd` default listen address (HTTP, localhost only)
- `~/.kyris/kyrisd.pid`: daemon PID file
- `~/.kyris/kyrisd.duckdb`: DuckDB event store
- `~/.kyris/kyrisd.yaml`: daemon config
- `~/.kyris/credentials.json`: sync credentials
- `~/.kyris/daemon.stdout.log`: `launchd` stdout
- `~/.kyris/daemon.stderr.log`: `launchd` stderr

## Dependencies

Kyris depends on the `agentpact` crate (local path dependency) for catalog lookups, policy loading, and protocol types. The `agentpact-client` crate provides the UDS client for communicating with `agentpactd`.
