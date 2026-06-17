# Contributing To Kyris

Kyris is building local governance infrastructure for AI agents. Good contributions make agent autonomy safer, clearer, faster to operate, or easier to extend without blurring the boundary between Kyris and AgentPact.

## Contributor License Agreement

All contributors must sign the [Kyris CLA](CLA.md). The CLA bot will prompt you on your first pull request.

## Before You Start

Read these first:

- [AGENTS.md](AGENTS.md) for repository-local engineering rules, crate layout, build commands, and runtime paths.
- [BOUNDARY.md](BOUNDARY.md) for project boundaries.

Docs may lag current implementation, so verify design intent against code and tests before making behavioral changes.

## Development Setup

Kyris is a Rust workspace. MSRV is 1.95, pinned in `rust-toolchain.toml`.

The current implementation and release process are macOS-first. Do not treat macOS as the permanent product boundary: Kyris is intended to support Windows and Linux in future releases. When adding platform-sensitive code, isolate platform behavior behind clear modules or traits and keep runtime paths, service management, shell integration, and process inspection portable where practical.

Kyris depends on [AgentPact](https://github.com/kyr-is/agentpact), the open governance contract it builds on. For local development you can check it out as a sibling directory (`../agentpact`); see [Local Dependency Mode](#local-dependency-mode) below.

The workspace currently contains:

| Path | Crate / Binary | Purpose |
| --- | --- | --- |
| `types/` | `kyris-types` | Shared schema and serialization types. |
| `core/` | `kyris-core` | Shared config, path, coverage, and AgentPact helpers. |
| `agentpact-client/` | `kyris-agentpact-client` | UDS client for `agentpactd`. |
| `daemon/` | `kyrisd` | Local routing proxy, storage, approvals, notifications, and sync. |
| `cli/` | `kyris` | CLI for setup, status, activity, policy, diagnostics, lifecycle, and agent integration. |
| `mcp/` | `kyris-mcp` | Stdio MCP wrapper. |
| `hooks/helper/` | `kyris-hook` | Shell hook helper binary. |
| `peer-cwd/` | `kyris-peer-cwd` | Resolve CWD for localhost peer processes. |
| `exec/` | `kyris-exec` | Execution helper. |
| `xtask/` | `xtask` | Development helper tasks. |

## Local Dependency Mode

Kyris depends on AgentPact. Release builds should use the intended pinned AgentPact dependency. Local development may use a sibling-path patch to `../agentpact` so changes can be tested across both repos.

Before touching AgentPact-related behavior, check `Cargo.toml` and confirm whether the workspace is using pinned dependencies or the local dev patch. Do not accidentally commit dependency mode churn as part of an unrelated change.

## Build And Test

Run the standard local checks before opening a PR:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

For daemon-sensitive changes, also run:

```sh
cargo bench -p kyrisd -- --test
```

Use package-specific tests while iterating, then run the full checks before you are done.

## Code Standards

- Keep code simple and closely scoped to the behavior being changed.
- Keep `#![forbid(unsafe_code)]` expectations intact.
- Keep clippy warning-free under the repository's deny-level settings.
- Use SPDX headers on Rust source files.
- Put operator-tunable defaults, knobs, catalogs, and pattern lists in YAML under `config/` rather than hardcoding them in Rust.
- Keep shell scripts thin. Rust binaries should own protocol parsing and decision logic.
- Keep provider adapters as provider-native passthrough paths. Do not introduce a broad provider-normalization layer without a design update.
- Keep coverage claims path-based. If Kyris is not on the path, do not report preventive enforcement.

## Architecture Boundaries

Kyris depends on AgentPact; AgentPact must not depend on Kyris.

Use this split when deciding where code belongs:

| Area | Belongs in |
| --- | --- |
| Portable policy semantics, protocol types, event schema, conformance vocabulary | `agentpact` |
| Kyris local install, setup, agent adapters, CLI UX, model routing, local storage, sync | `kyris` (this repo) |

When a change alters design intent, call out the needed doc update in the PR.

## Working On Agent Integrations

Agent support should stay descriptor-driven and shared-code-heavy. Prefer adding declarative behavior to the agent descriptor over creating one-off setup logic.

When changing or adding an agent integration:

- Identify the available execution, tool, and burn-control surfaces.
- Prefer live mediation when the agent exposes a reliable hook.
- Treat compiled policy as a compatibility bridge, not the destination.
- Keep unknown or unmapped actions conservative when the agent has no native backstop.
- Update setup, disconnect, status, and probe behavior together.
- Add tests that verify generated files, rollback, status reporting, and coverage evidence.
- Update the README support table when user-visible coverage changes.

Phase 1 supported agents are Claude Code, Cline, OpenCode, Codex CLI, and Gemini CLI.

## Working On Policy Or Governance Behavior

AgentPact owns portable policy semantics. Kyris should route actions to AgentPact and present useful local operator UX around those decisions.

When changing policy or governance behavior:

- Keep allow / ask / deny semantics aligned with AgentPact.
- Update config schema and YAML defaults when behavior becomes operator-tunable.
- Include degraded-mode and daemon-unavailable behavior in tests.
- Keep event and coverage reporting honest.
- Update user docs when visible behavior changes.

## Working On Installers And Runtime Paths

Kyris follows XDG Base Directory conventions for user data and uses `~/.kyris/` for install-managed runtime scaffolding.

Important paths:

| Path | Purpose |
| --- | --- |
| `~/.kyris/` | Runtime scaffolding managed by install/setup. |
| `~/.config/kyris/kyrisd.yaml` | User-editable config. |
| `~/.local/share/kyris/kyrisd.duckdb` | Local record store. |
| `~/.local/share/kyris/credentials.json` | Enrollment credentials. |
| `~/.local/state/kyris/log/` | Logs. |
| `~/.local/state/kyris/fail-open.jsonl` | Fail-open spool. |

Installer changes should preserve channel parity between Homebrew and the script path where practical. Normal uninstall should preserve user data; reset / zap paths may remove it.

## Testing Expectations

Keep test coverage proportional to risk.

- Unit tests belong with the crate that owns the behavior.
- CLI setup and rollback changes need integration tests under `cli/tests/`.
- Daemon wire behavior should be covered under `daemon/tests/` or focused module tests.
- MCP wrapper behavior should be covered under `mcp/tests/`.
- Agent integration changes should test generated config, undo behavior, and status/probe output.

For install/setup/agent work, also do a manual smoke test on a clean or disposable local profile when possible.

## Pull Requests

Before opening a PR:

- Run `cargo fmt --check`.
- Run `cargo clippy --all-targets -- -D warnings`.
- Run `cargo test`.
- Run `cargo deny check`.
- Update README when user-facing behavior, install flow, agent support, or architecture-guide content changes.
- Update CONTRIBUTING when contributor workflow, build/test commands, or mechanical conventions change.
- Keep unrelated formatting and dependency churn out of the PR.

All PRs must pass CI checks.

## Security

Do not include secrets, provider keys, private prompts, sensitive file paths, or full local audit logs in issues or PRs. Kyris records can contain command arguments, tool inputs, paths, prompts, and provider metadata.

Report security issues through the process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
