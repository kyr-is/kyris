# Kyris ↔ AgentPact Boundary

This document defines what code belongs in the [agentpact](https://github.com/kyr-is/agentpact) repo vs in this (kyris) repo, and the rules contributors must follow when adding new code on either side. It mirrors the corresponding `BOUNDARY.md` in the agentpact repo.

## The one-way rule

```
Kyris → AgentPact   (Kyris depends on AgentPact)
AgentPact ↛ Kyris   (AgentPact MUST NOT depend on Kyris)
```

Source: `README.md §3.1` ("The main architectural boundary is one-way dependency"), `forest/03-architecture.md:93`.

Concretely:

- Kyris crates may declare `agentpact` as a Cargo dependency.
- No agentpact crate, build script, test, or doc may declare or assume kyris.
- All daemon traffic from kyris to agentpactd goes through `kyris-agentpact-client`. Kyris crates other than `kyris-agentpact-client` must not import `agentpact::protocol::*` or build daemon wire messages directly.
- Kyris may import from agentpact's public API for catalog/policy types (e.g. `agentpact::policy::compound::CompoundResult`) — these are read-only consumers of the standard, not protocol traffic.

## What goes where

| Concern | Owner | Rationale |
|---|---|---|
| Policy format (`pact.yaml`, `caps.yaml`) | agentpact | The open standard. |
| Policy evaluation (allow/ask/deny decision) | agentpact | Daemon decides; everyone else routes. |
| Catalog of known commands & MCP tools | agentpact | Part of the policy contract. |
| Boundary defaults (CWD subtree, sensitive paths, network egress) | agentpact | Factory defaults the daemon applies. |
| Compound command parsing & strictest-wins aggregation | agentpact | Per spec §P-CC-01/02/03. |
| Attribution (process → agent identity, signature table) | agentpact | Spec-defined; lives with the daemon. |
| UDS protocol wire format & response codes | agentpact | The spec itself. |
| Daemon UDS client (request builders, parser, retries) | kyris-agentpact-client | The single, audited path kyris uses to talk to agentpactd. |
| Shell hooks (zsh/bash glue + `kyris-hook` helper) | kyris | Reachable surface; doesn't belong in the standard. |
| Native agent hook adapters (`kyris hook check`) | kyris | Per-agent payload mapping; doesn't belong in the standard. |
| Compiled-policy adapters (Cline, OpenCode, Codex, Gemini) | kyris | Compatibility bridges, not the standard. |
| MCP wrapping (`kyris-mcp` stdio, HTTP MCP routing in `kyrisd`) | kyris | Product surface. |
| LLM gateway / burn control / DuckDB | kyris | Product surface; not in the standard. |
| Approval popup UI (macOS alert from kyrisd) | kyris | See "Deliberate specialization" below. |
| `kyris status`, `timeline`, `replay`, `scan` | kyris | Local evidence UX; not in the standard. |

## Deliberate specialization (not boundary violations)

These cases look like they cross the line but are intentional. Don't "fix" them without re-reading this section.

1. **Kyrisd surfaces its own approval popup on `PACT_ASK`.** Per `agentpact/README.md:1753` (A-PP-03), the *agent* is supposed to prompt. Kyris instead routes Ask through `kyrisd` so the prompt is consistent across all agents and so non-interactive surfaces (shell hooks in no-TTY shells, MCP wrappers) have something to surface. Implementation: `kyris/cli/src/hook_cmd.rs::resolve_ask` → `kyris_core::pending::hold_poll_resolve` → `kyrisd /api/pending/*`.

2. **Compiled-policy adapters render agentpact policy into agent-native permission formats.** They are read-only reflections of policy, not an alternate policy source. Implementation: `kyris/cli/src/compile_policy.rs`.

3. **`kyrisd` records spend in DuckDB.** Until agents emit native AgentPact `usage.report` events for all model traffic, kyrisd's gateway records are the primary spend signal. Long-term these become a convenience cache cross-referenced against the agentpact event log.

4. **`kyris-hook` (`hooks/helper`) builds its `permission.request` / `permission.respond` JSON by hand instead of going through `kyris-agentpact-client`.** This is intentional and load-bearing: the helper sits on the synchronous hot path of *every* governed shell command, so it is deliberately `std`-only — its `Cargo.toml` declares no dependency on `agentpact`, `kyris-agentpact-client`, or `kyris-core` (see the comment at `hooks/helper/src/main.rs` on `MAX_COMMAND_LENGTH_CEILING`). Pulling the client crate (and its transitive `kyris-core`/`agentpact-types`/`uuid` graph) into this binary to satisfy the "only the client builds wire messages" rule would regress hook binary size and startup latency on the per-command hot path — the wrong trade. The duplicated wire shapes are kept from drifting by a real-binary contract test, not by sharing code: `hooks/helper/tests/shell_hook_contract.rs` runs the actual `kyris-hook` binary against a fake agentpactd socket and pins the emitted `permission.request` (method/action/detail/working_dir/exec_token/ppid_chain) and `permission.respond` (method/response/approval_token) shapes; `kyris-hook`'s runtime `check_protocol_version` guards version drift. If you change the wire shape on either side, that contract test is the tripwire. **This is the sole sanctioned exception to the "route through `kyris-agentpact-client`" rule; widening it requires a reviewer sign-off and a new entry here.**

## Rules for contributors

When adding code, ask in order:

1. **Is this policy?** (Decides whether an action proceeds.) → agentpact.
2. **Is this protocol?** (Wire format with agentpactd.) → agentpact, exposed through kyris-agentpact-client.
3. **Is this attribution?** (Who/what is asking?) → agentpact.
4. **Is this a reachable surface?** (Shell, MCP, model traffic, native hook.) → kyris.
5. **Is this evidence / inspection UX?** (Timeline, replay, stats, scan, popup.) → kyris.
6. **Is this configuration drift / install state?** → kyris.

If you find yourself building a JSON request that goes over the agentpactd socket from anywhere other than `kyris-agentpact-client`, stop and route it through `kyris-agentpact-client` instead. The single sanctioned exception is `kyris-hook` (`hooks/helper`), for the stdlib-only hot-path reason documented under "Deliberate specialization" above — and even there the wire shapes are pinned by a real-binary contract test.

## Enforcement

The one-way rule is enforced by two complementary checks in `.github/workflows/ci.yml`:

- **Module-import rule (the source grep).** `cargo deny` governs the dependency *graph* — which crates may link — but cannot express "only `kyris-agentpact-client` may import the `agentpact::protocol` *module*", because that is a source-path rule, not a graph edge. So the CI job `Boundary check (agentpact::protocol)` greps the source: `grep -rn 'agentpact::protocol' --include='*.rs' cli daemon mcp hooks core` must be empty except for the single allowlisted file below. It runs before the toolchain steps (it needs only the checkout) and fails the build on any new hit. Other kyris crates may still use `agentpact::policy::*` and `agentpact::catalog::*` (read-only types) and `agentpact::attribution::signatures::SignatureTable` (read-only signature data) — those are not `agentpact::protocol`.
  - **Allowlisted exception:** `daemon/tests/wire_contract.rs` imports `agentpact::protocol::types` on purpose, to pin kyris's wire spellings against the upstream protocol types. It is a contract test, not traffic. The grep excludes exactly this path; widening the allowlist requires a reviewer sign-off and a note here.
- **Dependency graph (`cargo deny check`).** `deny.toml` pins the allowed git source for `agentpact` (`allow-git`) and bans duplicate/yanked crates, keeping the linked graph honest. This is the graph-level half of the boundary.
- New kyris crates default to: agentpact dep allowed, `agentpact::protocol` disallowed (the grep covers them once their directory is added to the scan list). Override only with reviewer sign-off and a note here.

## Known gaps tracked elsewhere

- `kyris/cli/src/hook_cmd/hold.rs::discover_agent_pid` walks process ancestors using `agentpact::attribution::signatures::SignatureTable` inside kyris. The long-term home for this loop is agentpactd (kyris sends its own PID via `seed_boundary_pid` and the daemon does the walk). Tracked in the audit plan (P1.1/P1.2).

`core/src/agentpact.rs` no longer holds wire-message builders or a parser — those live in `kyris-agentpact-client`. What remains there is read-only value types (`Mode` re-export, `McpPermissionDecision`, `ApprovalResponse`, `McpContext`), approval-popup presentation (`format_ask_context`, kyris owns the UX), and the `default_socket_path` helper — none of which construct or interpret wire messages. The earlier "vestigial split" gap is closed.
