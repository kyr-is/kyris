// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Unit tests for the hook adapter. References items from every submodule
//! through the re-exports in `hook_cmd.rs`, so it keeps `use super::*`.

use super::*;

// --- workspace anchor resolution (`derive_session_cwd`) ---

#[test]
fn testDeriveSessionCwdPrefersLaunchDirOverPayloadCwd() {
    // The fixed launch dir (from launch_dir_env) wins over the payload cwd,
    // which for Claude Code is the mutable live cwd that must NOT anchor the
    // permitted domain.
    let input = serde_json::json!({ "cwd": "/live/cwd/after/cd" });
    assert_eq!(
        derive_session_cwd(Some("/project/root"), &input),
        Some("/project/root".to_string())
    );
}

#[test]
fn testDeriveSessionCwdFallsBackToPayloadCwd() {
    // No launch dir (agents whose payload cwd is already fixed, e.g. Codex).
    let input = serde_json::json!({ "cwd": "/session/launch/dir" });
    assert_eq!(
        derive_session_cwd(None, &input),
        Some("/session/launch/dir".to_string())
    );
}

#[test]
fn testDeriveSessionCwdBlankLaunchDirFallsThrough() {
    let input = serde_json::json!({ "cwd": "/payload/cwd" });
    assert_eq!(
        derive_session_cwd(Some("   "), &input),
        Some("/payload/cwd".to_string())
    );
}

#[test]
fn testDeriveSessionCwdUnknownIsNoneNotProcessCwd() {
    // No launch dir and no payload cwd → None. Critically, we do NOT fall
    // back to the hook process's current_dir(), which would anchor the
    // domain to the wrong tree; agentpactd fails safe on a None workspace.
    let input = serde_json::json!({ "tool_name": "Bash" });
    assert_eq!(derive_session_cwd(None, &input), None);
}

#[test]
fn testLaunchDirEnvWiredForLiveHookAgents() {
    use crate::agents::registry;
    // Claude Code's payload cwd is mutable → must use CLAUDE_PROJECT_DIR.
    assert_eq!(
        registry::agent_by_id("claude-code")
            .and_then(|a| a.launch_dir_env())
            .as_deref(),
        Some("CLAUDE_PROJECT_DIR")
    );
    assert_eq!(
        registry::agent_by_id("gemini-cli")
            .and_then(|a| a.launch_dir_env())
            .as_deref(),
        Some("GEMINI_PROJECT_DIR")
    );
    // Codex's payload cwd is already the fixed session dir → no env needed.
    assert_eq!(
        registry::agent_by_id("codex-cli").and_then(|a| a.launch_dir_env()),
        None
    );
}

// --- per-segment aggregation driver (`run_segments`) ---
//
// Pure logic, exercised with canned classifications/popup results so
// the all-allow / any-deny / short-circuit behavior is covered without
// a live daemon or popup.

fn seg_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

// --- read_tty_line: unbuffered, no cross-prompt over-read ---

#[test]
fn testReadTtyLineReturnsSingleLineWithNewline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tty");
    std::fs::write(&path, "always\n").unwrap();
    let f = std::fs::File::open(&path).unwrap();
    assert_eq!(read_tty_line(&f).as_deref(), Some("always\n"));
}

#[test]
fn testReadTtyLineDoesNotOverReadAcrossCalls() {
    // Two answers queued on one handle: the first read must stop at the
    // first newline and leave the second answer for the next prompt.
    // A BufReader would swallow the second line — this guards that.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tty");
    std::fs::write(&path, "y\nn\n").unwrap();
    let f = std::fs::File::open(&path).unwrap();
    assert_eq!(read_tty_line(&f).as_deref(), Some("y\n"));
    assert_eq!(read_tty_line(&f).as_deref(), Some("n\n"));
}

#[test]
fn testReadTtyLineEmptyIsNone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tty");
    std::fs::write(&path, "").unwrap();
    let f = std::fs::File::open(&path).unwrap();
    assert_eq!(read_tty_line(&f), None);
}

#[test]
fn testRunSegmentsAllAutoAllows() {
    // Every segment auto-allows → no popup invoked, allow.
    let segs = seg_vec(&["cat hello.txt", "grep hi"]);
    let mut prompted = 0;
    let result = run_segments(
        &segs,
        |_seg| SegClass::Auto,
        |_id, _tok, _seg, _allow, _detail| {
            prompted += 1;
            PopupResult::Approved {
                source: "user_approved",
            }
        },
    );
    assert_eq!(result.unwrap(), "agentpact_auto");
    assert_eq!(prompted, 0, "auto segments must not prompt");
}

#[test]
fn testRunSegmentsPromptsOnlyAskSegments() {
    // Mixed: only the unclassified segment is prompted; approval allows.
    // Also asserts the per-segment `allow_always` propagates to the prompt.
    let segs = seg_vec(&["cat hello.txt", "mystery-bin"]);
    let mut prompted = Vec::new();
    let mut prompted_allow_always = None;
    let result = run_segments(
        &segs,
        |seg| {
            if seg == "mystery-bin" {
                SegClass::Ask {
                    approval_id: "apr_1".to_string(),
                    approval_token: "tok_1".to_string(),
                    allow_always: true,
                    detail: None,
                }
            } else {
                SegClass::Auto
            }
        },
        |_id, _tok, seg, allow_always, _detail| {
            prompted.push(seg.to_string());
            prompted_allow_always = Some(allow_always);
            PopupResult::Approved {
                source: "user_approved",
            }
        },
    );
    assert_eq!(result.unwrap(), "user_approved");
    assert_eq!(prompted, vec!["mystery-bin".to_string()]);
    assert_eq!(prompted_allow_always, Some(true));
}

#[test]
fn testRunSegmentsDeniedSegmentBlocksAndShortCircuits() {
    // First segment's popup is denied → block, and the later segment is
    // never classified (short-circuit: the agent runs it as a unit).
    let segs = seg_vec(&["mystery-bin", "later-seg"]);
    let mut classified = Vec::new();
    let result = run_segments(
        &segs,
        |seg| {
            classified.push(seg.to_string());
            SegClass::Ask {
                approval_id: "a".to_string(),
                approval_token: "t".to_string(),
                allow_always: false,
                detail: None,
            }
        },
        |_id, _tok, _seg, _allow, _detail| PopupResult::Blocked {
            exit_code: 2,
            source: "user_denied",
            reason: "nope".to_string(),
        },
    );
    let block = result.unwrap_err();
    assert_eq!(block.exit_code, 2);
    assert_eq!(block.source, "user_denied");
    assert_eq!(
        classified,
        vec!["mystery-bin".to_string()],
        "must stop at the first denied segment"
    );
}

#[test]
fn testRunSegmentsPolicyDenyBlocks() {
    let segs = seg_vec(&["rm -rf /"]);
    let result = run_segments(
        &segs,
        |_seg| SegClass::Deny {
            reason: "blocked by policy".to_string(),
        },
        |_id, _tok, _seg, _allow, _detail| unreachable!("deny must not prompt"),
    );
    let block = result.unwrap_err();
    assert_eq!(block.source, "agentpact_deny");
    assert_eq!(block.reason, "blocked by policy");
}

#[test]
fn testRunSegmentsUnavailableBlocksAsDaemonUnreachable() {
    // The decider being down is reported as an `agentpact_unreachable`
    // block; run_segments itself never fails open or closed — the caller
    // (agent hook → defer, shell → fail open) decides what unavailability
    // means. `block_from_daemon_unavailable` recognizes this source.
    let segs = seg_vec(&["cmd"]);
    let result = run_segments(
        &segs,
        |_seg| SegClass::Unavailable {
            reason: "daemon down".to_string(),
        },
        |_id, _tok, _seg, _allow, _detail| unreachable!(),
    );
    let block = result.unwrap_err();
    assert_eq!(block.source, "agentpact_unreachable");
    assert!(block_from_daemon_unavailable(block.source));
}

#[test]
fn testAgentPromptForJsonShapeUsesDeclaredEffectNotShape() {
    // G2: emitting a JSON allow does not by itself silence the agent.
    // Claude's permissionDecision:allow genuinely suppresses its prompt
    // (suppresses=true → "none"); Gemini parses its {"decision":"allow"}
    // but prompts anyway (suppresses=false → "agent_decides"). The audit
    // must reflect the EFFECT, not the shape.
    let json = AllowResponse::Json {
        body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
    };
    assert_eq!(agent_prompt_for(&json, true), "none");
    assert_eq!(agent_prompt_for(&json, false), "agent_decides");
}

#[test]
fn testAgentPromptForEmptyStdoutDefersToAgent() {
    // EmptyStdout is "no decision" everywhere — the agent's own permission
    // rules apply regardless of any declared suppression flag.
    assert_eq!(
        agent_prompt_for(&AllowResponse::EmptyStdout, false),
        "agent_decides"
    );
    assert_eq!(
        agent_prompt_for(&AllowResponse::EmptyStdout, true),
        "agent_decides"
    );
}

#[test]
fn testAgentPromptMatchesEachAgentsVerifiedAllowEffect() {
    // Lock the per-agent audit value to the upstream-verified effects:
    // only Claude Code's allow shape actually suppresses its prompt.
    for (id, expected) in [
        ("claude-code", "none"),
        ("gemini-cli", "agent_decides"),
        ("codex-cli", "agent_decides"),
        ("cline", "agent_decides"),
        ("opencode", "agent_decides"),
    ] {
        let proto = registry::agent_by_id(id)
            .expect("known agent")
            .hook_protocol()
            .expect("hook protocol");
        assert_eq!(
            agent_prompt_for(
                &proto.allow_response,
                proto.runtime.allow_suppresses_agent_prompt
            ),
            expected,
            "agent_prompt audit value for {id}"
        );
    }
}

#[test]
fn testEffectiveAllowResponseEnforceModePreservesNativeJsonShape() {
    // When kyris is enforcing, Claude Code / Gemini CLI must get
    // their native JSON allow shape so kyris's "approved by
    // AgentPact policy" decision skips the agent's own prompt.
    let native = AllowResponse::Json {
        body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
    };
    match effective_allow_response(&native, false) {
        AllowResponse::Json { body } => {
            assert_eq!(
                body["hookSpecificOutput"]["permissionDecision"],
                serde_json::json!("allow")
            );
        }
        AllowResponse::EmptyStdout => {
            panic!("enforce mode must preserve the agent's native Json shape");
        }
    }
}

#[test]
fn testEffectiveAllowResponseLogModeForcesEmptyStdout() {
    // The whole point of this helper: in log mode the agent must
    // get to apply its own permission rules. Emitting the Json
    // "allow" shape would suppress Claude Code's prompt and
    // silently approve every command — the bug we're guarding
    // against.
    let native = AllowResponse::Json {
        body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
    };
    assert!(matches!(
        effective_allow_response(&native, true),
        AllowResponse::EmptyStdout
    ));
}

#[test]
fn testEffectiveAllowResponseLogModeKeepsEmptyStdoutAsEmptyStdout() {
    // Agents whose native shape is already EmptyStdout (Codex
    // CLI) shouldn't change behavior in log mode — it's the same
    // shape either way. Test guards against a future refactor
    // accidentally producing a different value.
    let native = AllowResponse::EmptyStdout;
    assert!(matches!(
        effective_allow_response(&native, true),
        AllowResponse::EmptyStdout
    ));
    assert!(matches!(
        effective_allow_response(&native, false),
        AllowResponse::EmptyStdout
    ));
}

#[test]
fn testAuditAgentPromptReflectsEffectiveResponseInLogMode() {
    // Audit log honesty: when kyris hands the decision back to
    // the agent (log mode), the audit field must say
    // "agent_decides" — not "none" (which would imply kyris
    // suppressed the prompt).
    let native = AllowResponse::Json {
        body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
    };
    let effective = effective_allow_response(&native, true);
    // Suppression is declared true here, but the effective shape in log
    // mode is EmptyStdout — the agent still decides.
    assert_eq!(agent_prompt_for(&effective, true), "agent_decides");
}

#[test]
fn testNonGovernedUnmappedDefersToAgentEvenInEnforce() {
    // The P0 fix: an unmapped tool must NEVER get the agent's native allow
    // shape (which suppresses the agent's own prompt and silently approves
    // an unknown tool). It gets EmptyStdout — "no decision" — so the
    // agent's own permission system decides, as if kyris weren't installed.
    let native = AllowResponse::Json {
        body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
    };
    assert!(matches!(
        non_governed_response(false, &native, false),
        AllowResponse::EmptyStdout
    ));
    // Same in log mode — unmapped is always defer.
    assert!(matches!(
        non_governed_response(false, &native, true),
        AllowResponse::EmptyStdout
    ));
    // Even when the agent's native shape is already EmptyStdout (Codex).
    assert!(matches!(
        non_governed_response(false, &AllowResponse::EmptyStdout, false),
        AllowResponse::EmptyStdout
    ));
}

#[test]
fn testNonGovernedPassThroughSuppressesAgentPromptInEnforce() {
    // Blessed primitives keep the frictionless behavior: in enforce mode
    // they get the agent's native allow shape (suppressing its prompt),
    // and in log mode they defer like everything else.
    let native = AllowResponse::Json {
        body: serde_json::json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
    };
    match non_governed_response(true, &native, false) {
        AllowResponse::Json { body } => assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            serde_json::json!("allow")
        ),
        AllowResponse::EmptyStdout => {
            panic!("pass-through in enforce must keep the native allow shape")
        }
    }
    assert!(matches!(
        non_governed_response(true, &native, true),
        AllowResponse::EmptyStdout
    ));
}

/// Neutral runtime contract for synthetic test protocols (backstopped,
/// 600s window) — the per-agent declared values are exercised via
/// `agent_protocol` below and locked in registry tests.
fn test_runtime() -> crate::agents::registry::HookRuntime {
    crate::agents::registry::HookRuntime {
        agent_hook_timeout_secs: 600,
        on_timeout: crate::agents::registry::HookTimeoutPosture::FailOpen,
        native_backstop: true,
        allow_suppresses_agent_prompt: false,
    }
}

#[test]
fn testMapPayloadWithoutProtocol() {
    let input = serde_json::json!({"method": "execute", "detail": "git status"});
    let (action, detail) = map_payload(None, &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "git status");
}

#[test]
fn testMapPayloadStringDetail() {
    let protocol = HookProtocol {
        tool_name_field: "tool_name".to_string(),
        detail_fields: vec!["tool_input".to_string()],
        tool_mappings: vec![ToolMapping {
            tool_name: "Bash".to_string(),
            action: "execute".to_string(),
            detail_key: Some("command".to_string()),
        }],
        pass_through_tools: Vec::new(),
        agent_owned_tools: Vec::new(),
        default_action: "call".to_string(),
        allow_response: AllowResponse::EmptyStdout,
        runtime: test_runtime(),
        permission_request_allow: None,
        mcp_tool_naming: None,
        native_ask: None,
    };
    let input = serde_json::json!({"tool_name": "Bash", "tool_input": "ls -la"});
    let (action, detail) = map_payload(Some(&protocol), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "ls -la");
}

#[test]
fn testMapPayloadStructuredDetailWithKey() {
    let protocol = HookProtocol {
        tool_name_field: "tool_name".to_string(),
        detail_fields: vec!["tool_input".to_string()],
        tool_mappings: vec![ToolMapping {
            tool_name: "Bash".to_string(),
            action: "execute".to_string(),
            detail_key: Some("command".to_string()),
        }],
        pass_through_tools: Vec::new(),
        agent_owned_tools: Vec::new(),
        default_action: "call".to_string(),
        allow_response: AllowResponse::EmptyStdout,
        runtime: test_runtime(),
        permission_request_allow: None,
        mcp_tool_naming: None,
        native_ask: None,
    };
    let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp"}});
    let (action, detail) = map_payload(Some(&protocol), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "rm -rf /tmp");
}

#[test]
fn testMapPayloadStructuredDetailFallbackJson() {
    let protocol = HookProtocol {
        tool_name_field: "tool_name".to_string(),
        detail_fields: vec!["tool_input".to_string()],
        tool_mappings: vec![ToolMapping {
            tool_name: "CustomTool".to_string(),
            action: "call".to_string(),
            detail_key: None,
        }],
        pass_through_tools: Vec::new(),
        agent_owned_tools: Vec::new(),
        default_action: "call".to_string(),
        allow_response: AllowResponse::EmptyStdout,
        runtime: test_runtime(),
        permission_request_allow: None,
        mcp_tool_naming: None,
        native_ask: None,
    };
    let input = serde_json::json!({"tool_name": "CustomTool", "tool_input": {"foo": "bar"}});
    let (action, detail) = map_payload(Some(&protocol), &input);
    assert_eq!(action, "call");
    assert_eq!(detail, r#"{"foo":"bar"}"#);
}

#[test]
fn testMapPayloadDefaultAction() {
    let protocol = HookProtocol {
        tool_name_field: "tool_name".to_string(),
        detail_fields: vec!["tool_input".to_string()],
        tool_mappings: vec![],
        pass_through_tools: Vec::new(),
        agent_owned_tools: Vec::new(),
        default_action: "call".to_string(),
        allow_response: AllowResponse::EmptyStdout,
        runtime: test_runtime(),
        permission_request_allow: None,
        mcp_tool_naming: None,
        native_ask: None,
    };
    let input = serde_json::json!({"tool_name": "Read", "tool_input": "/tmp/file"});
    let (action, detail) = map_payload(Some(&protocol), &input);
    assert_eq!(action, "call");
    assert_eq!(detail, "/tmp/file");
}

#[test]
fn testMapPayloadMissingFields() {
    let input = serde_json::json!({});
    let (action, detail) = map_payload(None, &input);
    assert_eq!(action, "call");
    assert_eq!(detail, "");
}

fn agent_protocol(id: &str) -> HookProtocol {
    registry::agent_by_id(id)
        .expect("agent exists")
        .hook_protocol()
        .expect("agent has hook protocol")
}

// --- Claude Code real payload fixtures ---

#[test]
fn testClaudeCodeBashStringPayload() {
    let proto = agent_protocol("claude-code");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "git diff --stat"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "git diff --stat");
}

#[test]
fn testClaudeCodeReadFilePayload() {
    let proto = agent_protocol("claude-code");
    let input = serde_json::json!({
        "tool_name": "Read",
        "tool_input": {"file_path": "/home/user/project/src/main.rs"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "read");
    assert_eq!(detail, "/home/user/project/src/main.rs");
}

#[test]
fn testClaudeCodeWriteFilePayload() {
    let proto = agent_protocol("claude-code");
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": {"file_path": "/tmp/output.txt", "content": "hello"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "write");
    assert_eq!(detail, "/tmp/output.txt");
}

#[test]
fn testClaudeCodeEditFilePayload() {
    let proto = agent_protocol("claude-code");
    let input = serde_json::json!({
        "tool_name": "Edit",
        "tool_input": {"file_path": "/home/user/lib.rs", "old_string": "foo", "new_string": "bar"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "write");
    assert_eq!(detail, "/home/user/lib.rs");
}

#[test]
fn testClaudeCodeLowercaseBashVariant() {
    let proto = agent_protocol("claude-code");
    let input = serde_json::json!({
        "tool_name": "bash",
        "tool_input": {"command": "npm test"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "npm test");
}

#[test]
fn testClaudeCodeUnknownToolDefaultsToCall() {
    let proto = agent_protocol("claude-code");
    let input = serde_json::json!({
        "tool_name": "WebSearch",
        "tool_input": {"query": "rust async"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "call");
    assert_eq!(detail, r#"{"query":"rust async"}"#);
}

// --- Codex CLI real payload fixtures ---

#[test]
fn testCodexCliBashPayload() {
    let proto = agent_protocol("codex-cli");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "cargo build --release"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "cargo build --release");
}

#[test]
fn testCodexCliShellSnapshotIsNoLongerExempt() {
    // Current codex spawns snapshot capture directly (no hook fires), so
    // the old `.codex/shell_snapshots/` substring exemption — and the
    // whole DetailPassThrough mechanism it justified — is gone. A command
    // merely MENTIONING the snapshot dir maps to a plain governed execute.
    let proto = agent_protocol("codex-cli");
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf ~ # .codex/shell_snapshots/"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "rm -rf ~ # .codex/shell_snapshots/");
}

#[test]
fn testCodexCliApplyPatchPayloadMapsToPatchAction() {
    // Review Finding 10: the patch envelope is parsed into per-file
    // decisions (drive_apply_patch), not treated as one write whose "path"
    // is the whole patch text.
    let proto = agent_protocol("codex-cli");
    let input = serde_json::json!({
        "tool_name": "apply_patch",
        "tool_input": {"command": "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-old\n+new\n*** End Patch"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "apply_patch");
    assert!(detail.contains("*** Update File: src/lib.rs"));
}

#[test]
fn testParseApplyPatchPathsSplitsWritesAndDeletes() {
    let patch = "*** Begin Patch\n\
                     *** Add File: new/thing.rs\n\
                     +content\n\
                     *** Update File: src/lib.rs\n\
                     *** Move to: src/renamed.rs\n\
                     @@\n\
                     -a\n\
                     +b\n\
                     *** Delete File: old/junk.rs\n\
                     *** End Patch";
    let parsed = parse_apply_patch_paths(patch);
    assert_eq!(
        parsed.writes,
        vec!["new/thing.rs", "src/lib.rs", "src/renamed.rs"]
    );
    assert_eq!(parsed.deletes, vec!["old/junk.rs"]);
}

#[test]
fn testParseApplyPatchPathsEmptyForNonPatchText() {
    // No markers → unparseable; the caller defers/denies, never guesses.
    let parsed = parse_apply_patch_paths("--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-o\n+n");
    assert!(parsed.writes.is_empty() && parsed.deletes.is_empty());
    // Diff body lines mentioning markers must not count: added lines
    // (+-prefixed) and space-prefixed CONTEXT lines — a patch updating a
    // file whose content cites the grammar must not grow phantom paths.
    let parsed = parse_apply_patch_paths("+ say '*** Delete File: x' loudly");
    assert!(parsed.deletes.is_empty());
    let parsed = parse_apply_patch_paths(
        "*** Update File: docs/grammar.md\n @@\n *** Delete File: example.rs\n",
    );
    assert_eq!(parsed.writes, vec!["docs/grammar.md"]);
    assert!(parsed.deletes.is_empty());
}

#[test]
fn testCodexPermissionRequestAllowBodyMatchesUpstreamContract() {
    // Verified upstream shape (hooks/src/schema.rs): camelCase,
    // hookSpecificOutput.decision.behavior, deny_unknown_fields.
    let proto = agent_protocol("codex-cli");
    let body = proto
        .permission_request_allow
        .expect("codex declares the PermissionRequest integration");
    assert_eq!(
        body["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
    assert_eq!(body["hookSpecificOutput"]["decision"]["behavior"], "allow");
    // Exactly these fields — upstream rejects unknown ones.
    assert_eq!(body.as_object().unwrap().len(), 1);
    assert_eq!(body["hookSpecificOutput"].as_object().unwrap().len(), 2);
    assert_eq!(
        body["hookSpecificOutput"]["decision"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn testCodexCliUnknownToolDefaultsToCall() {
    let proto = agent_protocol("codex-cli");
    let input = serde_json::json!({
        "tool_name": "browser",
        "tool_input": {"url": "https://example.com"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "call");
    assert_eq!(detail, r#"{"url":"https://example.com"}"#);
}

// --- Gemini CLI real payload fixtures ---

#[test]
fn testGeminiCliShellPayload() {
    let proto = agent_protocol("gemini-cli");
    let input = serde_json::json!({
        "tool_name": "run_shell_command",
        "tool_input": {"command": "python3 -m pytest"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "execute");
    assert_eq!(detail, "python3 -m pytest");
}

#[test]
fn testGeminiCliReadFilePayload() {
    let proto = agent_protocol("gemini-cli");
    let input = serde_json::json!({
        "tool_name": "read_file",
        "tool_input": {"file_path": "/home/user/package.json"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "read");
    assert_eq!(detail, "/home/user/package.json");
}

#[test]
fn testGeminiCliWriteFilePayload() {
    let proto = agent_protocol("gemini-cli");
    let input = serde_json::json!({
        "tool_name": "write_file",
        "tool_input": {"file_path": "/home/user/output.ts", "content": "new code"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "write");
    assert_eq!(detail, "/home/user/output.ts");
}

#[test]
fn testGeminiCliReplacePayload() {
    let proto = agent_protocol("gemini-cli");
    let input = serde_json::json!({
        "tool_name": "replace",
        "tool_input": {"file_path": "/home/user/index.ts", "old_text": "foo", "new_text": "bar"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "write");
    assert_eq!(detail, "/home/user/index.ts");
}

// --- cwd / relative-path resolution (P4) ---

#[test]
fn testResolveRelativePathAbsoluteUnchanged() {
    let out = resolve_relative_path("read", "/abs/foo.txt", Some("/proj"));
    assert_eq!(out, "/abs/foo.txt");
}

#[test]
fn testResolveRelativePathReadJoinsCwd() {
    let out = resolve_relative_path("read", "src/main.rs", Some("/proj"));
    assert_eq!(out, "/proj/src/main.rs");
}

#[test]
fn testResolveRelativePathWriteJoinsCwd() {
    let out = resolve_relative_path("write", "out.txt", Some("/proj"));
    assert_eq!(out, "/proj/out.txt");
}

#[test]
fn testResolveRelativePathExecutePassesThrough() {
    // Execute details are commands, not paths — never rewrite them.
    let out = resolve_relative_path("execute", "ls -la", Some("/proj"));
    assert_eq!(out, "ls -la");
}

#[test]
fn testResolveRelativePathNoCwdPassesThrough() {
    let out = resolve_relative_path("read", "src/main.rs", None);
    assert_eq!(out, "src/main.rs");
}

#[test]
fn testHookPayloadCwdParsedPreferredOverEnv() {
    // Sanity: the payload's cwd field must be a string and non-empty.
    // The actual env-vs-payload selection logic lives in run_check;
    // here we just confirm the JSON path used to extract it.
    let input = serde_json::json!({
        "cwd": "/Users/alex/proj",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/main.rs"}
    });
    assert_eq!(
        input.get("cwd").and_then(|v| v.as_str()),
        Some("/Users/alex/proj")
    );
}

#[test]
fn testGeminiCliUnknownToolDefaultsToCall() {
    let proto = agent_protocol("gemini-cli");
    let input = serde_json::json!({
        "tool_name": "google_search",
        "tool_input": {"query": "rust async runtime"}
    });
    let (action, detail) = map_payload(Some(&proto), &input);
    assert_eq!(action, "call");
    assert_eq!(detail, r#"{"query":"rust async runtime"}"#);
}

#[test]
fn testDaemonUnavailableSourcesNeverBlockTheDeveloper() {
    // A daemon being unavailable — the decider (agentpactd) down, or kyrisd
    // unable to render an ask — never blocks: the agent hook defers, the
    // shell gate fails open. No operator flag gates this anymore.
    assert!(
        block_from_daemon_unavailable("kyrisd_unreachable"),
        "kyrisd down (can't render ask) must hand back to the agent"
    );
    assert!(
        block_from_daemon_unavailable("agentpact_unreachable"),
        "agentpactd down (no decider) must hand back to the agent"
    );
    // Genuine decisions always block — they are not unavailability.
    for source in [
        "agentpact_deny",
        "user_denied",
        "user_timeout",
        "resolution_failed",
        "agentpact_auto",
    ] {
        assert!(
            !block_from_daemon_unavailable(source),
            "`{source}` is a real decision and must NOT be treated as daemon-unavailable"
        );
    }
}
