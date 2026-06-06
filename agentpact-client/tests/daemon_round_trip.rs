// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the `kyris-agentpact-client` request paths that talk
//! to a real (fake) `agentpactd` over the UDS — `send_trace_attach` and
//! `send_permission_response`. The e2e suite covers the
//! request→decision→event happy path and the daemon-unavailable fail-closed
//! path; these pin the two report-back calls that are otherwise only exercised
//! against an unreachable socket (see `kyris/OWED-TESTS.md`).
#![allow(non_snake_case)]

mod common;

use common::FakeDaemon;
use kyris_agentpact_client::{ApprovalResponse, send_permission_response, send_trace_attach};
use std::time::Duration;
use tempfile::TempDir;

fn socket(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("agentpact.sock")
}

const T: Option<Duration> = Some(Duration::from_secs(5));

// --- send_trace_attach -----------------------------------------------------

#[test]
fn testTraceAttachReturnsWorkingDirOnOk() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({"code": "PACT_OK", "working_dir": "/home/dev/proj"})],
    );

    let result = send_trace_attach(sock.to_str().unwrap(), "tok-abc", "trace-123", T);
    assert_eq!(result, Ok(Some("/home/dev/proj".to_string())));

    let reqs = daemon.finish();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0]["method"], "trace.attach");
    assert_eq!(reqs[0]["trace_token"], "tok-abc");
    assert_eq!(reqs[0]["trace_id"], "trace-123");
    assert!(
        reqs[0]["id"].as_str().unwrap().starts_with("kyrisd-trace-"),
        "id should be prefixed: {}",
        reqs[0]["id"]
    );
}

#[test]
fn testTraceAttachOmitsEmptyOrMissingWorkingDir() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    // No working_dir field, and an empty one — both must map to None.
    let daemon = FakeDaemon::start(
        &sock,
        vec![
            serde_json::json!({"code": "PACT_OK"}),
            serde_json::json!({"code": "PACT_OK", "working_dir": ""}),
        ],
    );

    assert_eq!(
        send_trace_attach(sock.to_str().unwrap(), "t", "x", T),
        Ok(None)
    );
    assert_eq!(
        send_trace_attach(sock.to_str().unwrap(), "t", "y", T),
        Ok(None)
    );
    daemon.finish();
}

#[test]
fn testTraceAttachRejectionSurfacesCodeAndError() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({"code": "PACT_PROTOCOL_ERROR", "error": "unknown trace token"})],
    );

    let err = send_trace_attach(sock.to_str().unwrap(), "bad", "trace-1", T).unwrap_err();
    assert!(err.contains("trace.attach rejected"), "got: {err}");
    assert!(err.contains("PACT_PROTOCOL_ERROR"), "got: {err}");
    assert!(err.contains("unknown trace token"), "got: {err}");
    daemon.finish();
}

#[test]
fn testTraceAttachMalformedResponseIsError() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    // No `code` field at all.
    let daemon = FakeDaemon::start(&sock, vec![serde_json::json!({"working_dir": "/x"})]);

    let err = send_trace_attach(sock.to_str().unwrap(), "t", "x", T).unwrap_err();
    assert!(err.contains("malformed"), "got: {err}");
    daemon.finish();
}

// --- send_permission_response ----------------------------------------------

#[test]
fn testPermissionResponseApprovedAcceptedAndWireShape() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({"code": "PACT_OK", "mode": "enforce"})],
    );

    let result = send_permission_response(
        sock.to_str().unwrap(),
        "kyris-resp",
        "apt_123",
        ApprovalResponse::Approved,
        T,
    );
    assert_eq!(result, Ok(None), "clean approve → no warning");

    let reqs = daemon.finish();
    assert_eq!(reqs[0]["method"], "permission.respond");
    assert_eq!(reqs[0]["approval_token"], "apt_123");
    assert_eq!(reqs[0]["response"], "approved");
    assert!(reqs[0]["id"].as_str().unwrap().starts_with("kyris-resp-"));
}

#[test]
fn testPermissionResponseSurfacesPersistWarning() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    // Applied, but the daemon attached an advisory reason (e.g. Always grant
    // approved once but could not be persisted).
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({
            "code": "PACT_OK",
            "mode": "enforce",
            "reason": "policy dir read-only; grant not persisted"
        })],
    );

    let result = send_permission_response(
        sock.to_str().unwrap(),
        "kyris-resp",
        "apt_always",
        ApprovalResponse::Always,
        T,
    );
    assert_eq!(
        result,
        Ok(Some(
            "policy dir read-only; grant not persisted".to_string()
        ))
    );
    let reqs = daemon.finish();
    assert_eq!(reqs[0]["response"], "always");
}

#[test]
fn testPermissionResponseDeniedDecisionAcceptedOnPactDenied() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    // A `Denied` decision legitimately produces PACT_DENIED — that is success.
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({"code": "PACT_DENIED", "reason": "denied by user"})],
    );

    let result = send_permission_response(
        sock.to_str().unwrap(),
        "kyris-resp",
        "apt_deny",
        ApprovalResponse::Denied,
        T,
    );
    assert!(
        result.is_ok(),
        "Denied + PACT_DENIED is success, got {result:?}"
    );
    let reqs = daemon.finish();
    assert_eq!(reqs[0]["response"], "denied");
}

#[test]
fn testPermissionResponseRejectionIsError() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    // An `Approved` decision but the daemon rejects the token → PACT_DENIED is
    // a rejection here (we asked to approve, it refused).
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({"code": "PACT_DENIED", "reason": "stale approval token"})],
    );

    let err = send_permission_response(
        sock.to_str().unwrap(),
        "kyris-resp",
        "apt_stale",
        ApprovalResponse::Approved,
        T,
    )
    .unwrap_err();
    assert!(err.contains("rejected approval response"), "got: {err}");
    assert!(err.contains("stale approval token"), "got: {err}");
    daemon.finish();
}

#[test]
fn testPermissionResponseUnexpectedAskIsError() {
    let dir = TempDir::new().unwrap();
    let sock = socket(&dir);
    // A well-formed PACT_ASK in response to a respond call is nonsensical →
    // error (not silently treated as allow/deny).
    let daemon = FakeDaemon::start(
        &sock,
        vec![serde_json::json!({
            "code": "PACT_ASK",
            "approval_id": "ap_1",
            "approval_token": "apt_1"
        })],
    );

    let err = send_permission_response(
        sock.to_str().unwrap(),
        "kyris-resp",
        "apt_x",
        ApprovalResponse::Approved,
        T,
    )
    .unwrap_err();
    assert!(err.contains("unexpected ask"), "got: {err}");
    daemon.finish();
}
