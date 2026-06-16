// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Wire-spelling contract between agentpact's authoritative wire enums and the
//! kyris-side mirrors that deliberately stay distinct types.
//!
//! Some wire value types (`Mode`, `Action`, `PlanStatus`) are consolidated into
//! `agentpact-types` so there is one definition. Two are NOT, on purpose:
//!
//! - `Decision` — agentpact's is the producer/policy-authoring verdict: a
//!   closed set with no `#[serde(other)]` so a misspelled policy value fails
//!   loudly. kyris's `event::Decision` is a *reader* that adds a forward-compat
//!   `Unknown`. Opposite stances; merging would push a meaningless `Unknown`
//!   verdict through the policy hot path.
//! - `ApprovalResponse` — agentpact's is the richer *inbound* parse
//!   (`+Voided/Expired/Unknown`); kyris-core's is the 3-variant *outbound* choice
//!   a user can actually pick.
//!
//! Keeping them distinct means the wire form could drift if someone renamed a
//! serde spelling on one side. This test is the tripwire that forbids that: it
//! pins the shared spellings across producer and consumer. Rename one and a
//! case here fails. See the doc comments on
//! `agentpact::protocol::types::{Decision, ApprovalResponse}`.

use agentpact::protocol::types::{ApprovalResponse as PactApproval, Decision as PactDecision};
use kyris_core::agentpact::ApprovalResponse as KyrisApproval;
use kyris_core::event::Decision as KyrisDecision;

#[test]
fn decision_shared_variants_serialize_identically() {
    // The four real verdicts agentpact produces must serialize to the exact
    // strings kyris reads back. kyris's extra `Unknown` is a forward-compat
    // reader concern, not a shared variant, so it is not part of the contract.
    let cases = [
        (PactDecision::Auto, KyrisDecision::Auto),
        (PactDecision::Inform, KyrisDecision::Inform),
        (PactDecision::Ask, KyrisDecision::Ask),
        (PactDecision::Deny, KyrisDecision::Deny),
    ];
    for (pact, kyris) in cases {
        let pact_json = serde_json::to_string(&pact).expect("serialize agentpact Decision");
        let kyris_json = serde_json::to_string(&kyris).expect("serialize kyris Decision");
        assert_eq!(
            pact_json, kyris_json,
            "Decision wire form drifted between agentpact and kyris"
        );
        // The producer's emitted form must deserialize into the matching
        // consumer variant (not fall through to kyris's `Unknown`).
        let round: KyrisDecision =
            serde_json::from_str(&pact_json).expect("kyris parses agentpact Decision");
        assert_eq!(round, kyris);
    }
}

#[test]
fn approval_answer_spellings_match_across_producer_and_consumer() {
    // kyris offers the user three choices and emits their wire spelling;
    // agentpact parses them inbound. The three shared answers must use
    // identical spellings. agentpact's `ApprovalResponse` is Deserialize-only,
    // so we assert the kyris-produced spelling parses into the matching
    // agentpact variant.
    let cases = [
        (KyrisApproval::Approved, PactApproval::Approved),
        (KyrisApproval::Denied, PactApproval::Denied),
        (KyrisApproval::Always, PactApproval::Always),
    ];
    for (kyris, pact) in cases {
        let wire = kyris.as_agentpact_response(); // "approved" | "denied" | "always"
        let parsed: PactApproval = serde_json::from_str(&format!("\"{wire}\""))
            .expect("agentpact parses kyris approval answer");
        assert_eq!(
            parsed, pact,
            "ApprovalResponse spelling drifted for `{wire}`"
        );
    }
}
