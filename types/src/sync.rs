// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

use crate::timeline::TimelineEntry;

/// One sync push from kyrisd to the relay. kyrisd is the single join owner, so
/// it ships **already-joined** [`TimelineEntry`] rows — the relay stores them
/// and only coordinates across machines. (This replaces the old
/// `EventBatch { events[], kyrisd_records[] }` two-raw-stream contract: the
/// relay no longer joins.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineBatch {
    pub machine_id: String,
    pub batch_id: String,
    pub entries: Vec<TimelineEntry>,
    pub cursor: SyncCursor,
}

/// kyrisd's progress marker through the agentpact event log. kyrisd drives the
/// join from this position (plus its own unsynced records), so the cursor stays
/// an event-log offset even though the payload is now joined entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCursor {
    pub filename: String,
    pub byte_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub version: String,
    pub signature: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EnrollRequest {
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub kyris_version: Option<String>,
    pub agentpact_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EnrollmentResponse {
    pub machine_token: String,
    pub machine_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testSyncCursorRoundTrip() {
        let cursor = SyncCursor {
            filename: "events.jsonl".to_string(),
            byte_offset: 4096,
        };
        let json = serde_json::to_string(&cursor).unwrap();
        let parsed: SyncCursor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.filename, "events.jsonl");
        assert_eq!(parsed.byte_offset, 4096);
    }

    #[test]
    fn testEnrollmentResponseRoundTrip() {
        let resp = EnrollmentResponse {
            machine_token: "mkt_abc123".to_string(),
            machine_id: "machine-1".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: EnrollmentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.machine_token, "mkt_abc123");
        assert_eq!(parsed.machine_id, "machine-1");
    }

    #[test]
    fn testTimelineBatchEmptyEntries() {
        let batch = TimelineBatch {
            machine_id: "m-1".to_string(),
            batch_id: "b-1".to_string(),
            entries: vec![],
            cursor: SyncCursor {
                filename: "events.jsonl".to_string(),
                byte_offset: 0,
            },
        };
        let json = serde_json::to_string(&batch).unwrap();
        let parsed: TimelineBatch = serde_json::from_str(&json).unwrap();
        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.cursor.byte_offset, 0);
    }

    #[test]
    fn testPolicyBundleRoundTrip() {
        let bundle = PolicyBundle {
            version: "v0.1.0".to_string(),
            signature: "sig_abc".to_string(),
            payload: serde_json::json!({"rules": []}),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: PolicyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "v0.1.0");
    }
}
