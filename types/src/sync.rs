// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

use crate::event::Event;
use crate::record::GatewayRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub machine_id: String,
    pub batch_id: String,
    pub events: Vec<Event>,
    #[serde(default)]
    pub kyrisd_records: Vec<GatewayRecord>,
    pub cursor: SyncCursor,
}

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
    fn testEventBatchEmptyEvents() {
        let batch = EventBatch {
            machine_id: "m-1".to_string(),
            batch_id: "b-1".to_string(),
            events: vec![],
            kyrisd_records: vec![],
            cursor: SyncCursor {
                filename: "events.jsonl".to_string(),
                byte_offset: 0,
            },
        };
        let json = serde_json::to_string(&batch).unwrap();
        let parsed: EventBatch = serde_json::from_str(&json).unwrap();
        assert!(parsed.events.is_empty());
        assert!(parsed.kyrisd_records.is_empty());
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
