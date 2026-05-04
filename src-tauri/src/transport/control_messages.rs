//! WebSocket message types — wire-compatible with the canonical relay at
//! `~/Documents/whisper-relay`. Field names match the Go server byte-for-byte.
//!
//! Type tags are snake_case (`deposit`, `retrieve`, `delivery`, `deposited`,
//! `notify`, `padding`, `error`, `accounting_request`, `accounting_response`).
//! Field names are mostly snake_case but the accounting types use **camelCase**
//! (`framesSent`, `framesReceivedFromClient`, …) to match the relay's JSON tags.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToRelay {
    Deposit {
        mailbox: String,
        blob: String, // base64
        ttl: u64,
    },
    Retrieve {
        mailboxes: Vec<String>,
    },
    /// Cover-traffic frame — relay silently ignores. We send these on a fixed
    /// schedule so the on-wire packet size + cadence is independent of activity.
    Padding,
    AccountingRequest {
        #[serde(rename = "framesSent")]
        frames_sent: u64,
        #[serde(rename = "framesReceived")]
        frames_received: u64,
        #[serde(rename = "bytesSent")]
        bytes_sent: u64,
        #[serde(rename = "bytesReceived")]
        bytes_received: u64,
        ts: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToClient {
    Deposited {
        mailbox: String,
        ok: bool,
    },
    /// Response to a `retrieve` — note the type tag is **`delivery`**.
    Delivery {
        mailboxes: Vec<DeliveryMailbox>,
    },
    Notify,
    AccountingResponse {
        #[serde(rename = "framesReceivedFromClient")]
        frames_received_from_client: u64,
        #[serde(rename = "framesSentToClient")]
        frames_sent_to_client: u64,
        #[serde(rename = "bytesReceivedFromClient")]
        bytes_received_from_client: u64,
        #[serde(rename = "bytesSentToClient")]
        bytes_sent_to_client: u64,
        ts: u64,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryMailbox {
    pub mailbox: String,
    pub blobs: Vec<String>, // base64-encoded wireMessages; empties are zero-pad blobs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_serialization_matches_relay() {
        let msg = ClientToRelay::Deposit {
            mailbox: "abcd".into(),
            blob: "Zm9v".into(),
            ttl: 172800,
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "deposit");
        assert_eq!(json["mailbox"], "abcd");
        assert_eq!(json["blob"], "Zm9v");
        assert_eq!(json["ttl"], 172800);
    }

    #[test]
    fn padding_serializes_as_unit_tag() {
        let msg = ClientToRelay::Padding;
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"padding"}"#);
    }

    #[test]
    fn accounting_request_uses_camelcase_fields() {
        let msg = ClientToRelay::AccountingRequest {
            frames_sent: 1,
            frames_received: 2,
            bytes_sent: 3,
            bytes_received: 4,
            ts: 1234,
        };
        let v = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "accounting_request");
        assert_eq!(v["framesSent"], 1);
        assert_eq!(v["framesReceived"], 2);
        assert_eq!(v["bytesSent"], 3);
        assert_eq!(v["bytesReceived"], 4);
        assert_eq!(v["ts"], 1234);
    }

    #[test]
    fn delivery_response_parses() {
        let body = r#"{
            "type":"delivery",
            "mailboxes":[{"mailbox":"aa","blobs":["Zm9v"]}]
        }"#;
        let parsed: RelayToClient = serde_json::from_str(body).unwrap();
        match parsed {
            RelayToClient::Delivery { mailboxes } => {
                assert_eq!(mailboxes.len(), 1);
                assert_eq!(mailboxes[0].mailbox, "aa");
                assert_eq!(mailboxes[0].blobs, vec!["Zm9v"]);
            }
            _ => panic!("expected delivery"),
        }
    }

    #[test]
    fn accounting_response_parses_camelcase() {
        let body = r#"{
            "type":"accounting_response",
            "framesReceivedFromClient":10,
            "framesSentToClient":11,
            "bytesReceivedFromClient":1000,
            "bytesSentToClient":1100,
            "ts":42
        }"#;
        let parsed: RelayToClient = serde_json::from_str(body).unwrap();
        match parsed {
            RelayToClient::AccountingResponse {
                frames_received_from_client,
                frames_sent_to_client,
                bytes_received_from_client,
                bytes_sent_to_client,
                ts,
            } => {
                assert_eq!(frames_received_from_client, 10);
                assert_eq!(frames_sent_to_client, 11);
                assert_eq!(bytes_received_from_client, 1000);
                assert_eq!(bytes_sent_to_client, 1100);
                assert_eq!(ts, 42);
            }
            _ => panic!("expected accounting_response"),
        }
    }

    #[test]
    fn notify_parses() {
        let parsed: RelayToClient = serde_json::from_str(r#"{"type":"notify"}"#).unwrap();
        assert!(matches!(parsed, RelayToClient::Notify));
    }
}

/// Inner control messages — sent encrypted inside the ratchet payload.
/// The relay never sees these in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InnerControl {
    RelayUpdate { url: String },
    VerifiedStatus { peer_alias: String, verified: bool },
    SessionReconnected,
    AttestationChallenge { nonce: String }, // base64
    AttestationResponse { cert_chain: Vec<String>, report: String },
    AttestationResult { trust_level: String },
}
