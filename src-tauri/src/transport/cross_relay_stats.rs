//! Per-relay activity counters for transient (cross-relay) WebSocket calls.
//!
//! The home relay's persistent connection has its own continuous frame
//! accounting (`FrameCounters` + `request_accounting`). Transient deposits
//! and retrieves bypass that channel — one short-lived WebSocket per call —
//! so they need a separate accountability surface. This module records each
//! transient call's outcome so the UI can show users how many of their
//! messages travelled cross-relay and whether any were rejected.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayCallStatus {
    Ok,
    Timeout,
    TlsMismatch,
    Rejected,
    OtherError,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayUsage {
    pub url: String,
    pub deposits_ok: u32,
    pub deposits_failed: u32,
    pub retrieves_ok: u32,
    pub retrieves_failed: u32,
    pub last_status: Option<RelayCallStatus>,
    pub last_at_ms: Option<u64>,
}

impl RelayUsage {
    fn new(url: String) -> Self {
        Self {
            url,
            deposits_ok: 0,
            deposits_failed: 0,
            retrieves_ok: 0,
            retrieves_failed: 0,
            last_status: None,
            last_at_ms: None,
        }
    }
}

#[derive(Default)]
pub struct CrossRelayStats {
    inner: Mutex<HashMap<String, RelayUsage>>,
}

impl CrossRelayStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_deposit(&self, url: &str, status: RelayCallStatus) {
        self.record(url, status, true)
    }

    pub fn record_retrieve(&self, url: &str, status: RelayCallStatus) {
        self.record(url, status, false)
    }

    fn record(&self, url: &str, status: RelayCallStatus, is_deposit: bool) {
        let mut g = self.inner.lock();
        let entry = g
            .entry(url.to_string())
            .or_insert_with(|| RelayUsage::new(url.to_string()));
        let ok = matches!(status, RelayCallStatus::Ok);
        if is_deposit {
            if ok { entry.deposits_ok += 1 } else { entry.deposits_failed += 1 }
        } else {
            if ok { entry.retrieves_ok += 1 } else { entry.retrieves_failed += 1 }
        }
        entry.last_status = Some(status);
        entry.last_at_ms = Some(now_unix_ms());
    }

    pub fn snapshot(&self) -> Vec<RelayUsage> {
        let g = self.inner.lock();
        let mut v: Vec<RelayUsage> = g.values().cloned().collect();
        v.sort_by(|a, b| b.last_at_ms.cmp(&a.last_at_ms));
        v
    }
}

pub fn classify_transport_error(e: &crate::transport::TransportError) -> RelayCallStatus {
    use crate::transport::TransportError as TE;
    match e {
        TE::TlsPinMismatch => RelayCallStatus::TlsMismatch,
        TE::Ws(s) if s.contains("timed out") => RelayCallStatus::Timeout,
        TE::Protocol(_) => RelayCallStatus::Rejected,
        _ => RelayCallStatus::OtherError,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_deposit_and_retrieve_independently() {
        let s = CrossRelayStats::new();
        s.record_deposit("wss://a", RelayCallStatus::Ok);
        s.record_deposit("wss://a", RelayCallStatus::Timeout);
        s.record_retrieve("wss://a", RelayCallStatus::Ok);

        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].deposits_ok, 1);
        assert_eq!(snap[0].deposits_failed, 1);
        assert_eq!(snap[0].retrieves_ok, 1);
        assert_eq!(snap[0].last_status, Some(RelayCallStatus::Ok));
    }

    #[test]
    fn snapshot_orders_by_recency() {
        let s = CrossRelayStats::new();
        s.record_deposit("wss://older", RelayCallStatus::Ok);
        std::thread::sleep(std::time::Duration::from_millis(2));
        s.record_deposit("wss://newer", RelayCallStatus::Ok);
        let snap = s.snapshot();
        assert_eq!(snap[0].url, "wss://newer");
        assert_eq!(snap[1].url, "wss://older");
    }
}
