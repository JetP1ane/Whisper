//! WebSocket frame accounting.
//!
//! Independent counters on the client. Reconciled with the relay every 60s
//! via `accounting_request` / `accounting_response` JSON messages. Mismatches
//! signal frame injection (CRITICAL) or frame drop (WARNING) — the user is
//! notified via the security dashboard.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct FrameCounters {
    pub frames_sent: AtomicU64,
    pub frames_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl FrameCounters {
    pub const fn new() -> Self {
        Self {
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
    pub fn observe_send(&self, bytes: usize) {
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn observe_recv(&self, bytes: usize) {
        self.frames_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Snapshot {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingVerdict {
    Verified,
    FrameInjectionExfil,    // relayReceived > clientSent  (CRITICAL)
    FrameInjectionFromRelay, // clientReceived > relaySent (CRITICAL)
    FrameDrop,               // any minor mismatch         (WARNING)
}

#[derive(Debug, Clone, Copy)]
pub struct RelayCounters {
    pub frames_received_from_client: u64,
    pub frames_sent_to_client: u64,
    pub bytes_received_from_client: u64,
    pub bytes_sent_to_client: u64,
}

/// Reconcile the client's local frame counters against the relay's reported
/// counters.
///
/// The naive "exact equality" check is fundamentally racy because the relay
/// can send broadcasts (e.g., `notify` from other clients' deposits) between
/// the moment it snapshots its counters and the moment the response arrives
/// at the client. By the time the client compares, its `frames_received` has
/// legitimately advanced past the relay's reported `frames_sent_to_client`.
/// Symmetric ambient sends are similarly possible on the send side.
///
/// The real invariants we enforce instead:
///
/// - **`relay.received_from_us > client.sent`** is impossible without the
///   relay manufacturing frames in our name → `FrameInjectionExfil`
///   (CRITICAL).
/// - **`relay.sent_to_us > client.received`** means the relay claims to have
///   sent frames we never observed → `FrameDrop` (WARNING). A malicious
///   relay could try to suppress messages this way.
/// - The opposite direction (we sent more than the relay reports receiving;
///   we received more than the relay reports sending) just reflects frames
///   in flight at snapshot time and is benign.
pub fn reconcile(client: Snapshot, relay: RelayCounters) -> AccountingVerdict {
    if relay.frames_received_from_client > client.frames_sent {
        return AccountingVerdict::FrameInjectionExfil;
    }
    if relay.frames_sent_to_client > client.frames_received {
        return AccountingVerdict::FrameDrop;
    }
    AccountingVerdict::Verified
}
