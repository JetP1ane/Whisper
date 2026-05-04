//! Relay transport (WebSocket / TLS 1.3) — wire-compatible with the Android client.
//!
//! - [`mailbox`] — daily-rotating BLAKE2b-128 mailbox addresses + decoy generation
//! - [`relay`] — WebSocket client with deposit/retrieve, FIFO acknowledgments,
//!               and notification-driven retrieval (30s fallback poll)
//! - [`frame_accounting`] — independent client-side frame counters, reconciled
//!                          with the relay every 60 s
//! - [`control_messages`] — ratchet-encrypted control message types

pub mod bundle_registry;
pub mod control_messages;
pub mod cross_relay_stats;
pub mod envelopes;
pub mod frame_accounting;
pub mod i2p;
pub mod mailbox;
pub mod relay;
pub mod tls_pin;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("websocket: {0}")]
    Ws(String),
    #[error("relay protocol: {0}")]
    Protocol(&'static str),
    #[error("tls pin mismatch")]
    TlsPinMismatch,
    #[error("frame accounting mismatch")]
    FrameMismatch,
    #[error("disconnected")]
    Disconnected,
    #[error("encoding: {0}")]
    Encoding(String),
}

pub type TransportResult<T> = Result<T, TransportError>;

pub const DEPOSIT_TTL_DEFAULT: u64 = 60 * 60 * 24; // 24h
pub const DEPOSIT_TTL_MAX: u64 = 60 * 60 * 48; // 48h
pub const RETRIEVE_BATCH_SIZE: usize = 8; // 2 real + 6 decoys
pub const FALLBACK_POLL_SECS: u64 = 30;
pub const FRAME_RECONCILE_SECS: u64 = 60;
/// How often the disappearing-message sweeper runs. Picked so the worst-case
/// "still visible after the timer should have ended" is small.
pub const DISAPPEAR_SWEEP_SECS: u64 = 10;
