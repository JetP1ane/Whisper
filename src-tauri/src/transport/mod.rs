//! Transport layer.
//!
//! All outbound and inbound traffic now rides I2P streams. The legacy
//! WebSocket relay transport (and its TLS-pinning, frame-accounting,
//! and cross-relay machinery) was removed when the desktop client went
//! I2P-only.
//!
//! - [`mailbox`] — daily-rotating BLAKE2b-128 mailbox addresses; the
//!                 32-byte ASCII prefix that still tags ratchet wires for
//!                 sender identification on the receiving end
//! - [`envelopes`] — magic-prefixed control envelopes (contact request,
//!                   session reset)
//! - [`i2p`]      — i2pd subprocess + SAM client + stream-based connection
//!                  manager + persistent send queue

pub mod envelopes;
pub mod i2p;
pub mod mailbox;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("encoding: {0}")]
    Encoding(String),
}

pub type TransportResult<T> = Result<T, TransportError>;

/// How often the disappearing-message sweeper runs. Picked so the worst-case
/// "still visible after the timer should have ended" is small.
pub const DISAPPEAR_SWEEP_SECS: u64 = 10;
