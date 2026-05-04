//! I2P transport — replaces the relay WebSocket with direct destination-to-
//! destination delivery over an embedded `i2pd` subprocess.
//!
//! Architecture:
//!
//! ```text
//!   Whisper UI / commands.rs
//!         │
//!         ▼
//!   ConnectionManager  ─────► outbound: SAM STREAM CONNECT to peer dest
//!         │                   inbound:  SAM STREAM ACCEPT loop
//!         │
//!   SamClient  (SAM v3.3 protocol over TCP/UDS to localhost i2pd)
//!         │
//!         ▼
//!   I2PManager (spawns + supervises the i2pd subprocess, watches readiness,
//!               provides our destination keypair, exposes a status snapshot)
//! ```
//!
//! The wire payload inside an I2P stream is byte-identical to what the relay
//! used to carry: the existing 4 KB padded ratchet wire for text + the
//! variable-length envelope for attachments. Only the *carrier* changes.
//!
//! Phase tracker (see PR description):
//!   - Phase 0: scaffold (this commit)
//!   - Phase 1: [`sam`] — SAM v3.3 client
//!   - Phase 1.5: [`destination`] — independent destination key gen + vault
//!   - Phase 2: [`manager`] — i2pd subprocess lifecycle
//!   - Phase 3: framing + connection manager
//!   - Phase 4: persistent send queue
//!   - Phases 5+: bundle / DB / commands / files / groups / tray / tests

pub mod connection;
pub mod destination;
pub mod dispatch;
pub mod framing;
pub mod lifecycle;
pub mod manager;
pub mod queue;
pub mod runtime;
pub mod sam;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum I2pError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sam protocol: {0}")]
    Sam(String),
    #[error("sam version mismatch: got {got}, want >= {want}")]
    SamVersion { got: String, want: String },
    #[error("session id reused or already taken: {0}")]
    SessionTaken(String),
    #[error("destination invalid: {0}")]
    InvalidDestination(String),
    #[error("i2pd subprocess: {0}")]
    Subprocess(String),
    #[error("not ready: tunnels not yet established")]
    NotReady,
    #[error("disconnected")]
    Disconnected,
    #[error("encoding: {0}")]
    Encoding(String),
}

pub type I2pResult<T> = Result<T, I2pError>;

/// SAM bridge defaults. The actual bind port is randomized at i2pd start
/// time — see `manager::pick_sam_port` — so this is only the default we
/// pass to i2pd's CLI when we *want* a deterministic port (tests).
pub const SAM_DEFAULT_PORT: u16 = 7656;
pub const SAM_DEFAULT_ADDR: &str = "127.0.0.1";

/// Minimum SAM protocol version we'll negotiate with i2pd.
pub const SAM_MIN_VERSION: &str = "3.1";
/// Maximum SAM protocol version we'll negotiate with i2pd.
pub const SAM_MAX_VERSION: &str = "3.3";

/// I2P encrypted leaseset type. Mod #2 in the design: contacts who don't
/// have our destination key cannot discover or build tunnels to us.
pub const I2CP_LEASESET_TYPE_ENCRYPTED: u8 = 5;

/// ECIES-X25519-AEAD leaseset encryption — paired with the encrypted
/// leaseset type above.
pub const I2CP_LEASESET_ENC_TYPE_ECIES_X25519: u8 = 4;

/// Connection idle keepalive before tearing down a cached SAM stream
/// (Mod: in design proposal §2 "Connection keep-alive").
pub const STREAM_IDLE_TIMEOUT_SECS: u64 = 60;

/// Max single-message frame size we'll accept on an inbound stream. Bigger
/// payloads (file chunks) are explicitly streamed in chunks of this size.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024; // 1 MiB
