//! Messaging orchestrator: turns user intents into wire bytes and persists
//! the result, owning the per-contact Double Ratchet state in the process.
//!
//! This module is the glue between [`crate::crypto`] (envelope + ratchet),
//! [`crate::transport`] (relay deposit / retrieve / mailbox addressing), and
//! [`crate::db`] (durable conversation history + ratchet snapshots).
//!
//! ```text
//! send_text:   plaintext  →  envelope  →  pad  →  ratchet.encrypt
//!                       →  pack_text_wire (4096 B)
//!                       →  [first-message wrapper if no prior session]
//!                       →  deposit on recipient's mailbox
//!                       →  persist row (TEE-encrypted + status='queued')
//!
//! handle_blob: wire bytes →  parse first-message wrapper if present
//!                       →  PQ-X3DH responder for new sessions
//!                       →  ratchet.decrypt
//!                       →  decode envelope
//!                       →  persist row (TEE-encrypted)
//! ```
//!
//! Ratchet sessions are loaded lazily from `ratchet_sessions` and saved back
//! after every encrypt / decrypt step. Serialization format is [`bincode`] —
//! desktop-internal only; not wire-compatible with the Android format.

pub mod attachments;
pub mod inbound;
pub mod ratchet_store;
pub mod room_keys;
pub mod sender;
pub mod receiver;
