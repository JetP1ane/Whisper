//! Cryptographic primitives and protocol implementation.
//!
//! Layout mirrors the Android client so wire-format compatibility is easy to audit:
//!
//! - [`keys`]      — long-term identity, prekeys, BIP39 alias derivation
//! - [`vault`]     — Argon2id passphrase KDF + DEK encryption
//! - [`pqx3dh`]    — hybrid post-quantum X3DH key agreement
//! - [`ratchet`]   — Double Ratchet (chain + DH ratchet) state machine
//! - [`message_crypto`] — wire format: padding, AEAD, header binding
//! - [`sealed`]    — biometric-gated sealed conversations
//! - [`tee_encryption`] — per-conversation Secure-Enclave-derived AEAD
//! - [`secure_enclave`] — macOS Secure Enclave / Keychain glue
//! - [`safety_numbers`] — out-of-band identity verification codes

pub mod bundle;
pub mod config_manifest;
pub mod keychain;
pub mod keys;
pub mod message_crypto;
pub mod pqx3dh;
pub mod ratchet;
pub mod safety_numbers;
pub mod seed;
pub mod sender_key;
pub mod sealed;
pub mod secure_enclave;
pub mod tee_encryption;
pub mod vault;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("AEAD failure (tag mismatch)")]
    AeadFailure,
    #[error("KDF failure: {0}")]
    KdfFailure(&'static str),
    #[error("Argon2 failure: {0}")]
    ArgonFailure(String),
    #[error("PQ-KEM failure: {0}")]
    KemFailure(&'static str),
    #[error("Secure Enclave error: {0}")]
    SecureEnclave(String),
    #[error("decode error: {0}")]
    Decode(&'static str),
    #[error("ratchet state error: {0}")]
    RatchetState(&'static str),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// --- Domain separation strings (must match Android byte-for-byte) ---
pub const X3DH_SALT: &[u8] = b"NoctisWhisper_v1";
pub const X3DH_INFO: &[u8] = b"NoctisWhisper_PQX3DH_v1";
pub const ROOT_CHAIN_INFO: &[u8] = b"NoctisWhisper_RootChain_v1";
pub const CHAIN_KEY_INFO: &[u8] = b"NoctisWhisper_ChainKey_v1";
pub const HARDWARE_DB_INFO: &[u8] = b"NoctisWhisper_HardwareBoundDB_v1";

// --- Wire format constants ---
pub const WIRE_MESSAGE_SIZE: usize = 4096;
pub const PAD_BLOCK: usize = 256;
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

// --- Type flags (plaintext envelope, byte 8) ---
pub const TYPE_FLAG_TEXT: u8 = 0x00;
pub const TYPE_FLAG_ATTACHMENT: u8 = 0x01;
/// Inner control envelope: payload is `[32B wire_hash]` of the original
/// deposited blob being acknowledged. Travels through the same Double
/// Ratchet channel as a regular text message so the relay can't see it.
pub const TYPE_FLAG_DELIVERY_RECEIPT: u8 = 0x02;
/// Inner control envelope: `[8B ts][1B 0x03][4B url_len BE][URL UTF-8]`.
/// Sent when a peer changes their home relay. The recipient stores the new
/// URL on the corresponding contact row so future deposits route correctly.
pub const TYPE_FLAG_RELAY_UPDATE: u8 = 0x03;
/// Inner control envelope: a room invite. Carries the room id, name,
/// description, owner's sender-key chain seed, and the full member list
/// (each member's Ed25519 identity pubkey). Sent over the pairwise Double
/// Ratchet by the room owner to every invited member.
pub const TYPE_FLAG_ROOM_INVITE: u8 = 0x04;
/// Inner control envelope: a single sender's chain-key seed for one room.
/// Sent over the pairwise Double Ratchet so each member learns every other
/// member's current sender key (required to decrypt their messages).
pub const TYPE_FLAG_ROOM_SENDER_KEY: u8 = 0x05;
/// Self-detonating text. Identical wire shape to TYPE_FLAG_TEXT except
/// that the envelope embeds an authenticated TTL: the sender specifies
/// "delete after N seconds" inside the AEAD-encrypted body, so neither
/// the relay nor a network adversary can strip or extend the timer
/// without breaking the AEAD tag. Compliant clients enforce.
pub const TYPE_FLAG_DETONATING_TEXT: u8 = 0x06;

// --- Skipped-message bounds ---
pub const MAX_SKIP_PER_CHAIN: u32 = 1000;
pub const MAX_CACHED_SKIPPED: usize = 2000;
