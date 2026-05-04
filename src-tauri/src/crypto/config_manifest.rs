//! Hardware-anchored configuration integrity.
//!
//! On first vault setup we generate an Ed25519 keypair (the **manifest
//! signer**) and persist its 32-byte seed inside the same combined Keychain
//! item as the vault DEK. After unlock, the signer lives only in process
//! memory.
//!
//! At every `relay_connect` we recompute a SHA-256 digest over the load-bearing
//! configuration (relay URL + TLS pin + KDF parameters + HKDF domain strings
//! + wire-format constants + app version) and verify it against a stored
//! Ed25519 signature. If the verification fails, the connection is refused
//! and a `security:manifest_tampered` event is emitted.
//!
//! Trade-off vs. the Android client's StrongBox-backed ECDSA P-256 signer:
//! after unlock the signer is in process memory, so RCE that can read the
//! keychain can still re-sign. The protection layer that survives is
//! tamper-evidence on disk: an attacker without the user's passphrase cannot
//! unseal the signer, so they cannot forge a manifest signature offline.
//! True per-use Touch ID gating requires raw `SecKeyCreateSignature` FFI
//! against an SE-bound key — a future hardening step.

use super::{
    CryptoError, CryptoResult, CHAIN_KEY_INFO, ROOT_CHAIN_INFO, X3DH_INFO, X3DH_SALT,
    HARDWARE_DB_INFO, PAD_BLOCK, WIRE_MESSAGE_SIZE,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Compute the manifest digest over every load-bearing configuration value.
/// Any change to relay URL, KDF params, wire constants, etc., invalidates
/// the existing signature.
pub fn manifest_digest(relay_url: &str, tls_spki_pin: Option<&[u8]>) -> [u8; 32] {
    let mut h = Sha256::new();

    // 1. Relay URL.
    h.update(b"relay_url:");
    h.update((relay_url.len() as u32).to_be_bytes());
    h.update(relay_url.as_bytes());

    // 2. TLS SPKI pin (32 bytes; all-zero if not pinned).
    h.update(b"tls_spki_pin:");
    let pin = tls_spki_pin.unwrap_or(&[0u8; 32]);
    h.update((pin.len() as u32).to_be_bytes());
    h.update(pin);

    // 3. Argon2id parameters (must match `crypto::vault`).
    h.update(b"argon2:");
    h.update(262_144u32.to_be_bytes()); // memory KiB
    h.update(4u32.to_be_bytes()); // iterations
    h.update(4u32.to_be_bytes()); // parallelism
    h.update(32u32.to_be_bytes()); // hash length

    // 4. HKDF domain strings (any tampering here would break crypto interop).
    h.update(b"hkdf:");
    h.update((X3DH_SALT.len() as u32).to_be_bytes());
    h.update(X3DH_SALT);
    h.update((X3DH_INFO.len() as u32).to_be_bytes());
    h.update(X3DH_INFO);
    h.update((ROOT_CHAIN_INFO.len() as u32).to_be_bytes());
    h.update(ROOT_CHAIN_INFO);
    h.update((CHAIN_KEY_INFO.len() as u32).to_be_bytes());
    h.update(CHAIN_KEY_INFO);
    h.update((HARDWARE_DB_INFO.len() as u32).to_be_bytes());
    h.update(HARDWARE_DB_INFO);

    // 5. Wire-format constants.
    h.update(b"wire:");
    h.update((WIRE_MESSAGE_SIZE as u32).to_be_bytes());
    h.update((PAD_BLOCK as u32).to_be_bytes());

    // 6. App version (so any binary upgrade re-signs the manifest).
    h.update(b"version:");
    h.update(APP_VERSION.as_bytes());

    h.finalize().into()
}

pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn sign(seed: &[u8; 32], digest: &[u8; 32]) -> [u8; 64] {
    signing_key_from_seed(seed).sign(digest).to_bytes()
}

pub fn verify(verifying_key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> CryptoResult<()> {
    let vk =
        VerifyingKey::from_bytes(verifying_key).map_err(|_| CryptoError::Decode("bad mfst pubkey"))?;
    let sig = Signature::from_bytes(signature);
    vk.verify(digest, &sig)
        .map_err(|_| CryptoError::AeadFailure)
}

pub fn verifying_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    signing_key_from_seed(seed).verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_changes_on_url_change() {
        let a = manifest_digest("ws://127.0.0.1:8080/ws", None);
        let b = manifest_digest("ws://127.0.0.1:9090/ws", None);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_on_pin_change() {
        let a = manifest_digest("ws://x", None);
        let b = manifest_digest("ws://x", Some(&[1u8; 32]));
        assert_ne!(a, b);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let seed = [0xAB; 32];
        let url = "ws://127.0.0.1:8080/ws";
        let digest = manifest_digest(url, None);
        let sig = sign(&seed, &digest);
        let vk = verifying_key_from_seed(&seed);
        assert!(verify(&vk, &digest, &sig).is_ok());
    }

    #[test]
    fn verify_fails_with_tampered_digest() {
        let seed = [0xAB; 32];
        let digest = manifest_digest("ws://x", None);
        let sig = sign(&seed, &digest);
        let other = manifest_digest("ws://y", None);
        let vk = verifying_key_from_seed(&seed);
        assert!(verify(&vk, &other, &sig).is_err());
    }
}
