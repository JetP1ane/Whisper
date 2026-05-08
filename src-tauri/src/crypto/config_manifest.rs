//! Hardware-anchored configuration integrity.
//!
//! On first vault setup we generate an Ed25519 keypair (the **manifest
//! signer**) and persist its 32-byte seed inside the same combined Keychain
//! item as the vault DEK. We compute a SHA-256 digest over every load-bearing
//! crypto constant (Argon2id parameters + HKDF domain strings + wire-format
//! constants), sign it, and store both the verifying key and the signature
//! inside the SQLCipher settings table.
//!
//! At every `vault_unlock` we recompute the digest over the live constants
//! and verify it against the stored signature. If the verification fails,
//! the unlock is refused — an attacker who modified the SQLite settings
//! row's `manifest_signature` (or any other on-disk artifact whose contents
//! re-derived the digest) cannot pass the check without the manifest signer
//! seed, which only the legitimate Keychain blob produces.
//!
//! What this catches: post-install tampering of any hashed constant that
//! survives a release-build replacement of the binary (e.g. an attacker
//! who rewrites `manifest_signature` in the user's vault DB to hide a
//! KDF/HKDF substitution they planted via a different vector). It is
//! explicitly redundant with macOS library validation (which catches
//! binary tampering) and the i2pd-bundle pin (NEW-3, which catches
//! native-library tampering); the manifest exists to surface tampering
//! at the SQLite-row layer that those other checks don't see.
//!
//! What it does NOT catch: an attacker who controls the running process
//! (RCE post-unlock, debugger attach in a relaxed-entitlement build) can
//! re-sign the manifest at will. That's a known limitation — the protection
//! layer that survives RCE is the keychain seed itself, which is
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never crosses
//! Synchronizable=true.

use super::{
    CryptoError, CryptoResult, CHAIN_KEY_INFO, ROOT_CHAIN_INFO, X3DH_INFO, X3DH_SALT,
    HARDWARE_DB_INFO, PAD_BLOCK, WIRE_MESSAGE_SIZE,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

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

    // (App version intentionally NOT in the digest. Including it would
    // break unlock on every release upgrade — and an attacker who can
    // mutate the binary's hardcoded version string can mutate the rest
    // of the binary anyway, where library validation owns the threat.)

    h.finalize().into()
}

/// The digest over the *currently compiled* crypto constants. With I2P-only
/// transport there is no relay URL or TLS pin to bind, so we pass empty
/// values for those slots — keeping the underlying byte layout identical
/// across versions so signed manifests don't drift.
pub fn current_digest() -> [u8; 32] {
    manifest_digest("", None)
}

/// Convenience: sign `current_digest()` with the seed produced at vault
/// setup. Returns hex so the caller can stash it into the settings table
/// without an extra encoding step.
pub fn sign_current_hex(seed: &[u8; 32]) -> String {
    hex::encode(sign(seed, &current_digest()))
}

/// Verify that a stored hex-encoded signature still matches the live
/// `current_digest()` under the stored hex-encoded verifying key. Used
/// at every `vault_unlock` to refuse opening a vault whose manifest
/// signature no longer matches the compiled-in constants.
pub fn verify_current_hex(
    verifying_key_hex: &str,
    signature_hex: &str,
) -> CryptoResult<()> {
    let vk_bytes: [u8; 32] = hex::decode(verifying_key_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Decode("manifest verifying key is not 32 bytes hex"))?;
    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(CryptoError::Decode("manifest signature is not 64 bytes hex"))?;
    verify(&vk_bytes, &current_digest(), &sig_bytes)
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
