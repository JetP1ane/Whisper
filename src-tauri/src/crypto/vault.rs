//! Argon2id passphrase KDF + DEK encryption.
//!
//! Pipeline (matches Android client):
//!
//! 1. `vault_key = Argon2id(passphrase, salt, m=256MiB, t=4, p=4, len=32)`
//! 2. DEK is a 32-byte random key, encrypted with `vault_key` via ChaCha20-Poly1305
//!    and stored as `nonce(12) || ciphertext(32) || tag(16) = 60 bytes`.
//! 3. The decrypted DEK feeds into the hardware-bound database key derivation
//!    (see [`crate::crypto::secure_enclave`]).

use super::{CryptoError, CryptoResult};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

pub const VAULT_SALT_LEN: usize = 32;
pub const DEK_LEN: usize = 32;
pub const DEK_BLOB_LEN: usize = 12 + DEK_LEN + 16; // 60

// Argon2id parameters — must match Android.
const ARGON_MEM_KIB: u32 = 262_144; // 256 MiB
const ARGON_ITER: u32 = 4;
const ARGON_PAR: u32 = 4;
const KEY_LEN: u32 = 32;

/// Run Argon2id to derive the vault key from a passphrase + salt.
pub fn derive_vault_key(passphrase: &[u8], salt: &[u8]) -> CryptoResult<Zeroizing<[u8; 32]>> {
    if salt.len() != VAULT_SALT_LEN {
        return Err(CryptoError::InvalidInput("vault salt must be 32 bytes"));
    }
    let params = Params::new(ARGON_MEM_KIB, ARGON_ITER, ARGON_PAR, Some(KEY_LEN as usize))
        .map_err(|e| CryptoError::ArgonFailure(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut *out)
        .map_err(|e| CryptoError::ArgonFailure(e.to_string()))?;
    Ok(out)
}

/// Generate a fresh random 32-byte salt.
pub fn generate_salt() -> [u8; VAULT_SALT_LEN] {
    let mut salt = [0u8; VAULT_SALT_LEN];
    // M-1: vault salt + DEK come from OsRng (getrandom syscall), not
    // thread_rng — these are master-key-tier secrets and the small
    // syscall cost is justified.
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a fresh random 32-byte DEK.
pub fn generate_dek() -> Zeroizing<[u8; DEK_LEN]> {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut *dek);
    dek
}

/// Encrypt the DEK with the vault key.
/// Returns: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
pub fn seal_dek(vault_key: &[u8; 32], dek: &[u8; DEK_LEN]) -> CryptoResult<[u8; DEK_BLOB_LEN]> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(vault_key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, dek.as_ref())
        .map_err(|_| CryptoError::AeadFailure)?;
    if ct.len() != DEK_LEN + 16 {
        return Err(CryptoError::InvalidInput("unexpected DEK ciphertext length"));
    }
    let mut out = [0u8; DEK_BLOB_LEN];
    out[..12].copy_from_slice(&nonce);
    out[12..].copy_from_slice(&ct);
    Ok(out)
}

/// Decrypt the DEK with the vault key. The returned buffer is `Zeroizing`.
pub fn open_dek(
    vault_key: &[u8; 32],
    blob: &[u8; DEK_BLOB_LEN],
) -> CryptoResult<Zeroizing<[u8; DEK_LEN]>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(vault_key));
    let nonce = Nonce::from_slice(&blob[..12]);
    let pt = cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|_| CryptoError::AeadFailure)?;
    if pt.len() != DEK_LEN {
        return Err(CryptoError::Decode("decrypted DEK has wrong length"));
    }
    let mut out = Zeroizing::new([0u8; DEK_LEN]);
    out.copy_from_slice(&pt);
    // Zeroize the heap copy from `decrypt`.
    let mut pt = pt;
    pt.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_dek() {
        // Use a small test vector (skip the slow Argon2 round-trip in unit tests).
        let vault_key = [0x42u8; 32];
        let dek = [0x77u8; DEK_LEN];
        let blob = seal_dek(&vault_key, &dek).unwrap();
        let opened = open_dek(&vault_key, &blob).unwrap();
        assert_eq!(*opened, dek);
    }

    #[test]
    fn wrong_vault_key_fails() {
        let dek = [0x11u8; DEK_LEN];
        let blob = seal_dek(&[0u8; 32], &dek).unwrap();
        assert!(open_dek(&[1u8; 32], &blob).is_err());
    }
}
