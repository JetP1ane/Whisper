//! Per-conversation message encryption using a Secure-Enclave-derived key.
//!
//! Format on disk: `nonce(12) || ciphertext || tag(16)`.

use super::{secure_enclave, CryptoError, CryptoResult};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

pub fn encrypt_for_conversation(conversation_id: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let key = secure_enclave::derive_conversation_key(conversation_id)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::AeadFailure)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_for_conversation(conversation_id: &[u8], blob: &[u8]) -> CryptoResult<Vec<u8>> {
    if blob.len() < 12 + 16 {
        return Err(CryptoError::Decode("TEE blob too short"));
    }
    let key = secure_enclave::derive_conversation_key(conversation_id)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    cipher
        .decrypt(Nonce::from_slice(&blob[..12]), &blob[12..])
        .map_err(|_| CryptoError::AeadFailure)
}
