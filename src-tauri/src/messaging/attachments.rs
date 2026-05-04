//! On-disk storage for attachment payloads.
//!
//! Attachment bytes are too large to keep in the SQLite database without
//! hurting query performance. We write them out under
//! `<profile_data_dir>/attachments/<message_id>.bin`, encrypted with the
//! same per-conversation TEE key that protects message envelopes — so a
//! file pulled directly off disk without unlocking the vault stays opaque.

use crate::crypto::{tee_encryption, CryptoError};
use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn attachments_dir(profile_dir: &Path) -> PathBuf {
    profile_dir.join("attachments")
}

pub fn attachment_path(profile_dir: &Path, message_id: &str) -> PathBuf {
    attachments_dir(profile_dir).join(format!("{message_id}.bin"))
}

/// Encrypt and write `bytes` to the attachment store.
pub fn store(
    profile_dir: &Path,
    message_id: &str,
    conversation_id: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    let dir = attachments_dir(profile_dir);
    fs::create_dir_all(&dir)?;
    let sealed = tee_encryption::encrypt_for_conversation(conversation_id.as_bytes(), bytes)
        .map_err(|e: CryptoError| anyhow!(e.to_string()))?;
    let path = attachment_path(profile_dir, message_id);
    fs::write(&path, &sealed)?;
    Ok(path)
}

/// Decrypt and return the bytes stored for `message_id`.
pub fn load(
    profile_dir: &Path,
    message_id: &str,
    conversation_id: &str,
) -> Result<Vec<u8>> {
    let path = attachment_path(profile_dir, message_id);
    let sealed = fs::read(&path)?;
    let plaintext =
        tee_encryption::decrypt_for_conversation(conversation_id.as_bytes(), &sealed)
            .map_err(|e: CryptoError| anyhow!(e.to_string()))?;
    Ok(plaintext)
}

/// Delete the attachment file, ignoring "not found" errors. Used when a
/// message row is purged by the disappearing-message sweeper.
pub fn delete(profile_dir: &Path, message_id: &str) {
    let path = attachment_path(profile_dir, message_id);
    let _ = fs::remove_file(path);
}
