//! BLAKE2b-128 mailbox addressing.
//!
//! ```text
//! mailbox = BLAKE2b-128(recipient_pubkey || epoch_day_BE)
//! epoch_day = unix_ms / 86_400_000
//! ```
//!
//! Mailboxes rotate daily; both today and yesterday are checked at retrieval
//! time so a message deposited just before midnight isn't lost.

use rand::RngCore;

pub const MAILBOX_LEN: usize = 16;

/// Length of the ASCII-hex mailbox prefix prepended to each relay-format
/// blob (32 hex chars = 16 mailbox bytes). The I2P transport strips this
/// prefix because destination routing replaces mailbox addressing.
pub const MAILBOX_PREFIX_LEN: usize = 32;

const MS_PER_DAY: u64 = 86_400_000;

pub fn epoch_day(unix_ms: u64) -> u64 {
    unix_ms / MS_PER_DAY
}

pub fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute a mailbox for the given recipient pubkey and epoch day.
///
/// Matches the Android client byte-for-byte: BLAKE2b configured with a 16-byte
/// (128-bit) output length — *not* BLAKE2b-512 truncated to 16 bytes. The two
/// produce different hashes because BLAKE2b's parameter block embeds the
/// requested output length into the IV.
pub fn compute(recipient_pubkey: &[u8], day: u64) -> [u8; MAILBOX_LEN] {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;
    let mut h = Blake2bVar::new(MAILBOX_LEN).expect("16-byte output is valid");
    h.update(recipient_pubkey);
    h.update(&day.to_be_bytes());
    let mut out = [0u8; MAILBOX_LEN];
    h.finalize_variable(&mut out).expect("16-byte buffer fits");
    out
}

/// Hex-encode a mailbox address (lowercase, 32 chars).
pub fn hex(mailbox: &[u8; MAILBOX_LEN]) -> String {
    hex::encode(mailbox)
}

/// Build a retrieve batch matching the Android client: **1 real mailbox + 7
/// random decoys**, shuffled. Yesterday's mailbox is requested separately
/// (e.g. on a slower cadence at startup or near-midnight) — it's not part of
/// every batch. The relay enforces exactly 8 mailboxes per retrieve request.
pub fn build_retrieve_batch(real_mailbox: &[u8; MAILBOX_LEN]) -> Vec<[u8; MAILBOX_LEN]> {
    let mut batch: Vec<[u8; MAILBOX_LEN]> = Vec::with_capacity(8);
    batch.push(*real_mailbox);
    for _ in 0..7 {
        let mut decoy = [0u8; MAILBOX_LEN];
        rand::thread_rng().fill_bytes(&mut decoy);
        batch.push(decoy);
    }
    shuffle_in_place(&mut batch);
    batch
}

/// Today's mailbox for a recipient public key.
pub fn current_mailbox(recipient_pubkey: &[u8]) -> [u8; MAILBOX_LEN] {
    compute(recipient_pubkey, epoch_day(now_unix_ms()))
}

/// Yesterday's mailbox (cross-midnight delivery recovery).
pub fn previous_mailbox(recipient_pubkey: &[u8]) -> [u8; MAILBOX_LEN] {
    compute(
        recipient_pubkey,
        epoch_day(now_unix_ms()).saturating_sub(1),
    )
}

/// Fisher-Yates shuffle using OsRng-equivalent randomness.
fn shuffle_in_place<T>(slice: &mut [T]) {
    use rand::seq::SliceRandom;
    slice.shuffle(&mut rand::thread_rng());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_mailbox() {
        let pk = [3u8; 32];
        assert_eq!(compute(&pk, 100), compute(&pk, 100));
        assert_ne!(compute(&pk, 100), compute(&pk, 101));
    }

    #[test]
    fn batch_has_eight_entries() {
        let real = current_mailbox(&[7u8; 32]);
        let batch = build_retrieve_batch(&real);
        assert_eq!(batch.len(), 8);
        assert!(batch.contains(&real));
    }
}

