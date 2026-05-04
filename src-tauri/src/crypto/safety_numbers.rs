//! Safety numbers and key fingerprints for out-of-band identity verification.
//!
//! Algorithm (matches Android client):
//!
//! ```text
//! prefix   = SHA-256("NoctisWhisper_v1")
//! hashA    = SHA-512(prefix || my_identity_key)
//! hashB    = SHA-512(prefix || peer_identity_key)
//! combined = (lex sort) hashA || hashB
//! 12 groups: each = (5 bytes from combined as big-endian u64) mod 100000
//! ```
//!
//! Output: 12 × 5-digit groups = 60 digits.

use sha2::{Digest, Sha256, Sha512};

const PREFIX_INPUT: &[u8] = b"NoctisWhisper_v1";

pub fn safety_numbers(my_id: &[u8; 32], peer_id: &[u8; 32]) -> [u32; 12] {
    let prefix = Sha256::digest(PREFIX_INPUT);
    let hash_a = sha512_with_prefix(&prefix, my_id);
    let hash_b = sha512_with_prefix(&prefix, peer_id);

    // Lexicographic sort so both peers produce identical output.
    let (lo, hi) = if hash_a.as_slice() <= hash_b.as_slice() {
        (hash_a, hash_b)
    } else {
        (hash_b, hash_a)
    };
    let mut combined = [0u8; 128];
    combined[..64].copy_from_slice(&lo);
    combined[64..].copy_from_slice(&hi);

    let mut out = [0u32; 12];
    for (i, slot) in out.iter_mut().enumerate() {
        let off = i * 5;
        let mut buf = [0u8; 8];
        buf[3..].copy_from_slice(&combined[off..off + 5]);
        let v = u64::from_be_bytes(buf);
        *slot = (v % 100_000) as u32;
    }
    out
}

fn sha512_with_prefix(prefix: &[u8], key: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(prefix);
    h.update(key);
    let digest = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Format the Ed25519 identity key as uppercase hex grouped in 4-character
/// (2-byte) chunks — matches the Android client's `chunked(4)` output.
pub fn hex_fingerprint(ed25519_pub: &[u8; 32]) -> String {
    let hex_str = hex::encode_upper(ed25519_pub);
    let mut grouped = String::with_capacity(hex_str.len() + hex_str.len() / 4);
    for (i, c) in hex_str.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            grouped.push(' ');
        }
        grouped.push(c);
    }
    grouped
}

/// Format safety numbers as "12345 67890 ..." for display.
pub fn format_safety_numbers(numbers: &[u32; 12]) -> String {
    numbers
        .iter()
        .map(|n| format!("{:05}", n))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_numbers_symmetric() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(safety_numbers(&a, &b), safety_numbers(&b, &a));
    }

    #[test]
    fn formatted_groups() {
        let numbers = [12345u32; 12];
        let s = format_safety_numbers(&numbers);
        assert_eq!(s.split(' ').count(), 12);
    }

    #[test]
    fn hex_fp_grouping() {
        let key = [0xABu8; 32];
        let s = hex_fingerprint(&key);
        // 32 bytes = 64 hex chars in 16 groups of 4 chars + 15 separator spaces.
        assert_eq!(s.len(), 64 + 15);
        assert_eq!(s.split(' ').count(), 16);
    }
}
