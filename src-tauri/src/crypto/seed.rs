//! BIP39 seed-phrase identity (12 words / 128-bit entropy).
//!
//! Workflow:
//!
//! 1. `generate()` — fresh 16 bytes of entropy → 12 BIP39 words + 4-bit
//!    checksum (per BIP-0039). The 12 words are what the user writes
//!    down; the 16-byte entropy and the BIP39-stretched 64-byte master
//!    seed are what we keep on disk (encrypted).
//!
//! 2. `entropy_from_phrase()` — 12 words → 16-byte entropy. Verifies the
//!    BIP39 checksum so a user typo on recovery fails fast instead of
//!    silently materializing a different identity.
//!
//! 3. `master_from_phrase()` — runs the BIP39 PBKDF2-HMAC-SHA512 stretch
//!    (2048 iterations, salt = "mnemonic" + optional passphrase) to derive
//!    the 64-byte master seed.
//!
//! 4. `derive_identity_seeds()` — HKDF-SHA256 the master into the
//!    individual key seeds (Ed25519 32B, X25519 32B, ML-KEM RNG seed 32B)
//!    using domain-separated infos so a leak of one doesn't reveal others.
//!
//! Storage: only the 16-byte entropy is persisted (encrypted under the
//! vault DEK). The 64-byte master is derived on demand so a vault dump
//! without the passphrase yields nothing.

use super::CryptoError;
use crate::crypto::keys::BIP39_WORDS;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

const ENTROPY_BYTES: usize = 16; // 12-word phrase
const CHECKSUM_BITS: usize = 4;
const WORD_COUNT: usize = 12;

/// Generate fresh BIP39 entropy and return the matching 12-word phrase.
pub fn generate() -> (Zeroizing<[u8; ENTROPY_BYTES]>, String) {
    let mut entropy = [0u8; ENTROPY_BYTES];
    OsRng.fill_bytes(&mut entropy);
    let phrase = phrase_from_entropy(&entropy);
    (Zeroizing::new(entropy), phrase)
}

/// Convert 16-byte entropy into a 12-word BIP39 phrase. Public so the
/// recovery flow can re-verify the words a user types match the
/// re-derived entropy (round-trip sanity check).
pub fn phrase_from_entropy(entropy: &[u8; ENTROPY_BYTES]) -> String {
    // BIP39: SHA-256(entropy)[0..CS] = checksum, where CS = entropy_len/4.
    let mut h = Sha256::new();
    h.update(entropy);
    let digest = h.finalize();
    let checksum = digest[0] >> (8 - CHECKSUM_BITS);

    // Concatenate entropy bits + checksum bits, then split into 11-bit
    // groups. 132 bits / 11 = 12 words for 128-bit entropy.
    let mut bits = Vec::with_capacity(ENTROPY_BYTES * 8 + CHECKSUM_BITS);
    for byte in entropy {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1);
        }
    }
    for i in 0..CHECKSUM_BITS {
        bits.push((checksum >> (CHECKSUM_BITS - 1 - i)) & 1);
    }

    let mut words = Vec::with_capacity(WORD_COUNT);
    for chunk in bits.chunks(11) {
        let mut idx: u16 = 0;
        for &b in chunk {
            idx = (idx << 1) | b as u16;
        }
        words.push(BIP39_WORDS[idx as usize]);
    }
    words.join(" ")
}

/// Parse a 12-word phrase back to entropy. Verifies the BIP39 checksum.
pub fn entropy_from_phrase(phrase: &str) -> Result<[u8; ENTROPY_BYTES], CryptoError> {
    let normalized: Vec<&str> = phrase
        .split_whitespace()
        .map(|w| w.trim_end_matches(','))
        .collect();
    if normalized.len() != WORD_COUNT {
        return Err(CryptoError::InvalidInput("phrase must be exactly 12 words"));
    }

    let mut bits: Vec<u8> = Vec::with_capacity(ENTROPY_BYTES * 8 + CHECKSUM_BITS);
    for w in &normalized {
        let lower = w.to_lowercase();
        let idx = BIP39_WORDS
            .iter()
            .position(|x| **x == lower)
            .ok_or(CryptoError::InvalidInput("word not in BIP39 list"))?;
        for i in 0..11 {
            bits.push(((idx >> (10 - i)) & 1) as u8);
        }
    }

    let mut entropy = [0u8; ENTROPY_BYTES];
    for (i, byte) in entropy.iter_mut().enumerate() {
        let mut b: u8 = 0;
        for j in 0..8 {
            b = (b << 1) | bits[i * 8 + j];
        }
        *byte = b;
    }

    let mut checksum: u8 = 0;
    for j in 0..CHECKSUM_BITS {
        checksum = (checksum << 1) | bits[ENTROPY_BYTES * 8 + j];
    }
    let mut h = Sha256::new();
    h.update(entropy);
    let expected = h.finalize()[0] >> (8 - CHECKSUM_BITS);
    if checksum != expected {
        return Err(CryptoError::InvalidInput(
            "phrase checksum mismatch — check for typos",
        ));
    }
    Ok(entropy)
}

/// Run BIP39's PBKDF2-HMAC-SHA512 stretch to derive the 64-byte master
/// seed from a phrase. The optional passphrase is the BIP39 "passphrase"
/// (independent from our vault DEK passphrase) — we currently leave it
/// empty since recovery already gates on the vault passphrase.
pub fn master_from_phrase(phrase: &str, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let salt = format!("mnemonic{passphrase}");
    let mut master = [0u8; 64];
    let _ = pbkdf2::<Hmac<Sha512>>(phrase.as_bytes(), salt.as_bytes(), 2048, &mut master);
    Zeroizing::new(master)
}

/// HKDF-derived per-key seeds. The two classical keys (Ed25519, X25519)
/// are *identity-anchoring* — the alias is `derive_alias(ed25519_pub)`,
/// and pairwise PQ-X3DH agreements DH against `x25519`. Both must be
/// reproducible across recoveries so the user's alias and direct-chat
/// identity survive.
///
/// ML-KEM intentionally is **not** seed-derived. The pqcrypto-mlkem crate
/// doesn't expose a seeded keygen, and the identity-level ML-KEM key is
/// only used during PQ-X3DH bootstrap; the bundle republishes after every
/// OTPK consumption anyway, so a fresh ML-KEM key per recovery is
/// transparent to peers.
pub struct IdentitySeeds {
    pub ed25519: Zeroizing<[u8; 32]>,
    pub x25519: Zeroizing<[u8; 32]>,
}

pub fn derive_identity_seeds(master: &[u8; 64]) -> IdentitySeeds {
    use hkdf::Hkdf;
    let h = Hkdf::<Sha512>::new(None, master);
    let mut ed = [0u8; 32];
    let mut x = [0u8; 32];
    h.expand(b"NoctisWhisper_Identity_Ed25519_v1", &mut ed)
        .expect("hkdf");
    h.expand(b"NoctisWhisper_Identity_X25519_v1", &mut x)
        .expect("hkdf");
    IdentitySeeds {
        ed25519: Zeroizing::new(ed),
        x25519: Zeroizing::new(x),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_round_trip_via_phrase() {
        let (entropy, phrase) = generate();
        let recovered = entropy_from_phrase(&phrase).unwrap();
        assert_eq!(recovered, *entropy);
    }

    #[test]
    fn rejects_bad_checksum() {
        // The 4-bit BIP39 checksum means a random last-word swap has a
        // ~6% chance of accidentally re-validating. The original test
        // tried exactly one swap and was flaky for that reason. We
        // instead generate a fresh phrase and walk through replacement
        // candidates until one breaks the checksum, asserting that
        // such a replacement exists for any phrase. Bounded loop so a
        // genuine bug can't hang the test.
        let (_, phrase) = generate();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let last = words.last().copied().unwrap();
        let candidates = [
            "abandon", "ability", "able", "about", "above",
            "absent", "absorb", "abstract", "absurd", "abuse",
            "access", "accident", "account", "accuse", "achieve",
            "acid", "acoustic",
        ];
        let mut hit_failure = false;
        for &cand in candidates.iter() {
            if cand == last {
                continue;
            }
            let mut new_phrase = words[..words.len() - 1].join(" ");
            new_phrase.push(' ');
            new_phrase.push_str(cand);
            match entropy_from_phrase(&new_phrase) {
                Err(CryptoError::InvalidInput(_)) => {
                    hit_failure = true;
                    break;
                }
                Ok(_) => continue,
                other => panic!("unexpected error variant: {other:?}"),
            }
        }
        assert!(
            hit_failure,
            "no candidate last-word swap produced a checksum failure — \
             this is statistically impossible (each candidate has ~94% \
             chance) so something is very wrong"
        );
    }

    #[test]
    fn rejects_unknown_word() {
        let bad = "bogus zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo";
        assert!(entropy_from_phrase(bad).is_err());
    }

    #[test]
    fn rejects_wrong_word_count() {
        assert!(entropy_from_phrase("abandon abandon").is_err());
    }

    #[test]
    fn master_is_deterministic_from_phrase() {
        let (_entropy, phrase) = generate();
        let m1 = master_from_phrase(&phrase, "");
        let m2 = master_from_phrase(&phrase, "");
        assert_eq!(*m1, *m2);
    }

    #[test]
    fn identity_seeds_are_distinct() {
        let (_, phrase) = generate();
        let master = master_from_phrase(&phrase, "");
        let s = derive_identity_seeds(&master);
        assert_ne!(*s.ed25519, *s.x25519);
    }

    #[test]
    fn identity_seeds_are_deterministic() {
        let (_entropy, phrase) = generate();
        let m1 = master_from_phrase(&phrase, "");
        let m2 = master_from_phrase(&phrase, "");
        let s1 = derive_identity_seeds(&m1);
        let s2 = derive_identity_seeds(&m2);
        assert_eq!(*s1.ed25519, *s2.ed25519);
        assert_eq!(*s1.x25519, *s2.x25519);
    }
}
