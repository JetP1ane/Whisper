//! Identity and prekey generation, plus BIP39 three-word alias derivation.
//!
//! Identity layout (matches Android client):
//!
//! - **Identity Key (IK)**: Ed25519, used only for signatures.
//! - **X25519 base key**:   long-term DH key (separate from IK).
//! - **ML-KEM-1024 base**:  long-term post-quantum KEM key.
//! - **Signed Prekey (SPK)**: rotating X25519 + ML-KEM-1024 pair, signed by IK.
//! - **One-Time Prekeys**:    10 X25519 + ML-KEM-1024 pairs, consumed on use.

use ed25519_dalek::{Signer, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::ZeroizeOnDrop;

// --- Public bundle ---

#[derive(Clone, Debug)]
pub struct PublicBundle {
    pub ed25519_public: [u8; 32],
    pub x25519_public: [u8; 32],
    pub mlkem_public: Vec<u8>, // 1568 bytes
    pub spk_x25519_public: [u8; 32],
    pub spk_mlkem_public: Vec<u8>,
    pub spk_signature: [u8; 64],
    pub one_time_prekeys: Vec<OneTimePrekeyPublic>,
}

#[derive(Clone, Debug)]
pub struct OneTimePrekeyPublic {
    pub id: u32,
    pub x25519_public: [u8; 32],
    pub mlkem_public: Vec<u8>,
}

// --- Private state (zeroized on drop) ---
//
// We keep both public and secret ML-KEM bytes together because the
// `pqcrypto-mlkem` API does not expose a public-from-secret derivation.

#[derive(ZeroizeOnDrop)]
pub struct IdentityKeys {
    #[zeroize(skip)]
    pub ed25519_signing: EdSigningKey,
    pub x25519_secret: XStaticSecret,
    pub mlkem_secret: Vec<u8>, // 3168 bytes for ML-KEM-1024
    #[zeroize(skip)]
    pub mlkem_public: Vec<u8>, // 1568 bytes
}

#[derive(ZeroizeOnDrop)]
pub struct SignedPrekey {
    pub id: u32,
    pub x25519_secret: XStaticSecret,
    pub mlkem_secret: Vec<u8>,
    #[zeroize(skip)]
    pub mlkem_public: Vec<u8>,
    #[zeroize(skip)]
    pub signature: [u8; 64],
}

#[derive(ZeroizeOnDrop)]
pub struct OneTimePrekey {
    pub id: u32,
    pub x25519_secret: XStaticSecret,
    pub mlkem_secret: Vec<u8>,
    #[zeroize(skip)]
    pub mlkem_public: Vec<u8>,
}

// --- Generators ---

pub fn generate_identity() -> IdentityKeys {
    let mut csprng = OsRng;
    let ed25519_signing = EdSigningKey::generate(&mut csprng);
    let x25519_secret = XStaticSecret::random_from_rng(OsRng);
    let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();
    IdentityKeys {
        ed25519_signing,
        x25519_secret,
        mlkem_secret: mlkem_sk.as_bytes().to_vec(),
        mlkem_public: mlkem_pk.as_bytes().to_vec(),
    }
}

/// Same as `generate_identity` but uses BIP39-derived per-key seeds for
/// the classical keys so vault recovery from a seed phrase produces the
/// exact same alias (Ed25519 pubkey) and X25519 identity. ML-KEM stays
/// random per device — see crypto::seed for rationale.
pub fn generate_identity_from_seeds(
    seeds: &crate::crypto::seed::IdentitySeeds,
) -> IdentityKeys {
    let ed25519_signing = EdSigningKey::from_bytes(&seeds.ed25519);
    let x25519_secret = XStaticSecret::from(*seeds.x25519);
    let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();
    IdentityKeys {
        ed25519_signing,
        x25519_secret,
        mlkem_secret: mlkem_sk.as_bytes().to_vec(),
        mlkem_public: mlkem_pk.as_bytes().to_vec(),
    }
}

pub fn generate_signed_prekey(id: u32, ik: &IdentityKeys) -> SignedPrekey {
    let x25519_secret = XStaticSecret::random_from_rng(OsRng);
    let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();

    // Signature payload = x25519_pub || mlkem_pub  (matches Android client)
    let x25519_pub = XPublicKey::from(&x25519_secret);
    let mut msg = Vec::with_capacity(32 + 1568);
    msg.extend_from_slice(x25519_pub.as_bytes());
    msg.extend_from_slice(mlkem_pk.as_bytes());

    let sig = ik.ed25519_signing.sign(&msg);
    SignedPrekey {
        id,
        x25519_secret,
        mlkem_secret: mlkem_sk.as_bytes().to_vec(),
        mlkem_public: mlkem_pk.as_bytes().to_vec(),
        signature: sig.to_bytes(),
    }
}

pub fn generate_one_time_prekeys(count: usize, start_id: u32) -> Vec<OneTimePrekey> {
    (0..count)
        .map(|i| {
            let x25519_secret = XStaticSecret::random_from_rng(OsRng);
            let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();
            OneTimePrekey {
                id: start_id + i as u32,
                x25519_secret,
                mlkem_secret: mlkem_sk.as_bytes().to_vec(),
                mlkem_public: mlkem_pk.as_bytes().to_vec(),
            }
        })
        .collect()
}

// --- Public-key extraction ---

impl IdentityKeys {
    pub fn ed25519_verifying(&self) -> EdVerifyingKey {
        self.ed25519_signing.verifying_key()
    }
    pub fn x25519_public(&self) -> XPublicKey {
        XPublicKey::from(&self.x25519_secret)
    }
    pub fn mlkem_public_bytes(&self) -> &[u8] {
        &self.mlkem_public
    }
}

// --- BIP39 three-word alias ---
//
// Algorithm (must match Android byte-for-byte):
//   hash = SHA-256(public_key)
//   word_i = BIP39[ extract_11_bits(hash, i*11 .. i*11+11) ] for i in 0..3
//   alias = "{w0}-{w1}-{w2}"
//
// We use the Ed25519 verifying key bytes as `public_key`.

pub fn derive_alias(ed25519_public: &[u8; 32]) -> String {
    let hash = Sha256::digest(ed25519_public);
    let i0 = extract_11_bits(&hash, 0);
    let i1 = extract_11_bits(&hash, 11);
    let i2 = extract_11_bits(&hash, 22);
    format!(
        "{}-{}-{}",
        BIP39_WORDS[i0 as usize], BIP39_WORDS[i1 as usize], BIP39_WORDS[i2 as usize]
    )
}

/// Extract `bit_len = 11` bits from `data` starting at `bit_offset`, big-endian.
fn extract_11_bits(data: &[u8], bit_offset: usize) -> u16 {
    let byte_idx = bit_offset / 8;
    let bit_idx = bit_offset % 8;
    // We need up to 3 bytes to span an 11-bit window.
    let b0 = *data.get(byte_idx).unwrap_or(&0) as u32;
    let b1 = *data.get(byte_idx + 1).unwrap_or(&0) as u32;
    let b2 = *data.get(byte_idx + 2).unwrap_or(&0) as u32;
    let combined = (b0 << 16) | (b1 << 8) | b2;
    let shift = 24 - bit_idx - 11;
    ((combined >> shift) & 0x7FF) as u16
}

/// Embedded BIP39 English wordlist (2048 words).
/// Loaded from a separate file to keep this module readable.
pub static BIP39_WORDS: &[&str; 2048] = &include!("bip39_english.in");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_is_deterministic() {
        let pk = [42u8; 32];
        let a = derive_alias(&pk);
        let b = derive_alias(&pk);
        assert_eq!(a, b);
        assert_eq!(a.split('-').count(), 3);
    }

    #[test]
    fn alias_words_are_valid_bip39() {
        let pk = [7u8; 32];
        let alias = derive_alias(&pk);
        for word in alias.split('-') {
            assert!(BIP39_WORDS.contains(&word), "{} not in BIP39", word);
        }
    }
}
