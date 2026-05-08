//! Hybrid post-quantum X3DH.
//!
//! ```text
//! dh1 = X25519(IK_alice,  SPK_bob)
//! dh2 = X25519(EK_alice,  IK_bob.x25519)
//! dh3 = X25519(EK_alice,  SPK_bob)
//! dh4 = X25519(EK_alice,  OTPK_bob)              -- if present
//!
//! kem1_secret, kem1_ct = ML-KEM.Encapsulate(SPK_bob.kyber_pub)
//! kem2_secret, kem2_ct = ML-KEM.Encapsulate(OTPK_bob.kyber_pub)  -- if present
//!
//! IKM = dh1 || dh2 || dh3 || dh4 || kem1_secret || kem2_secret
//! master = HKDF-SHA256(IKM, salt = X3DH_SALT, info = X3DH_INFO, len = 32)
//! ```
//!
//! Domain strings live in [`super::X3DH_SALT`] / [`super::X3DH_INFO`].
//!
//! Known hardening gap (M-2/M-3, deferred to a protocol-bump release):
//!
//! The IKM transcript currently binds the X25519 identity keys *only via
//! their use inside dh1/dh2*. The Ed25519 identity keys are not in the
//! transcript, nor are the KEM ciphertexts or SPK/OTPK IDs. Adding
//! `IK_alice_ed25519 || IK_bob_ed25519 || kem1_ct || kem2_ct || spk_id ||
//! otpk_id` to the IKM would close two narrow gaps:
//!   1. An attacker who learns one of Bob's X25519 identity keys (without
//!      learning the Ed25519 identity that derives the alias) cannot
//!      currently be detected by the transcript — adding the Ed25519
//!      key forces the alias-binding into the master derivation.
//!   2. A KEM-ciphertext substitution by a MITM (e.g., re-using a
//!      replayed kem1_ct against a still-valid SPK) would change the
//!      transcript hash and fail.
//!
//! This change is **deferred** because the wire format (and therefore
//! the IKM byte order) is shared byte-for-byte with the Android client
//! — see [`pack_session_init`]. Applying it desktop-only would silently
//! fork session-init compatibility. The fix requires a coordinated
//! version-bumped release across both clients with a v4-vs-v5 bundle
//! tag selecting the binding mode.

use super::{CryptoError, CryptoResult, X3DH_INFO, X3DH_SALT};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroizing;

/// Inputs needed by an initiator (Alice) to compute the master secret.
///
/// Note: Bob's OTPK X25519 public key is **always required** (matches the
/// Android client). Only the OTPK ML-KEM portion is optional, because compact
/// QR bundles omit the 1568-byte kyber key for size.
pub struct InitiatorInputs<'a> {
    pub ik_alice: &'a XStaticSecret,         // Alice's long-term X25519 secret
    pub ek_alice: &'a XStaticSecret,         // Alice's ephemeral X25519 secret
    pub spk_bob_x25519: &'a XPublicKey,
    pub ik_bob_x25519: &'a XPublicKey,
    pub otpk_bob_x25519: &'a XPublicKey,
    pub spk_bob_mlkem_pub: &'a [u8],         // 1568-byte ML-KEM-1024 public key
    pub otpk_bob_mlkem_pub: Option<&'a [u8]>,
}

pub struct InitiatorOutput {
    pub master_secret: Zeroizing<[u8; 32]>,
    pub kem1_ciphertext: Vec<u8>,         // ML-KEM-1024 ciphertext (1568 bytes)
    pub kem2_ciphertext: Option<Vec<u8>>, // present iff OTPK was used
}

pub fn initiator_agree(input: InitiatorInputs<'_>) -> CryptoResult<InitiatorOutput> {
    // --- DH chunks ---
    let dh1 = input.ik_alice.diffie_hellman(input.spk_bob_x25519);
    let dh2 = input.ek_alice.diffie_hellman(input.ik_bob_x25519);
    let dh3 = input.ek_alice.diffie_hellman(input.spk_bob_x25519);
    let dh4 = input.ek_alice.diffie_hellman(input.otpk_bob_x25519);

    // --- KEM chunks ---
    let spk_pk = mlkem1024::PublicKey::from_bytes(input.spk_bob_mlkem_pub)
        .map_err(|_| CryptoError::KemFailure("invalid SPK ML-KEM public key"))?;
    let (kem1_secret, kem1_ct) = mlkem1024::encapsulate(&spk_pk);

    let (kem2_secret, kem2_ct) = match input.otpk_bob_mlkem_pub {
        Some(bytes) => {
            let pk = mlkem1024::PublicKey::from_bytes(bytes)
                .map_err(|_| CryptoError::KemFailure("invalid OTPK ML-KEM public key"))?;
            let (s, c) = mlkem1024::encapsulate(&pk);
            (Some(s), Some(c))
        }
        None => (None, None),
    };

    // --- IKM ---
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 4 + 32 * 2));
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    ikm.extend_from_slice(dh4.as_bytes());
    ikm.extend_from_slice(kem1_secret.as_bytes());
    if let Some(s2) = &kem2_secret {
        ikm.extend_from_slice(s2.as_bytes());
    }

    let mut master = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha256>::new(Some(X3DH_SALT), &ikm);
    hk.expand(X3DH_INFO, &mut *master)
        .map_err(|_| CryptoError::KdfFailure("HKDF expand failed"))?;

    Ok(InitiatorOutput {
        master_secret: master,
        kem1_ciphertext: kem1_ct.as_bytes().to_vec(),
        kem2_ciphertext: kem2_ct.map(|c| c.as_bytes().to_vec()),
    })
}

/// Inputs needed by a responder (Bob) to compute the master secret from a session-init message.
pub struct ResponderInputs<'a> {
    pub ik_bob_x25519: &'a XStaticSecret,
    pub spk_bob_x25519: &'a XStaticSecret,
    pub spk_bob_mlkem_secret: &'a [u8], // raw ML-KEM secret bytes
    pub otpk_bob_x25519: &'a XStaticSecret,
    pub otpk_bob_mlkem_secret: Option<&'a [u8]>,
    pub ik_alice_x25519_pub: &'a XPublicKey,
    pub ek_alice_pub: &'a XPublicKey,
    pub kem1_ciphertext: &'a [u8],
    pub kem2_ciphertext: Option<&'a [u8]>,
}

pub fn responder_agree(input: ResponderInputs<'_>) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let dh1 = input.spk_bob_x25519.diffie_hellman(input.ik_alice_x25519_pub);
    let dh2 = input.ik_bob_x25519.diffie_hellman(input.ek_alice_pub);
    let dh3 = input.spk_bob_x25519.diffie_hellman(input.ek_alice_pub);
    let dh4 = input.otpk_bob_x25519.diffie_hellman(input.ek_alice_pub);

    let spk_sk = mlkem1024::SecretKey::from_bytes(input.spk_bob_mlkem_secret)
        .map_err(|_| CryptoError::KemFailure("invalid SPK ML-KEM secret"))?;
    let kem1_ct = mlkem1024::Ciphertext::from_bytes(input.kem1_ciphertext)
        .map_err(|_| CryptoError::KemFailure("invalid SPK ML-KEM ciphertext"))?;
    let kem1_secret = mlkem1024::decapsulate(&kem1_ct, &spk_sk);

    let kem2_secret = match (input.otpk_bob_mlkem_secret, input.kem2_ciphertext) {
        (Some(sk_bytes), Some(ct_bytes)) => {
            let sk = mlkem1024::SecretKey::from_bytes(sk_bytes)
                .map_err(|_| CryptoError::KemFailure("invalid OTPK ML-KEM secret"))?;
            let ct = mlkem1024::Ciphertext::from_bytes(ct_bytes)
                .map_err(|_| CryptoError::KemFailure("invalid OTPK ML-KEM ciphertext"))?;
            Some(mlkem1024::decapsulate(&ct, &sk))
        }
        _ => None,
    };

    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 4 + 32 * 2));
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    ikm.extend_from_slice(dh4.as_bytes());
    ikm.extend_from_slice(kem1_secret.as_bytes());
    if let Some(s2) = &kem2_secret {
        ikm.extend_from_slice(s2.as_bytes());
    }

    let mut master = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha256>::new(Some(X3DH_SALT), &ikm);
    hk.expand(X3DH_INFO, &mut *master)
        .map_err(|_| CryptoError::KdfFailure("HKDF expand failed"))?;
    Ok(master)
}

/// Session-init binary layout — matches Android `MessageCrypto.serializeSessionInit`:
///
/// ```text
/// writeField(initiator_x25519_pub)     // [4B len BE][bytes]
/// writeField(initiator_ephemeral_pub)
/// writeField(kem1_ciphertext)
/// writeField(kem2_ciphertext)          // length 0 if no OTPK kyber
/// writeInt(used_otpk_id)               // [4B BE], i32
/// ```
///
/// Note: the first field is Alice's **X25519** public key, not her Ed25519
/// identity key — the receiver uses it for `dh1 = SPK_bob × IK_alice.x25519`.
///
/// Wrapped for transmission with [`pack_first_message`]:
/// `[4B session_init_len][session_init_bytes][4096B encrypted_message]`.
pub fn pack_session_init(
    ik_alice_x25519: &[u8; 32],
    ek_alice: &[u8; 32],
    kem1_ct: &[u8],
    kem2_ct: Option<&[u8]>,
    used_otpk_id: u32,
) -> Vec<u8> {
    fn write_field(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    let kem2 = kem2_ct.unwrap_or(&[]);
    let mut out = Vec::with_capacity(4 + 32 + 4 + 32 + 4 + kem1_ct.len() + 4 + kem2.len() + 4);
    write_field(&mut out, ik_alice_x25519);
    write_field(&mut out, ek_alice);
    write_field(&mut out, kem1_ct);
    write_field(&mut out, kem2);
    out.extend_from_slice(&used_otpk_id.to_be_bytes());
    out
}

/// Wrap a session-init blob and a 4096-byte encrypted message into the
/// first-message payload sent on the relay:
/// `[4B session_init_len BE][session_init][4096B encrypted_message]`.
pub fn pack_first_message(session_init: &[u8], encrypted_message_4096: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + session_init.len() + encrypted_message_4096.len());
    out.extend_from_slice(&(session_init.len() as u32).to_be_bytes());
    out.extend_from_slice(session_init);
    out.extend_from_slice(encrypted_message_4096);
    out
}
