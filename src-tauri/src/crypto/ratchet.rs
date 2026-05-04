//! Double Ratchet state and KDFs.
//!
//! Two HKDF-SHA256 chains with domain separation:
//!
//! - Root chain → `(new_root_key, new_chain_key)` per DH ratchet step.
//!   Info: [`super::ROOT_CHAIN_INFO`].
//! - Chain key → `(next_chain_key, message_key)` per message.
//!   Info: [`super::CHAIN_KEY_INFO`].
//!
//! AAD (40 bytes): `ratchet_key || prev_chain_len_be || msg_num_be`.
//!
//! This module deliberately does not perform AEAD encryption — that's wired in
//! by the caller using [`super::message_crypto`]. We only own state and KDFs,
//! since AEAD/wire-format and ratchet state evolve at different layers.

use super::{
    CryptoError, CryptoResult, CHAIN_KEY_INFO, MAX_CACHED_SKIPPED, MAX_SKIP_PER_CHAIN,
    ROOT_CHAIN_INFO,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    /// Our current sending DH secret (raw bytes — must zeroize on drop manually).
    pub dh_send_secret: [u8; 32],
    pub dh_send_public: [u8; 32],
    /// Peer's current DH public key.
    pub dh_recv_public: Option<[u8; 32]>,
    pub send_msg_num: u32,
    pub recv_msg_num: u32,
    pub prev_send_len: u32,
    /// Skipped message keys: (recv_dh_pub, msg_num) → message_key.
    pub skipped: HashMap<SkipKey, [u8; 32]>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkipKey {
    pub dh_pub: [u8; 32],
    pub msg_num: u32,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(k) = &mut self.send_chain_key {
            k.zeroize();
        }
        if let Some(k) = &mut self.recv_chain_key {
            k.zeroize();
        }
        self.dh_send_secret.zeroize();
        for v in self.skipped.values_mut() {
            v.zeroize();
        }
    }
}

impl RatchetState {
    /// Initialize state on the initiator (Alice) side after PQ-X3DH:
    /// Alice does not yet know Bob's first DH ratchet public key, so the
    /// receive chain is empty. The first DH ratchet step happens when she
    /// gets Bob's first message back.
    pub fn init_initiator(master: &[u8; 32], dh_send_secret: XStaticSecret) -> Self {
        let dh_send_public = XPublicKey::from(&dh_send_secret);
        Self {
            root_key: *master,
            send_chain_key: None,
            recv_chain_key: None,
            dh_send_secret: dh_send_secret.to_bytes(),
            dh_send_public: *dh_send_public.as_bytes(),
            dh_recv_public: None,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_send_len: 0,
            skipped: HashMap::new(),
        }
    }

    /// Initialize state on the responder (Bob) side after PQ-X3DH.
    ///
    /// **No DH step is performed here.** Bob holds the master secret as the
    /// root key and his SPK keypair as the current ratchet keypair. When the
    /// first message arrives, the regular DH ratchet step path picks up the
    /// peer's ratchet pubkey from the wire, advances the root once with
    /// `dh1 = my_spk × peer_ratchet` (matching Alice's bootstrap), and
    /// derives the matching receive chain. A second advancement after
    /// rolling Bob's keypair derives Bob's send chain.
    ///
    /// This mirrors the Android client's `DoubleRatchet.initAsResponder`,
    /// which similarly leaves all chains null and `receivingRatchetKey` null
    /// at init time.
    pub fn init_responder(
        master: &[u8; 32],
        dh_send_secret: XStaticSecret,
    ) -> CryptoResult<Self> {
        let dh_send_public = XPublicKey::from(&dh_send_secret);
        Ok(Self {
            root_key: *master,
            send_chain_key: None,
            recv_chain_key: None,
            dh_send_secret: dh_send_secret.to_bytes(),
            dh_send_public: *dh_send_public.as_bytes(),
            dh_recv_public: None,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_send_len: 0,
            skipped: HashMap::new(),
        })
    }
}

/// HKDF: (root_key, dh_output) → (new_root_key, new_chain_key).
/// 64-byte output, split.
pub fn root_kdf(root_key: &[u8; 32], dh_output: &[u8; 32]) -> CryptoResult<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(ROOT_CHAIN_INFO, &mut *out)
        .map_err(|_| CryptoError::KdfFailure("root HKDF expand"))?;
    let mut nr = [0u8; 32];
    let mut nc = [0u8; 32];
    nr.copy_from_slice(&out[..32]);
    nc.copy_from_slice(&out[32..]);
    Ok((nr, nc))
}

/// HKDF: chain_key → (next_chain_key, message_key).
/// Single 64-byte expand split (matches Signal §5.2 / Android client).
pub fn chain_kdf(chain_key: &[u8; 32]) -> CryptoResult<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(CHAIN_KEY_INFO, &mut *out)
        .map_err(|_| CryptoError::KdfFailure("chain HKDF expand"))?;
    let mut new_chain = [0u8; 32];
    let mut msg_key = [0u8; 32];
    new_chain.copy_from_slice(&out[..32]);
    msg_key.copy_from_slice(&out[32..]);
    Ok((new_chain, msg_key))
}

// --- Public API: encrypt / decrypt one message ---

pub struct Encrypted {
    pub ratchet_key: [u8; 32],
    pub prev_chain_len: u32,
    pub msg_num: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_message(
    state: &mut RatchetState,
    plaintext_padded: &[u8],
    aad_builder: impl Fn(&[u8; 32], u32, u32) -> [u8; 40],
) -> CryptoResult<Encrypted> {
    let chain = state
        .send_chain_key
        .as_ref()
        .copied()
        .ok_or(CryptoError::RatchetState("no send chain key established"))?;
    let (next_chain, mk) = chain_kdf(&chain)?;
    state.send_chain_key = Some(next_chain);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = aad_builder(&state.dh_send_public, state.prev_send_len, state.send_msg_num);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext_padded,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)?;

    let out = Encrypted {
        ratchet_key: state.dh_send_public,
        prev_chain_len: state.prev_send_len,
        msg_num: state.send_msg_num,
        nonce: nonce_bytes,
        ciphertext: ct,
    };
    state.send_msg_num += 1;
    let mut mk = mk;
    mk.zeroize();
    Ok(out)
}

pub fn decrypt_message(
    state: &mut RatchetState,
    sender_dh_pub: &[u8; 32],
    prev_chain_len: u32,
    msg_num: u32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad_builder: impl Fn(&[u8; 32], u32, u32) -> [u8; 40],
) -> CryptoResult<Vec<u8>> {
    // 1) try cached skipped key
    let key = SkipKey {
        dh_pub: *sender_dh_pub,
        msg_num,
    };
    if let Some(mk) = state.skipped.remove(&key) {
        return aead_open(&mk, nonce, ciphertext, &aad_builder(sender_dh_pub, prev_chain_len, msg_num));
    }

    // 2) DH ratchet step if peer's pub changed
    let needs_step = match state.dh_recv_public {
        Some(p) => p != *sender_dh_pub,
        None => true,
    };
    if needs_step {
        // Cache any skipped keys from the *previous* recv chain up to prev_chain_len.
        if let (Some(_), Some(prev_recv_chain)) = (state.dh_recv_public, state.recv_chain_key) {
            cache_skipped_keys(state, &prev_recv_chain, state.recv_msg_num, prev_chain_len)?;
        }
        dh_ratchet_step(state, sender_dh_pub)?;
    }

    // 3) advance the recv chain to msg_num, caching message keys we skip
    let recv_chain = state
        .recv_chain_key
        .as_ref()
        .copied()
        .ok_or(CryptoError::RatchetState("recv chain not established"))?;
    let (final_chain, msg_key) = advance_chain_to(state, recv_chain, msg_num, sender_dh_pub)?;
    state.recv_chain_key = Some(final_chain);
    state.recv_msg_num = msg_num + 1;

    aead_open(
        &msg_key,
        nonce,
        ciphertext,
        &aad_builder(sender_dh_pub, prev_chain_len, msg_num),
    )
}

fn dh_ratchet_step(state: &mut RatchetState, peer_dh_pub: &[u8; 32]) -> CryptoResult<()> {
    let peer_pub = XPublicKey::from(*peer_dh_pub);
    state.prev_send_len = state.send_msg_num;
    state.send_msg_num = 0;
    state.recv_msg_num = 0;
    state.dh_recv_public = Some(*peer_dh_pub);

    // Receive chain
    let our_old = XStaticSecret::from(state.dh_send_secret);
    let dh_old_peer = our_old.diffie_hellman(&peer_pub);
    let (root1, recv_chain) = root_kdf(&state.root_key, dh_old_peer.as_bytes())?;
    state.root_key = root1;
    state.recv_chain_key = Some(recv_chain);

    // Roll our DH key
    let new_secret = XStaticSecret::random_from_rng(OsRng);
    let new_pub = XPublicKey::from(&new_secret);
    state.dh_send_secret = new_secret.to_bytes();
    state.dh_send_public = *new_pub.as_bytes();

    let dh_new_peer = new_secret.diffie_hellman(&peer_pub);
    let (root2, send_chain) = root_kdf(&state.root_key, dh_new_peer.as_bytes())?;
    state.root_key = root2;
    state.send_chain_key = Some(send_chain);
    Ok(())
}

fn advance_chain_to(
    state: &mut RatchetState,
    mut chain: [u8; 32],
    target_num: u32,
    sender_dh_pub: &[u8; 32],
) -> CryptoResult<([u8; 32], [u8; 32])> {
    let from = state.recv_msg_num;
    if target_num < from {
        return Err(CryptoError::RatchetState("message number out of order"));
    }
    let to_skip = target_num - from;
    if to_skip > MAX_SKIP_PER_CHAIN {
        return Err(CryptoError::RatchetState("skipped messages exceed bound"));
    }
    for n in from..target_num {
        let (next, mk) = chain_kdf(&chain)?;
        cache_skip_one(state, sender_dh_pub, n, mk);
        chain = next;
    }
    let (final_chain, msg_key) = chain_kdf(&chain)?;
    Ok((final_chain, msg_key))
}

fn cache_skipped_keys(
    state: &mut RatchetState,
    prev_chain: &[u8; 32],
    from: u32,
    to_exclusive: u32,
) -> CryptoResult<()> {
    if to_exclusive < from {
        return Ok(());
    }
    let count = to_exclusive - from;
    if count > MAX_SKIP_PER_CHAIN {
        return Err(CryptoError::RatchetState("prev chain skip exceeds bound"));
    }
    let prev_pub = state
        .dh_recv_public
        .ok_or(CryptoError::RatchetState("cannot cache without prev pub"))?;
    let mut chain = *prev_chain;
    for n in from..to_exclusive {
        let (next, mk) = chain_kdf(&chain)?;
        cache_skip_one(state, &prev_pub, n, mk);
        chain = next;
    }
    Ok(())
}

fn cache_skip_one(state: &mut RatchetState, dh_pub: &[u8; 32], msg_num: u32, mk: [u8; 32]) {
    if state.skipped.len() >= MAX_CACHED_SKIPPED {
        // LRU-ish eviction: remove an arbitrary entry.
        if let Some(k) = state.skipped.keys().next().cloned() {
            if let Some(mut v) = state.skipped.remove(&k) {
                v.zeroize();
            }
        }
    }
    state.skipped.insert(
        SkipKey {
            dh_pub: *dh_pub,
            msg_num,
        },
        mk,
    );
}

fn aead_open(
    msg_key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8; 40],
) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(msg_key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)
}

fn generate_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut n = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut n);
    n
}
