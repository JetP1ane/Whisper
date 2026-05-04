//! Sender keys for group conversations.
//!
//! Every member of a room owns one *sender key* per room: a 32-byte chain
//! key plus a monotonically increasing message counter. To encrypt a room
//! message the member derives a fresh per-message AEAD key from the chain,
//! ratchets the chain forward, and broadcasts the ciphertext (along with
//! the counter so receivers can re-derive the same per-message key).
//!
//! Decryption tracks the highest counter we've seen from each sender. To
//! handle out-of-order arrivals up to a small window we replay the chain
//! forward to the requested counter; we cap the catch-up to bound the
//! cost of malicious counter spoofing (an attacker can force at most
//! `MAX_SK_CATCHUP` HKDF advances per failed decrypt).
//!
//! Wire format (`pack_room_wire`):
//! ```text
//! [4B magic = 0xFFFFFFFF]
//! [16B room_id (UUID bytes)]
//! [32B sender_ed25519_pub]
//! [4B counter BE]
//! [12B nonce]
//! [4B ciphertext_len BE][ciphertext]
//! ```
//!
//! AEAD: ChaCha20-Poly1305. The AAD binds (room_id || sender_pub || counter)
//! so a receiver can't be tricked into accepting a message under a different
//! room or sender's identity.
//!
//! Trust boundaries (mirroring the Android client):
//! - Sender keys are distributed through the existing pairwise Double Ratchet
//!   channel as a `RoomSenderKey` envelope, so confidentiality / integrity /
//!   forward secrecy of the *distribution* matches direct messaging.
//! - This v1 does not yet rotate keys on member eviction; that's a future
//!   hardening step covered by the `MAX_SK_CATCHUP` cap which keeps the cost
//!   of a misbehaving sender bounded even without rotation.

use super::{CryptoError, CryptoResult};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const ROOM_WIRE_MAGIC: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
pub const ROOM_ID_LEN: usize = 16;
pub const SENDER_PUB_LEN: usize = 32;
pub const SK_NONCE_LEN: usize = 12;
pub const SK_KEY_LEN: usize = 32;
const MAX_SK_CATCHUP: u32 = 1024;

const CHAIN_INFO: &[u8] = b"NoctisWhisper_RoomChain_v1";
const MSG_INFO: &[u8] = b"NoctisWhisper_RoomMessage_v1";

/// Ratcheting state for one (room, member) pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKey {
    pub chain_key: [u8; SK_KEY_LEN],
    pub counter: u32,
}

impl SenderKey {
    /// Generate a fresh sender key with random chain.
    pub fn random() -> Self {
        let mut chain_key = [0u8; SK_KEY_LEN];
        OsRng.fill_bytes(&mut chain_key);
        Self {
            chain_key,
            counter: 0,
        }
    }

    /// Construct from a pre-shared 32-byte chain seed (the bytes we
    /// distribute over the pairwise channel). Counter starts at 0.
    pub fn from_seed(seed: [u8; SK_KEY_LEN]) -> Self {
        Self {
            chain_key: seed,
            counter: 0,
        }
    }

    /// Snapshot the chain seed for transport over the pairwise channel.
    /// Receivers reconstruct their view of this sender's chain via
    /// [`SenderKey::from_seed`].
    pub fn chain_seed(&self) -> [u8; SK_KEY_LEN] {
        self.chain_key
    }
}

/// Derive the per-message AEAD key for `counter` and advance the chain.
fn derive_message_key(chain_key: &[u8; SK_KEY_LEN]) -> ([u8; SK_KEY_LEN], [u8; SK_KEY_LEN]) {
    // Two HKDF expansions off the same chain: one for the next chain key,
    // one for this message key. Both derived from `chain_key` keep the
    // ratchet tight against partial-state leaks.
    let h = Hkdf::<Sha256>::new(None, chain_key);
    let mut next_chain = [0u8; SK_KEY_LEN];
    let mut msg_key = [0u8; SK_KEY_LEN];
    h.expand_multi_info(&[CHAIN_INFO], &mut next_chain).unwrap();
    h.expand_multi_info(&[MSG_INFO], &mut msg_key).unwrap();
    (next_chain, msg_key)
}

#[derive(Debug)]
pub struct RoomEncrypted {
    pub counter: u32,
    pub nonce: [u8; SK_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` for a room message under the caller's sender key,
/// advancing the chain by one step. AAD binds the room+sender+counter.
pub fn encrypt(
    state: &mut SenderKey,
    room_id: &[u8; ROOM_ID_LEN],
    sender_pub: &[u8; SENDER_PUB_LEN],
    plaintext: &[u8],
) -> CryptoResult<RoomEncrypted> {
    let (next_chain, msg_key) = derive_message_key(&state.chain_key);
    let counter = state.counter;

    let mut nonce = [0u8; SK_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let aad = build_aad(room_id, sender_pub, counter);
    let cipher = ChaCha20Poly1305::new((&msg_key).into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)?;

    state.chain_key = next_chain;
    state.counter = counter.wrapping_add(1);

    Ok(RoomEncrypted {
        counter,
        nonce,
        ciphertext,
    })
}

/// Decrypt a room message given the caller's known view of `sender`'s
/// sender key. Advances the chain forward to `target_counter` if needed
/// (replaying past the highest counter we've seen). The chain is not
/// rewound — late arrivals before the last seen counter fail with
/// `RatchetState`. To handle small reorderings, callers should retain
/// previously-derived message keys; this implementation favors simplicity.
pub fn decrypt(
    state: &mut SenderKey,
    room_id: &[u8; ROOM_ID_LEN],
    sender_pub: &[u8; SENDER_PUB_LEN],
    target_counter: u32,
    nonce: &[u8; SK_NONCE_LEN],
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    if target_counter < state.counter {
        return Err(CryptoError::RatchetState(
            "room message counter older than seen — replay or out-of-order",
        ));
    }
    let advance = target_counter - state.counter;
    if advance > MAX_SK_CATCHUP {
        return Err(CryptoError::RatchetState(
            "room sender-key catchup exceeds cap",
        ));
    }

    // Walk the chain forward until our counter equals target_counter.
    // The message key for `target_counter` falls out of the final step.
    let mut chain = state.chain_key;
    let mut local_counter = state.counter;
    let mut last_msg_key = Zeroizing::new([0u8; SK_KEY_LEN]);
    while local_counter <= target_counter {
        let (next_chain, msg_key) = derive_message_key(&chain);
        if local_counter == target_counter {
            *last_msg_key = msg_key;
            chain = next_chain;
            local_counter = local_counter.wrapping_add(1);
            break;
        }
        chain = next_chain;
        local_counter = local_counter.wrapping_add(1);
    }

    let aad = build_aad(room_id, sender_pub, target_counter);
    let cipher = ChaCha20Poly1305::new((&*last_msg_key).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)?;

    state.chain_key = chain;
    state.counter = local_counter;
    Ok(plaintext)
}

fn build_aad(
    room_id: &[u8; ROOM_ID_LEN],
    sender_pub: &[u8; SENDER_PUB_LEN],
    counter: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ROOM_ID_LEN + SENDER_PUB_LEN + 4);
    aad.extend_from_slice(room_id);
    aad.extend_from_slice(sender_pub);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad
}

/// Pack a room-message wire blob with the magic prefix the inbound
/// dispatcher uses to distinguish from pairwise wires.
pub fn pack_room_wire(
    room_id: &[u8; ROOM_ID_LEN],
    sender_pub: &[u8; SENDER_PUB_LEN],
    enc: &RoomEncrypted,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ROOM_ID_LEN + SENDER_PUB_LEN + 4 + SK_NONCE_LEN + 4 + enc.ciphertext.len());
    out.extend_from_slice(&ROOM_WIRE_MAGIC);
    out.extend_from_slice(room_id);
    out.extend_from_slice(sender_pub);
    out.extend_from_slice(&enc.counter.to_be_bytes());
    out.extend_from_slice(&enc.nonce);
    out.extend_from_slice(&(enc.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&enc.ciphertext);
    out
}

#[derive(Debug)]
pub struct ParsedRoomWire {
    pub room_id: [u8; ROOM_ID_LEN],
    pub sender_pub: [u8; SENDER_PUB_LEN],
    pub counter: u32,
    pub nonce: [u8; SK_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn parse_room_wire(buf: &[u8]) -> CryptoResult<ParsedRoomWire> {
    let mut p = 0;
    if buf.len() < 4 + ROOM_ID_LEN + SENDER_PUB_LEN + 4 + SK_NONCE_LEN + 4 {
        return Err(CryptoError::Decode("room wire too short"));
    }
    if buf[..4] != ROOM_WIRE_MAGIC {
        return Err(CryptoError::Decode("room wire magic mismatch"));
    }
    p += 4;

    let mut room_id = [0u8; ROOM_ID_LEN];
    room_id.copy_from_slice(&buf[p..p + ROOM_ID_LEN]);
    p += ROOM_ID_LEN;

    let mut sender_pub = [0u8; SENDER_PUB_LEN];
    sender_pub.copy_from_slice(&buf[p..p + SENDER_PUB_LEN]);
    p += SENDER_PUB_LEN;

    let counter = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap());
    p += 4;

    let mut nonce = [0u8; SK_NONCE_LEN];
    nonce.copy_from_slice(&buf[p..p + SK_NONCE_LEN]);
    p += SK_NONCE_LEN;

    let ct_len = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    if p + ct_len > buf.len() {
        return Err(CryptoError::Decode("room wire ciphertext truncated"));
    }
    let ciphertext = buf[p..p + ct_len].to_vec();

    Ok(ParsedRoomWire {
        room_id,
        sender_pub,
        counter,
        nonce,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keys() -> ([u8; ROOM_ID_LEN], [u8; SENDER_PUB_LEN]) {
        let mut room = [0u8; ROOM_ID_LEN];
        OsRng.fill_bytes(&mut room);
        let mut pubk = [0u8; SENDER_PUB_LEN];
        OsRng.fill_bytes(&mut pubk);
        (room, pubk)
    }

    #[test]
    fn round_trip_in_order() {
        let (room, pubk) = make_keys();
        let mut alice_send = SenderKey::random();
        let mut bob_recv = SenderKey::from_seed(alice_send.chain_seed());

        for i in 0..5u32 {
            let plaintext = format!("msg {i}");
            let enc = encrypt(&mut alice_send, &room, &pubk, plaintext.as_bytes()).unwrap();
            let pt =
                decrypt(&mut bob_recv, &room, &pubk, enc.counter, &enc.nonce, &enc.ciphertext)
                    .unwrap();
            assert_eq!(pt, plaintext.as_bytes());
        }
    }

    #[test]
    fn aad_binds_sender_pubkey() {
        let (room, pubk) = make_keys();
        let mut alice_send = SenderKey::random();
        let mut bob_recv = SenderKey::from_seed(alice_send.chain_seed());

        let enc = encrypt(&mut alice_send, &room, &pubk, b"hello").unwrap();
        let mut other_pubk = pubk;
        other_pubk[0] ^= 0xFF;

        let result = decrypt(
            &mut bob_recv,
            &room,
            &other_pubk,
            enc.counter,
            &enc.nonce,
            &enc.ciphertext,
        );
        assert!(matches!(result, Err(CryptoError::AeadFailure)));
    }

    #[test]
    fn wire_round_trip() {
        let (room, pubk) = make_keys();
        let mut sk = SenderKey::random();
        let enc = encrypt(&mut sk, &room, &pubk, b"on the wire").unwrap();
        let bytes = pack_room_wire(&room, &pubk, &enc);
        let parsed = parse_room_wire(&bytes).unwrap();
        assert_eq!(parsed.room_id, room);
        assert_eq!(parsed.sender_pub, pubk);
        assert_eq!(parsed.counter, enc.counter);
        assert_eq!(parsed.nonce, enc.nonce);
        assert_eq!(parsed.ciphertext, enc.ciphertext);
    }

    #[test]
    fn skip_within_cap_succeeds() {
        let (room, pubk) = make_keys();
        let mut alice_send = SenderKey::random();
        let mut bob_recv = SenderKey::from_seed(alice_send.chain_seed());

        // Burn a few messages on the sender side without delivery.
        for _ in 0..3 {
            let _ = encrypt(&mut alice_send, &room, &pubk, b"missed").unwrap();
        }
        let enc = encrypt(&mut alice_send, &room, &pubk, b"caught up").unwrap();
        let pt =
            decrypt(&mut bob_recv, &room, &pubk, enc.counter, &enc.nonce, &enc.ciphertext)
                .unwrap();
        assert_eq!(pt, b"caught up");
    }
}
