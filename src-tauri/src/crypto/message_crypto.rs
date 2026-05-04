//! Wire format: plaintext envelope, padding, AEAD, and outer ratchet wire layout.
//!
//! Plaintext envelope (inside AEAD):
//!
//! ```text
//! Text:
//!   [8B sender ts (Unix ms, BE)] [1B 0x00] [N B UTF-8 text]
//!
//! Attachment:
//!   [8B ts] [1B 0x01]
//!   [4B filename_len BE] [filename UTF-8]
//!   [4B mime_len BE]     [mime UTF-8]
//!   [N B file bytes]
//! ```
//!
//! After PKCS#7 padding to 256-byte blocks, the AEAD ciphertext is wrapped in:
//!
//! ```text
//! Wire message:
//!   [4B ratchet_key_len] [ratchet_key]
//!   [4B prev_chain_len]  [4B msg_num]
//!   [12B nonce]          [4B ciphertext_len] [ciphertext]
//!   [1B sentinel_digest_flag] [0 or 32B sentinel_digest]
//!   [zero-padding to 4096]   <-- text only; attachments are unpadded variable-size
//! ```
//!
//! AAD = `ratchet_key || prev_chain_len_be || msg_num_be` (40 bytes).

use super::{
    CryptoError, CryptoResult, MAX_ATTACHMENT_BYTES, TYPE_FLAG_ATTACHMENT,
    TYPE_FLAG_DELIVERY_RECEIPT, TYPE_FLAG_DETONATING_TEXT, TYPE_FLAG_RELAY_UPDATE,
    TYPE_FLAG_ROOM_INVITE, TYPE_FLAG_ROOM_SENDER_KEY, TYPE_FLAG_TEXT, WIRE_MESSAGE_SIZE,
};

#[cfg(test)]
use super::PAD_BLOCK;

// --- Plaintext envelopes ---

pub fn build_text_envelope(timestamp_ms: u64, text: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9 + text.len());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_TEXT);
    buf.extend_from_slice(text.as_bytes());
    buf
}

/// Self-detonating text envelope:
/// `[8B ts][1B 0x06][4B detonate_secs BE][text bytes]`.
/// Both the timestamp and the TTL are inside the AEAD; tampering breaks
/// the Poly1305 tag.
pub fn build_detonating_text_envelope(
    timestamp_ms: u64,
    detonate_secs: u32,
    text: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13 + text.len());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_DETONATING_TEXT);
    buf.extend_from_slice(&detonate_secs.to_be_bytes());
    buf.extend_from_slice(text.as_bytes());
    buf
}

pub fn build_attachment_envelope(
    timestamp_ms: u64,
    filename: &str,
    mime_type: &str,
    bytes: &[u8],
) -> CryptoResult<Vec<u8>> {
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(CryptoError::InvalidInput("attachment exceeds 10 MB"));
    }
    let fname = filename.as_bytes();
    let mime = mime_type.as_bytes();
    let mut buf = Vec::with_capacity(9 + 4 + fname.len() + 4 + mime.len() + bytes.len());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_ATTACHMENT);
    buf.extend_from_slice(&(fname.len() as u32).to_be_bytes());
    buf.extend_from_slice(fname);
    buf.extend_from_slice(&(mime.len() as u32).to_be_bytes());
    buf.extend_from_slice(mime);
    buf.extend_from_slice(bytes);
    Ok(buf)
}

#[derive(Debug, Clone)]
pub enum DecodedEnvelope {
    Text {
        timestamp_ms: u64,
        text: String,
    },
    Attachment {
        timestamp_ms: u64,
        filename: String,
        mime_type: String,
        bytes: Vec<u8>,
    },
    DeliveryReceipt {
        timestamp_ms: u64,
        wire_hash: [u8; 32],
    },
    RelayUpdate {
        timestamp_ms: u64,
        new_relay_url: String,
    },
    RoomInvite {
        timestamp_ms: u64,
        room_id: [u8; 16],
        name: String,
        description: String,
        owner_chain_seed: [u8; 32],
        member_pubkeys: Vec<[u8; 32]>,
    },
    RoomSenderKey {
        timestamp_ms: u64,
        room_id: [u8; 16],
        chain_seed: [u8; 32],
    },
    DetonatingText {
        timestamp_ms: u64,
        detonate_secs: u32,
        text: String,
    },
}

/// Build a delivery-receipt envelope: `[8B ts][1B 0x02][32B wire_hash]`.
/// The receipt rides through the same Double Ratchet channel as a regular
/// text message; the relay only sees the outer 4096-byte ciphertext.
pub fn build_delivery_receipt_envelope(timestamp_ms: u64, wire_hash: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 1 + 32);
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_DELIVERY_RECEIPT);
    buf.extend_from_slice(wire_hash);
    buf
}

/// Build a relay-update envelope: `[8B ts][1B 0x03][4B url_len BE][URL]`.
/// Sent when this user changes their home relay; the recipient updates
/// the corresponding contact row's `relay_url`.
pub fn build_relay_update_envelope(timestamp_ms: u64, new_relay_url: &str) -> Vec<u8> {
    let url = new_relay_url.as_bytes();
    let mut buf = Vec::with_capacity(8 + 1 + 4 + url.len());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_RELAY_UPDATE);
    buf.extend_from_slice(&(url.len() as u32).to_be_bytes());
    buf.extend_from_slice(url);
    buf
}

/// Build a room-invite envelope:
/// `[8B ts][1B 0x04][16B room_id][32B owner_chain_seed]
///  [2B name_len][name][2B desc_len][desc]
///  [2B member_count][per-member: 32B contact_ed25519_pub]`.
pub fn build_room_invite_envelope(
    timestamp_ms: u64,
    room_id: &[u8; 16],
    name: &str,
    description: &str,
    owner_chain_seed: &[u8; 32],
    member_pubkeys: &[[u8; 32]],
) -> CryptoResult<Vec<u8>> {
    if name.len() > u16::MAX as usize
        || description.len() > u16::MAX as usize
        || member_pubkeys.len() > u16::MAX as usize
    {
        return Err(CryptoError::InvalidInput("room invite field too large"));
    }
    let mut buf = Vec::with_capacity(
        8 + 1 + 16 + 32 + 2 + name.len() + 2 + description.len() + 2 + 32 * member_pubkeys.len(),
    );
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_ROOM_INVITE);
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(owner_chain_seed);
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(&(description.len() as u16).to_be_bytes());
    buf.extend_from_slice(description.as_bytes());
    buf.extend_from_slice(&(member_pubkeys.len() as u16).to_be_bytes());
    for m in member_pubkeys {
        buf.extend_from_slice(m);
    }
    Ok(buf)
}

/// Build a room-sender-key envelope:
/// `[8B ts][1B 0x05][16B room_id][32B chain_seed]`.
pub fn build_room_sender_key_envelope(
    timestamp_ms: u64,
    room_id: &[u8; 16],
    chain_seed: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 1 + 16 + 32);
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.push(TYPE_FLAG_ROOM_SENDER_KEY);
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(chain_seed);
    buf
}

pub fn decode_envelope(env: &[u8]) -> CryptoResult<DecodedEnvelope> {
    if env.len() < 9 {
        return Err(CryptoError::Decode("envelope too short"));
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&env[..8]);
    let timestamp_ms = u64::from_be_bytes(ts_bytes);
    let type_flag = env[8];
    let payload = &env[9..];
    match type_flag {
        TYPE_FLAG_TEXT => {
            let text = std::str::from_utf8(payload)
                .map_err(|_| CryptoError::Decode("text envelope not UTF-8"))?
                .to_string();
            Ok(DecodedEnvelope::Text { timestamp_ms, text })
        }
        TYPE_FLAG_DELIVERY_RECEIPT => {
            if payload.len() < 32 {
                return Err(CryptoError::Decode("delivery receipt too short"));
            }
            let mut wh = [0u8; 32];
            wh.copy_from_slice(&payload[..32]);
            Ok(DecodedEnvelope::DeliveryReceipt {
                timestamp_ms,
                wire_hash: wh,
            })
        }
        TYPE_FLAG_RELAY_UPDATE => {
            if payload.len() < 4 {
                return Err(CryptoError::Decode("relay-update missing length"));
            }
            let url_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
            if payload.len() < 4 + url_len {
                return Err(CryptoError::Decode("relay-update truncated"));
            }
            let url = std::str::from_utf8(&payload[4..4 + url_len])
                .map_err(|_| CryptoError::Decode("relay-update url not UTF-8"))?
                .to_string();
            Ok(DecodedEnvelope::RelayUpdate {
                timestamp_ms,
                new_relay_url: url,
            })
        }
        TYPE_FLAG_ATTACHMENT => {
            if payload.len() < 4 {
                return Err(CryptoError::Decode("attachment missing filename header"));
            }
            let fname_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
            let rest = &payload[4..];
            if rest.len() < fname_len + 4 {
                return Err(CryptoError::Decode("attachment header truncated"));
            }
            let filename = std::str::from_utf8(&rest[..fname_len])
                .map_err(|_| CryptoError::Decode("attachment filename not UTF-8"))?
                .to_string();
            let after_name = &rest[fname_len..];
            let mime_len = u32::from_be_bytes(after_name[..4].try_into().unwrap()) as usize;
            let after_mime_hdr = &after_name[4..];
            if after_mime_hdr.len() < mime_len {
                return Err(CryptoError::Decode("attachment mime header truncated"));
            }
            let mime_type = std::str::from_utf8(&after_mime_hdr[..mime_len])
                .map_err(|_| CryptoError::Decode("attachment mime not UTF-8"))?
                .to_string();
            let bytes = after_mime_hdr[mime_len..].to_vec();
            if bytes.len() > MAX_ATTACHMENT_BYTES {
                return Err(CryptoError::Decode("attachment bytes exceed limit"));
            }
            Ok(DecodedEnvelope::Attachment {
                timestamp_ms,
                filename,
                mime_type,
                bytes,
            })
        }
        TYPE_FLAG_ROOM_INVITE => {
            // Layout: [16B room_id][32B chain_seed][2B name_len][name][2B desc_len][desc][2B member_count][32B*N]
            if payload.len() < 16 + 32 + 2 {
                return Err(CryptoError::Decode("room invite header truncated"));
            }
            let mut room_id = [0u8; 16];
            room_id.copy_from_slice(&payload[..16]);
            let mut owner_chain_seed = [0u8; 32];
            owner_chain_seed.copy_from_slice(&payload[16..48]);

            let mut p = 48;
            let name_len = u16::from_be_bytes(payload[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            if payload.len() < p + name_len + 2 {
                return Err(CryptoError::Decode("room invite name truncated"));
            }
            let name = std::str::from_utf8(&payload[p..p + name_len])
                .map_err(|_| CryptoError::Decode("room invite name not UTF-8"))?
                .to_string();
            p += name_len;
            let desc_len = u16::from_be_bytes(payload[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            if payload.len() < p + desc_len + 2 {
                return Err(CryptoError::Decode("room invite description truncated"));
            }
            let description = std::str::from_utf8(&payload[p..p + desc_len])
                .map_err(|_| CryptoError::Decode("room invite description not UTF-8"))?
                .to_string();
            p += desc_len;
            let count = u16::from_be_bytes(payload[p..p + 2].try_into().unwrap()) as usize;
            p += 2;
            if payload.len() < p + 32 * count {
                return Err(CryptoError::Decode("room invite member list truncated"));
            }
            let mut member_pubkeys = Vec::with_capacity(count);
            for _ in 0..count {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&payload[p..p + 32]);
                member_pubkeys.push(pk);
                p += 32;
            }
            Ok(DecodedEnvelope::RoomInvite {
                timestamp_ms,
                room_id,
                name,
                description,
                owner_chain_seed,
                member_pubkeys,
            })
        }
        TYPE_FLAG_ROOM_SENDER_KEY => {
            if payload.len() < 16 + 32 {
                return Err(CryptoError::Decode("room sender-key envelope too short"));
            }
            let mut room_id = [0u8; 16];
            room_id.copy_from_slice(&payload[..16]);
            let mut chain_seed = [0u8; 32];
            chain_seed.copy_from_slice(&payload[16..48]);
            Ok(DecodedEnvelope::RoomSenderKey {
                timestamp_ms,
                room_id,
                chain_seed,
            })
        }
        TYPE_FLAG_DETONATING_TEXT => {
            if payload.len() < 4 {
                return Err(CryptoError::Decode("detonating envelope missing TTL"));
            }
            let detonate_secs = u32::from_be_bytes(payload[..4].try_into().unwrap());
            let text = std::str::from_utf8(&payload[4..])
                .map_err(|_| CryptoError::Decode("detonating text not UTF-8"))?
                .to_string();
            Ok(DecodedEnvelope::DetonatingText {
                timestamp_ms,
                detonate_secs,
                text,
            })
        }
        _ => {
            // Unknown type flags are treated as text for backward compatibility.
            let text = std::str::from_utf8(&env[8..])
                .map_err(|_| CryptoError::Decode("unknown envelope, not UTF-8"))?
                .to_string();
            Ok(DecodedEnvelope::Text { timestamp_ms, text })
        }
    }
}

// --- PKCS#7-style padding (matches Android `MessageCrypto.padToBlock` /
// `unpad` exactly, including its quirks).
//
// `pad_pkcs7`:
//   - `pad = block - (len % block)` — always in `1..=block`.
//   - The byte stored is `(pad & 0xFF)`. For the canonical `block = 256`, an
//     already-aligned input gets 256 trailing zero bytes.
//
// `unpad_pkcs7`: deliberately lenient ("invalid padding ⇒ return input
// unchanged"). The AEAD tag is the actual integrity boundary; this function
// is only a length trimmer. The Android client behaves identically:
//   - last byte == 0 ⇒ no trim (so 256-byte aligned inputs round-trip with
//     trailing zero bytes preserved — matches Android).
//   - last byte > data.len() ⇒ no trim.
//   - any pad-byte mismatch ⇒ no trim.

pub fn pad_pkcs7(data: &[u8], block: usize) -> Vec<u8> {
    assert!(block > 0 && block <= 256);
    let pad = block - (data.len() % block);
    let pad_byte = (pad & 0xFF) as u8;
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(pad_byte).take(pad));
    out
}

pub fn unpad_pkcs7(data: &[u8]) -> CryptoResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let last = *data.last().unwrap();
    let pad = last as usize;
    if pad == 0 || pad > data.len() {
        return Ok(data.to_vec());
    }
    let cut = data.len() - pad;
    if !data[cut..].iter().all(|&b| b == last) {
        return Ok(data.to_vec());
    }
    Ok(data[..cut].to_vec())
}

// --- AAD ---

pub fn build_aad(ratchet_key: &[u8; 32], prev_chain_len: u32, msg_num: u32) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[..32].copy_from_slice(ratchet_key);
    aad[32..36].copy_from_slice(&prev_chain_len.to_be_bytes());
    aad[36..40].copy_from_slice(&msg_num.to_be_bytes());
    aad
}

// --- Wire layout (outer) ---

pub struct RatchetWire<'a> {
    pub ratchet_key: &'a [u8; 32],
    pub prev_chain_len: u32,
    pub msg_num: u32,
    pub nonce: &'a [u8; 12],
    pub ciphertext: &'a [u8],
    pub sentinel_digest: Option<&'a [u8; 32]>,
}

pub fn pack_text_wire(w: &RatchetWire<'_>) -> CryptoResult<Vec<u8>> {
    let body = pack_inner(w);
    if body.len() > WIRE_MESSAGE_SIZE {
        return Err(CryptoError::InvalidInput(
            "text wire body exceeds 4096 bytes",
        ));
    }
    let mut out = Vec::with_capacity(WIRE_MESSAGE_SIZE);
    out.extend_from_slice(&body);
    out.resize(WIRE_MESSAGE_SIZE, 0);
    Ok(out)
}

pub fn pack_attachment_wire(w: &RatchetWire<'_>) -> Vec<u8> {
    pack_inner(w)
}

fn pack_inner(w: &RatchetWire<'_>) -> Vec<u8> {
    let rk_len = w.ratchet_key.len() as u32;
    let ct_len = w.ciphertext.len() as u32;
    let digest_flag: u8 = w.sentinel_digest.is_some() as u8;
    let cap = 4 + 32 + 4 + 4 + 12 + 4 + w.ciphertext.len() + 1 + if digest_flag == 1 { 32 } else { 0 };
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&rk_len.to_be_bytes());
    out.extend_from_slice(w.ratchet_key);
    out.extend_from_slice(&w.prev_chain_len.to_be_bytes());
    out.extend_from_slice(&w.msg_num.to_be_bytes());
    out.extend_from_slice(w.nonce);
    out.extend_from_slice(&ct_len.to_be_bytes());
    out.extend_from_slice(w.ciphertext);
    out.push(digest_flag);
    if let Some(d) = w.sentinel_digest {
        out.extend_from_slice(d);
    }
    out
}

#[derive(Debug)]
pub struct ParsedWire {
    pub ratchet_key: [u8; 32],
    pub prev_chain_len: u32,
    pub msg_num: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub sentinel_digest: Option<[u8; 32]>,
}

pub fn parse_wire(buf: &[u8]) -> CryptoResult<ParsedWire> {
    let mut p = 0;
    let read_u32 = |b: &[u8], p: &mut usize| -> CryptoResult<u32> {
        if *p + 4 > b.len() {
            return Err(CryptoError::Decode("wire truncated (u32)"));
        }
        let v = u32::from_be_bytes(b[*p..*p + 4].try_into().unwrap());
        *p += 4;
        Ok(v)
    };

    let rk_len = read_u32(buf, &mut p)? as usize;
    if rk_len != 32 || p + rk_len > buf.len() {
        return Err(CryptoError::Decode("wire ratchet_key length invalid"));
    }
    let mut ratchet_key = [0u8; 32];
    ratchet_key.copy_from_slice(&buf[p..p + 32]);
    p += 32;

    let prev_chain_len = read_u32(buf, &mut p)?;
    let msg_num = read_u32(buf, &mut p)?;

    if p + 12 > buf.len() {
        return Err(CryptoError::Decode("wire nonce truncated"));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buf[p..p + 12]);
    p += 12;

    let ct_len = read_u32(buf, &mut p)? as usize;
    if p + ct_len > buf.len() {
        return Err(CryptoError::Decode("wire ciphertext truncated"));
    }
    let ciphertext = buf[p..p + ct_len].to_vec();
    p += ct_len;

    if p + 1 > buf.len() {
        return Err(CryptoError::Decode("wire sentinel flag missing"));
    }
    let flag = buf[p];
    p += 1;
    let sentinel_digest = if flag == 1 {
        if p + 32 > buf.len() {
            return Err(CryptoError::Decode("wire sentinel digest truncated"));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&buf[p..p + 32]);
        Some(d)
    } else {
        None
    };

    Ok(ParsedWire {
        ratchet_key,
        prev_chain_len,
        msg_num,
        nonce,
        ciphertext,
        sentinel_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_round_trip_non_aligned() {
        // Non-aligned, non-empty inputs round-trip exactly.
        // (1024 is excluded — it's a 256-multiple and falls under the
        //  "aligned" lenient-unpad case below.)
        for len in [1usize, 16, 255, 257, 1023] {
            let data = vec![0xAB; len];
            let padded = pad_pkcs7(&data, PAD_BLOCK);
            assert_eq!(
                padded.len() % PAD_BLOCK,
                0,
                "padded len not block-aligned for len={}",
                len
            );
            let out = unpad_pkcs7(&padded).unwrap();
            assert_eq!(out, data, "round-trip failed for len={}", len);
        }
    }

    #[test]
    fn pad_aligned_input_appends_full_zero_block_and_unpad_is_lenient() {
        // For inputs that are already a multiple of the block size, padding
        // appends a full block of zero bytes (Android's quirk: pad value is
        // 256 which truncates to byte 0). The lenient unpad treats trailing
        // 0 bytes as "no padding" and returns the buffer unchanged.
        let aligned = vec![0xABu8; PAD_BLOCK];
        let padded = pad_pkcs7(&aligned, PAD_BLOCK);
        assert_eq!(padded.len(), 2 * PAD_BLOCK);
        assert!(padded[..PAD_BLOCK].iter().all(|&b| b == 0xAB));
        assert!(padded[PAD_BLOCK..].iter().all(|&b| b == 0));
        let out = unpad_pkcs7(&padded).unwrap();
        assert_eq!(out, padded);
    }

    #[test]
    fn pad_empty_input_is_full_zero_block() {
        let padded = pad_pkcs7(&[], PAD_BLOCK);
        assert_eq!(padded.len(), PAD_BLOCK);
        assert!(padded.iter().all(|&b| b == 0));
        // Lenient unpad: trailing zero ⇒ unchanged.
        assert_eq!(unpad_pkcs7(&padded).unwrap(), padded);
    }

    #[test]
    fn text_envelope_round_trip() {
        let env = build_text_envelope(123_456_789, "hello whisper");
        match decode_envelope(&env).unwrap() {
            DecodedEnvelope::Text { timestamp_ms, text } => {
                assert_eq!(timestamp_ms, 123_456_789);
                assert_eq!(text, "hello whisper");
            }
            _ => panic!("expected text envelope"),
        }
    }

    #[test]
    fn detonating_text_envelope_round_trip() {
        let env = build_detonating_text_envelope(987_654_321, 30, "self-destruct");
        match decode_envelope(&env).unwrap() {
            DecodedEnvelope::DetonatingText {
                timestamp_ms,
                detonate_secs,
                text,
            } => {
                assert_eq!(timestamp_ms, 987_654_321);
                assert_eq!(detonate_secs, 30);
                assert_eq!(text, "self-destruct");
            }
            other => panic!("expected DetonatingText, got {other:?}"),
        }
    }

    #[test]
    fn detonating_text_envelope_round_trip_via_pkcs7() {
        // Mirrors the receiver's exact path: pad → unpad → decode.
        let env = build_detonating_text_envelope(1, 60, "boom");
        let padded = pad_pkcs7(&env, PAD_BLOCK);
        let unpadded = unpad_pkcs7(&padded).unwrap();
        match decode_envelope(&unpadded).unwrap() {
            DecodedEnvelope::DetonatingText { detonate_secs, text, .. } => {
                assert_eq!(detonate_secs, 60);
                assert_eq!(text, "boom");
            }
            other => panic!("expected DetonatingText via pkcs7, got {other:?}"),
        }
    }

    #[test]
    fn attachment_envelope_round_trip() {
        let bytes = vec![0xFFu8; 1024];
        let env =
            build_attachment_envelope(42, "shot.jpg", "image/jpeg", &bytes).unwrap();
        match decode_envelope(&env).unwrap() {
            DecodedEnvelope::Attachment {
                timestamp_ms,
                filename,
                mime_type,
                bytes: out,
            } => {
                assert_eq!(timestamp_ms, 42);
                assert_eq!(filename, "shot.jpg");
                assert_eq!(mime_type, "image/jpeg");
                assert_eq!(out, bytes);
            }
            _ => panic!("expected attachment"),
        }
    }

    #[test]
    fn wire_round_trip() {
        let rk = [9u8; 32];
        let nonce = [1u8; 12];
        let ct = vec![0xAB; 100];
        let w = RatchetWire {
            ratchet_key: &rk,
            prev_chain_len: 7,
            msg_num: 13,
            nonce: &nonce,
            ciphertext: &ct,
            sentinel_digest: None,
        };
        let wire = pack_text_wire(&w).unwrap();
        assert_eq!(wire.len(), WIRE_MESSAGE_SIZE);
        let parsed = parse_wire(&wire).unwrap();
        assert_eq!(parsed.ratchet_key, rk);
        assert_eq!(parsed.prev_chain_len, 7);
        assert_eq!(parsed.msg_num, 13);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.ciphertext, ct);
        assert!(parsed.sentinel_digest.is_none());
    }
}
