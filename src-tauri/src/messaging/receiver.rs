//! Receive path: blob → first-message-or-not → PQ-X3DH responder if needed
//! → ratchet.decrypt → envelope → persist.

use super::ratchet_store;
use crate::crypto::message_crypto::{
    build_aad, decode_envelope, parse_wire, unpad_pkcs7, DecodedEnvelope,
};
use crate::crypto::pqx3dh::{self, ResponderInputs};
use crate::crypto::ratchet::{self, RatchetState};
use crate::crypto::WIRE_MESSAGE_SIZE;
use crate::db::contacts::Contact;
use crate::db::messages::Message;
use crate::db::Database;
use crate::identity::LoadedIdentity;
use anyhow::{anyhow, Result};
use uuid::Uuid;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

pub struct ReceiveOutcome {
    pub message: Message,
    pub plaintext: Option<String>,
    pub is_attachment: bool,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

/// Decrypt a single inbound blob from the relay. The caller already knows the
/// sender (resolved from the mailbox prefix).
pub fn handle_blob(
    db: &Database,
    me: &LoadedIdentity,
    contact: &Contact,
    conversation_id: &str,
    wire_bytes: &[u8],
) -> Result<ReceiveOutcome> {
    // 1. Was this a first message? If yes, run PQ-X3DH responder + bootstrap.
    let (encrypted_4096, first_msg) = split_first_message(wire_bytes)?;

    let mut state = match (ratchet_store::load(db, &contact.id)?, first_msg) {
        (Some(s), None) => s,
        (None, Some(init_bytes)) => bootstrap_responder(db, me, &init_bytes)?,
        (Some(_), Some(init_bytes)) => {
            // Existing session AND a new session-init was received → peer reset.
            // For now treat as a fresh responder bootstrap (Android prompts the
            // user; we'll surface a notification once the UI hook is wired).
            bootstrap_responder(db, me, &init_bytes)?
        }
        (None, None) => {
            return Err(anyhow!(
                "no ratchet session and no session-init bundle on inbound blob"
            ));
        }
    };

    // 2. Parse the ratchet wire and decrypt.
    let parsed = parse_wire(&encrypted_4096)?;
    let plaintext_padded = ratchet::decrypt_message(
        &mut state,
        &parsed.ratchet_key,
        parsed.prev_chain_len,
        parsed.msg_num,
        &parsed.nonce,
        &parsed.ciphertext,
        build_aad,
    )?;

    // 3. Persist the updated ratchet state.
    ratchet_store::save(db, &contact.id, &state)?;

    // 4. Decode the envelope.
    let unpadded = unpad_pkcs7(&plaintext_padded)?;
    let decoded = decode_envelope(&unpadded)?;
    let now_ms = now_unix_ms();

    let (plaintext, is_attachment, filename, mime_type, bytes) = match decoded {
        DecodedEnvelope::Text { text, .. } => (Some(text), false, None, None, None),
        DecodedEnvelope::DetonatingText { text, .. } => (Some(text), false, None, None, None),
        DecodedEnvelope::DeliveryReceipt { .. }
        | DecodedEnvelope::RelayUpdate { .. }
        | DecodedEnvelope::RoomInvite { .. }
        | DecodedEnvelope::RoomSenderKey { .. }
        | DecodedEnvelope::RoomSenderKeyAck { .. }
        | DecodedEnvelope::MessageReaction { .. } => {
            // Legacy single-shot receiver path doesn't handle inner control
            // envelopes; the pump-driven `inbound` module is the live one.
            return Err(anyhow!(
                "control envelope arrived on unused receiver path"
            ));
        }
        DecodedEnvelope::Attachment {
            filename,
            mime_type,
            bytes,
            ..
        } => (
            None,
            true,
            Some(filename),
            Some(mime_type),
            Some(bytes),
        ),
    };

    // 5. Persist the row (TEE-encrypted, never plaintext).
    let envelope_bytes = if is_attachment {
        unpadded.clone()
    } else {
        unpadded.clone()
    };
    let tee = crate::crypto::tee_encryption::encrypt_for_conversation(
        conversation_id.as_bytes(),
        &envelope_bytes,
    )?;
    let message = Message {
        id: Uuid::new_v4().to_string(),
        conversation_id: conversation_id.into(),
        sender_alias: contact.alias.clone(),
        is_outbound: false,
        plaintext: None,
        is_attachment,
        filename: filename.clone(),
        mime_type: mime_type.clone(),
        file_size: bytes.as_ref().map(|b| b.len() as i64),
        status: "delivered".into(),
        disappear_at: None,
        created_at: now_ms,
    };
    db.insert_message(&message, Some(&tee), None, None)?;

    Ok(ReceiveOutcome {
        message,
        plaintext,
        is_attachment,
        filename,
        mime_type,
        bytes,
    })
}

/// If the blob is exactly 4096 bytes it's a regular ratchet message; if it's
/// larger, it's wrapped in a first-message header. Returns the inner 4096-byte
/// ratchet message and the optional session-init payload.
fn split_first_message(wire: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    if wire.len() == WIRE_MESSAGE_SIZE {
        return Ok((wire.to_vec(), None));
    }
    if wire.len() < 4 + WIRE_MESSAGE_SIZE {
        return Err(anyhow!("blob too short for first-message wrapper"));
    }
    let init_len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
    let total_needed = 4 + init_len + WIRE_MESSAGE_SIZE;
    if wire.len() < total_needed {
        return Err(anyhow!(
            "first-message wrapper truncated (need {}, have {})",
            total_needed,
            wire.len()
        ));
    }
    let init = wire[4..4 + init_len].to_vec();
    let inner = wire[4 + init_len..4 + init_len + WIRE_MESSAGE_SIZE].to_vec();
    Ok((inner, Some(init)))
}

fn bootstrap_responder(
    db: &Database,
    me: &LoadedIdentity,
    init_bytes: &[u8],
) -> Result<RatchetState> {
    // Parse the session-init payload (matches Android `MessageCrypto.deserializeSessionInit`).
    let mut c = SessionInitCursor { data: init_bytes, off: 0 };
    let initiator_x25519_pub = c.read_field()?;
    let initiator_ek_pub = c.read_field()?;
    let kem1_ct = c.read_field()?;
    let kem2_ct = c.read_field()?;
    let used_otpk_id = c.read_i32()? as u32;

    let ik_alice_x = XPublicKey::from(<[u8; 32]>::try_from(initiator_x25519_pub)?);
    let ek_alice = XPublicKey::from(<[u8; 32]>::try_from(initiator_ek_pub)?);

    // Look up our SPK + the OTPK Alice consumed.
    let spk = db
        .current_signed_prekey()?
        .ok_or_else(|| anyhow!("no active SPK to respond with"))?;
    let otpk = db
        .one_time_prekey_by_id(used_otpk_id)?
        .ok_or_else(|| anyhow!("OTPK {used_otpk_id} not found"))?;
    if otpk.consumed {
        return Err(anyhow!("OTPK {used_otpk_id} already consumed"));
    }

    let spk_secret = XStaticSecret::from(<[u8; 32]>::try_from(spk.x25519_secret.as_slice())?);
    let otpk_secret = XStaticSecret::from(<[u8; 32]>::try_from(otpk.x25519_secret.as_slice())?);

    let kem2_opt: Option<&[u8]> = if kem2_ct.is_empty() { None } else { Some(kem2_ct) };
    let otpk_kyber_opt: Option<&[u8]> = if otpk.mlkem_secret.is_empty() {
        None
    } else {
        Some(&otpk.mlkem_secret)
    };

    let master = pqx3dh::responder_agree(ResponderInputs {
        ik_bob_x25519: &me.keys.x25519_secret,
        spk_bob_x25519: &spk_secret,
        spk_bob_mlkem_secret: &spk.mlkem_secret,
        otpk_bob_x25519: &otpk_secret,
        otpk_bob_mlkem_secret: otpk_kyber_opt,
        ik_alice_x25519_pub: &ik_alice_x,
        ek_alice_pub: &ek_alice,
        kem1_ciphertext: kem1_ct,
        kem2_ciphertext: kem2_opt,
    })?;

    // Bob's ratchet keypair is his SPK x25519 pair; Alice's first message
    // triggers the first DH ratchet step using `ek_alice` as the peer key.
    let state = RatchetState::init_responder(&master, spk_secret)?;
    let _ = ek_alice;

    // Mark the OTPK consumed.
    db.mark_one_time_prekey_consumed(used_otpk_id)?;

    Ok(state)
}

struct SessionInitCursor<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> SessionInitCursor<'a> {
    fn read_i32(&mut self) -> Result<i32> {
        if self.off + 4 > self.data.len() {
            return Err(anyhow!("session-init truncated (i32)"));
        }
        let v = i32::from_be_bytes(self.data[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }
    fn read_field(&mut self) -> Result<&'a [u8]> {
        let raw = self.read_i32()?;
        if raw < 0 {
            return Err(anyhow!("session-init field has negative length"));
        }
        let len = raw as usize;
        if len > self.data.len().saturating_sub(self.off) {
            return Err(anyhow!("session-init truncated (field)"));
        }
        let s = &self.data[self.off..self.off + len];
        self.off += len;
        Ok(s)
    }
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
