//! Send path: text → envelope → pad → ratchet.encrypt → pack → deposit.

use super::ratchet_store;
use crate::crypto::bundle::PublicKeyBundle;
use crate::crypto::message_crypto::{
    build_aad, build_attachment_envelope, build_detonating_text_envelope, build_text_envelope,
    pack_attachment_wire, pack_text_wire, pad_pkcs7, RatchetWire,
};
use crate::crypto::pqx3dh::{self, InitiatorInputs};
use crate::crypto::ratchet::{self, RatchetState};
use crate::crypto::PAD_BLOCK;
use crate::db::contacts::Contact;
use crate::db::messages::Message;
use crate::db::Database;
use crate::identity::LoadedIdentity;
use crate::transport::mailbox;
use anyhow::Result;
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

/// What the caller (`commands::message_send`) needs to actually deliver the
/// encrypted blob — either via the home relay (fast path) or to a different
/// What `commands::message_send*` needs to dispatch the encrypted blob
/// over I2P. `target_relay_url` was a relay-era field and is gone.
pub struct PreparedSend {
    pub message: Message,
    pub mailbox_hex: String,
    pub blob: Vec<u8>,
    pub msg_id: String,
}

/// Synchronous core: encrypt + persist + decide where the deposit should go.
/// The caller actually performs the deposit (sync via the home relay client
/// or async via `relay::transient_deposit`).
pub fn prepare_send_text(
    db: &Database,
    me: &LoadedIdentity,
    contact: &Contact,
    contact_bundle: &PublicKeyBundle,
    conversation_id: &str,
    text: &str,
    _home_relay_url: Option<&str>,
) -> Result<PreparedSend> {
    prepare_send_text_inner(db, me, contact, contact_bundle, conversation_id, text, None)
}

/// Self-detonating text variant: the TTL is sealed inside the AEAD, so
/// the relay and any network adversary can't strip or extend it without
/// breaking the tag. Both sides' clients enforce by setting `disappear_at`
/// on the message row, which the existing sweeper purges.
pub fn prepare_send_detonating_text(
    db: &Database,
    me: &LoadedIdentity,
    contact: &Contact,
    contact_bundle: &PublicKeyBundle,
    conversation_id: &str,
    text: &str,
    detonate_secs: u32,
    _home_relay_url: Option<&str>,
) -> Result<PreparedSend> {
    prepare_send_text_inner(
        db,
        me,
        contact,
        contact_bundle,
        conversation_id,
        text,
        Some(detonate_secs),
    )
}

fn prepare_send_text_inner(
    db: &Database,
    me: &LoadedIdentity,
    contact: &Contact,
    contact_bundle: &PublicKeyBundle,
    conversation_id: &str,
    text: &str,
    detonate_secs: Option<u32>,
) -> Result<PreparedSend> {
    let now_ms = now_unix_ms();

    // 1. Plaintext envelope + padding.
    let envelope = match detonate_secs {
        None => build_text_envelope(now_ms as u64, text),
        Some(secs) => build_detonating_text_envelope(now_ms as u64, secs, text),
    };
    let padded = pad_pkcs7(&envelope, PAD_BLOCK);

    // 2. Load (or bootstrap) the ratchet for this peer.
    let mut state = ratchet_store::load(db, &contact.id)?;
    let mut session_init_blob: Option<Vec<u8>> = None;

    if state.is_none() {
        let (master, init_bytes, fresh_state) = bootstrap_initiator(me, contact_bundle)?;
        let _ = master; // master_secret already absorbed into fresh_state
        state = Some(fresh_state);
        session_init_blob = Some(init_bytes);
    }
    let mut state = state.unwrap();

    // 3. Encrypt with the ratchet.
    let enc = ratchet::encrypt_message(&mut state, &padded, build_aad)?;

    // 4. Pack the 4096-byte wire message.
    let wire_bytes = pack_text_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    })?;

    // 5. Wrap with session-init for the very first message of a fresh session.
    let wire = if let Some(init) = &session_init_blob {
        pqx3dh::pack_first_message(init, &wire_bytes)
    } else {
        wire_bytes
    };

    // 6. Persist the updated ratchet state.
    ratchet_store::save(db, &contact.id, &state)?;

    // 7. Build the on-the-wire blob: `[32B sender_mailbox_hex_ascii][wire]`
    //    (matches Android's `RelayTransport` blob layout). The recipient
    //    uses the prefix to dispatch to the right contact without trying
    //    every ratchet session.
    let recipient_mb = mailbox::current_mailbox(&contact.ed25519_public);
    let recipient_mb_hex = mailbox::hex(&recipient_mb);
    let sender_mb = mailbox::current_mailbox(&me.keys.ed25519_verifying().to_bytes());
    let sender_mb_hex = mailbox::hex(&sender_mb);
    let mut blob = Vec::with_capacity(32 + wire.len());
    blob.extend_from_slice(sender_mb_hex.as_bytes()); // 32 ASCII chars
    blob.extend_from_slice(&wire);

    let msg_id = Uuid::new_v4().to_string();

    // SHA-256 of the deposited blob — recorded on the row so an inbound
    // delivery receipt referencing the same hash flips status `sent` →
    // `delivered`. Both sides compute it from the identical bytes.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&blob);
    let wire_hash: [u8; 32] = h.finalize().into();

    // 8. Persist message row. Per-message detonate_secs (when set) wins
    //    over the conversation-level disappear_timer.
    let disappear_at = if let Some(secs) = detonate_secs {
        Some(now_ms + (secs as i64).saturating_mul(1000))
    } else {
        db.conversation_disappear_timer(conversation_id)
            .ok()
            .flatten()
            .map(|secs| now_ms + secs.saturating_mul(1000))
    };
    let message = Message {
        id: msg_id.clone(),
        conversation_id: conversation_id.into(),
        sender_alias: me.alias.clone(),
        is_outbound: true,
        plaintext: None,
        is_attachment: false,
        filename: None,
        mime_type: None,
        file_size: None,
        status: "queued".into(),
        disappear_at,
        created_at: now_ms,
    };
    let tee = crate::crypto::tee_encryption::encrypt_for_conversation(
        conversation_id.as_bytes(),
        &envelope,
    )?;
    db.insert_message(&message, Some(&tee), None, Some(&wire_hash))?;

    Ok(PreparedSend {
        message,
        mailbox_hex: recipient_mb_hex,
        blob,
        msg_id,
    })
}

/// Synchronous core for attachment sends. Mirrors `prepare_send_text`'s
/// shape so the caller dispatches the resulting blob over I2P.
pub fn prepare_send_attachment(
    db: &Database,
    me: &LoadedIdentity,
    contact: &Contact,
    contact_bundle: &PublicKeyBundle,
    conversation_id: &str,
    filename: &str,
    mime_type: &str,
    bytes: &[u8],
    _home_relay_url: Option<&str>,
) -> Result<PreparedSend> {
    let now_ms = now_unix_ms();

    let envelope = build_attachment_envelope(now_ms as u64, filename, mime_type, bytes)?;

    let mut state = ratchet_store::load(db, &contact.id)?;
    let mut session_init_blob: Option<Vec<u8>> = None;
    if state.is_none() {
        let (master, init_bytes, fresh_state) = bootstrap_initiator(me, contact_bundle)?;
        let _ = master;
        state = Some(fresh_state);
        session_init_blob = Some(init_bytes);
    }
    let mut state = state.unwrap();

    let enc = ratchet::encrypt_message(&mut state, &envelope, build_aad)?;

    let wire_bytes = pack_attachment_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    });

    let wire = if let Some(init) = &session_init_blob {
        pqx3dh::pack_first_message(init, &wire_bytes)
    } else {
        wire_bytes
    };

    ratchet_store::save(db, &contact.id, &state)?;

    let recipient_mb = mailbox::current_mailbox(&contact.ed25519_public);
    let recipient_mb_hex = mailbox::hex(&recipient_mb);
    let sender_mb = mailbox::current_mailbox(&me.keys.ed25519_verifying().to_bytes());
    let sender_mb_hex = mailbox::hex(&sender_mb);
    let mut blob = Vec::with_capacity(32 + wire.len());
    blob.extend_from_slice(sender_mb_hex.as_bytes());
    blob.extend_from_slice(&wire);

    let msg_id = Uuid::new_v4().to_string();

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&blob);
    let wire_hash: [u8; 32] = h.finalize().into();

    let disappear_at = db
        .conversation_disappear_timer(conversation_id)
        .ok()
        .flatten()
        .map(|secs| now_ms + secs.saturating_mul(1000));
    let message = Message {
        id: msg_id.clone(),
        conversation_id: conversation_id.into(),
        sender_alias: me.alias.clone(),
        is_outbound: true,
        plaintext: None,
        is_attachment: true,
        filename: Some(filename.to_string()),
        mime_type: Some(mime_type.to_string()),
        file_size: Some(bytes.len() as i64),
        status: "queued".into(),
        disappear_at,
        created_at: now_ms,
    };
    db.insert_message(&message, None, None, Some(&wire_hash))?;

    Ok(PreparedSend {
        message,
        mailbox_hex: recipient_mb_hex,
        blob,
        msg_id,
    })
}

fn bootstrap_initiator(
    me: &LoadedIdentity,
    bundle: &PublicKeyBundle,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, Vec<u8>, RatchetState)> {
    let ek_alice = XStaticSecret::random_from_rng(OsRng);
    let ek_alice_pub = XPublicKey::from(&ek_alice);

    let spk_x_pub = XPublicKey::from(bundle.signed_prekey.x25519_pub);
    let ik_b_x_pub = XPublicKey::from(bundle.x25519_key);
    let otpk_x_pub = XPublicKey::from(bundle.one_time_prekey.x25519_pub);

    let otpk_kyber_opt: Option<&[u8]> = if bundle.one_time_prekey.kyber_pub.is_empty() {
        None
    } else {
        Some(&bundle.one_time_prekey.kyber_pub)
    };

    let inputs = InitiatorInputs {
        ik_alice: &me.keys.x25519_secret,
        ek_alice: &ek_alice,
        spk_bob_x25519: &spk_x_pub,
        ik_bob_x25519: &ik_b_x_pub,
        otpk_bob_x25519: &otpk_x_pub,
        spk_bob_mlkem_pub: &bundle.signed_prekey.kyber_pub,
        otpk_bob_mlkem_pub: otpk_kyber_opt,
    };
    let out = pqx3dh::initiator_agree(inputs)?;

    // Initiator's ratchet starts using a fresh ratchet keypair against
    // Bob's SPK X25519 — matches the Android `initAsInitiator(masterSecret, peerRatchetKey = Bob.spk.x25519_pub)`.
    let initial_send_secret = XStaticSecret::random_from_rng(OsRng);
    let mut state = RatchetState::init_initiator(&out.master_secret, initial_send_secret);

    // Pre-load the receive-end peer key as Bob's SPK X25519 so the first
    // ratchet step on receipt creates the right sending chain.
    state.dh_recv_public = Some(bundle.signed_prekey.x25519_pub);
    let dh = XStaticSecret::from(state.dh_send_secret).diffie_hellman(&spk_x_pub);
    let (new_root, new_chain) = ratchet::root_kdf(&state.root_key, dh.as_bytes())?;
    state.root_key = new_root;
    state.send_chain_key = Some(new_chain);

    let init_bytes = pqx3dh::pack_session_init(
        me.keys.x25519_public().as_bytes(),
        ek_alice_pub.as_bytes(),
        &out.kem1_ciphertext,
        out.kem2_ciphertext.as_deref(),
        bundle.one_time_prekey.id,
    );
    Ok((out.master_secret, init_bytes, state))
}

/// Convenience export of the local `bootstrap_initiator` for callers
/// in `messaging::inbound` that need to start a fresh ratchet without
/// going through the full `prepare_send_text` path (e.g. the room
/// sender-key fan-out, where we want the init bytes + state but no
/// message persistence). Returns the same triple as the internal
/// helper minus the unused `master_secret`.
pub fn bootstrap_initiator_for(
    me: &LoadedIdentity,
    bundle: &PublicKeyBundle,
) -> Result<(Vec<u8>, RatchetState)> {
    let (_master, init, state) = bootstrap_initiator(me, bundle)?;
    Ok((init, state))
}

/// Public wrapper around `bootstrap_initiator` returning just the
/// session-init bytes + initial ratchet state. Kept for any
/// straggling callers; new code should use `bootstrap_initiator_for`.
pub fn prepare_initiator_first_room_message(
    me: &LoadedIdentity,
    bundle: &PublicKeyBundle,
) -> Result<(Vec<u8>, RatchetState)> {
    let (master, init_bytes, state) = bootstrap_initiator(me, bundle)?;
    let _ = master;
    Ok((init_bytes, state))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
