//! Inbound pump: drains the relay's `Delivery` events, identifies the sender
//! from each blob's mailbox prefix, decrypts via the ratchet (bootstrapping
//! a fresh PQ-X3DH session for first messages), persists the row, and emits
//! a Tauri event so the frontend re-renders.

use super::receiver;
use crate::crypto::bundle;
use crate::crypto::message_crypto::{decode_envelope, parse_wire, unpad_pkcs7, DecodedEnvelope};
use crate::crypto::pqx3dh::{self, ResponderInputs};
use crate::crypto::ratchet::{self, RatchetState};
use crate::crypto::{secure_enclave, WIRE_MESSAGE_SIZE};
use crate::db::contacts::Contact;
use crate::db::messages::{Conversation, Message};
use crate::state::AppState;
use crate::transport::envelopes::{is_session_request, unwrap_contact_request};
use crate::transport::mailbox;
use crate::transport::relay::{InboundEvent, RelayClient};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use uuid::Uuid;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::transport::mailbox::MAILBOX_PREFIX_LEN;

/// Spawn the inbound pump. Owns `events_rx`; emits `message:received` on
/// every successful decode. Exits when the channel closes.
pub fn spawn_pump(
    app: AppHandle,
    state: Arc<AppState>,
    relay: RelayClient,
    mut events_rx: mpsc::UnboundedReceiver<InboundEvent>,
) {
    tokio::spawn(async move {
        tracing::info!("inbound pump: started");
        while let Some(evt) = events_rx.recv().await {
            match evt {
                InboundEvent::Notify => {
                    // Trigger an immediate retrieve via the relay client.
                    if let Some(me_pk) = me_pubkey(&state) {
                        let real = mailbox::current_mailbox(&me_pk);
                        let batch = mailbox::build_retrieve_batch(&real);
                        let hex: Vec<String> = batch.iter().map(mailbox::hex).collect();
                        let _ = relay.retrieve(hex);
                    }
                }
                InboundEvent::Delivery(mailboxes) => {
                    for slot in mailboxes {
                        for blob_b64 in slot.blobs {
                            if let Err(e) = handle_one(&app, &state, &blob_b64).await {
                                tracing::warn!("inbound: skip blob: {e:#}");
                            }
                        }
                    }
                }
                InboundEvent::Deposited { message_id, ok } => {
                    tracing::info!("inbound: deposited id={message_id} ok={ok}");
                    // Don't downgrade a row already promoted to "delivered"
                    // by a delivery receipt — only flip "queued" → "sent".
                    if ok && !message_id.is_empty() {
                        let new_status = "sent";
                        let updated = {
                            let guard = state.vault.lock();
                            match guard.as_ref() {
                                Some(rt) => {
                                    let _ = rt.db.conn.execute(
                                        "UPDATE messages SET status = ?1
                                         WHERE id = ?2 AND status = 'queued'",
                                        rusqlite::params![new_status, &message_id],
                                    );
                                    true
                                }
                                None => false,
                            }
                        };
                        if updated {
                            #[derive(serde::Serialize, Clone)]
                            struct Status<'a> {
                                message_id: &'a str,
                                status: &'a str,
                            }
                            let _ = app.emit(
                                "message:status",
                                Status {
                                    message_id: &message_id,
                                    status: new_status,
                                },
                            );
                        }
                    }
                }
                InboundEvent::AccountingResponse(rc) => {
                    let snapshot = relay.counters().snapshot();
                    let verdict = crate::transport::frame_accounting::reconcile(snapshot, rc);
                    use crate::transport::frame_accounting::AccountingVerdict;
                    let (severity, label) = match verdict {
                        AccountingVerdict::Verified => ("ok", "verified"),
                        AccountingVerdict::FrameDrop => ("warn", "frame_drop"),
                        AccountingVerdict::FrameInjectionExfil => {
                            ("critical", "injection_exfil")
                        }
                        AccountingVerdict::FrameInjectionFromRelay => {
                            ("critical", "injection_from_relay")
                        }
                    };
                    tracing::info!(
                        "frame accounting verdict={label} severity={severity} \
                         client(↑sent={} ↓rcv={}) relay(rcv_from_us={} sent_to_us={})",
                        snapshot.frames_sent,
                        snapshot.frames_received,
                        rc.frames_received_from_client,
                        rc.frames_sent_to_client,
                    );
                    #[derive(serde::Serialize, Clone)]
                    struct Payload<'a> {
                        verdict: &'a str,
                        severity: &'a str,
                        client_sent: u64,
                        client_received: u64,
                        relay_received_from_client: u64,
                        relay_sent_to_client: u64,
                    }
                    let _ = app.emit(
                        "security:frame_accounting",
                        Payload {
                            verdict: label,
                            severity,
                            client_sent: snapshot.frames_sent,
                            client_received: snapshot.frames_received,
                            relay_received_from_client: rc.frames_received_from_client,
                            relay_sent_to_client: rc.frames_sent_to_client,
                        },
                    );
                }
                InboundEvent::Error(e) => {
                    tracing::warn!("inbound: relay error: {e}");
                }
            }
        }
        tracing::info!("inbound pump: events channel closed; pump exiting");
    });
}

fn me_pubkey(state: &AppState) -> Option<[u8; 32]> {
    let guard = state.vault.lock();
    guard
        .as_ref()
        .map(|rt| rt.identity.keys.ed25519_verifying().to_bytes())
}

/// Decode one base64 blob delivered by the relay and dispatch by shape:
///
/// - Empty mailbox / decoy: ignore.
/// - `[32B mailbox][0xCF,0xC0,0xDE,0x01][bundle_bytes]` → contact request.
/// - `[32B mailbox][0xCF,0xC0,0x5E,0x01][8B ts]` → session-reset request.
/// - `[32B mailbox][4096B wire]` → regular ratchet message.
/// - `[32B mailbox][>4096B wrapped wire]` → first message (PQ-X3DH bootstrap).
async fn handle_one(app: &AppHandle, state: &AppState, blob_b64: &str) -> Result<()> {
    let bytes = B64.decode(blob_b64).map_err(|_| anyhow!("non-base64 blob"))?;

    if bytes.len() < MAILBOX_PREFIX_LEN {
        return Ok(());
    }

    // Empty mailbox / decoy: prefix is all-zero ASCII NUL bytes. The
    // canonical empty blob is 4096 bytes of 0x00.
    if bytes[..MAILBOX_PREFIX_LEN].iter().all(|&b| b == 0) {
        return Ok(());
    }
    if !bytes[..MAILBOX_PREFIX_LEN].iter().all(|b| b.is_ascii_hexdigit()) {
        return Ok(());
    }

    let sender_mb_hex = std::str::from_utf8(&bytes[..MAILBOX_PREFIX_LEN])
        .map_err(|_| anyhow!("sender mailbox prefix not ASCII"))?
        .to_string();
    let body = &bytes[MAILBOX_PREFIX_LEN..];

    // Contact-request envelope: magic prefix + raw signed bundle bytes.
    if let Some(bundle_bytes) = unwrap_contact_request(body) {
        return handle_contact_request(app, state, &sender_mb_hex, bundle_bytes).await;
    }

    // Session-request envelope: 12 bytes total (4 magic + 8 ts).
    if is_session_request(body) {
        tracing::info!("inbound: session-request from `{}` (ignored — manual recovery only)", sender_mb_hex);
        return Ok(());
    }

    // Regular ratchet body. Discriminate wrapped (first-message) vs.
    // unwrapped vs. room-message by peeking at the leading 4 bytes:
    //   - unwrapped wire    begins with rk_len = 0x00 0x00 0x00 0x20 (32, BE)
    //   - first-message     begins with init_len (a few thousand)
    //   - room ciphertext   begins with the magic 0xFF 0xFF 0xFF 0xFF
    if body.len() < 40 {
        return Ok(());
    }
    if body.iter().all(|&b| b == 0) {
        return Ok(());
    }

    const RATCHET_KEY_LEN_BE: [u8; 4] = [0, 0, 0, 32];
    if body[..4] == crate::crypto::sender_key::ROOM_WIRE_MAGIC {
        handle_room_message(app, state, body).await
    } else if body[..4] == RATCHET_KEY_LEN_BE {
        handle_subsequent(app, state, &sender_mb_hex, body).await
    } else {
        handle_first(app, state, &sender_mb_hex, body).await
    }
}

/// Bob receives Alice's bundle as a contact request and adds her as a
/// contact + conversation. Idempotent — repeating it just refreshes the row.
async fn handle_contact_request(
    app: &AppHandle,
    state: &AppState,
    sender_mb_hex: &str,
    bundle_bytes: &[u8],
) -> Result<()> {
    let parsed = bundle::deserialize(bundle_bytes)
        .map_err(|e| anyhow!("contact-request bundle deserialize: {e}"))?;
    bundle::verify_bundle(&parsed)
        .map_err(|e| anyhow!("contact-request bundle signature: {e}"))?;

    let alias = parsed.alias.clone();
    let now = now_unix_ms();

    let (conv_id_for_event, was_already_active) = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;

        // Look up by ed25519 pubkey; if exists, refresh; else create fresh row.
        let existing_id = rt
            .db
            .list_contacts()?
            .into_iter()
            .find(|c| c.ed25519_public == parsed.identity_key.to_vec())
            .map(|c| c.id);

        let contact_id = existing_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Note: do NOT wipe the ratchet on a contact-request from a known
        // peer. A contact-request can mean either:
        //   (a) the peer just accepted our invite and is sending their
        //       bundle back — our ratchet is FRESH and must not be wiped;
        //   (b) the peer deleted us and re-added — they will send a
        //       follow-up first-message wrapped wire whose `(Some, Some)`
        //       arm in `run_decrypt` already replaces our stale ratchet
        //       via `bootstrap_responder`.
        // Wiping unconditionally breaks (a) without helping (b).

        let i2p_destination = if parsed.i2p_destination.is_empty() {
            None
        } else {
            Some(parsed.i2p_destination.clone())
        };
        let contact = Contact {
            id: contact_id.clone(),
            alias: alias.clone(),
            ed25519_public: parsed.identity_key.to_vec(),
            x25519_public: parsed.x25519_key.to_vec(),
            mlkem_public: parsed.kyber_key.clone(),
            relay_url: state.relay.current_url(),
            i2p_destination,
            verified: false,
            peer_has_verified_us: false,
            hide_until_verified: false,
            is_sealed: false,
            nickname: None,
            created_at: now,
            updated_at: now,
        };
        rt.db.upsert_contact(&contact)?;

        // Determine whether the conversation already exists and, if so,
        // whether it's already accepted (active). If we sent the original
        // invite, our local conversation is already non-pending — receiving
        // their bundle back must NOT downgrade us to pending.
        let already_active = rt
            .db
            .list_conversations()?
            .into_iter()
            .any(|c| c.contact_id.as_deref() == Some(contact.id.as_str()) && !c.is_pending);

        if !already_active {
            rt.db.upsert_conversation(&Conversation {
                id: contact.id.clone(),
                kind: "direct".into(),
                contact_id: Some(contact.id.clone()),
                contact_alias: None,
            contact_nickname: None,
                room_name: None,
                room_description: None,
                disappear_timer: None,
                is_sealed: false,
                is_pending: true, // requires explicit accept on this side
                last_message_at: None,
                unread_count: 0,
                created_at: now,
            })?;
        }

        tracing::info!(
            "inbound: contact-request from `{}` → conversation {} (already_active={})",
            alias,
            contact.id,
            already_active
        );
        (contact.id, already_active)
    };

    let _ = was_already_active;

    // Tell the frontend: refresh the sidebar.
    #[derive(serde::Serialize, Clone)]
    struct ContactRequestPayload<'a> {
        sender_alias: &'a str,
        conversation_id: &'a str,
    }
    let _ = app.emit(
        "contact:received",
        ContactRequestPayload {
            sender_alias: &alias,
            conversation_id: &conv_id_for_event,
        },
    );
    Ok(())
}

async fn handle_subsequent(
    app: &AppHandle,
    state: &AppState,
    sender_mb_hex: &str,
    wire: &[u8],
) -> Result<()> {
    let (me, contact, conv_id) = match resolve_sender(state, sender_mb_hex)? {
        Some(v) => v,
        None => {
            tracing::warn!(
                "inbound: subsequent msg from unknown mailbox `{sender_mb_hex}` — dropping"
            );
            return Ok(());
        }
    };

    let inbound_full_blob_hash = sha256_blob(sender_mb_hex.as_bytes(), wire);
    let outcome = run_decrypt(state, &me, &contact, &conv_id, wire, None)?;
    handle_outcome(app, state, &contact, &conv_id, &inbound_full_blob_hash, outcome);
    Ok(())
}

async fn handle_first(
    app: &AppHandle,
    state: &AppState,
    sender_mb_hex: &str,
    wire: &[u8],
) -> Result<()> {
    if wire.len() < 4 {
        return Err(anyhow!("first-message blob too short"));
    }
    let init_len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
    if wire.len() < 4 + init_len {
        return Err(anyhow!("first-message wrapper truncated"));
    }
    let init_bytes = wire[4..4 + init_len].to_vec();
    // Inner wire length is whatever remains after the wrapper. For text
    // wires this will be exactly 4096; for attachments it's variable.
    let inner = wire[4 + init_len..].to_vec();

    // Already know this peer? If so, just decrypt + reset session.
    if let Some((me, contact, conv_id)) = resolve_sender(state, sender_mb_hex)? {
        // First-message blob = `[4B init_len][init][N inner]` where N is
        // 4096 for text and variable for attachments. The hash we record
        // is over the FULL deposited bytes (mailbox prefix + the wrapped
        // wire), matching what the sender computes.
        let mut full = Vec::with_capacity(MAILBOX_PREFIX_LEN + 4 + init_bytes.len() + inner.len());
        full.extend_from_slice(sender_mb_hex.as_bytes());
        full.extend_from_slice(&(init_bytes.len() as u32).to_be_bytes());
        full.extend_from_slice(&init_bytes);
        full.extend_from_slice(&inner);
        let blob_hash = sha256_bytes(&full);
        let outcome = run_decrypt(state, &me, &contact, &conv_id, &inner, Some(init_bytes))?;
        handle_outcome(app, state, &contact, &conv_id, &blob_hash, outcome);
        return Ok(());
    }

    // Unknown sender — bootstrap a new contact + conversation. Parse the
    // session-init for Alice's identity X25519 pub key and derive her alias
    // (we need her bundle from the relay to fill in details like ML-KEM pub).
    let init = parse_session_init(&init_bytes)?;
    let relay_url = state.relay.current_url().ok_or_else(|| anyhow!("no relay"))?;
    let _ = relay_url;

    // Derive the candidate alias from the X25519 public key — wait, the alias
    // is derived from the Ed25519 identity key, which is *not* in the
    // session-init. We need the full bundle.  Try every aliased bundle on the
    // relay? No — instead, the relay-published bundle's `x25519_key` matches
    // what's in `initiatorIdentityKey`, so iterate through bundles by the
    // X25519 hash. The relay doesn't expose an enumeration API, so we look up
    // by the alias derived from a SHA-256 of the contact's known pubkey…
    // but we only have X25519, not Ed25519.
    //
    // Practical bootstrap: the sender mailbox hex pins down the *Ed25519* key
    // that produced it (mailbox = BLAKE2b-128(ed25519_pub || epoch_day)). We
    // don't currently have a mailbox→pubkey reverse map. The pragmatic path:
    // the sender's first message includes their alias inside the session-init
    // in the Android client; on desktop we don't yet, so we surface a
    // diagnostic and skip persistence until that's added.
    tracing::warn!(
        "inbound: first message from unknown peer (mailbox `{}`); persistence requires the sender's alias to resolve their bundle. Wiring this needs sender-alias-in-init or a mailbox→pubkey discovery path. session_init={} bytes",
        sender_mb_hex,
        init_bytes.len()
    );
    let _ = (init, inner); // suppress unused-warning until done
    Ok(())
}

/// Walk all stored contacts and find the one whose current-day or
/// previous-day mailbox matches `sender_mb_hex`.
fn resolve_sender(
    state: &AppState,
    sender_mb_hex: &str,
) -> Result<Option<(ResolvedSelf, Contact, String)>> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
    let me = ResolvedSelf {
        ed25519_pub: rt.identity.keys.ed25519_verifying().to_bytes(),
    };
    let contacts = rt.db.list_contacts()?;

    for c in contacts {
        let today = mailbox::hex(&mailbox::current_mailbox(&c.ed25519_public));
        if today == sender_mb_hex {
            let conv_id = direct_conversation_id_for(&rt.db, &c.id)?;
            return Ok(Some((me, c, conv_id)));
        }
        let yesterday = mailbox::hex(&mailbox::previous_mailbox(&c.ed25519_public));
        if yesterday == sender_mb_hex {
            let conv_id = direct_conversation_id_for(&rt.db, &c.id)?;
            return Ok(Some((me, c, conv_id)));
        }
    }
    Ok(None)
}

fn direct_conversation_id_for(
    db: &crate::db::Database,
    contact_id: &str,
) -> Result<String> {
    let convs = db.list_conversations()?;
    if let Some(c) = convs
        .into_iter()
        .find(|c| c.kind == "direct" && c.contact_id.as_deref() == Some(contact_id))
    {
        return Ok(c.id);
    }
    let now = now_unix_ms();
    let id = contact_id.to_string();
    db.upsert_conversation(&Conversation {
        id: id.clone(),
        kind: "direct".into(),
        contact_id: Some(contact_id.to_string()),
        contact_alias: None,
            contact_nickname: None,
        room_name: None,
        room_description: None,
        disappear_timer: None,
        is_sealed: false,
        is_pending: false,
        last_message_at: None,
        unread_count: 0,
        created_at: now,
    })?;
    Ok(id)
}

struct ResolvedSelf {
    ed25519_pub: [u8; 32],
}

enum DecryptOutcome {
    UserMessage {
        plaintext: Option<String>,
        is_attachment: bool,
        sender_alias: String,
    },
    /// Room invite landed. We carry the payload up so the actual side-effect
    /// (creating the room conversation, persisting sender keys, fanning out
    /// our own seed to peers) runs *outside* `run_decrypt`'s vault lock —
    /// otherwise the inbound handler would deadlock on its own re-lock.
    RoomInvite {
        room_id: [u8; 16],
        name: String,
        description: String,
        owner_chain_seed: [u8; 32],
        member_pubkeys: Vec<[u8; 32]>,
    },
    /// A peer shared their per-room sender-key seed via pairwise channel.
    /// Same lock-deferral rationale as `RoomInvite`.
    RoomSenderKey {
        room_id: [u8; 16],
        chain_seed: [u8; 32],
    },
    /// Decrypted blob was an inner delivery-receipt — no row was persisted;
    /// the caller has already flipped the matching outbound row's status.
    Receipt {
        wire_hash: [u8; 32],
        updated_message_id: Option<String>,
    },
}

fn run_decrypt(
    state: &AppState,
    _me: &ResolvedSelf,
    contact: &Contact,
    conversation_id: &str,
    wire: &[u8],
    first_message_init: Option<Vec<u8>>,
) -> Result<DecryptOutcome> {
    use crate::crypto::message_crypto::build_aad;
    use crate::messaging::ratchet_store;

    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;

    // Fresh PQ-X3DH responder bootstrap if this is a session-init blob OR
    // the existing session is unusable.
    let mut state_obj: RatchetState = match (
        ratchet_store::load(&rt.db, &contact.id)?,
        first_message_init,
    ) {
        (Some(s), None) => s,
        (None, Some(init)) => bootstrap_responder(&rt.db, &rt.identity, &init)?,
        (Some(_), Some(init)) => {
            // Peer reset. Rebuild from the new session-init.
            bootstrap_responder(&rt.db, &rt.identity, &init)?
        }
        (None, None) => {
            return Err(anyhow!("no ratchet session and no session-init"));
        }
    };

    let parsed = parse_wire(wire)?;
    let plaintext_padded = ratchet::decrypt_message(
        &mut state_obj,
        &parsed.ratchet_key,
        parsed.prev_chain_len,
        parsed.msg_num,
        &parsed.nonce,
        &parsed.ciphertext,
        build_aad,
    )?;

    ratchet_store::save(&rt.db, &contact.id, &state_obj)?;

    // Type byte sits at offset 8 in every envelope (after the 8-byte
    // timestamp). Attachment envelopes (0x01) are NOT PKCS7-padded — they
    // exceed PAD_BLOCK so padding would be wasteful. Text + control envelopes
    // are always padded to PAD_BLOCK.
    use crate::crypto::TYPE_FLAG_ATTACHMENT;
    let unpadded = if plaintext_padded.len() > 8
        && plaintext_padded[8] == TYPE_FLAG_ATTACHMENT
    {
        plaintext_padded
    } else {
        unpad_pkcs7(&plaintext_padded)?
    };
    let decoded = decode_envelope(&unpadded)?;
    let now_ms = now_unix_ms();

    // Per-message TTL pulled from a TYPE_FLAG_DETONATING_TEXT envelope
    // (otherwise None, in which case we fall back to the conversation-
    // level disappear_timer below).
    let mut envelope_detonate_secs: Option<u32> = None;

    let (plaintext, is_attachment, filename, mime_type, file_size, attachment_bytes) =
        match decoded {
            DecodedEnvelope::Text { text, .. } => {
                (Some(text), false, None, None, None, None)
            }
            DecodedEnvelope::DetonatingText {
                text,
                detonate_secs,
                ..
            } => {
                envelope_detonate_secs = Some(detonate_secs);
                (Some(text), false, None, None, None, None)
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
                Some(bytes.len() as i64),
                Some(bytes),
            ),
        DecodedEnvelope::DeliveryReceipt { wire_hash, .. } => {
            // Flip the original outbound row to `delivered` and emit a
            // status event. We never persist a "message" for a receipt.
            let updated = rt.db.mark_delivered_by_wire_hash(&wire_hash).ok().flatten();
            return Ok(DecryptOutcome::Receipt {
                wire_hash,
                updated_message_id: updated,
            });
        }
        DecodedEnvelope::RelayUpdate { new_relay_url, .. } => {
            // Peer told us their home relay changed. Update the contact row
            // so future deposits go to the new URL.
            tracing::info!(
                "inbound: relay-update from `{}` → {}",
                contact.alias,
                new_relay_url
            );
            let _ = rt.db.set_contact_relay_url(&contact.id, &new_relay_url);
            return Ok(DecryptOutcome::Receipt {
                wire_hash: [0u8; 32],
                updated_message_id: None,
            });
        }
        DecodedEnvelope::RoomInvite {
            room_id,
            name,
            description,
            owner_chain_seed,
            member_pubkeys,
            ..
        } => {
            // Defer the actual room-create side-effects to handle_outcome;
            // the vault lock is held here and the side-effects re-lock.
            return Ok(DecryptOutcome::RoomInvite {
                room_id,
                name,
                description,
                owner_chain_seed,
                member_pubkeys,
            });
        }
        DecodedEnvelope::RoomSenderKey {
            room_id,
            chain_seed,
            ..
        } => {
            return Ok(DecryptOutcome::RoomSenderKey {
                room_id,
                chain_seed,
            });
        }
    };

    let envelope_bytes = unpadded;
    let tee = secure_enclave::derive_conversation_key(conversation_id.as_bytes())
        .ok()
        .map(|_| {
            crate::crypto::tee_encryption::encrypt_for_conversation(
                conversation_id.as_bytes(),
                &envelope_bytes,
            )
        })
        .transpose()?;

    // Per-message detonation always wins over the conversation-level
    // disappear_timer — the sender explicitly opted in to a tighter window.
    let disappear_at = if let Some(secs) = envelope_detonate_secs {
        Some(now_ms + (secs as i64).saturating_mul(1000))
    } else {
        rt.db
            .conversation_disappear_timer(conversation_id)
            .ok()
            .flatten()
            .map(|secs| now_ms + secs.saturating_mul(1000))
    };
    if let Some(deadline) = disappear_at {
        tracing::info!(
            "inbound: detonating message from `{}` — deadline_ms={} (in {}s, envelope_secs={:?})",
            contact.alias,
            deadline,
            (deadline - now_ms) / 1000,
            envelope_detonate_secs
        );
    }
    let message = Message {
        id: Uuid::new_v4().to_string(),
        conversation_id: conversation_id.into(),
        sender_alias: contact.alias.clone(),
        is_outbound: false,
        plaintext: None,
        is_attachment,
        filename: filename.clone(),
        mime_type: mime_type.clone(),
        file_size,
        status: "delivered".into(),
        disappear_at,
        created_at: now_ms,
    };
    rt.db.insert_message(&message, tee.as_deref(), None, None)?;

    // Stash the decrypted attachment bytes encrypted-at-rest under the
    // profile dir so the UI can re-open the file later.
    if let Some(bytes) = attachment_bytes {
        let profile_dir = crate::profile::data_dir();
        if let Err(e) = crate::messaging::attachments::store(
            &profile_dir,
            &message.id,
            conversation_id,
            &bytes,
        ) {
            tracing::warn!("attachment_store (receiver side) failed: {e}");
        }
    }

    // Bump conversation last_message_at + unread.
    let _ = rt.db.conn.execute(
        "UPDATE conversations
         SET last_message_at = ?1,
             unread_count    = unread_count + 1
         WHERE id = ?2",
        rusqlite::params![now_ms, conversation_id],
    );

    Ok(DecryptOutcome::UserMessage {
        plaintext,
        is_attachment,
        sender_alias: contact.alias.clone(),
    })
}

fn bootstrap_responder(
    db: &crate::db::Database,
    me: &crate::identity::LoadedIdentity,
    init_bytes: &[u8],
) -> Result<RatchetState> {
    let init = parse_session_init(init_bytes)?;

    let ik_alice_x = XPublicKey::from(<[u8; 32]>::try_from(init.initiator_x25519_pub.as_slice())?);
    let ek_alice = XPublicKey::from(<[u8; 32]>::try_from(init.ek_alice.as_slice())?);

    let spk = db
        .current_signed_prekey()?
        .ok_or_else(|| anyhow!("no active SPK"))?;
    let otpk = db
        .one_time_prekey_by_id(init.used_otpk_id)?
        .ok_or_else(|| anyhow!("OTPK {} not found", init.used_otpk_id))?;
    if otpk.consumed {
        return Err(anyhow!("OTPK {} already consumed", init.used_otpk_id));
    }

    let spk_secret = XStaticSecret::from(<[u8; 32]>::try_from(spk.x25519_secret.as_slice())?);
    let otpk_secret = XStaticSecret::from(<[u8; 32]>::try_from(otpk.x25519_secret.as_slice())?);

    let kem2_opt: Option<&[u8]> = if init.kem2_ct.is_empty() {
        None
    } else {
        Some(&init.kem2_ct)
    };
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
        kem1_ciphertext: &init.kem1_ct,
        kem2_ciphertext: kem2_opt,
    })?;

    let state = RatchetState::init_responder(&master, spk_secret)?;
    let _ = ek_alice; // kept above only for use inside `responder_agree`
    db.mark_one_time_prekey_consumed(init.used_otpk_id)?;
    // The OTPK we just consumed is the one currently advertised in our
    // published bundle. Without an immediate republish, the next initiator
    // who fetches our bundle would receive the same stale OTPK_id, and
    // their first-message would fail when our responder rejects an
    // already-consumed OTPK. Republish in the background so the relay's
    // bundle catches up before another initiator hits us.
    schedule_bundle_republish();
    Ok(state)
}

/// Spawn a background task that re-fetches the next unconsumed OTPK +
/// re-signs the bundle + PUTs it to the relay. Best-effort: a network
/// failure leaves the stale bundle in place — the next consumed OTPK
/// retries.
fn schedule_bundle_republish() {
    let state_arc = match crate::commands::shared_state() {
        Some(a) => a,
        None => return,
    };
    tokio::spawn(async move {
        let (bundle_bytes, alias, relay_url) = {
            let guard = state_arc.vault.lock();
            let Some(rt) = guard.as_ref() else { return };
            let bundle = match crate::identity::build_published_bundle(&rt.db, &rt.identity)
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("republish: build_published_bundle failed: {e}");
                    return;
                }
            };
            let bytes = crate::crypto::bundle::serialize(&bundle);
            let alias = rt.identity.alias.clone();
            let url = match state_arc.relay.current_url() {
                Some(u) => u,
                None => {
                    tracing::warn!("republish: no relay URL");
                    return;
                }
            };
            (bytes, alias, url)
        };
        if let Err(e) =
            crate::transport::bundle_registry::put_bundle(&relay_url, &alias, &bundle_bytes)
                .await
        {
            tracing::warn!("republish: PUT failed for `{alias}`: {e}");
        } else {
            tracing::info!(
                "republish: bumped bundle for `{alias}` after OTPK consumption"
            );
        }
    });
}

struct ParsedSessionInit {
    initiator_x25519_pub: Vec<u8>,
    ek_alice: Vec<u8>,
    kem1_ct: Vec<u8>,
    kem2_ct: Vec<u8>,
    used_otpk_id: u32,
}

fn parse_session_init(b: &[u8]) -> Result<ParsedSessionInit> {
    let mut off = 0usize;
    let read_u32 = |off: &mut usize| -> Result<u32> {
        if *off + 4 > b.len() {
            return Err(anyhow!("session-init truncated (u32)"));
        }
        let v = u32::from_be_bytes(b[*off..*off + 4].try_into().unwrap());
        *off += 4;
        Ok(v)
    };
    let read_field = |off: &mut usize| -> Result<Vec<u8>> {
        let len = read_u32(off)? as usize;
        if *off + len > b.len() {
            return Err(anyhow!("session-init truncated (field)"));
        }
        let s = b[*off..*off + len].to_vec();
        *off += len;
        Ok(s)
    };

    let initiator_x25519_pub = read_field(&mut off)?;
    let ek_alice = read_field(&mut off)?;
    let kem1_ct = read_field(&mut off)?;
    let kem2_ct = read_field(&mut off)?;
    let used_otpk_id = read_u32(&mut off)?;
    Ok(ParsedSessionInit {
        initiator_x25519_pub,
        ek_alice,
        kem1_ct,
        kem2_ct,
        used_otpk_id,
    })
}

/// Dispatch on the decrypt outcome:
/// - A real user message → emit `message:received`, deposit a delivery
///   receipt back to the sender so their row flips `sent` → `delivered`.
/// - A delivery receipt → emit `message:status` so the sender's UI
///   re-renders the affected row.
fn handle_outcome(
    app: &AppHandle,
    state: &AppState,
    contact: &Contact,
    conversation_id: &str,
    inbound_blob_hash: &[u8; 32],
    outcome: DecryptOutcome,
) {
    match outcome {
        DecryptOutcome::UserMessage {
            plaintext,
            is_attachment,
            sender_alias,
        } => {
            #[derive(serde::Serialize, Clone)]
            struct Payload<'a> {
                conversation_id: &'a str,
                sender_alias: &'a str,
                preview: Option<&'a str>,
                is_attachment: bool,
            }
            let _ = app.emit(
                "message:received",
                Payload {
                    conversation_id,
                    sender_alias: &sender_alias,
                    preview: plaintext.as_deref(),
                    is_attachment,
                },
            );

            // OS notification, gated on user prefs and window focus state.
            maybe_fire_notification(
                app,
                state,
                &sender_alias,
                plaintext.as_deref(),
                is_attachment,
            );

            // Acknowledge the sender — fire-and-forget. We send the receipt
            // through the same Double Ratchet channel.
            if let Err(e) = send_delivery_receipt(state, contact, conversation_id, inbound_blob_hash) {
                tracing::warn!("inbound: failed to send delivery receipt: {e:#}");
            }
        }
        DecryptOutcome::Receipt { wire_hash, updated_message_id } => {
            tracing::info!(
                "inbound: delivery receipt for hash={} → message {:?}",
                hex::encode(&wire_hash[..8]),
                updated_message_id
            );
            if let Some(id) = updated_message_id {
                #[derive(serde::Serialize, Clone)]
                struct Status<'a> {
                    message_id: &'a str,
                    status: &'a str,
                }
                let _ = app.emit(
                    "message:status",
                    Status {
                        message_id: &id,
                        status: "delivered",
                    },
                );
            }
        }
        DecryptOutcome::RoomInvite {
            room_id,
            name,
            description,
            owner_chain_seed,
            member_pubkeys,
        } => {
            // Run the side-effects here, OUTSIDE the run_decrypt vault lock,
            // so the inner re-lock inside handle_room_invite is safe.
            handle_room_invite(
                state,
                contact,
                &room_id,
                &name,
                &description,
                &owner_chain_seed,
                &member_pubkeys,
            );
            let _ = app.emit("rooms:changed", serde_json::json!({}));
        }
        DecryptOutcome::RoomSenderKey { room_id, chain_seed } => {
            handle_room_sender_key(state, contact, &room_id, &chain_seed);
            let _ = app.emit("rooms:changed", serde_json::json!({}));
            // Role-split reciprocation: if my pubkey is larger, the peer was
            // the initiator who just delivered their seed to us. They never
            // received ours (they didn't fire a follow-up bootstrap because
            // we never sent them a contact-request). Send our seed back over
            // the now-established pairwise ratchet so room messages we
            // produce are also decryptable on their side.
            let me_pub_opt = {
                let guard = state.vault.lock();
                guard
                    .as_ref()
                    .map(|rt| rt.identity.keys.ed25519_verifying().to_bytes())
            };
            if let Some(me_pub) = me_pub_opt {
                if me_pub.as_slice() > contact.ed25519_public.as_slice() {
                    reciprocate_sender_key(contact, &room_id);
                }
            }
        }
    }
}

/// Encrypt a delivery-receipt envelope through the existing Double Ratchet
/// session with `contact` and deposit it on their mailbox.
fn send_delivery_receipt(
    state: &AppState,
    contact: &Contact,
    _conversation_id: &str,
    inbound_blob_hash: &[u8; 32],
) -> Result<()> {
    use crate::crypto::message_crypto::{
        build_aad, build_delivery_receipt_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
    };
    use crate::crypto::ratchet::{self, RatchetState};
    use crate::crypto::PAD_BLOCK;
    use crate::messaging::ratchet_store;

    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;

    let mut ratchet_state: RatchetState = ratchet_store::load(&rt.db, &contact.id)?
        .ok_or_else(|| anyhow!("no ratchet session for receipt"))?;

    let envelope = build_delivery_receipt_envelope(now_unix_ms() as u64, inbound_blob_hash);
    let padded = pad_pkcs7(&envelope, PAD_BLOCK);
    let enc = ratchet::encrypt_message(&mut ratchet_state, &padded, build_aad)?;
    let wire = pack_text_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    })?;

    ratchet_store::save(&rt.db, &contact.id, &ratchet_state)?;

    let recipient_mb = mailbox::current_mailbox(&contact.ed25519_public);
    let recipient_mb_hex = mailbox::hex(&recipient_mb);
    let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
    let sender_mb_hex = mailbox::hex(&mailbox::current_mailbox(&me_pub));

    let mut blob = Vec::with_capacity(MAILBOX_PREFIX_LEN + wire.len());
    blob.extend_from_slice(sender_mb_hex.as_bytes());
    blob.extend_from_slice(&wire);

    let id = uuid::Uuid::new_v4().to_string();
    state
        .relay
        .deposit(recipient_mb_hex, &blob, 60 * 60 * 24, id)
        .map_err(|e| anyhow!("deposit receipt: {e}"))?;
    Ok(())
}

fn sha256_blob(prefix: &[u8], wire: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prefix);
    h.update(wire);
    h.finalize().into()
}

fn sha256_bytes(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Bob got a room-invite from Alice. Bob:
///   1. creates the local room conversation row;
///   2. persists Alice (the owner) as a member with her shared chain seed;
///   3. persists every other invited member as a pending row (no key yet);
///   4. generates Bob's own sender key for the room and stores it on his
///      self-row;
///   5. fans out a `RoomSenderKey` envelope to every other invited member
///      via the existing pairwise Double Ratchet so they can decrypt Bob.
///
/// Steps 1–4 happen synchronously under the vault lock. Step 5 is delegated
/// to a fresh tokio task because it may need cross-relay deposits.
fn handle_room_invite(
    state: &AppState,
    from_contact: &Contact,
    room_id: &[u8; 16],
    name: &str,
    description: &str,
    owner_chain_seed: &[u8; 32],
    member_pubkeys: &[[u8; 32]],
) {
    use crate::crypto::sender_key::SenderKey;
    use crate::db::messages::Conversation;
    use rand::{rngs::OsRng, RngCore};
    use uuid::Uuid;

    let room_uuid = Uuid::from_bytes(*room_id).to_string();
    let now = now_unix_ms();

    // We need our own pubkey + the contact's pubkey for the upcoming
    // sender-key fan-out, so collect identity + member rows once.
    let my_chain_seed = {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    };

    let outcome = {
        let guard = state.vault.lock();
        let Some(rt) = guard.as_ref() else { return };
        let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();

        // Skip if we're not actually one of the invited members.
        if !member_pubkeys.iter().any(|p| *p == me_pub)
            && !member_pubkeys.is_empty()
        {
            tracing::warn!(
                "inbound: room invite from `{}` excludes me — ignoring",
                from_contact.alias
            );
            return;
        }

        // 1. Conversation row.
        let _ = rt.db.upsert_conversation(&Conversation {
            id: room_uuid.clone(),
            kind: "room".into(),
            contact_id: None,
            contact_alias: None,
            contact_nickname: None,
            room_name: Some(name.to_string()),
            room_description: Some(description.to_string()),
            disappear_timer: None,
            is_sealed: false,
            is_pending: false,
            last_message_at: None,
            unread_count: 0,
            created_at: now,
        });

        // 2. Owner as a member with their shared seed.
        let _ = crate::messaging::room_keys::upsert_member_with_seed(
            &rt.db,
            &room_uuid,
            &from_contact.id,
            "owner",
            owner_chain_seed,
            now,
        );

        // 3. Build the broadcast list for our own sender-key share. Every
        //    OTHER member needs our seed to decrypt our future messages —
        //    *including* the owner who invited us. The owner row has
        //    already been inserted in step 2, so we just don't re-upsert
        //    them as pending. Members we don't yet have a contact for go
        //    into `unknown_pubkeys` for an out-of-band auto-bootstrap.
        let mut peers_to_notify: Vec<crate::db::contacts::Contact> = Vec::new();
        let mut unknown_pubkeys: Vec<[u8; 32]> = Vec::new();
        let known_contacts = rt.db.list_contacts().unwrap_or_default();
        for pk in member_pubkeys {
            if *pk == me_pub {
                continue;
            }
            let is_owner = from_contact.ed25519_public.as_slice() == pk.as_slice();
            if let Some(c) = known_contacts
                .iter()
                .find(|c| c.ed25519_public.as_slice() == pk.as_slice())
            {
                if !is_owner {
                    let _ = crate::messaging::room_keys::upsert_member_pending(
                        &rt.db,
                        &room_uuid,
                        &c.id,
                        "member",
                        now,
                    );
                }
                peers_to_notify.push(c.clone());
            } else if is_owner {
                peers_to_notify.push(from_contact.clone());
            } else {
                // Co-participant we've never talked to before (e.g. Alice
                // invited us into a room with Charlie, and we have no prior
                // pairwise session with Charlie). Defer the bootstrap to a
                // background task that fetches Charlie's bundle, sends him a
                // contact-request, and then shares our sender-key seed.
                unknown_pubkeys.push(*pk);
            }
        }

        // 4. Our own sender-key for this room (separate from peer rows
        //    because we don't FK against a contact row for ourselves).
        let me_sk = SenderKey::from_seed(my_chain_seed);
        let _ = crate::messaging::room_keys::save_self(&rt.db, &room_uuid, &me_sk);

        Some((my_chain_seed, peers_to_notify, unknown_pubkeys))
    };

    // 5. Fan out our sender key to every other member, and bootstrap any
    //    co-participants we don't yet have a contact for.
    if let Some((seed, peers, unknown)) = outcome {
        broadcast_sender_key(state, *room_id, seed, peers);
        if !unknown.is_empty() {
            bootstrap_unknown_room_peers(*room_id, seed, unknown);
        }
    }
}

/// Persist a peer's sender-key seed for an existing room. Creates or updates
/// the (room, contact) row.
fn handle_room_sender_key(
    state: &AppState,
    from_contact: &Contact,
    room_id: &[u8; 16],
    chain_seed: &[u8; 32],
) {
    use uuid::Uuid;
    let room_uuid = Uuid::from_bytes(*room_id).to_string();
    let now = now_unix_ms();

    let guard = state.vault.lock();
    let Some(rt) = guard.as_ref() else { return };
    let _ = crate::messaging::room_keys::upsert_member_with_seed(
        &rt.db,
        &room_uuid,
        &from_contact.id,
        "member",
        chain_seed,
        now,
    );
    tracing::info!(
        "inbound: stored sender-key for {} in room {}",
        from_contact.alias,
        &room_uuid[..8]
    );
}

/// Send a `RoomSenderKey` envelope to every contact in `peers` over the
/// existing pairwise Double Ratchet. Spawned as a fresh task to avoid
/// holding the vault lock across awaits.
fn broadcast_sender_key(
    state: &AppState,
    room_id_bytes: [u8; 16],
    chain_seed: [u8; 32],
    peers: Vec<Contact>,
) {
    use crate::crypto::message_crypto::{
        build_aad, build_room_sender_key_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
    };
    use crate::crypto::ratchet;
    use crate::crypto::PAD_BLOCK;
    use std::time::Duration;
    let state_arc = match crate::commands::shared_state() {
        Some(a) => a,
        None => return,
    };
    let now_ms = now_unix_ms();
    tokio::spawn(async move {
        for contact in peers {
            let envelope =
                build_room_sender_key_envelope(now_ms as u64, &room_id_bytes, &chain_seed);
            let padded = pad_pkcs7(&envelope, PAD_BLOCK);
            let prepared = {
                let guard = state_arc.vault.lock();
                let Some(rt) = guard.as_ref() else { break };
                let mut state =
                    match crate::messaging::ratchet_store::load(&rt.db, &contact.id)
                        .ok()
                        .flatten()
                    {
                        Some(s) => s,
                        None => continue,
                    };
                let enc = match ratchet::encrypt_message(&mut state, &padded, build_aad) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let wire = match pack_text_wire(&RatchetWire {
                    ratchet_key: &enc.ratchet_key,
                    prev_chain_len: enc.prev_chain_len,
                    msg_num: enc.msg_num,
                    nonce: &enc.nonce,
                    ciphertext: &enc.ciphertext,
                    sentinel_digest: None,
                }) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                let _ = crate::messaging::ratchet_store::save(&rt.db, &contact.id, &state);

                let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
                let sender_mb_hex = crate::transport::mailbox::hex(
                    &crate::transport::mailbox::current_mailbox(&me_pub),
                );
                let recipient_mb_hex = crate::transport::mailbox::hex(
                    &crate::transport::mailbox::current_mailbox(&contact.ed25519_public),
                );

                let mut blob = Vec::with_capacity(32 + wire.len());
                blob.extend_from_slice(sender_mb_hex.as_bytes());
                blob.extend_from_slice(&wire);
                Some((
                    blob,
                    recipient_mb_hex,
                    contact.relay_url.clone(),
                ))
            };

            let Some((blob, recipient_mb_hex, target)) = prepared else {
                continue;
            };
            let home = state_arc.relay.current_url();
            let cross = match (target.as_deref(), home.as_deref()) {
                (Some(t), Some(h)) if !t.is_empty() && t != h => Some(t.to_string()),
                (Some(t), None) if !t.is_empty() => Some(t.to_string()),
                _ => None,
            };
            match cross {
                Some(url) => {
                    let _ = crate::transport::relay::transient_deposit(
                        &url,
                        &recipient_mb_hex,
                        &blob,
                        60 * 60 * 24,
                        Duration::from_secs(10),
                        None,
                    )
                    .await;
                }
                None => {
                    let _ = state_arc.relay.deposit(
                        recipient_mb_hex,
                        &blob,
                        60 * 60 * 24,
                        uuid::Uuid::new_v4().to_string(),
                    );
                }
            }
        }
    });
}

/// Send our own room sender-key seed back to a peer who just shared theirs
/// with us. Spawned as a tokio task because it involves a deposit to the
/// peer's mailbox (potentially via a transient cross-relay connection).
///
/// Used by the handle_outcome RoomSenderKey reciprocation path: when peer
/// X (the smaller-pubkey initiator) sends us their seed, we (the
/// larger-pubkey side) need to ship ours back over the now-established
/// pairwise ratchet so X can decrypt our future room messages.
fn reciprocate_sender_key(peer: &Contact, room_id: &[u8; 16]) {
    let state_arc = match crate::commands::shared_state() {
        Some(a) => a,
        None => return,
    };
    let peer = peer.clone();
    let room_id_bytes = *room_id;
    let room_uuid = uuid::Uuid::from_bytes(room_id_bytes).to_string();
    tokio::spawn(async move {
        // Load my sender-key seed for this room.
        let my_seed = {
            let guard = state_arc.vault.lock();
            let Some(rt) = guard.as_ref() else { return };
            match crate::messaging::room_keys::load_self(&rt.db, &room_uuid) {
                Ok(Some(sk)) => sk.chain_seed(),
                Ok(None) => {
                    tracing::warn!(
                        "reciprocate: no self sender-key for room {}",
                        &room_uuid[..8]
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!("reciprocate: load_self failed: {e}");
                    return;
                }
            }
        };

        // Encrypt + deposit a RoomSenderKey envelope under our existing
        // pairwise ratchet with the peer.
        use crate::crypto::message_crypto::{
            build_aad, build_room_sender_key_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
        };
        use crate::crypto::ratchet;
        use crate::transport::mailbox;
        let now_ms = now_unix_ms();
        let envelope =
            build_room_sender_key_envelope(now_ms as u64, &room_id_bytes, &my_seed);
        let padded = pad_pkcs7(&envelope, crate::crypto::PAD_BLOCK);

        let prepared = {
            let guard = state_arc.vault.lock();
            let Some(rt) = guard.as_ref() else { return };
            let mut state =
                match crate::messaging::ratchet_store::load(&rt.db, &peer.id).ok().flatten() {
                    Some(s) => s,
                    None => {
                        tracing::warn!(
                            "reciprocate: no ratchet for {} (room {})",
                            peer.alias,
                            &room_uuid[..8]
                        );
                        return;
                    }
                };
            let enc = match ratchet::encrypt_message(&mut state, &padded, build_aad) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("reciprocate: ratchet encrypt failed: {e}");
                    return;
                }
            };
            let wire = match pack_text_wire(&RatchetWire {
                ratchet_key: &enc.ratchet_key,
                prev_chain_len: enc.prev_chain_len,
                msg_num: enc.msg_num,
                nonce: &enc.nonce,
                ciphertext: &enc.ciphertext,
                sentinel_digest: None,
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("reciprocate: pack_text_wire failed: {e}");
                    return;
                }
            };
            let _ = crate::messaging::ratchet_store::save(&rt.db, &peer.id, &state);

            let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
            let sender_mb_hex = mailbox::hex(&mailbox::current_mailbox(&me_pub));
            let recipient_mb_hex =
                mailbox::hex(&mailbox::current_mailbox(&peer.ed25519_public));
            let mut blob = Vec::with_capacity(32 + wire.len());
            blob.extend_from_slice(sender_mb_hex.as_bytes());
            blob.extend_from_slice(&wire);
            (blob, recipient_mb_hex, peer.relay_url.clone())
        };

        let (blob, recipient_mb_hex, target) = prepared;
        let home = state_arc.relay.current_url();
        let cross = match (target.as_deref(), home.as_deref()) {
            (Some(t), Some(h)) if !t.is_empty() && t != h => Some(t.to_string()),
            (Some(t), None) if !t.is_empty() => Some(t.to_string()),
            _ => None,
        };
        match cross {
            Some(url) => {
                let _ = crate::transport::relay::transient_deposit(
                    &url,
                    &recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    std::time::Duration::from_secs(10),
                    None,
                )
                .await;
            }
            None => {
                let _ = state_arc.relay.deposit(
                    recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    uuid::Uuid::new_v4().to_string(),
                );
            }
        }
        tracing::info!(
            "reciprocate: sent my sender-key for room {} to `{}`",
            &room_uuid[..8],
            peer.alias
        );
    });
}

/// Bootstrap a contact for every co-participant in a room we don't yet
/// know. To avoid the dual-bootstrap race that produces parallel
/// PQ-X3DH sessions (each side's bootstrap_responder of the *other's*
/// init-bytes clobbers their own initiator state, leaving the two sides
/// holding responder halves of *different* sessions), we use a
/// deterministic role split:
///
///   - if `me_pub < peer_pub`: I run the full bootstrap. I fetch their
///     bundle, persist them as a contact, send a contact-request +
///     first-message-wrapped RoomSenderKey. They will accept it.
///   - if `me_pub > peer_pub`: I just persist a placeholder contact (no
///     ratchet, no announce) so my pump can resolve their inbound mailbox.
///     They will initiate the session; I receive their first-message
///     wrapper, bootstrap_responder, and decrypt their RoomSenderKey.
///
/// Net effect: exactly one PQ-X3DH session per pair, no race.
fn bootstrap_unknown_room_peers(
    room_id_bytes: [u8; 16],
    chain_seed: [u8; 32],
    unknown_pubkeys: Vec<[u8; 32]>,
) {
    use crate::crypto::keys::derive_alias;
    let state_arc = match crate::commands::shared_state() {
        Some(a) => a,
        None => return,
    };
    let me_pub = {
        let guard = state_arc.vault.lock();
        match guard.as_ref() {
            Some(rt) => rt.identity.keys.ed25519_verifying().to_bytes(),
            None => return,
        }
    };
    tokio::spawn(async move {
        let relay_url = match state_arc.relay.current_url() {
            Some(u) => u,
            None => {
                tracing::warn!("room-bootstrap: no home relay; skipping");
                return;
            }
        };
        for pk in unknown_pubkeys {
            let alias = derive_alias(&pk);
            // Deterministic role: smaller pubkey initiates.
            let i_should_initiate = me_pub.as_slice() < pk.as_slice();
            tracing::info!(
                "room-bootstrap: peer `{}` — i_should_initiate={}",
                alias,
                i_should_initiate
            );
            let bundle = match crate::transport::bundle_registry::get_bundle(
                &relay_url,
                &alias,
            )
            .await
            {
                Ok(Some(b)) => b,
                Ok(None) => {
                    tracing::warn!("room-bootstrap: no bundle for `{}`", alias);
                    continue;
                }
                Err(e) => {
                    tracing::warn!("room-bootstrap: bundle fetch for `{}`: {}", alias, e);
                    continue;
                }
            };
            if bundle.identity_key != pk {
                tracing::warn!(
                    "room-bootstrap: bundle for `{}` has different identity key — relay tampering?",
                    alias
                );
                continue;
            }
            let new_contact = match persist_room_peer_as_contact(&state_arc, &bundle) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        "room-bootstrap: persist contact for `{}` failed: {}",
                        alias,
                        e
                    );
                    continue;
                }
            };

            if !i_should_initiate {
                // Wait for the peer to initiate. Their first-message wrapper
                // will arrive at us, handle_first will resolve them (we just
                // persisted them as a contact), and run_decrypt will
                // bootstrap_responder — establishing the single session.
                tracing::info!(
                    "room-bootstrap: persisted `{}` and waiting for their initiation",
                    new_contact.alias
                );
                continue;
            }

            // I initiate. Send contact-request first so the peer adds me as
            // a contact (their handle_first needs to resolve my mailbox to
            // me before it can call run_decrypt on my first-message wire).
            if let Err(e) = announce_to_peer(&state_arc, &new_contact).await {
                tracing::warn!(
                    "room-bootstrap: contact-request to `{}`: {}",
                    new_contact.alias,
                    e
                );
                continue;
            }

            // Then share our sender-key seed via PQ-X3DH initiator.
            if let Err(e) = send_room_sender_key_to(
                &state_arc,
                &new_contact,
                &room_id_bytes,
                &chain_seed,
            )
            .await
            {
                tracing::warn!(
                    "room-bootstrap: sender-key share to `{}`: {}",
                    new_contact.alias,
                    e
                );
            }
        }
    });
}

/// Persist a room co-participant we just learned about via an invite.
/// Idempotent w.r.t. the Ed25519 identity key — if a contact already exists
/// for this peer (from an earlier contact-request that won the race), we
/// reuse its row and just promote any pending conversation to active. This
/// keeps the auto-bootstrap from creating a duplicate chat.
fn persist_room_peer_as_contact(
    state: &AppState,
    bundle: &crate::crypto::bundle::PublicKeyBundle,
) -> Result<Contact> {
    use crate::db::messages::Conversation;
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
    let now = now_unix_ms();
    let relay_url = if bundle.relay_url.is_empty() {
        state.relay.current_url()
    } else {
        Some(bundle.relay_url.clone())
    };

    // If we already know this peer (e.g. the contact-request that arrived
    // milliseconds before the bootstrap finished racing), reuse that row.
    let existing = rt
        .db
        .list_contacts()?
        .into_iter()
        .find(|c| c.ed25519_public.as_slice() == bundle.identity_key.as_slice());

    let i2p_destination = if bundle.i2p_destination.is_empty() {
        None
    } else {
        Some(bundle.i2p_destination.clone())
    };
    let contact = match existing {
        Some(mut c) => {
            // Refresh the bundle-derived fields — the peer may have rotated
            // their X25519 / ML-KEM keys, and the relay_url may have changed.
            c.alias = bundle.alias.clone();
            c.x25519_public = bundle.x25519_key.to_vec();
            c.mlkem_public = bundle.kyber_key.clone();
            c.relay_url = relay_url;
            // Refresh the I2P destination too — peers can rotate.
            if i2p_destination.is_some() {
                c.i2p_destination = i2p_destination.clone();
            }
            c.updated_at = now;
            rt.db.upsert_contact(&c)?;
            c
        }
        None => {
            let c = Contact {
                id: Uuid::new_v4().to_string(),
                alias: bundle.alias.clone(),
                ed25519_public: bundle.identity_key.to_vec(),
                x25519_public: bundle.x25519_key.to_vec(),
                mlkem_public: bundle.kyber_key.clone(),
                relay_url,
                i2p_destination: i2p_destination.clone(),
                verified: false,
                peer_has_verified_us: false,
                hide_until_verified: false,
                is_sealed: false,
                nickname: None,
                created_at: now,
                updated_at: now,
            };
            rt.db.upsert_contact(&c)?;
            c
        }
    };

    // Always upsert the conversation as active. If a pending row exists from
    // a prior contact-request, this promotes it; if no row exists, this
    // creates one. The room-bootstrap is an explicit "we're co-participants"
    // signal, so a pending request is the wrong UI state.
    rt.db.upsert_conversation(&Conversation {
        id: contact.id.clone(),
        kind: "direct".into(),
        contact_id: Some(contact.id.clone()),
        contact_alias: None,
            contact_nickname: None,
        room_name: None,
        room_description: None,
        disappear_timer: None,
        is_sealed: false,
        is_pending: false,
        last_message_at: None,
        unread_count: 0,
        created_at: now,
    })?;
    Ok(contact)
}

/// Send our published bundle to `peer` as a contact-request envelope.
/// Their `handle_contact_request` will persist us as a contact, after which
/// our follow-up encrypted wires will resolve correctly.
async fn announce_to_peer(state: &Arc<AppState>, peer: &Contact) -> Result<()> {
    use crate::transport::envelopes::wrap_contact_request;
    use crate::transport::mailbox;
    let (my_bundle_bytes, sender_mb_hex, recipient_mb_hex) = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
        let my_bundle = crate::identity::build_published_bundle(&rt.db, &rt.identity)?;
        let bytes = crate::crypto::bundle::serialize(&my_bundle);
        let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
        let sender = mailbox::hex(&mailbox::current_mailbox(&me_pub));
        let recipient = mailbox::hex(&mailbox::current_mailbox(&peer.ed25519_public));
        (bytes, sender, recipient)
    };
    let envelope = wrap_contact_request(&my_bundle_bytes);
    let mut blob = Vec::with_capacity(32 + envelope.len());
    blob.extend_from_slice(sender_mb_hex.as_bytes());
    blob.extend_from_slice(&envelope);

    let home = state.relay.current_url();
    let target = match peer.relay_url.as_deref() {
        Some(c) if !c.is_empty() && Some(c) != home.as_deref() => Some(c.to_string()),
        _ => None,
    };
    match target {
        Some(url) => {
            crate::transport::relay::transient_deposit(
                &url,
                &recipient_mb_hex,
                &blob,
                60 * 60 * 24,
                std::time::Duration::from_secs(10),
                None,
            )
            .await
            .map_err(|e| anyhow!("transient deposit: {e}"))?;
        }
        None => {
            state
                .relay
                .deposit(
                    recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    Uuid::new_v4().to_string(),
                )
                .map_err(|e| anyhow!("deposit: {e}"))?;
        }
    }
    Ok(())
}

/// Send a single RoomSenderKey envelope through a fresh PQ-X3DH session.
/// Used by the auto-bootstrap path when we've just persisted a brand-new
/// contact and need to share our seed.
async fn send_room_sender_key_to(
    state: &Arc<AppState>,
    peer: &Contact,
    room_id: &[u8; 16],
    chain_seed: &[u8; 32],
) -> Result<()> {
    use crate::crypto::message_crypto::{
        build_aad, build_room_sender_key_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
    };
    use crate::crypto::ratchet;
    use crate::messaging::sender::prepare_initiator_first_room_message;
    use crate::transport::mailbox;

    let now_ms = now_unix_ms();
    let envelope = build_room_sender_key_envelope(now_ms as u64, room_id, chain_seed);
    let padded = pad_pkcs7(&envelope, crate::crypto::PAD_BLOCK);

    // Refetch the peer's bundle: the contact row only has identity bits, not
    // their signed prekey + one-time prekey + ML-KEM public keys that
    // PQ-X3DH initiator needs.
    let relay_url = state
        .relay
        .current_url()
        .ok_or_else(|| anyhow!("no relay"))?;
    let bundle = crate::transport::bundle_registry::get_bundle(&relay_url, &peer.alias)
        .await
        .map_err(|e| anyhow!("re-fetch bundle for {}: {}", peer.alias, e))?
        .ok_or_else(|| anyhow!("bundle missing for {}", peer.alias))?;
    let peer_clone = peer.clone();

    // Bootstrap initiator + encrypt + pack + deposit, all under a short lock.
    let (blob, recipient_mb_hex, target_relay) = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
        let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
        let (init_bytes, mut ratchet_state) =
            prepare_initiator_first_room_message(&rt.identity, &bundle)?;
        let enc = ratchet::encrypt_message(&mut ratchet_state, &padded, build_aad)?;
        let inner_wire = pack_text_wire(&RatchetWire {
            ratchet_key: &enc.ratchet_key,
            prev_chain_len: enc.prev_chain_len,
            msg_num: enc.msg_num,
            nonce: &enc.nonce,
            ciphertext: &enc.ciphertext,
            sentinel_digest: None,
        })?;
        let wire = crate::crypto::pqx3dh::pack_first_message(&init_bytes, &inner_wire);
        crate::messaging::ratchet_store::save(&rt.db, &peer_clone.id, &ratchet_state)?;

        let sender_mb_hex = mailbox::hex(&mailbox::current_mailbox(&me_pub));
        let recipient_mb_hex =
            mailbox::hex(&mailbox::current_mailbox(&peer_clone.ed25519_public));
        let mut blob = Vec::with_capacity(32 + wire.len());
        blob.extend_from_slice(sender_mb_hex.as_bytes());
        blob.extend_from_slice(&wire);
        (blob, recipient_mb_hex, peer_clone.relay_url.clone())
    };

    let home = state.relay.current_url();
    let target = match target_relay.as_deref() {
        Some(c) if !c.is_empty() && Some(c) != home.as_deref() => Some(c.to_string()),
        _ => None,
    };
    match target {
        Some(url) => {
            crate::transport::relay::transient_deposit(
                &url,
                &recipient_mb_hex,
                &blob,
                60 * 60 * 24,
                std::time::Duration::from_secs(10),
                None,
            )
            .await
            .map_err(|e| anyhow!("transient deposit: {e}"))?;
        }
        None => {
            state
                .relay
                .deposit(
                    recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    Uuid::new_v4().to_string(),
                )
                .map_err(|e| anyhow!("deposit: {e}"))?;
        }
    }
    Ok(())
}

/// Decrypt an incoming room-message wire, persist the plaintext as a
/// message row in the room's conversation, and emit `message:received`.
async fn handle_room_message(app: &AppHandle, state: &AppState, body: &[u8]) -> Result<()> {
    use crate::crypto::sender_key::{self, ParsedRoomWire};
    let parsed: ParsedRoomWire = sender_key::parse_room_wire(body)
        .map_err(|e| anyhow!("parse room wire: {e}"))?;
    let room_uuid = Uuid::from_bytes(parsed.room_id).to_string();

    // Look up which contact this sender_pub belongs to + load their stored
    // sender-key state for this room. If we don't have a key for them yet
    // (they haven't shared one), drop the message — they'll resend later
    // OR we missed an earlier handshake.
    let plaintext_opt = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
        let contacts = rt.db.list_contacts()?;
        let Some(contact) = contacts
            .iter()
            .find(|c| c.ed25519_public.as_slice() == parsed.sender_pub.as_slice())
            .cloned()
        else {
            tracing::warn!(
                "room: ciphertext from unknown sender pub `{}`",
                hex::encode(&parsed.sender_pub[..8])
            );
            return Ok(());
        };
        let member = match rt.db.room_member(&room_uuid, &contact.id)? {
            Some(m) => m,
            None => {
                tracing::warn!(
                    "room: ciphertext for room {} from {} (not a member)",
                    &room_uuid[..8],
                    contact.alias
                );
                return Ok(());
            }
        };
        let Some(mut sk) = crate::messaging::room_keys::decode(member.sender_key.as_deref())?
        else {
            tracing::warn!(
                "room: no sender-key for {} in room {} yet — dropping",
                contact.alias,
                &room_uuid[..8]
            );
            return Ok(());
        };
        let pt = sender_key::decrypt(
            &mut sk,
            &parsed.room_id,
            &parsed.sender_pub,
            parsed.counter,
            &parsed.nonce,
            &parsed.ciphertext,
        )
        .map_err(|e| anyhow!("room aead: {e}"))?;
        let _ = crate::messaging::room_keys::save(&rt.db, &room_uuid, &contact.id, &sk);
        Some((contact, pt))
    };
    let Some((contact, pt)) = plaintext_opt else {
        return Ok(());
    };

    use crate::crypto::message_crypto::{decode_envelope, unpad_pkcs7, DecodedEnvelope};
    let unpadded = unpad_pkcs7(&pt).unwrap_or(pt);
    let decoded = decode_envelope(&unpadded)?;
    let (text_opt, is_attachment, filename, mime_type, file_size) = match decoded {
        DecodedEnvelope::Text { text, .. } => (Some(text), false, None, None, None),
        DecodedEnvelope::DetonatingText { text, .. } => {
            (Some(text), false, None, None, None)
        }
        _ => return Ok(()), // attachments-in-rooms are out of MVP scope
    };

    let now_ms = now_unix_ms();
    let envelope_bytes = unpadded;
    let tee = crate::crypto::tee_encryption::encrypt_for_conversation(
        room_uuid.as_bytes(),
        &envelope_bytes,
    )
    .ok();

    {
        let guard = state.vault.lock();
        let Some(rt) = guard.as_ref() else { return Ok(()) };
        let _ = rt.db.insert_message(
            &Message {
                id: Uuid::new_v4().to_string(),
                conversation_id: room_uuid.clone(),
                sender_alias: contact.alias.clone(),
                is_outbound: false,
                plaintext: None,
                is_attachment,
                filename,
                mime_type,
                file_size,
                status: "delivered".into(),
                disappear_at: rt
                    .db
                    .conversation_disappear_timer(&room_uuid)
                    .ok()
                    .flatten()
                    .map(|s| now_ms + s.saturating_mul(1000)),
                created_at: now_ms,
            },
            tee.as_deref(),
            None,
            None,
        );
        let _ = rt.db.conn.execute(
            "UPDATE conversations
             SET last_message_at = ?1, unread_count = unread_count + 1
             WHERE id = ?2",
            rusqlite::params![now_ms, &room_uuid],
        );
    }

    #[derive(serde::Serialize, Clone)]
    struct Payload<'a> {
        conversation_id: &'a str,
        sender_alias: &'a str,
        preview: Option<&'a str>,
        is_attachment: bool,
    }
    let _ = app.emit(
        "message:received",
        Payload {
            conversation_id: &room_uuid,
            sender_alias: &contact.alias,
            preview: text_opt.as_deref(),
            is_attachment,
        },
    );
    maybe_fire_notification(
        app,
        state,
        &contact.alias,
        text_opt.as_deref(),
        is_attachment,
    );
    Ok(())
}

/// Notification preferences live in `settings`:
/// - `notify_enabled`: "1" / "0" (default "1")
/// - `notify_show_preview`: "1" / "0" (default "1")
/// - `notify_sound`: "1" / "0" (default "1")
fn read_notify_prefs(state: &AppState) -> (bool, bool, bool) {
    let guard = state.vault.lock();
    let Some(rt) = guard.as_ref() else {
        return (false, false, false);
    };
    let read_bool = |k: &str, default_val: bool| -> bool {
        match rt.db.settings_get(k).ok().flatten().as_deref() {
            Some("0") => false,
            Some("1") => true,
            _ => default_val,
        }
    };
    (
        read_bool("notify_enabled", true),
        read_bool("notify_show_preview", true),
        read_bool("notify_sound", true),
    )
}

/// Fire an OS notification for a freshly-decrypted inbound message.
/// Suppressed when the main window is currently focused — there's no
/// value in alerting users about content they're already looking at.
fn maybe_fire_notification(
    app: &AppHandle,
    state: &AppState,
    sender_alias: &str,
    plaintext: Option<&str>,
    is_attachment: bool,
) {
    let (enabled, show_preview, sound) = read_notify_prefs(state);
    if !enabled {
        return;
    }
    // Skip the notification when the main window is focused — the message
    // has already been handed to the foreground UI and a banner would just
    // be noise.
    let focused = app
        .get_webview_window("main")
        .and_then(|w| w.is_focused().ok())
        .unwrap_or(false);
    if focused {
        return;
    }

    let title = format!("{} sent you a message", sender_alias);
    let body = if !show_preview {
        "New message".to_string()
    } else if is_attachment {
        "📎 Attachment".to_string()
    } else {
        match plaintext {
            Some(t) if !t.is_empty() => {
                let trimmed: String = t.chars().take(120).collect();
                if t.chars().count() > 120 {
                    format!("{trimmed}…")
                } else {
                    trimmed
                }
            }
            _ => "New message".to_string(),
        }
    };

    use tauri_plugin_notification::NotificationExt;
    let mut builder = app.notification().builder().title(&title).body(&body);
    if sound {
        builder = builder.sound("default");
    }
    if let Err(e) = builder.show() {
        tracing::warn!("notification: failed to fire: {e}");
    }
}

// Unused imports kept for future use (first-message bootstrap path).
#[allow(dead_code)]
fn _suppress_unused(_: bundle::PublicKeyBundle, _: receiver::ReceiveOutcome) {}
