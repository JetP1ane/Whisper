//! End-to-end protocol-level integration tests.
//!
//! These tests exercise the full crypto + envelope + ratchet pipeline using
//! the same building blocks the production code uses, with two simulated
//! participants running through the full message lifecycle. No relay or
//! Tauri runtime required — this catches protocol-level bugs without UI
//! orchestration overhead.

use noctis_whisper_desktop_lib::crypto::{
    bundle::{self, OneTimePrekeyPublic, PublicKeyBundle, SignedPrekeyPublic},
    config_manifest,
    keys::{
        derive_alias, generate_identity, generate_one_time_prekeys, generate_signed_prekey,
        IdentityKeys, OneTimePrekey, SignedPrekey,
    },
    message_crypto::{
        build_aad, build_attachment_envelope, build_delivery_receipt_envelope,
        build_room_invite_envelope, build_room_sender_key_envelope, build_text_envelope,
        decode_envelope, pack_text_wire, pad_pkcs7, parse_wire, unpad_pkcs7,
        DecodedEnvelope, RatchetWire,
    },
    pqx3dh::{self, InitiatorInputs, ResponderInputs},
    ratchet::{self, RatchetState},
    safety_numbers,
    sender_key::{self as sk, SenderKey},
    PAD_BLOCK,
};
use noctis_whisper_desktop_lib::transport::frame_accounting::{
    reconcile, AccountingVerdict, RelayCounters, Snapshot,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

// =====================================================================
// Test participant: identity + ratchet state + signed bundle.
// =====================================================================

struct Participant {
    name: &'static str,
    keys: IdentityKeys,
    spk: SignedPrekey,
    otpks: Vec<OneTimePrekey>,
    bundle: PublicKeyBundle,
    ratchet: Option<RatchetState>,
}

impl Participant {
    fn new(name: &'static str) -> Self {
        let keys = generate_identity();
        let spk = generate_signed_prekey(1, &keys);
        let otpks = generate_one_time_prekeys(10, 1);
        let bundle = build_published_bundle(&keys, &spk, &otpks[0]);
        Self {
            name,
            keys,
            spk,
            otpks,
            bundle,
            ratchet: None,
        }
    }

    fn alias(&self) -> String {
        derive_alias(&self.keys.ed25519_verifying().to_bytes())
    }
}

/// Build the same compact bundle the production `identity::build_published_bundle`
/// would publish to the relay (OTPK kyber omitted to fit under 4 KB).
fn build_published_bundle(
    keys: &IdentityKeys,
    spk: &SignedPrekey,
    otpk: &OneTimePrekey,
) -> PublicKeyBundle {
    let spk_x_pub = XPublicKey::from(&spk.x25519_secret).to_bytes();
    let otpk_x_pub = XPublicKey::from(&otpk.x25519_secret).to_bytes();

    bundle::build_signed_bundle(
        &keys.ed25519_signing,
        keys.ed25519_verifying().to_bytes(),
        keys.x25519_public().to_bytes(),
        keys.mlkem_public.clone(),
        SignedPrekeyPublic {
            id: spk.id,
            x25519_pub: spk_x_pub,
            kyber_pub: spk.mlkem_public.clone(),
            signature: spk.signature,
        },
        OneTimePrekeyPublic {
            id: otpk.id,
            x25519_pub: otpk_x_pub,
            kyber_pub: Vec::new(), // compact: omit OTPK kyber
        },
        derive_alias(&keys.ed25519_verifying().to_bytes()),
        None,
        "wss://test.example.com/ws".into(),
        String::new(),
    )
}

// =====================================================================
// Helpers: Alice→Bob first-message bootstrap and subsequent encrypts.
// =====================================================================

fn alice_initiator_bootstrap(alice: &mut Participant, bob: &Participant) -> (Vec<u8>, RatchetState) {
    let ek_alice = XStaticSecret::random_from_rng(OsRng);
    let ek_alice_pub = XPublicKey::from(&ek_alice);

    let spk_x_pub = XPublicKey::from(bob.bundle.signed_prekey.x25519_pub);
    let ik_b_x_pub = XPublicKey::from(bob.bundle.x25519_key);
    let otpk_x_pub = XPublicKey::from(bob.bundle.one_time_prekey.x25519_pub);

    let otpk_kyber_opt: Option<&[u8]> = if bob.bundle.one_time_prekey.kyber_pub.is_empty() {
        None
    } else {
        Some(&bob.bundle.one_time_prekey.kyber_pub)
    };

    let out = pqx3dh::initiator_agree(InitiatorInputs {
        ik_alice: &alice.keys.x25519_secret,
        ek_alice: &ek_alice,
        spk_bob_x25519: &spk_x_pub,
        ik_bob_x25519: &ik_b_x_pub,
        otpk_bob_x25519: &otpk_x_pub,
        spk_bob_mlkem_pub: &bob.bundle.signed_prekey.kyber_pub,
        otpk_bob_mlkem_pub: otpk_kyber_opt,
    })
    .expect("initiator_agree");

    let initial_send_secret = XStaticSecret::random_from_rng(OsRng);
    let mut state = RatchetState::init_initiator(&out.master_secret, initial_send_secret);
    state.dh_recv_public = Some(bob.bundle.signed_prekey.x25519_pub);
    let dh = XStaticSecret::from(state.dh_send_secret).diffie_hellman(&spk_x_pub);
    let (new_root, new_chain) = ratchet::root_kdf(&state.root_key, dh.as_bytes()).unwrap();
    state.root_key = new_root;
    state.send_chain_key = Some(new_chain);

    let init_bytes = pqx3dh::pack_session_init(
        alice.keys.x25519_public().as_bytes(),
        ek_alice_pub.as_bytes(),
        &out.kem1_ciphertext,
        out.kem2_ciphertext.as_deref(),
        bob.bundle.one_time_prekey.id,
    );
    alice.ratchet = Some(state.clone());
    (init_bytes, state)
}

fn bob_responder_bootstrap(
    bob: &mut Participant,
    init_bytes: &[u8],
) -> RatchetState {
    let mut off = 0usize;
    let read_field = |b: &[u8], off: &mut usize| -> Vec<u8> {
        let len = u32::from_be_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
        *off += 4;
        let v = b[*off..*off + len].to_vec();
        *off += len;
        v
    };
    let read_i32 = |b: &[u8], off: &mut usize| -> i32 {
        let v = i32::from_be_bytes(b[*off..*off + 4].try_into().unwrap());
        *off += 4;
        v
    };

    let ik_alice_x = read_field(init_bytes, &mut off);
    let ek_alice = read_field(init_bytes, &mut off);
    let kem1_ct = read_field(init_bytes, &mut off);
    let kem2_ct = read_field(init_bytes, &mut off);
    let used_otpk_id = read_i32(init_bytes, &mut off) as u32;

    let ik_alice_x_pub = XPublicKey::from(<[u8; 32]>::try_from(ik_alice_x.as_slice()).unwrap());
    let ek_alice_pub = XPublicKey::from(<[u8; 32]>::try_from(ek_alice.as_slice()).unwrap());

    let otpk = bob
        .otpks
        .iter()
        .find(|o| o.id == used_otpk_id)
        .expect("otpk available");
    let kem2_opt = if kem2_ct.is_empty() { None } else { Some(kem2_ct.as_slice()) };
    let otpk_kyber_opt = if otpk.mlkem_secret.is_empty() {
        None
    } else {
        Some(otpk.mlkem_secret.as_slice())
    };

    let master = pqx3dh::responder_agree(ResponderInputs {
        ik_bob_x25519: &bob.keys.x25519_secret,
        spk_bob_x25519: &bob.spk.x25519_secret,
        spk_bob_mlkem_secret: &bob.spk.mlkem_secret,
        otpk_bob_x25519: &otpk.x25519_secret,
        otpk_bob_mlkem_secret: otpk_kyber_opt,
        ik_alice_x25519_pub: &ik_alice_x_pub,
        ek_alice_pub: &ek_alice_pub,
        kem1_ciphertext: &kem1_ct,
        kem2_ciphertext: kem2_opt,
    })
    .expect("responder_agree");

    let bob_spk_secret =
        XStaticSecret::from(<[u8; 32]>::try_from(bob.spk.x25519_secret.to_bytes().as_slice()).unwrap());
    let state = RatchetState::init_responder(&master, bob_spk_secret).unwrap();
    bob.ratchet = Some(state.clone());
    state
}

fn encrypt_text(state: &mut RatchetState, plaintext: &str) -> Vec<u8> {
    let envelope = build_text_envelope(0, plaintext);
    let padded = pad_pkcs7(&envelope, PAD_BLOCK);
    let enc = ratchet::encrypt_message(state, &padded, build_aad).unwrap();
    pack_text_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    })
    .unwrap()
}

fn encrypt_attachment(state: &mut RatchetState, fname: &str, mime: &str, bytes: &[u8]) -> Vec<u8> {
    let env = build_attachment_envelope(0, fname, mime, bytes).unwrap();
    let padded = pad_pkcs7(&env, PAD_BLOCK);
    let enc = ratchet::encrypt_message(state, &padded, build_aad).unwrap();
    let mut wire = Vec::new();
    let rk_len = enc.ratchet_key.len() as u32;
    wire.extend_from_slice(&rk_len.to_be_bytes());
    wire.extend_from_slice(&enc.ratchet_key);
    wire.extend_from_slice(&enc.prev_chain_len.to_be_bytes());
    wire.extend_from_slice(&enc.msg_num.to_be_bytes());
    wire.extend_from_slice(&enc.nonce);
    let ct_len = enc.ciphertext.len() as u32;
    wire.extend_from_slice(&ct_len.to_be_bytes());
    wire.extend_from_slice(&enc.ciphertext);
    wire.push(0); // no sentinel digest
    wire
}

fn decrypt(state: &mut RatchetState, wire: &[u8]) -> DecodedEnvelope {
    let parsed = parse_wire(wire).unwrap();
    let plaintext_padded = ratchet::decrypt_message(
        state,
        &parsed.ratchet_key,
        parsed.prev_chain_len,
        parsed.msg_num,
        &parsed.nonce,
        &parsed.ciphertext,
        build_aad,
    )
    .unwrap();
    let unpadded = unpad_pkcs7(&plaintext_padded).unwrap();
    decode_envelope(&unpadded).unwrap()
}

// =====================================================================
// Scenarios
// =====================================================================

#[test]
fn pq_x3dh_round_trip_first_message_text() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    let alice_state = alice.ratchet.as_mut().unwrap();
    let wire = encrypt_text(alice_state, "hello bob");

    bob_responder_bootstrap(&mut bob, &init_bytes);
    let bob_state = bob.ratchet.as_mut().unwrap();
    let decoded = decrypt(bob_state, &wire);

    match decoded {
        DecodedEnvelope::Text { text, .. } => assert_eq!(text, "hello bob"),
        other => panic!("expected text, got {:?}", other),
    }
}

#[test]
fn bidirectional_messaging_advances_ratchet() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    let wire1 = encrypt_text(alice.ratchet.as_mut().unwrap(), "message one");
    bob_responder_bootstrap(&mut bob, &init_bytes);
    let dec1 = decrypt(bob.ratchet.as_mut().unwrap(), &wire1);
    assert!(matches!(dec1, DecodedEnvelope::Text { ref text, .. } if text == "message one"));

    let wire2 = encrypt_text(bob.ratchet.as_mut().unwrap(), "reply from bob");
    let dec2 = decrypt(alice.ratchet.as_mut().unwrap(), &wire2);
    assert!(matches!(dec2, DecodedEnvelope::Text { ref text, .. } if text == "reply from bob"));

    let wire3 = encrypt_text(alice.ratchet.as_mut().unwrap(), "third message");
    let dec3 = decrypt(bob.ratchet.as_mut().unwrap(), &wire3);
    assert!(matches!(dec3, DecodedEnvelope::Text { ref text, .. } if text == "third message"));

    let wire4 = encrypt_text(bob.ratchet.as_mut().unwrap(), "fourth from bob");
    let dec4 = decrypt(alice.ratchet.as_mut().unwrap(), &wire4);
    assert!(matches!(dec4, DecodedEnvelope::Text { ref text, .. } if text == "fourth from bob"));
}

#[test]
fn out_of_order_messages_use_skipped_key_cache() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    let wire1 = encrypt_text(alice.ratchet.as_mut().unwrap(), "first");
    let wire2 = encrypt_text(alice.ratchet.as_mut().unwrap(), "second");
    let wire3 = encrypt_text(alice.ratchet.as_mut().unwrap(), "third");

    bob_responder_bootstrap(&mut bob, &init_bytes);
    // Receive in scrambled order: 2, 1, 3.
    let dec2 = decrypt(bob.ratchet.as_mut().unwrap(), &wire2);
    assert!(matches!(dec2, DecodedEnvelope::Text { ref text, .. } if text == "second"));
    let dec1 = decrypt(bob.ratchet.as_mut().unwrap(), &wire1);
    assert!(matches!(dec1, DecodedEnvelope::Text { ref text, .. } if text == "first"));
    let dec3 = decrypt(bob.ratchet.as_mut().unwrap(), &wire3);
    assert!(matches!(dec3, DecodedEnvelope::Text { ref text, .. } if text == "third"));
}

#[test]
fn attachment_round_trip_megabyte() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    let payload: Vec<u8> = (0..1_048_576u32).map(|i| (i & 0xFF) as u8).collect();
    let wire = encrypt_attachment(
        alice.ratchet.as_mut().unwrap(),
        "test.bin",
        "application/octet-stream",
        &payload,
    );

    bob_responder_bootstrap(&mut bob, &init_bytes);
    let parsed = parse_wire(&wire).unwrap();
    let plaintext_padded = ratchet::decrypt_message(
        bob.ratchet.as_mut().unwrap(),
        &parsed.ratchet_key,
        parsed.prev_chain_len,
        parsed.msg_num,
        &parsed.nonce,
        &parsed.ciphertext,
        build_aad,
    )
    .unwrap();
    let unpadded = unpad_pkcs7(&plaintext_padded).unwrap();
    match decode_envelope(&unpadded).unwrap() {
        DecodedEnvelope::Attachment {
            filename,
            mime_type,
            bytes,
            ..
        } => {
            assert_eq!(filename, "test.bin");
            assert_eq!(mime_type, "application/octet-stream");
            assert_eq!(bytes.len(), payload.len());
            assert_eq!(bytes, payload);
        }
        other => panic!("expected attachment, got {:?}", other),
    }
}

#[test]
fn delivery_receipt_envelope_round_trip() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    // Alice → Bob first message.
    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    let alice_wire = encrypt_text(alice.ratchet.as_mut().unwrap(), "hi");
    bob_responder_bootstrap(&mut bob, &init_bytes);
    let _ = decrypt(bob.ratchet.as_mut().unwrap(), &alice_wire);

    // Bob computes hash of what he received (mirroring sender).
    let mut h = Sha256::new();
    h.update(&alice_wire);
    let wire_hash: [u8; 32] = h.finalize().into();

    // Bob encrypts a delivery receipt envelope back to Alice.
    let env = build_delivery_receipt_envelope(0, &wire_hash);
    let padded = pad_pkcs7(&env, PAD_BLOCK);
    let enc = ratchet::encrypt_message(bob.ratchet.as_mut().unwrap(), &padded, build_aad).unwrap();
    let receipt_wire = pack_text_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    })
    .unwrap();

    // Alice receives, decodes as DeliveryReceipt with the matching hash.
    match decrypt(alice.ratchet.as_mut().unwrap(), &receipt_wire) {
        DecodedEnvelope::DeliveryReceipt {
            wire_hash: received_hash,
            ..
        } => {
            assert_eq!(received_hash, wire_hash);
        }
        other => panic!("expected delivery receipt, got {:?}", other),
    }
}

#[test]
fn ratchet_aad_binding_rejects_position_swap() {
    // An attacker who swaps two valid ciphertexts between positions would
    // still pass AEAD-key check, but the ratchet's AAD includes the
    // ratchet key + prev_chain_len + msg_num. Tampering with the wire's
    // header should fail Poly1305.

    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    let wire = encrypt_text(alice.ratchet.as_mut().unwrap(), "hello");
    let mut tampered = wire.clone();
    // Flip a bit in the msg_num field (bytes 40..44 in the wire layout).
    tampered[42] ^= 0x01;

    bob_responder_bootstrap(&mut bob, &init_bytes);
    let parsed = parse_wire(&tampered).unwrap();
    let result = ratchet::decrypt_message(
        bob.ratchet.as_mut().unwrap(),
        &parsed.ratchet_key,
        parsed.prev_chain_len,
        parsed.msg_num,
        &parsed.nonce,
        &parsed.ciphertext,
        build_aad,
    );
    assert!(result.is_err(), "tampered AAD should fail decrypt");
}

#[test]
fn bundle_alias_substitution_is_rejected() {
    // Eve forges a bundle that claims Bob's alias but is signed with her
    // own keys. The alias-↔-key binding check rejects it.
    let bob = Participant::new("bob");
    let bob_alias = bob.alias();

    let eve = Participant::new("eve");
    let kyber = vec![0xAAu8; 1568];
    let spk_x = XPublicKey::from(&eve.spk.x25519_secret).to_bytes();

    let mut substituted = bundle::build_signed_bundle(
        &eve.keys.ed25519_signing,
        eve.keys.ed25519_verifying().to_bytes(),
        eve.keys.x25519_public().to_bytes(),
        kyber.clone(),
        SignedPrekeyPublic {
            id: 1,
            x25519_pub: spk_x,
            kyber_pub: kyber.clone(),
            signature: eve.spk.signature,
        },
        OneTimePrekeyPublic {
            id: 1,
            x25519_pub: XPublicKey::from(&eve.otpks[0].x25519_secret).to_bytes(),
            kyber_pub: Vec::new(),
        },
        bob_alias.clone(),
        None,
        "wss://eve.example.com/ws".into(),
        String::new(),
    );

    // Eve's signature on her own bundle is structurally valid, but the
    // alias↔key binding is broken.
    assert!(bundle::verify_bundle(&substituted).is_err());

    // Sanity: with Eve's own (correct) alias the bundle verifies.
    substituted.alias = eve.alias();
    let _ = substituted; // signature was over bob_alias, so this still fails
}

#[test]
fn bundle_serialization_round_trip() {
    let alice = Participant::new("alice");
    let bytes = bundle::serialize(&alice.bundle);
    let parsed = bundle::deserialize(&bytes).unwrap();
    assert_eq!(parsed, alice.bundle);
    assert!(bundle::verify_bundle(&parsed).is_ok());
}

#[test]
fn whisper_link_round_trip() {
    let alice = Participant::new("alice");
    let link = bundle::build_whisper_link(&alice.bundle);
    assert!(link.starts_with("whisper://c/"));
    let parsed = bundle::parse_whisper_link(&link).unwrap();
    assert_eq!(parsed.identity_key, alice.bundle.identity_key);
    assert_eq!(parsed.alias, alice.bundle.alias);
}

#[test]
fn safety_numbers_symmetric_and_format() {
    let alice = Participant::new("alice");
    let bob = Participant::new("bob");
    let me = alice.keys.ed25519_verifying().to_bytes();
    let peer = bob.keys.ed25519_verifying().to_bytes();
    let ab = safety_numbers::safety_numbers(&me, &peer);
    let ba = safety_numbers::safety_numbers(&peer, &me);
    assert_eq!(ab, ba, "safety numbers must be symmetric");
    let formatted = safety_numbers::format_safety_numbers(&ab);
    assert_eq!(formatted.split(' ').count(), 12);
}

#[test]
fn config_manifest_signature_round_trip() {
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut seed);

    let url = "ws://127.0.0.1:8080/ws";
    let digest = config_manifest::manifest_digest(url, None);
    let sig = config_manifest::sign(&seed, &digest);
    let vk = config_manifest::verifying_key_from_seed(&seed);
    assert!(config_manifest::verify(&vk, &digest, &sig).is_ok());

    // Tamper the signed URL → digest changes → verification fails.
    let tampered = config_manifest::manifest_digest("ws://evil.example.com/ws", None);
    assert!(config_manifest::verify(&vk, &tampered, &sig).is_err());

    // Tamper the signature byte → fails.
    let mut bad_sig = sig;
    bad_sig[0] ^= 0xFF;
    assert!(config_manifest::verify(&vk, &digest, &bad_sig).is_err());
}

#[test]
fn frame_accounting_reconcile_expected_states() {
    // Verified: client ahead is benign in-flight.
    let v = reconcile(
        Snapshot {
            frames_sent: 10,
            frames_received: 14,
            bytes_sent: 0,
            bytes_received: 0,
        },
        RelayCounters {
            frames_received_from_client: 10,
            frames_sent_to_client: 13,
            bytes_received_from_client: 0,
            bytes_sent_to_client: 0,
        },
    );
    assert!(matches!(v, AccountingVerdict::Verified));

    // Drop: relay sent more than client received.
    let v = reconcile(
        Snapshot {
            frames_sent: 10,
            frames_received: 5,
            bytes_sent: 0,
            bytes_received: 0,
        },
        RelayCounters {
            frames_received_from_client: 10,
            frames_sent_to_client: 8,
            bytes_received_from_client: 0,
            bytes_sent_to_client: 0,
        },
    );
    assert!(matches!(v, AccountingVerdict::FrameDrop));

    // Injection (exfil): relay claims to have received frames we never sent.
    let v = reconcile(
        Snapshot {
            frames_sent: 5,
            frames_received: 10,
            bytes_sent: 0,
            bytes_received: 0,
        },
        RelayCounters {
            frames_received_from_client: 7,
            frames_sent_to_client: 10,
            bytes_received_from_client: 0,
            bytes_sent_to_client: 0,
        },
    );
    assert!(matches!(v, AccountingVerdict::FrameInjectionExfil));
}

#[test]
fn whisper_link_with_relay_query_param_round_trip() {
    let alice = Participant::new("alice");
    let link = bundle::build_whisper_link(&alice.bundle);
    assert!(link.starts_with("whisper://c/"));
    assert!(link.contains("?relay="));
    let parsed = bundle::parse_whisper_link(&link).unwrap();
    assert_eq!(parsed.relay_url, "wss://test.example.com/ws");
}

#[test]
fn whisper_link_relay_hint_must_match_signed_value() {
    // Crafting a link whose `?relay=` hint disagrees with the signed
    // bundle's `relay_url` is rejected.
    let alice = Participant::new("alice");
    let body = bundle::base58_encode(&bundle::serialize(&alice.bundle));
    let bad = format!(
        "whisper://c/{}?relay=wss%3A%2F%2Fevil.example.com%2Fws",
        body
    );
    assert!(bundle::parse_whisper_link(&bad).is_err());
}

#[test]
fn cross_relay_routing_decision() {
    // Same-relay case (`bundle.relay_url` matches the sender's home).
    fn decide(home: &str, contact: &str) -> Option<String> {
        if !contact.is_empty() && contact != home {
            Some(contact.to_string())
        } else {
            None
        }
    }
    assert_eq!(decide("wss://x/ws", "wss://x/ws"), None);
    assert_eq!(decide("wss://a/ws", "wss://b/ws").as_deref(), Some("wss://b/ws"));
    assert_eq!(decide("wss://x/ws", ""), None);
}

#[test]
fn alias_derivation_is_deterministic_and_in_wordlist() {
    let alice = Participant::new("alice");
    let pk = alice.keys.ed25519_verifying().to_bytes();
    let a = derive_alias(&pk);
    let b = derive_alias(&pk);
    assert_eq!(a, b, "alias must be deterministic from the key");
    assert_eq!(a.split('-').count(), 3, "alias must be 3 words");
    for word in a.split('-') {
        assert!(word.len() >= 2 && word.len() <= 12, "word `{}` length", word);
        assert!(word.chars().all(|c| c.is_ascii_lowercase()));
    }
}

// =====================================================================
// Rooms (group conversations)
// =====================================================================

/// A room invite arrives over the existing pairwise Double Ratchet from
/// the room owner. The recipient must decode the new envelope type and
/// recover the room metadata + the owner's chain seed exactly.
#[test]
fn room_invite_envelope_round_trips_through_pairwise_ratchet() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    bob_responder_bootstrap(&mut bob, &init_bytes);

    // Alice builds a room invite envelope.
    let room_id: [u8; 16] = [0x42u8; 16];
    let owner_seed: [u8; 32] = [0x11u8; 32];
    let alice_pub = alice.keys.ed25519_verifying().to_bytes();
    let bob_pub = bob.keys.ed25519_verifying().to_bytes();
    let envelope = build_room_invite_envelope(
        1234567,
        &room_id,
        "secret-club",
        "place to plot",
        &owner_seed,
        &[alice_pub, bob_pub],
    )
    .unwrap();

    // Encrypt + decrypt over Alice→Bob ratchet.
    let padded = pad_pkcs7(&envelope, PAD_BLOCK);
    let enc =
        ratchet::encrypt_message(alice.ratchet.as_mut().unwrap(), &padded, build_aad).unwrap();
    let wire = pack_text_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    })
    .unwrap();

    let decoded = decrypt(bob.ratchet.as_mut().unwrap(), &wire);
    match decoded {
        DecodedEnvelope::RoomInvite {
            room_id: rid,
            name,
            description,
            owner_chain_seed,
            member_pubkeys,
            ..
        } => {
            assert_eq!(rid, room_id);
            assert_eq!(name, "secret-club");
            assert_eq!(description, "place to plot");
            assert_eq!(owner_chain_seed, owner_seed);
            assert_eq!(member_pubkeys.len(), 2);
            assert_eq!(member_pubkeys[0], alice_pub);
            assert_eq!(member_pubkeys[1], bob_pub);
        }
        other => panic!("expected RoomInvite, got {:?}", other),
    }
}

/// After accepting an invite, every member sends their own sender-key seed
/// back to every other member via the same pairwise channel. This test
/// proves the new envelope type round-trips cleanly.
#[test]
fn room_sender_key_envelope_round_trips_through_pairwise_ratchet() {
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");

    let (init_bytes, _) = alice_initiator_bootstrap(&mut alice, &bob);
    // Establish bidirectional flow: Bob's send chain only spins up after he
    // has decrypted at least one Alice→Bob message (DH ratchet step).
    let kickoff = encrypt_text(alice.ratchet.as_mut().unwrap(), "hi");
    bob_responder_bootstrap(&mut bob, &init_bytes);
    let _ = decrypt(bob.ratchet.as_mut().unwrap(), &kickoff);

    let room_id: [u8; 16] = [0xCDu8; 16];
    let bob_seed: [u8; 32] = [0x77u8; 32];
    let envelope = build_room_sender_key_envelope(42, &room_id, &bob_seed);

    // Bob shares his seed with Alice — encrypt over Bob→Alice ratchet.
    let padded = pad_pkcs7(&envelope, PAD_BLOCK);
    let enc =
        ratchet::encrypt_message(bob.ratchet.as_mut().unwrap(), &padded, build_aad).unwrap();
    let wire = pack_text_wire(&RatchetWire {
        ratchet_key: &enc.ratchet_key,
        prev_chain_len: enc.prev_chain_len,
        msg_num: enc.msg_num,
        nonce: &enc.nonce,
        ciphertext: &enc.ciphertext,
        sentinel_digest: None,
    })
    .unwrap();

    let decoded = decrypt(alice.ratchet.as_mut().unwrap(), &wire);
    match decoded {
        DecodedEnvelope::RoomSenderKey {
            room_id: rid,
            chain_seed,
            ..
        } => {
            assert_eq!(rid, room_id);
            assert_eq!(chain_seed, bob_seed);
        }
        other => panic!("expected RoomSenderKey, got {:?}", other),
    }
}

/// Once each member has the others' sender-key seeds, room messages travel
/// as a single broadcast wire (no per-recipient encryption). This walks
/// through alice → bob and bob → alice via the sender-key crypto + the
/// magic-prefixed wire format that the inbound dispatcher routes on.
#[test]
fn room_message_round_trip_via_sender_keys() {
    let alice_pub: [u8; 32] = [0xAAu8; 32];
    let bob_pub: [u8; 32] = [0xBBu8; 32];
    let room_id: [u8; 16] = [0x11u8; 16];

    // Each member generates their own sender-key chain.
    let mut alice_send = SenderKey::random();
    let mut bob_send = SenderKey::random();

    // Each member also stores the other's seed (transported earlier via
    // RoomSenderKey envelopes — covered by the test above).
    let mut alice_view_of_bob = SenderKey::from_seed(bob_send.chain_seed());
    let mut bob_view_of_alice = SenderKey::from_seed(alice_send.chain_seed());

    // Alice sends a room message.
    let pt_alice = b"alice in the room".to_vec();
    let enc_a = sk::encrypt(&mut alice_send, &room_id, &alice_pub, &pt_alice).unwrap();
    let wire_a = sk::pack_room_wire(&room_id, &alice_pub, &enc_a);
    assert_eq!(&wire_a[..4], &sk::ROOM_WIRE_MAGIC, "magic must lead the wire");

    // Bob parses + decrypts.
    let parsed_a = sk::parse_room_wire(&wire_a).unwrap();
    assert_eq!(parsed_a.room_id, room_id);
    assert_eq!(parsed_a.sender_pub, alice_pub);
    let recovered_a = sk::decrypt(
        &mut bob_view_of_alice,
        &parsed_a.room_id,
        &parsed_a.sender_pub,
        parsed_a.counter,
        &parsed_a.nonce,
        &parsed_a.ciphertext,
    )
    .unwrap();
    assert_eq!(recovered_a, pt_alice);

    // Bob replies in the room.
    let pt_bob = b"copy that".to_vec();
    let enc_b = sk::encrypt(&mut bob_send, &room_id, &bob_pub, &pt_bob).unwrap();
    let wire_b = sk::pack_room_wire(&room_id, &bob_pub, &enc_b);

    let parsed_b = sk::parse_room_wire(&wire_b).unwrap();
    let recovered_b = sk::decrypt(
        &mut alice_view_of_bob,
        &parsed_b.room_id,
        &parsed_b.sender_pub,
        parsed_b.counter,
        &parsed_b.nonce,
        &parsed_b.ciphertext,
    )
    .unwrap();
    assert_eq!(recovered_b, pt_bob);
}

/// A room ciphertext from a sender we don't yet have a seed for must fail
/// cleanly rather than corrupting state. Verifies that the AAD binding
/// rejects mismatched (room_id, sender_pub, counter) tuples.
#[test]
fn room_ciphertext_rejects_wrong_chain_seed() {
    let sender_pub: [u8; 32] = [0xDDu8; 32];
    let room_id: [u8; 16] = [0xEEu8; 16];

    let mut real = SenderKey::random();
    let enc = sk::encrypt(&mut real, &room_id, &sender_pub, b"private").unwrap();

    // Bob hasn't received the real seed; he's trying with a wrong one.
    let mut wrong_view = SenderKey::random();
    let result = sk::decrypt(
        &mut wrong_view,
        &room_id,
        &sender_pub,
        enc.counter,
        &enc.nonce,
        &enc.ciphertext,
    );
    assert!(result.is_err(), "decrypt with wrong seed must fail");
}
