//! Multi-party room integration test.
//!
//! Stress-tests the room flow where some members have no prior pairwise
//! session, exactly the scenario users hit when an existing contact
//! invites two strangers into a group:
//!
//! ```text
//!   Alice ──── pairwise ──── Bob
//!     │
//!     └────── pairwise ──── Charlie
//!     │
//!     └────── pairwise ──── Dave
//!
//!   Bob ←────── ??? ──────→ Charlie    (no prior session)
//!   Bob ←────── ??? ──────→ Dave       (no prior session)
//!   Charlie ←── ??? ──────→ Dave       (no prior session)
//! ```
//!
//! Test asserts:
//!   1. Alice's RoomInvite reaches each invitee, payload decrypts.
//!   2. Each invitee generates a sender-key, shares it with every other
//!      member — including pairs with no pre-existing session, where they
//!      must bootstrap a fresh PQ-X3DH initiator session on the fly.
//!   3. Every member ends up with every other member's chain seed.
//!   4. Each member can encrypt a room message and every OTHER member can
//!      decrypt it — i.e., the sender-key broadcast is symmetric and
//!      complete.
//!
//! This catches regressions in:
//!   - the room invite envelope round-trip (covered by protocol.rs but
//!     re-asserted here in the multi-party harness)
//!   - sender-key fan-out completeness (every pair must share keys)
//!   - PQ-X3DH initiator/responder symmetry across multiple concurrent
//!     bootstraps
//!   - the room ciphertext wire dispatch + decrypt path

use noctis_whisper_desktop_lib::crypto::{
    bundle::{self, OneTimePrekeyPublic, PublicKeyBundle, SignedPrekeyPublic},
    keys::{
        derive_alias, generate_identity, generate_one_time_prekeys, generate_signed_prekey,
        IdentityKeys, OneTimePrekey, SignedPrekey,
    },
    message_crypto::{
        build_aad, build_room_invite_envelope, build_room_sender_key_envelope,
        decode_envelope, pack_text_wire, pad_pkcs7, parse_wire, unpad_pkcs7,
        DecodedEnvelope, RatchetWire,
    },
    pqx3dh::{self, InitiatorInputs, ResponderInputs},
    ratchet::{self, RatchetState},
    sender_key::{self as sk, SenderKey},
    PAD_BLOCK,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

// =====================================================================
// Test participant
// =====================================================================

struct Member {
    name: &'static str,
    keys: IdentityKeys,
    spk: SignedPrekey,
    otpks: Vec<OneTimePrekey>,
    bundle: PublicKeyBundle,
    /// Per-peer pairwise ratchet state, keyed by the peer's Ed25519 pubkey.
    pairwise: HashMap<[u8; 32], RatchetState>,
    /// My own room sender-key (chain advances as I encrypt).
    self_room_sk: Option<SenderKey>,
    /// Per-peer view of THEIR sender-key chain, keyed by their Ed25519
    /// pubkey. Advances as I decrypt their room messages.
    peer_room_sks: HashMap<[u8; 32], SenderKey>,
}

impl Member {
    fn new(name: &'static str) -> Self {
        let keys = generate_identity();
        let spk = generate_signed_prekey(1, &keys);
        let otpks = generate_one_time_prekeys(20, 1);
        let bundle = build_published_bundle(&keys, &spk, &otpks[0]);
        Self {
            name,
            keys,
            spk,
            otpks,
            bundle,
            pairwise: HashMap::new(),
            self_room_sk: None,
            peer_room_sks: HashMap::new(),
        }
    }

    fn pubkey(&self) -> [u8; 32] {
        self.keys.ed25519_verifying().to_bytes()
    }

    fn alias(&self) -> String {
        derive_alias(&self.pubkey())
    }
}

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
            kyber_pub: Vec::new(),
        },
        derive_alias(&keys.ed25519_verifying().to_bytes()),
        None,
        "wss://test.example.com/ws".into(),
        String::new(),
    )
}

// =====================================================================
// PQ-X3DH bootstrap helpers (initiator + responder)
// =====================================================================

/// `me` initiates a fresh PQ-X3DH session with `peer`, returning the
/// session-init bytes plus the resulting initial ratchet state.
fn initiate_pqx3dh(me: &IdentityKeys, peer_bundle: &PublicKeyBundle) -> (Vec<u8>, RatchetState) {
    let ek_alice = XStaticSecret::random_from_rng(OsRng);
    let ek_alice_pub = XPublicKey::from(&ek_alice);
    let spk_x_pub = XPublicKey::from(peer_bundle.signed_prekey.x25519_pub);
    let ik_b_x_pub = XPublicKey::from(peer_bundle.x25519_key);
    let otpk_x_pub = XPublicKey::from(peer_bundle.one_time_prekey.x25519_pub);
    let otpk_kyber_opt: Option<&[u8]> = if peer_bundle.one_time_prekey.kyber_pub.is_empty() {
        None
    } else {
        Some(&peer_bundle.one_time_prekey.kyber_pub)
    };
    let inputs = InitiatorInputs {
        ik_alice: &me.x25519_secret,
        ek_alice: &ek_alice,
        spk_bob_x25519: &spk_x_pub,
        ik_bob_x25519: &ik_b_x_pub,
        otpk_bob_x25519: &otpk_x_pub,
        spk_bob_mlkem_pub: &peer_bundle.signed_prekey.kyber_pub,
        otpk_bob_mlkem_pub: otpk_kyber_opt,
    };
    let out = pqx3dh::initiator_agree(inputs).expect("pqx3dh initiator");
    let initial_send_secret = XStaticSecret::random_from_rng(OsRng);
    let mut state = RatchetState::init_initiator(&out.master_secret, initial_send_secret);
    state.dh_recv_public = Some(peer_bundle.signed_prekey.x25519_pub);
    let dh = XStaticSecret::from(state.dh_send_secret).diffie_hellman(&spk_x_pub);
    let (new_root, new_chain) = ratchet::root_kdf(&state.root_key, dh.as_bytes()).unwrap();
    state.root_key = new_root;
    state.send_chain_key = Some(new_chain);

    let init_bytes = pqx3dh::pack_session_init(
        me.x25519_public().as_bytes(),
        ek_alice_pub.as_bytes(),
        &out.kem1_ciphertext,
        out.kem2_ciphertext.as_deref(),
        peer_bundle.one_time_prekey.id,
    );
    (init_bytes, state)
}

/// `me` is on the receiving end of `init_bytes` from `peer`. Reconstructs
/// the same master secret and returns a fresh responder ratchet state.
fn respond_pqx3dh(me: &Member, init_bytes: &[u8]) -> RatchetState {
    let parsed = parse_session_init(init_bytes);
    let ik_alice_x = XPublicKey::from(<[u8; 32]>::try_from(parsed.initiator_x25519_pub.as_slice()).unwrap());
    let ek_alice = XPublicKey::from(<[u8; 32]>::try_from(parsed.ek_alice.as_slice()).unwrap());
    let otpk = me
        .otpks
        .iter()
        .find(|o| o.id == parsed.used_otpk_id)
        .expect("otpk for responder");
    let kem2_opt = parsed.kem2_ciphertext.as_deref();
    let otpk_kyber_opt = if otpk.mlkem_secret.is_empty() {
        None
    } else {
        Some(otpk.mlkem_secret.as_slice())
    };
    let master = pqx3dh::responder_agree(ResponderInputs {
        ik_bob_x25519: &me.keys.x25519_secret,
        spk_bob_x25519: &me.spk.x25519_secret,
        spk_bob_mlkem_secret: &me.spk.mlkem_secret,
        otpk_bob_x25519: &otpk.x25519_secret,
        otpk_bob_mlkem_secret: otpk_kyber_opt,
        ik_alice_x25519_pub: &ik_alice_x,
        ek_alice_pub: &ek_alice,
        kem1_ciphertext: &parsed.kem1_ciphertext,
        kem2_ciphertext: kem2_opt,
    })
    .expect("responder_agree");
    let bob_spk_secret = XStaticSecret::from(
        <[u8; 32]>::try_from(me.spk.x25519_secret.to_bytes().as_slice()).unwrap(),
    );
    RatchetState::init_responder(&master, bob_spk_secret).expect("responder ratchet")
}

#[derive(Debug)]
struct ParsedInit {
    initiator_x25519_pub: Vec<u8>,
    ek_alice: Vec<u8>,
    kem1_ciphertext: Vec<u8>,
    kem2_ciphertext: Option<Vec<u8>>,
    used_otpk_id: u32,
}

fn parse_session_init(b: &[u8]) -> ParsedInit {
    let mut off = 0;
    let read_u32 = |b: &[u8], off: &mut usize| -> u32 {
        let v = u32::from_be_bytes(b[*off..*off + 4].try_into().unwrap());
        *off += 4;
        v
    };
    let read_field = |off: &mut usize| -> Vec<u8> {
        let len = read_u32(b, off) as usize;
        let v = b[*off..*off + len].to_vec();
        *off += len;
        v
    };
    let initiator_x25519_pub = read_field(&mut off);
    let ek_alice = read_field(&mut off);
    let kem1_ciphertext = read_field(&mut off);
    let kem2_field = read_field(&mut off);
    let kem2_ciphertext = if kem2_field.is_empty() {
        None
    } else {
        Some(kem2_field)
    };
    let used_otpk_id = read_u32(b, &mut off);
    ParsedInit {
        initiator_x25519_pub,
        ek_alice,
        kem1_ciphertext,
        kem2_ciphertext,
        used_otpk_id,
    }
}

// =====================================================================
// Pairwise envelope helpers
// =====================================================================

/// Encrypt a fully-padded envelope under `me`'s ratchet to `peer`. Returns
/// the wire bytes (4096-byte text wire, no first-message wrapper).
fn pairwise_encrypt(me_state: &mut RatchetState, envelope: &[u8]) -> Vec<u8> {
    let padded = pad_pkcs7(envelope, PAD_BLOCK);
    let enc = ratchet::encrypt_message(me_state, &padded, build_aad).unwrap();
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

/// Decrypt a 4096-byte text wire under `me`'s pairwise ratchet to peer.
fn pairwise_decrypt(me_state: &mut RatchetState, wire: &[u8]) -> DecodedEnvelope {
    let parsed = parse_wire(wire).unwrap();
    let plaintext_padded = ratchet::decrypt_message(
        me_state,
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

/// Establish bidirectional pairwise sessions for `(initiator, responder)`.
/// After this, both ends can encrypt + decrypt to each other.
fn establish_pairwise(initiator: &mut Member, responder: &mut Member) {
    let r_pub = responder.pubkey();
    let i_pub = initiator.pubkey();

    // initiator -> responder
    let (init_bytes, init_state) = initiate_pqx3dh(&initiator.keys, &responder.bundle);
    initiator.pairwise.insert(r_pub, init_state);

    // responder reconstructs from init_bytes
    let resp_state = respond_pqx3dh(responder, &init_bytes);
    responder.pairwise.insert(i_pub, resp_state);

    // Send a kickoff message from initiator → responder so the responder's
    // send chain spins up (responder's send chain only initializes on
    // first decrypt of an initiator message — DH ratchet step).
    let env = build_room_sender_key_envelope(0, &[0u8; 16], &[0u8; 32]);
    // We don't actually use this — the kickoff just primes the ratchet.
    let init_state = initiator.pairwise.get_mut(&r_pub).unwrap();
    let wire = pairwise_encrypt(init_state, &env);
    let resp_state = responder.pairwise.get_mut(&i_pub).unwrap();
    let _ = pairwise_decrypt(resp_state, &wire);
}

// =====================================================================
// Room flow simulation
// =====================================================================

const ROOM_ID: [u8; 16] = [0x42u8; 16];
const ROOM_NAME: &str = "stress-test-room";

/// Simulate the full multi-party invite + sender-key broadcast flow.
/// `owner` invites every member in `others`; this function handles the
/// owner's send + each recipient's processing + the reciprocal sender-key
/// shares (including pairs that need fresh PQ-X3DH bootstraps).
fn simulate_room_create(owner: &mut Member, others: &mut [&mut Member]) {
    // 1. Owner generates sender key.
    owner.self_room_sk = Some(SenderKey::random());
    let owner_seed = owner.self_room_sk.as_ref().unwrap().chain_seed();
    let owner_pub = owner.pubkey();

    // 2. Build member pubkey list.
    let mut all_pubkeys = vec![owner_pub];
    for o in others.iter() {
        all_pubkeys.push(o.pubkey());
    }

    // 3. Owner sends a RoomInvite envelope to every other member via the
    //    pairwise ratchet established above.
    for member in others.iter_mut() {
        let envelope = build_room_invite_envelope(
            0,
            &ROOM_ID,
            ROOM_NAME,
            "",
            &owner_seed,
            &all_pubkeys,
        )
        .unwrap();
        let wire = {
            let s = owner.pairwise.get_mut(&member.pubkey()).expect("owner pairwise");
            pairwise_encrypt(s, &envelope)
        };
        let decoded = {
            let s = member.pairwise.get_mut(&owner_pub).expect("member pairwise");
            pairwise_decrypt(s, &wire)
        };
        match decoded {
            DecodedEnvelope::RoomInvite {
                owner_chain_seed,
                member_pubkeys,
                ..
            } => {
                assert_eq!(owner_chain_seed, owner_seed);
                // Recipient learns the owner's seed.
                member
                    .peer_room_sks
                    .insert(owner_pub, SenderKey::from_seed(owner_chain_seed));
                // Recipient learns the member list (we'll iterate to share
                // our key with each non-self, non-owner peer below).
                let _ = member_pubkeys;
            }
            other => panic!("expected RoomInvite, got {:?}", other),
        }
        // Recipient generates their own sender key for the room.
        member.self_room_sk = Some(SenderKey::random());
    }

    // 4. Owner receives back each member's sender-key seed via pairwise.
    for member in others.iter_mut() {
        let my_seed = member.self_room_sk.as_ref().unwrap().chain_seed();
        let envelope = build_room_sender_key_envelope(0, &ROOM_ID, &my_seed);
        let wire = {
            let s = member.pairwise.get_mut(&owner_pub).expect("member pairwise");
            pairwise_encrypt(s, &envelope)
        };
        let decoded = {
            let s = owner.pairwise.get_mut(&member.pubkey()).expect("owner pairwise");
            pairwise_decrypt(s, &wire)
        };
        match decoded {
            DecodedEnvelope::RoomSenderKey { chain_seed, .. } => {
                assert_eq!(chain_seed, my_seed);
                owner
                    .peer_room_sks
                    .insert(member.pubkey(), SenderKey::from_seed(chain_seed));
            }
            other => panic!("expected RoomSenderKey, got {:?}", other),
        }
    }

    // 5. Each pair of NON-OWNER members must share their sender-key seeds
    //    with each other. They have NO prior pairwise session, so they
    //    bootstrap a fresh PQ-X3DH session on the fly — this is the
    //    "auto-bootstrap unknown room peer" path in production.
    // Role-split: only the smaller-pubkey side initiates. The larger-pubkey
    // side persists the contact and waits for the initiator's first-message
    // wrapper, then reciprocates with their own seed via the now-established
    // pairwise ratchet. This mirrors `bootstrap_unknown_room_peers` +
    // `reciprocate_sender_key` in production.
    let n = others.len();
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            // Only the smaller-pubkey side initiates the bootstrap.
            if others[i].pubkey().as_slice() >= others[j].pubkey().as_slice() {
                continue;
            }

            let sender_pub = others[i].pubkey();
            let sender_seed = others[i].self_room_sk.as_ref().unwrap().chain_seed();
            let peer_pub = others[j].pubkey();
            let peer_bundle = others[j].bundle.clone();

            // Initiator → responder: PQ-X3DH bootstrap + first-message
            // wrapped RoomSenderKey envelope.
            let (init_bytes, init_state) = initiate_pqx3dh(&others[i].keys, &peer_bundle);
            others[i].pairwise.insert(peer_pub, init_state);
            let envelope = build_room_sender_key_envelope(0, &ROOM_ID, &sender_seed);
            let inner_wire = {
                let s = others[i].pairwise.get_mut(&peer_pub).unwrap();
                pairwise_encrypt(s, &envelope)
            };
            let wrapped = pqx3dh::pack_first_message(&init_bytes, &inner_wire);

            // Responder receives, bootstraps responder, decrypts, stores
            // initiator's seed.
            let peer_state = respond_pqx3dh(&others[j], &init_bytes);
            let init_len = u32::from_be_bytes(wrapped[..4].try_into().unwrap()) as usize;
            let inner = wrapped[4 + init_len..].to_vec();
            others[j].pairwise.insert(sender_pub, peer_state);
            {
                let s = others[j].pairwise.get_mut(&sender_pub).unwrap();
                let decoded = pairwise_decrypt(s, &inner);
                match decoded {
                    DecodedEnvelope::RoomSenderKey { chain_seed, .. } => {
                        others[j]
                            .peer_room_sks
                            .insert(sender_pub, SenderKey::from_seed(chain_seed));
                    }
                    other => panic!("expected RoomSenderKey, got {:?}", other),
                }
            }

            // Reciprocation: responder shares their seed back via the
            // now-established pairwise ratchet (subsequent ratchet message,
            // not first-message-wrapped).
            let resp_seed = others[j].self_room_sk.as_ref().unwrap().chain_seed();
            let resp_envelope = build_room_sender_key_envelope(0, &ROOM_ID, &resp_seed);
            let resp_wire = {
                let s = others[j].pairwise.get_mut(&sender_pub).unwrap();
                pairwise_encrypt(s, &resp_envelope)
            };
            {
                let s = others[i].pairwise.get_mut(&peer_pub).unwrap();
                let decoded = pairwise_decrypt(s, &resp_wire);
                match decoded {
                    DecodedEnvelope::RoomSenderKey { chain_seed, .. } => {
                        others[i]
                            .peer_room_sks
                            .insert(peer_pub, SenderKey::from_seed(chain_seed));
                    }
                    other => panic!("expected RoomSenderKey reciprocation, got {:?}", other),
                }
            }
        }
    }
}

/// Have `sender` encrypt a room message; assert every other listed peer
/// can decrypt it via their stored sender-key seed for `sender`.
fn assert_broadcast(
    sender: &mut Member,
    listeners: &mut [&mut Member],
    plaintext: &str,
) {
    let sender_pub = sender.pubkey();
    let sk_state = sender.self_room_sk.as_mut().unwrap();
    let enc = sk::encrypt(sk_state, &ROOM_ID, &sender_pub, plaintext.as_bytes()).unwrap();
    let wire = sk::pack_room_wire(&ROOM_ID, &sender_pub, &enc);

    for l in listeners.iter_mut() {
        let parsed = sk::parse_room_wire(&wire).unwrap();
        let view = l
            .peer_room_sks
            .get_mut(&sender_pub)
            .unwrap_or_else(|| panic!("{}: no stored sender-key for {}", l.name, sender.name));
        let recovered = sk::decrypt(
            view,
            &parsed.room_id,
            &parsed.sender_pub,
            parsed.counter,
            &parsed.nonce,
            &parsed.ciphertext,
        )
        .unwrap_or_else(|e| {
            panic!("{} failed to decrypt {}'s room msg: {e}", l.name, sender.name)
        });
        assert_eq!(
            recovered,
            plaintext.as_bytes(),
            "{} got wrong plaintext for {}'s msg",
            l.name,
            sender.name
        );
    }
}

// =====================================================================
// Tests
// =====================================================================

#[test]
fn three_party_room_with_no_prior_bob_charlie_session() {
    // Alice has prior pairwise sessions with Bob and Charlie.
    // Bob and Charlie have NEVER exchanged direct messages.
    let mut alice = Member::new("alice");
    let mut bob = Member::new("bob");
    let mut charlie = Member::new("charlie");

    establish_pairwise(&mut alice, &mut bob);
    establish_pairwise(&mut alice, &mut charlie);

    // Critical assertion: Bob and Charlie do NOT have a pairwise session
    // before the room is created.
    assert!(bob.pairwise.get(&charlie.pubkey()).is_none());
    assert!(charlie.pairwise.get(&bob.pubkey()).is_none());

    // Simulate the full room flow: Alice invites both, members exchange
    // sender-keys including across the unknown Bob<->Charlie pair.
    {
        let mut others: Vec<&mut Member> = vec![&mut bob, &mut charlie];
        simulate_room_create(&mut alice, &mut others);
    }

    // After the flow, Bob and Charlie now DO have a pairwise session
    // because the auto-bootstrap path established one for the
    // sender-key share.
    assert!(bob.pairwise.get(&charlie.pubkey()).is_some());
    assert!(charlie.pairwise.get(&bob.pubkey()).is_some());

    // Every member has every other member's sender-key seed.
    for me in [&alice, &bob, &charlie] {
        for other in [&alice, &bob, &charlie] {
            if me.pubkey() == other.pubkey() {
                continue;
            }
            assert!(
                me.peer_room_sks.contains_key(&other.pubkey()),
                "{} missing sender-key for {}",
                me.name,
                other.name
            );
        }
    }

    // Bob's room message reaches Alice AND Charlie.
    {
        let mut listeners: Vec<&mut Member> = vec![&mut alice, &mut charlie];
        assert_broadcast(&mut bob, &mut listeners, "hi from bob");
    }

    // Charlie's room message reaches Alice AND Bob — including Bob, who
    // had no prior pairwise session with Charlie before the auto-bootstrap.
    {
        let mut listeners: Vec<&mut Member> = vec![&mut alice, &mut bob];
        assert_broadcast(&mut charlie, &mut listeners, "hi from charlie");
    }

    // Alice's room message reaches Bob AND Charlie.
    {
        let mut listeners: Vec<&mut Member> = vec![&mut bob, &mut charlie];
        assert_broadcast(&mut alice, &mut listeners, "hi from alice");
    }
}

#[test]
fn five_party_room_full_mesh() {
    // Stress test: alice invites 4 strangers. Every pair other than
    // alice<->X needs an on-the-fly bootstrap.
    let mut alice = Member::new("alice");
    let mut bob = Member::new("bob");
    let mut charlie = Member::new("charlie");
    let mut dave = Member::new("dave");
    let mut eve = Member::new("eve");

    establish_pairwise(&mut alice, &mut bob);
    establish_pairwise(&mut alice, &mut charlie);
    establish_pairwise(&mut alice, &mut dave);
    establish_pairwise(&mut alice, &mut eve);

    {
        let mut others: Vec<&mut Member> = vec![&mut bob, &mut charlie, &mut dave, &mut eve];
        simulate_room_create(&mut alice, &mut others);
    }

    // Every pair has a sender-key for the other.
    for a in [&alice, &bob, &charlie, &dave, &eve] {
        for b in [&alice, &bob, &charlie, &dave, &eve] {
            if a.pubkey() == b.pubkey() {
                continue;
            }
            assert!(
                a.peer_room_sks.contains_key(&b.pubkey()),
                "{} missing sender-key for {}",
                a.name,
                b.name
            );
        }
    }

    // Pick a non-owner sender (dave) and assert every other member can
    // decrypt — exercises the longest auto-bootstrap chains.
    {
        let mut listeners: Vec<&mut Member> =
            vec![&mut alice, &mut bob, &mut charlie, &mut eve];
        assert_broadcast(&mut dave, &mut listeners, "hello from dave");
    }
}

#[test]
fn unknown_chain_seed_decrypt_fails_gracefully() {
    // If a member somehow ends up with the wrong seed for a peer (e.g.
    // a malicious relay swapped a sender-key share), decrypt must fail
    // cleanly rather than producing garbage plaintext.
    let mut alice = Member::new("alice");
    let mut bob = Member::new("bob");
    let mut charlie = Member::new("charlie");

    establish_pairwise(&mut alice, &mut bob);
    establish_pairwise(&mut alice, &mut charlie);
    {
        let mut others: Vec<&mut Member> = vec![&mut bob, &mut charlie];
        simulate_room_create(&mut alice, &mut others);
    }

    // Charlie tampers with his stored view of Bob's chain seed.
    let bob_pub = bob.pubkey();
    *charlie.peer_room_sks.get_mut(&bob_pub).unwrap() = SenderKey::random();

    // Bob sends a room message; Charlie's tampered view must reject it.
    let bob_pub2 = bob.pubkey();
    let sk_state = bob.self_room_sk.as_mut().unwrap();
    let enc = sk::encrypt(sk_state, &ROOM_ID, &bob_pub2, b"private").unwrap();
    let wire = sk::pack_room_wire(&ROOM_ID, &bob_pub2, &enc);
    let parsed = sk::parse_room_wire(&wire).unwrap();
    let result = sk::decrypt(
        charlie.peer_room_sks.get_mut(&bob_pub2).unwrap(),
        &parsed.room_id,
        &parsed.sender_pub,
        parsed.counter,
        &parsed.nonce,
        &parsed.ciphertext,
    );
    assert!(result.is_err(), "wrong seed must produce AEAD failure");
}
