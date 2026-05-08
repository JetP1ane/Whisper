//! End-to-end test of the room sender-key ACK gate, exercised entirely
//! through the production DB helpers. Regression coverage for the
//! "owner receives all messages but members can't see each other"
//! class of bugs.
//!
//! What this test simulates:
//!   1. Alice creates a room, inserts owner-side state.
//!   2. Alice sends an invite to Bob. Bob persists owner row + ACKs.
//!   3. Bob spawns a sender-key share to Alice. Alice persists Bob's
//!      seed onto the existing pending row + records Bob's ACK back.
//!   4. The same dance for Carol.
//!   5. Bob ↔ Carol cross-share their sender-keys.
//!
//! After every transition the test inspects the room_members table
//! directly to confirm:
//!   - sender_key columns hold the right per-peer seed,
//!   - peer_acked_my_key_at is set in the correct direction,
//!   - the column is NEVER wiped by a subsequent add_room_member call
//!     (the regression that broke real-world rooms),
//!   - room_send's gate (peer_has_acked_my_key) returns true exactly
//!     when fan-out should be unblocked,
//!   - room_pending_fanout buffers and drains in the right order.
//!
//! No I2P, no Tauri, no actual encryption — the gate's job is to
//! decide *whether* to send, not to send. If the state-machine logic
//! is sound, the production fan-out code wraps it correctly.

use noctis_whisper_desktop_lib::db::rooms::RoomMember;
use noctis_whisper_desktop_lib::db::Database;
use noctis_whisper_desktop_lib::messaging::room_keys;
use rusqlite::params;

fn fresh() -> Database {
    let db = Database::open_in_memory_for_tests();
    noctis_whisper_desktop_lib::db::schema::apply(&db.conn).expect("schema");
    db
}

fn seed_room(db: &Database, room_id: &str, members: &[(&str, &str)]) {
    db.conn
        .execute(
            "INSERT INTO conversations (id, type, created_at) VALUES (?1, 'room', 0)",
            params![room_id],
        )
        .unwrap();
    for (cid, alias) in members {
        db.conn
            .execute(
                "INSERT INTO contacts
                    (id, alias, ed25519_public, x25519_public, mlkem_public,
                     created_at, updated_at)
                 VALUES (?1, ?2, x'', x'', x'', 0, 0)",
                params![cid, alias],
            )
            .unwrap();
    }
}

fn member_row(db: &Database, room_id: &str, contact_id: &str) -> Option<RoomMember> {
    db.room_member(room_id, contact_id).unwrap()
}

fn ack_ts(db: &Database, room_id: &str, contact_id: &str) -> Option<i64> {
    db.conn
        .query_row(
            "SELECT peer_acked_my_key_at FROM room_members
             WHERE room_id = ?1 AND contact_id = ?2",
            params![room_id, contact_id],
            |r| r.get::<_, Option<i64>>(0),
        )
        .ok()
        .flatten()
}

#[test]
fn three_party_room_gate_walks_to_full_unblock() {
    let room = "room-3p";

    // Each participant has their own DB. The test pretends each one
    // is a separate process; we drive the state transitions directly.
    let alice = fresh();
    let bob = fresh();
    let carol = fresh();
    seed_room(&alice, room, &[("bob", "bob"), ("carol", "carol")]);
    seed_room(&bob, room, &[("alice", "alice"), ("carol", "carol")]);
    seed_room(&carol, room, &[("alice", "alice"), ("bob", "bob")]);

    // ---- Step 1: Alice creates the room. Stores her own seed and
    //              inserts pending placeholders for Bob and Carol. ----
    let alice_seed = vec![0xA1u8; 32];
    alice
        .put_self_room_key(room, &alice_seed)
        .unwrap();
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 0,
        })
        .unwrap();
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "carol".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 0,
        })
        .unwrap();

    // Alice has her own seed, no peer ACKs yet. Her room_send should
    // see both peers as gated.
    assert!(!room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap());
    assert!(!room_keys::peer_has_acked_my_key(&alice, room, "carol").unwrap());

    // ---- Step 2: Bob receives the RoomInvite. Persists alice's seed
    //              from owner_chain_seed, sets up his own self-seed. ----
    let bob_seed = vec![0xB1u8; 32];
    let alice_seed_copy = alice_seed.clone();
    bob.put_self_room_key(room, &bob_seed).unwrap();
    bob.add_room_member(&RoomMember {
        room_id: room.into(),
        contact_id: "alice".into(),
        role: "owner".into(),
        sender_key: Some(alice_seed_copy.clone()),
        joined_at: 1,
    })
    .unwrap();
    // Bob also persists carol from the inline bundle.
    bob.add_room_member(&RoomMember {
        room_id: room.into(),
        contact_id: "carol".into(),
        role: "member".into(),
        sender_key: None,
        joined_at: 1,
    })
    .unwrap();

    // ---- Step 3: Bob fires a RoomSenderKeyAck back to Alice. This is
    //              the new behaviour added to handle_room_invite — the
    //              owner's seed travels in the invite, so the only ACK
    //              signal she gets is this explicit one. Without it,
    //              Alice's gate for Bob never opens. ----
    room_keys::mark_peer_acked_my_key(&alice, room, "bob", 100).unwrap();

    // Alice's gate for Bob is now armed; Carol's still not.
    assert!(room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap());
    assert!(!room_keys::peer_has_acked_my_key(&alice, room, "carol").unwrap());

    // ---- Step 4: Carol does the same as Bob. ----
    let carol_seed = vec![0xC1u8; 32];
    carol.put_self_room_key(room, &carol_seed).unwrap();
    carol
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "alice".into(),
            role: "owner".into(),
            sender_key: Some(alice_seed.clone()),
            joined_at: 2,
        })
        .unwrap();
    carol
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 2,
        })
        .unwrap();
    // Carol → Alice ACK.
    room_keys::mark_peer_acked_my_key(&alice, room, "carol", 110).unwrap();

    // Alice's gate is now fully open in both directions.
    assert!(room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap());
    assert!(room_keys::peer_has_acked_my_key(&alice, room, "carol").unwrap());

    // ---- Step 5: Bob's RoomSenderKey envelope arrives at Alice. She
    //              persists his seed onto the existing pending row.
    //              CRITICAL: this must NOT wipe peer_acked_my_key_at. ----
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: Some(bob_seed.clone()),
            joined_at: 200,
        })
        .unwrap();
    // Alice now has Bob's seed.
    let row = member_row(&alice, room, "bob").unwrap();
    assert_eq!(row.sender_key, Some(bob_seed.clone()));
    // ACK timestamp survived.
    assert_eq!(ack_ts(&alice, room, "bob"), Some(100));

    // Bob's ACK to Alice is implied by his sending the RoomSenderKey,
    // but the production code uses an explicit ack envelope. We model
    // it the same way: Alice fires an ack back when receiving the seed,
    // but for Alice's gate logic the relevant ack is the one she
    // already received in step 3.
    room_keys::mark_peer_acked_my_key(&bob, room, "alice", 210).unwrap();
    assert!(room_keys::peer_has_acked_my_key(&bob, room, "alice").unwrap());

    // ---- Step 6: Bob's RoomSenderKey reaches Carol via X3DH first
    //              message. Carol persists Bob's seed on the existing
    //              pending row, fires back the ACK. ----
    carol
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: Some(bob_seed.clone()),
            joined_at: 220,
        })
        .unwrap();
    room_keys::mark_peer_acked_my_key(&bob, room, "carol", 230).unwrap();
    assert!(room_keys::peer_has_acked_my_key(&bob, room, "carol").unwrap());

    // ---- Step 7: Carol's RoomSenderKey reaches Bob. Bob persists
    //              Carol's seed; the ACK timestamp Carol already wrote
    //              to her own state for Bob (step 4) survives. ----
    bob.add_room_member(&RoomMember {
        room_id: room.into(),
        contact_id: "carol".into(),
        role: "member".into(),
        sender_key: Some(carol_seed.clone()),
        joined_at: 240,
    })
    .unwrap();
    room_keys::mark_peer_acked_my_key(&carol, room, "bob", 250).unwrap();
    assert!(room_keys::peer_has_acked_my_key(&carol, room, "bob").unwrap());

    // ---- Step 8: Carol's RoomSenderKey also reaches Alice (the owner
    //              gets sender-keys from every member). Alice persists
    //              Carol's seed onto her existing pending row. ----
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "carol".into(),
            role: "member".into(),
            sender_key: Some(carol_seed.clone()),
            joined_at: 260,
        })
        .unwrap();
    // Alice's ACK to Carol — Carol's gate for Alice arms.
    room_keys::mark_peer_acked_my_key(&carol, room, "alice", 270).unwrap();
    assert_eq!(ack_ts(&alice, room, "carol"), Some(110));
    assert!(room_keys::peer_has_acked_my_key(&carol, room, "alice").unwrap());

    // Final invariants: every participant has a populated sender-key
    // for every other participant in their room_members table, and
    // every gate is open (or, for the owner who never receives a
    // RoomSenderKey envelope from an invitee for HER seed, the gate
    // is opened explicitly by the invite-side ACK).
    assert!(member_row(&alice, room, "bob").unwrap().sender_key.is_some());
    assert!(member_row(&alice, room, "carol").unwrap().sender_key.is_some());
    assert!(member_row(&bob, room, "alice").unwrap().sender_key.is_some());
    assert!(member_row(&bob, room, "carol").unwrap().sender_key.is_some());
    assert!(member_row(&carol, room, "alice").unwrap().sender_key.is_some());
    assert!(member_row(&carol, room, "bob").unwrap().sender_key.is_some());

    // Every gate is open.
    for (db, room_id, peer) in [
        (&alice, room, "bob"),
        (&alice, room, "carol"),
        (&bob, room, "alice"),
        (&bob, room, "carol"),
        (&carol, room, "alice"),
        (&carol, room, "bob"),
    ] {
        assert!(
            room_keys::peer_has_acked_my_key(db, room_id, peer).unwrap(),
            "gate not armed for {} → {}",
            room_id,
            peer
        );
    }
}

#[test]
fn pending_fanout_unblocks_on_ack() {
    // Alice tries to send a room message to Bob before Bob has ACKed.
    // The production code path enqueues the blob in room_pending_fanout
    // and drains it when the ACK arrives. Verify drain returns the
    // exact bytes in the right order.
    let alice = fresh();
    let room = "room-buf";
    seed_room(&alice, room, &[("bob", "bob")]);
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 0,
        })
        .unwrap();
    // Bob has not ACKed — gate is closed.
    assert!(!room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap());

    // Alice's room_send buffers blobs.
    alice
        .enqueue_room_pending_fanout("q1", room, "bob", "msg-1", b"hello", 1)
        .unwrap();
    alice
        .enqueue_room_pending_fanout("q2", room, "bob", "msg-2", b"world", 2)
        .unwrap();

    // ACK arrives. Gate opens. Drain in order.
    room_keys::mark_peer_acked_my_key(&alice, room, "bob", 5).unwrap();
    assert!(room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap());
    let drained = alice.drain_room_pending_fanout(room, "bob").unwrap();
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].0, "msg-1");
    assert_eq!(drained[0].1, b"hello");
    assert_eq!(drained[1].0, "msg-2");
    assert_eq!(drained[1].1, b"world");
}

#[test]
fn owner_gate_arms_only_via_explicit_ack_not_via_member_seed_arrival() {
    // This test pins the bug we just fixed: the owner's seed travels
    // inline in the RoomInvite, so the invitee never sends a
    // RoomSenderKey envelope for it. The owner therefore never gets
    // an ACK *unless* the invitee fires a separate RoomSenderKeyAck
    // on invite receipt.
    //
    // We simulate the broken path (no invite-side ACK) and verify the
    // gate stays closed even after the invitee's RoomSenderKey arrives
    // with their own seed — proving the explicit ACK is the only thing
    // that arms the owner's gate.
    let alice = fresh();
    let room = "room-owner-gate";
    seed_room(&alice, room, &[("bob", "bob")]);
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 0,
        })
        .unwrap();

    // Bob's RoomSenderKey arrives. Alice persists his seed.
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: Some(vec![0xBB; 32]),
            joined_at: 100,
        })
        .unwrap();
    // Without the invite-side ACK from Bob, the gate must stay closed.
    assert!(
        !room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap(),
        "owner's gate must NOT arm just because the member's seed arrived"
    );

    // The explicit ACK fires the gate open.
    room_keys::mark_peer_acked_my_key(&alice, room, "bob", 200).unwrap();
    assert!(room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap());

    // Belt-and-suspenders: a second add_room_member (e.g. a re-broadcast
    // of bob's seed) must not silently re-close the gate.
    alice
        .add_room_member(&RoomMember {
            room_id: room.into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: Some(vec![0xBB; 32]),
            joined_at: 300,
        })
        .unwrap();
    assert!(
        room_keys::peer_has_acked_my_key(&alice, room, "bob").unwrap(),
        "ACK timestamp must survive a subsequent add_room_member"
    );
}
