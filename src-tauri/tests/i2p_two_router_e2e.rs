//! Two-router end-to-end test.
//!
//! Spins up two independent `I2PManager`s (each with its own datadir,
//! SAM port, and destination), then:
//!
//! 1. Has router B listen for inbound frames via `ConnectionManager::
//!    run_inbound`, recording every frame it sees into a channel.
//! 2. Has router A `send_blob` a `Message` frame to B's destination.
//! 3. Asserts B's accept loop saw the frame and that the payload bytes
//!    matched what A sent.
//!
//! Gated behind `WHISPER_I2P_E2E=1` because:
//!   - It depends on the live I2P network (both routers need to find
//!     floodfill peers and publish their encrypted leasesets).
//!   - First-run reseed + tunnel build can take 60-120 seconds per
//!     router, so the wall clock can stretch past three minutes.
//!   - It uses real bandwidth.
//!
//! Run locally with:
//!
//! ```sh
//! WHISPER_I2P_E2E=1 cargo test --test i2p_two_router_e2e -- --nocapture
//! ```

use noctis_whisper_desktop_lib::db::Database;
use noctis_whisper_desktop_lib::transport::i2p::{
    connection::ConnectionManager,
    framing::{Frame, FrameType},
    manager::{I2PManager, I2pConfig},
    runtime::FrameDispatcher,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

fn enabled() -> bool {
    std::env::var("WHISPER_I2P_E2E").as_deref() == Ok("1")
}

/// Build a fresh DB with the schema and a stub identity row, returning
/// the `Database` ready to be passed to `I2PManager::start`.
fn fresh_db_for_router(profile_dir: &std::path::Path) -> Database {
    std::fs::create_dir_all(profile_dir).unwrap();
    let db = Database::open_in_memory_for_tests();
    noctis_whisper_desktop_lib::db::schema::apply(&db.conn).expect("schema");
    db.conn
        .execute(
            "INSERT INTO identity
                (id, ed25519_public, ed25519_secret, x25519_public, x25519_secret,
                 mlkem_public, mlkem_secret, alias, display_name, created_at)
             VALUES ('self', x'', x'', x'', x'', x'', x'', 't-e-st', NULL, 0)",
            [],
        )
        .unwrap();
    db
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_to_bob_message_round_trips() {
    if !enabled() {
        eprintln!("skipping: set WHISPER_I2P_E2E=1 to run");
        return;
    }

    let alice_dir = std::env::temp_dir().join(format!(
        "whisper-i2p-e2e-alice-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let bob_dir = std::env::temp_dir().join(format!(
        "whisper-i2p-e2e-bob-{}",
        uuid::Uuid::new_v4().simple()
    ));

    let alice_db = fresh_db_for_router(&alice_dir);
    let bob_db = fresh_db_for_router(&bob_dir);

    eprintln!("== starting alice's i2pd ==");
    let alice_mgr = Arc::new(
        timeout(
            Duration::from_secs(180),
            I2PManager::start(alice_db, I2pConfig {
                profile_dir: alice_dir.clone(),
                enable_transit: false,
            }),
        )
        .await
        .expect("alice start timeout")
        .expect("alice start failed"),
    );

    eprintln!("== starting bob's i2pd ==");
    let bob_mgr = Arc::new(
        timeout(
            Duration::from_secs(180),
            I2PManager::start(bob_db, I2pConfig {
                profile_dir: bob_dir.clone(),
                enable_transit: false,
            }),
        )
        .await
        .expect("bob start timeout")
        .expect("bob start failed"),
    );

    let alice_dest = alice_mgr.destination_pub().to_string();
    let bob_dest = bob_mgr.destination_pub().to_string();
    eprintln!("alice dest: {}…", &alice_dest[..32]);
    eprintln!("bob   dest: {}…", &bob_dest[..32]);

    // Bob's inbound: log every frame into a channel so the test can
    // observe it.
    let bob_conn = Arc::new(ConnectionManager::new(&bob_mgr));
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, Frame)>();
    let dispatcher: FrameDispatcher = Arc::new(move |peer_dest, frame| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send((peer_dest, frame));
            Ok(())
        })
    });
    bob_conn
        .run_inbound(dispatcher)
        .await
        .expect("bob inbound start");

    // Alice's outbound.
    let alice_conn = Arc::new(ConnectionManager::new(&alice_mgr));

    // Encrypted leasesets need a few seconds to publish to floodfill
    // peers before the first dial will succeed. Give the network
    // some breathing room.
    eprintln!("waiting 20s for leasesets to publish…");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // Try sending with retries — the first dial often fails with
    // CANT_REACH_PEER until enough floodfills have B's leaseset.
    let payload = b"NoctisWhisper:E2E:hello-from-alice".to_vec();
    let mut sent = false;
    for attempt in 1..=10 {
        eprintln!("== alice → bob send attempt {} ==", attempt);
        match alice_conn
            .send_blob(&bob_dest, FrameType::Message, &payload)
            .await
        {
            Ok(()) => {
                eprintln!("  send OK");
                sent = true;
                break;
            }
            Err(e) => {
                eprintln!("  send failed: {e}; retrying in 10s");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
    assert!(sent, "alice could not reach bob after 10 attempts");

    // Bob's accept loop should have written the frame into rx by now.
    let received = timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("rx.recv timeout — frame did not arrive at bob")
        .expect("rx closed unexpectedly");
    let (peer_dest_seen, frame) = received;

    eprintln!("bob received {} bytes from {}…", frame.payload.len(), &peer_dest_seen[..32]);
    assert_eq!(frame.kind, FrameType::Message, "wrong frame type");
    assert_eq!(frame.payload, payload, "payload bytes mismatch");
    assert_eq!(peer_dest_seen, alice_dest, "peer destination mismatch");

    // Cleanup.
    bob_conn.shutdown_inbound().await;
    drop(alice_conn);
    drop(bob_conn);
    if let Ok(m) = Arc::try_unwrap(alice_mgr) {
        let _ = m.shutdown().await;
    }
    if let Ok(m) = Arc::try_unwrap(bob_mgr) {
        let _ = m.shutdown().await;
    }
    let _ = std::fs::remove_dir_all(&alice_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
}
