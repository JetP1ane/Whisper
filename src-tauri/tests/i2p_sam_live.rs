//! Integration tests against a *live* `i2pd` SAM bridge.
//!
//! These are gated behind the env var `WHISPER_I2PD_SAM_ADDR` (e.g.
//! `127.0.0.1:7656`). When unset, the tests fall back to `#[ignore]`-style
//! soft skips so `cargo test` still passes without an i2pd running.
//!
//! Recommended local run:
//!
//! ```sh
//! /opt/homebrew/opt/i2pd/bin/i2pd \
//!   --datadir=/tmp/i2pd-whisper-test \
//!   --conf=/tmp/i2pd-whisper-test/i2pd.conf \
//!   --daemon
//! # wait until SAM is listening
//! WHISPER_I2PD_SAM_ADDR=127.0.0.1:7656 \
//!   cargo test --test i2p_sam_live -- --nocapture
//! ```
//!
//! Each test is `#[tokio::test]` and times out after 60s — i2pd's first
//! tunnel build on a fresh datadir can take 30-45s, but subsequent builds
//! are 2-5s.

use noctis_whisper_desktop_lib::db::Database;
use noctis_whisper_desktop_lib::transport::i2p::{
    destination,
    sam::{self, default_session_options, SamReply},
};
use std::time::Duration;
use tokio::time::timeout;

fn sam_addr() -> Option<String> {
    std::env::var("WHISPER_I2PD_SAM_ADDR").ok()
}

/// Soft-skip helper: log + return early when no SAM addr is configured. We
/// don't `panic!("skipped")` because the harness would fail the test.
macro_rules! require_sam {
    () => {{
        match sam_addr() {
            Some(a) => a,
            None => {
                eprintln!(
                    "skipping: WHISPER_I2PD_SAM_ADDR unset (set to 127.0.0.1:7656 to enable)"
                );
                return;
            }
        }
    }};
}

#[tokio::test]
async fn hello_handshake_negotiates_a_version() {
    let addr = require_sam!();
    let mut buf = sam::connect(&addr).await.expect("connect SAM");
    let version = timeout(Duration::from_secs(10), sam::hello(&mut buf))
        .await
        .expect("HELLO timeout")
        .expect("HELLO failed");
    eprintln!("negotiated SAM version: {version}");
    // Bridge will pick something in [3.1, 3.3].
    assert!(
        version.starts_with("3."),
        "unexpected SAM version: {version}"
    );
}

#[tokio::test]
async fn mint_and_store_destination_round_trips_through_sqlite() {
    let addr = require_sam!();
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
        .expect("seed identity");

    // Mint via SAM — this is the actual i2pd round trip.
    let db_mu = parking_lot::Mutex::new(db);
    let minted = timeout(
        Duration::from_secs(20),
        destination::mint_and_store(&db_mu, &addr),
    )
    .await
    .expect("mint timeout")
    .expect("mint failed");
    assert!(minted.pub_b64.len() > 400, "PUB suspiciously short: {}", minted.pub_b64.len());
    assert!(minted.priv_b64.len() > 800, "PRIV suspiciously short: {}", minted.priv_b64.len());

    // Read it back from the row — round trip without any network.
    let loaded = {
        let g = db_mu.lock();
        destination::load(&g).unwrap().expect("destination present")
    };
    assert_eq!(loaded.pub_b64, minted.pub_b64);
    assert_eq!(loaded.priv_b64, minted.priv_b64);

    // load_or_mint should hit the existing row, not call the SAM bridge
    // (we test the cache by passing an obviously-bad address — if it
    // tried to hit the network it would error out).
    let cached = timeout(
        Duration::from_secs(2),
        destination::load_or_mint(&db_mu, "127.0.0.1:1"),
    )
    .await
    .expect("load_or_mint timeout")
    .expect("load_or_mint should hit cache");
    assert_eq!(cached.pub_b64, minted.pub_b64);
}

#[tokio::test]
async fn dest_generate_returns_pub_and_priv() {
    let addr = require_sam!();
    let (pub_b64, priv_b64) = timeout(Duration::from_secs(10), sam::dest_generate_oneshot(&addr))
        .await
        .expect("DEST GENERATE timeout")
        .expect("DEST GENERATE failed");
    assert!(!pub_b64.is_empty(), "PUB empty");
    assert!(!priv_b64.is_empty(), "PRIV empty");
    // The PRIV blob always starts with the same bytes as PUB (they share
    // the public destination prefix). It's the only sanity check we can
    // do without parsing the i2p destination format.
    assert!(
        priv_b64.starts_with(&pub_b64[..32.min(pub_b64.len())]),
        "PRIV does not contain PUB as prefix"
    );
    eprintln!("PUB: {} chars; PRIV: {} chars", pub_b64.len(), priv_b64.len());
}

/// End-to-end smoke test: stand up a STREAM session, then in the same
/// process open a STREAM ACCEPT and a STREAM CONNECT against ourselves
/// and exchange a few bytes.
///
/// **Why `#[ignore]` by default**: I2P self-loopback through a single
/// router fails with `CANT_REACH_PEER` until the encrypted leaseset
/// publishes to a floodfill peer — typically 30-90s on a fresh datadir,
/// and not always possible if the router doesn't have stable peers yet.
/// The realistic test fixture (Phase 12) spins up TWO i2pd instances on
/// the same host with cross-connected peer state and exchanges between
/// them. Run this test only when you've already verified the router
/// has built its leaseset:
///
/// ```sh
/// curl -s http://127.0.0.1:7070/?page=local_destinations | grep -q published
/// ```
#[tokio::test]
#[ignore = "self-loopback unreliable on single i2pd; see Phase 12 for two-router test"]
async fn loopback_self_send_round_trips_through_i2p() {
    let addr = require_sam!();

    // --- Session: build it on a long-lived control socket. The control
    // socket must stay open for the lifetime of the session — closing it
    // tears down the session in i2pd.
    let mut ctl = sam::connect(&addr).await.expect("connect SAM ctl");
    sam::hello(&mut ctl).await.expect("HELLO ctl");

    let session_id = format!("whisper-loopback-{}", std::process::id());
    let our_dest = timeout(
        Duration::from_secs(60),
        sam::session_create_stream(&mut ctl, &session_id, "TRANSIENT", &[]),
    )
    .await
    .expect("SESSION CREATE timeout (i2pd might still be reseeding)")
    .expect("SESSION CREATE failed");
    eprintln!("our destination: {} bytes b64", our_dest.len());

    // --- ACCEPT: spawn a task that takes the *next* inbound connection.
    // It echoes whatever it receives back to the sender and closes.
    let accept_addr = addr.clone();
    let accept_session = session_id.clone();
    let accept_task = tokio::spawn(async move {
        let (mut sock, peer_dest) =
            sam::stream_accept(&accept_addr, &accept_session)
                .await
                .expect("STREAM ACCEPT");
        eprintln!("accepted connection from peer ({} chars)", peer_dest.len());
        let buf = sam::read_to_cap(&mut sock, 4096)
            .await
            .expect("read after accept");
        eprintln!("accepted received {} bytes", buf.len());
        // Echo back so the connect side can verify two-way data flow.
        use tokio::io::AsyncWriteExt;
        sock.write_all(&buf).await.expect("echo back");
        sock.shutdown().await.ok();
        buf
    });

    // Give i2pd a moment to register the ACCEPT before we dial ourselves.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // --- CONNECT: dial our own destination from a fresh SAM socket and
    // send a test payload.
    let payload = b"hello-from-whisper-loopback\n";
    let mut conn_sock = timeout(
        Duration::from_secs(60),
        sam::stream_connect(&addr, &session_id, &our_dest),
    )
    .await
    .expect("STREAM CONNECT timeout")
    .expect("STREAM CONNECT failed");
    eprintln!("dialed self");

    use tokio::io::AsyncWriteExt;
    conn_sock.write_all(payload).await.expect("write payload");
    conn_sock.shutdown().await.ok();

    // Wait for accept side to finish + verify what it saw.
    let received = timeout(Duration::from_secs(30), accept_task)
        .await
        .expect("accept task timeout")
        .expect("accept task panicked");
    assert_eq!(
        received.as_slice(),
        payload,
        "accept side received unexpected payload"
    );

    // Read echoed bytes back on the connect side.
    let echoed = sam::read_to_cap(&mut conn_sock, 4096)
        .await
        .expect("read echo");
    assert_eq!(echoed.as_slice(), payload, "echo mismatch");

    drop(ctl); // tears down session
    let _ = SamReply { // silence unused warning if test compiles before all helpers used
        verb: String::new(),
        kv: Default::default(),
    };
    let _ = default_session_options();
}
