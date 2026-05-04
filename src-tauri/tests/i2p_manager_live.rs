//! Live I2PManager integration test.
//!
//! Unlike `i2p_sam_live.rs`, this test does NOT require a pre-running
//! i2pd. It spins up its own subprocess via the manager, waits for SAM
//! readiness, and tears it down. It's the realistic shape of what
//! happens when the user unlocks their vault.
//!
//! Gated behind `WHISPER_I2P_MANAGER_LIVE=1` because each run takes
//! 30-60s (i2pd reseed + tunnel build) and consumes a few MB of disk
//! under a temp datadir. CI can run it on a nightly schedule rather
//! than on every PR.
//!
//! ```sh
//! WHISPER_I2P_MANAGER_LIVE=1 cargo test --test i2p_manager_live -- --nocapture
//! ```

use noctis_whisper_desktop_lib::db::Database;
use noctis_whisper_desktop_lib::transport::i2p::manager::{I2PManager, I2pConfig};
use std::time::Duration;
use tokio::time::timeout;

fn enabled() -> bool {
    std::env::var("WHISPER_I2P_MANAGER_LIVE").as_deref() == Ok("1")
}

#[tokio::test]
async fn manager_spawns_i2pd_mints_destination_and_shuts_down() {
    if !enabled() {
        eprintln!("skipping: set WHISPER_I2P_MANAGER_LIVE=1 to run");
        return;
    }

    // Ephemeral profile dir; cleaned up at end of test.
    let profile_dir = std::env::temp_dir().join(format!(
        "whisper-i2p-mgr-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&profile_dir).unwrap();

    // Bare in-memory db with the schema applied + a stub identity row,
    // since `destination::load_or_mint` writes through the identity row.
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

    let cfg = I2pConfig {
        profile_dir: profile_dir.clone(),
        enable_transit: false, // Mod #1 default
    };

    let manager = timeout(Duration::from_secs(180), I2PManager::start(&db, cfg))
        .await
        .expect("manager start timeout — first reseed can take >60s")
        .expect("manager start failed");

    eprintln!("destination pub: {}", manager.destination_pub().len());
    eprintln!("sam addr: {}", manager.sam_addr());
    eprintln!("session id: {}", manager.session_id());
    eprintln!("log path: {}", manager.log_path().display());

    assert!(manager.destination_pub().len() > 400);
    assert!(manager.sam_addr().starts_with("127.0.0.1:"));
    assert!(!manager.session_id().is_empty());

    // Verify the destination round-tripped to the DB row.
    let stored = noctis_whisper_desktop_lib::transport::i2p::destination::load(&db)
        .unwrap()
        .expect("destination persisted");
    assert_eq!(stored.pub_b64, manager.destination_pub());

    // Graceful shutdown should not error.
    timeout(Duration::from_secs(15), manager.shutdown())
        .await
        .expect("shutdown timeout")
        .expect("shutdown failed");

    // Cleanup.
    let _ = std::fs::remove_dir_all(&profile_dir);
}
