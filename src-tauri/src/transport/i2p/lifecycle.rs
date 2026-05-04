//! Lifecycle helpers for the I2P transport.
//!
//! `commands::vault_unlock` calls `start()` after the DB is open and
//! the identity is loaded; `commands::vault_lock` calls `stop()` before
//! tearing down the vault. Both are async and bounded — `start()` waits
//! up to ~120 s for i2pd's first reseed, `stop()` waits up to ~6 s for
//! a graceful subprocess exit.

use super::manager::I2PManager;
use super::runtime::{self, I2PRuntime};
use super::I2pResult;
use crate::db::Database;
use std::path::PathBuf;
use std::sync::Arc;

/// Bring the I2P transport up.
///
/// Steps:
///   1. Spawn i2pd (subprocess), pick a randomized SAM port (Mod #1).
///   2. Wait for SAM HELLO to succeed.
///   3. Mint or load the persistent destination from the unlocked DB.
///   4. Stand up the master STREAM session.
///   5. Start the inbound accept loop with the supplied `dispatcher`.
///
/// The persistent send-queue worker is wired separately in Phase 6.5
/// once the second-DB-handle pattern is in place. For now, callers
/// using `dispatch::dispatch_send` and the in-memory connection cache
/// get fully functional sends + auto-reconnect; offline-peer durability
/// (the queue) lights up next.
pub async fn start(
    db: Database,
    profile_dir: PathBuf,
    enable_transit: bool,
    dispatcher: super::runtime::FrameDispatcher,
) -> I2pResult<I2PRuntime> {
    let cfg = runtime::config_for(profile_dir, enable_transit);
    let manager = Arc::new(I2PManager::start(db, cfg).await?);

    let connection = Arc::new(super::connection::ConnectionManager::new(&manager));
    connection
        .run_inbound(dispatcher.clone())
        .await
        .map_err(|e| {
            tracing::error!("i2p: inbound loop failed to start: {e}");
            e
        })?;

    // Placeholder queue handle — a no-op task that lives forever, so
    // `I2PRuntime::shutdown` can `abort()` something concrete. Replaced
    // with the real worker in Phase 6.5.
    let queue_worker = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });

    Ok(I2PRuntime::from_parts(manager, connection, queue_worker))
}

/// Tear the runtime down. Always called from `vault_lock`. Idempotent —
/// passing an already-shutdown runtime is a no-op.
pub async fn stop(runtime: I2PRuntime) {
    runtime.shutdown().await;
}
