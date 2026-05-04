//! Lifecycle helpers for the I2P transport.
//!
//! `commands::vault_unlock` calls `start()` after the DB is open and
//! the identity is loaded; `commands::vault_lock` calls `stop()` before
//! tearing down the vault. Both are async and bounded — `start()` waits
//! up to ~120 s for i2pd's first reseed, `stop()` waits up to ~6 s for
//! a graceful subprocess exit.

use super::manager::I2PManager;
use super::queue;
use super::runtime::{self, I2PRuntime};
use super::I2pResult;
use crate::db::Database;
use parking_lot::Mutex;
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

    // Persistent send-queue worker: takes a shared Mutex<Option<Database>>
    // wrapper so it can detect "vault locked" (None) without crashing.
    // We point that wrapper at the I2PManager's owned DB Mutex by way of
    // a small bridge struct: clone the Arc'd manager so the worker keeps
    // a live reference into it.
    let queue_db: Arc<Mutex<Option<Database>>> = Arc::new(Mutex::new(None));
    {
        // Move the I2PManager's DB into our Arc<Mutex<Option<Database>>>
        // by taking the inner value out under the manager's lock. The
        // queue worker now owns it; the manager's `db_mutex` accessor
        // still returns the same Mutex pointer (Rust borrow rules let
        // us share the same Mutex across two Arc-y references).
        // For clarity we instead share the *manager's* Mutex directly:
        // wrap a fresh adapter that reads through to it.
        let _ = (&queue_db,);
    }
    // Cleaner approach: share the manager's Mutex directly. Rebuild the
    // queue worker around a Database-borrow pattern. The existing
    // `queue::run_worker(Arc<Mutex<Option<Database>>>, Arc<Conn>)`
    // signature wants a layered Option, so we adapt by spawning a
    // task that re-locks the manager each tick.
    let queue_conn = connection.clone();
    let queue_manager = manager.clone();
    let queue_worker = tokio::spawn(async move {
        let tick = std::time::Duration::from_secs(5);
        loop {
            tokio::time::sleep(tick).await;
            let _ = queue::process_once_with_manager(
                queue_manager.db_mutex(),
                &queue_conn,
            )
            .await;
        }
    });

    Ok(I2PRuntime::from_parts(manager, connection, queue_worker))
}

/// Tear the runtime down. Always called from `vault_lock`. Idempotent —
/// passing an already-shutdown runtime is a no-op.
pub async fn stop(runtime: I2PRuntime) {
    runtime.shutdown().await;
}
