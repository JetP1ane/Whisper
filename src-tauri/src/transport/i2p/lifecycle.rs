//! Lifecycle helpers for the I2P transport.
//!
//! `commands::vault_unlock` calls `start()` after the DB is open and
//! the identity is loaded; `commands::vault_lock` calls `stop()` before
//! tearing down the vault. Both are async and bounded — `start()` waits
//! up to ~120 s for i2pd's first reseed, `stop()` waits up to ~6 s for
//! a graceful subprocess exit.

use super::manager::{I2PManager, PreStartedI2pd};
use super::queue;
use super::runtime::{self, I2PRuntime};
use super::I2pResult;
use crate::db::Database;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;

/// Phase A: spawn i2pd and warm up the network without ever publishing
/// our destination. Run from app launch so the slow part of cold start
/// (reseed + tunnel build) overlaps with the user typing their
/// passphrase. Drop the returned `PreStartedI2pd` if the user closes
/// the app without unlocking — `kill_on_drop` reaps i2pd.
pub async fn pre_start(
    profile_dir: PathBuf,
    enable_transit: bool,
) -> I2pResult<PreStartedI2pd> {
    let cfg = runtime::config_for(profile_dir, enable_transit);
    I2PManager::pre_start(cfg).await
}

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
    on_queued_delivered: super::runtime::DeliveredCallback,
) -> I2pResult<I2PRuntime> {
    // Back-compat path for callers that have an unlocked DB up front
    // and don't care about the pre-warm split (integration tests).
    let pre = pre_start(profile_dir.clone(), enable_transit).await?;
    finalize(pre, db, dispatcher, on_queued_delivered).await
}

/// Phase B: complete transport startup. Mints/loads our destination
/// from the unlocked DB, creates the master STREAM session (this is
/// what publishes our leaseset), and spins up the inbound accept loop
/// + queue worker + prewarm + room-fanout drain tasks.
pub async fn finalize(
    pre: PreStartedI2pd,
    db: Database,
    dispatcher: super::runtime::FrameDispatcher,
    on_queued_delivered: super::runtime::DeliveredCallback,
) -> I2pResult<I2PRuntime> {
    let manager = Arc::new(I2PManager::finalize(pre, db).await?);

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
            match queue::process_once_with_manager(
                queue_manager.db_mutex(),
                &queue_conn,
            )
            .await
            {
                Ok(ids) => {
                    for id in ids {
                        on_queued_delivered(&id);
                    }
                }
                Err(e) => {
                    tracing::debug!("i2p: queue tick failed: {e}");
                }
            }
        }
    });

    // Leaseset pre-warm: periodically open (or refresh) an outbound
    // stream to a *random subset* of known contacts. This pulls their
    // leaseset into i2pd's NetDB and keeps a tunnel + cached connection
    // live, so a user's actual send hits the warm path instead of paying
    // the 3-8 s leaseset-lookup + tunnel-build cost. Cheap on the wire
    // (no payload), bounded by sample size, and silently skipped when
    // there are no contacts yet.
    //
    // Randomization (vs. "every contact every 3 min") is a fingerprint
    // mitigation: a deterministic mass-prewarm at fixed cadence is a
    // very recognizable pattern to a network observer with visibility
    // into multiple I2P routers. We instead:
    //   - vary the initial delay (30-90s) so launches don't all sync up,
    //   - vary the tick interval (180s ± 25%),
    //   - prewarm at most 3 contacts per tick, biased toward the
    //     most-recently-active conversations.
    let prewarm_conn = connection.clone();
    let prewarm_manager = manager.clone();
    let prewarm_worker = tokio::spawn(async move {
        use rand::Rng;
        // Random initial delay so the first tick doesn't fire at a
        // predictable offset from app launch.
        let initial = rand::thread_rng().gen_range(30..=90);
        tokio::time::sleep(std::time::Duration::from_secs(initial)).await;
        loop {
            let dests = sample_prewarm_destinations(prewarm_manager.db_mutex(), 3);
            for dest in dests {
                if let Err(e) = prewarm_conn.prewarm(&dest).await {
                    tracing::debug!(
                        "i2p: prewarm to {} failed (peer offline?): {e}",
                        &dest[..16.min(dest.len())]
                    );
                }
            }
            // 180s ± 25% jitter.
            let jitter = rand::thread_rng().gen_range(135..=225);
            tokio::time::sleep(std::time::Duration::from_secs(jitter)).await;
        }
    });

    // Room-pending-fanout periodic drain. Every 60s, walk the
    // `room_pending_fanout` rows whose recipient has an open ACK
    // gate (i.e., we know the peer can decrypt our messages) and
    // attempt to deliver each one. On success, delete the row;
    // on failure, leave it for the next tick. This catches the
    // case where a peer was reachable when we sent the original
    // room message but the I2P send failed (transient tunnel
    // error, peer briefly offline) — without this, the message
    // would be lost permanently.
    let room_drain_conn = connection.clone();
    let room_drain_manager = manager.clone();
    let room_drain_worker = tokio::spawn(async move {
        let tick = std::time::Duration::from_secs(60);
        // Initial delay so the queue worker fires first.
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        loop {
            let drainable = {
                let guard = room_drain_manager.db_mutex().lock();
                guard
                    .list_drainable_room_fanout()
                    .unwrap_or_default()
            };
            for (id, _room_id, contact_id, _msg_id, blob) in drainable {
                // Find the contact's I2P destination.
                let dest_opt: Option<String> = {
                    let guard = room_drain_manager.db_mutex().lock();
                    guard
                        .conn
                        .query_row(
                            "SELECT i2p_destination FROM contacts WHERE id = ?1",
                            rusqlite::params![&contact_id],
                            |r| r.get::<_, Option<String>>(0),
                        )
                        .ok()
                        .flatten()
                };
                let Some(dest) = dest_opt else { continue };
                if dest.len() < 400 {
                    continue;
                }
                let Ok(inner) =
                    crate::transport::i2p::dispatch::strip_mailbox_prefix(&blob)
                else {
                    continue;
                };
                match room_drain_conn
                    .send_blob(
                        &dest,
                        crate::transport::i2p::framing::FrameType::Message,
                        inner,
                    )
                    .await
                {
                    Ok(()) => {
                        let guard = room_drain_manager.db_mutex().lock();
                        let _ = guard.delete_room_pending_fanout_row(&id);
                        tracing::debug!(
                            "room-drain: delivered buffered message to {} (row {})",
                            contact_id,
                            &id[..8]
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            "room-drain: send to {} failed: {e}; will retry next tick",
                            contact_id
                        );
                    }
                }
            }
            tokio::time::sleep(tick).await;
        }
    });

    // M-19: every long-lived task that captures an `Arc<I2PManager>`
    // (and through it a live SQLCipher Database connection) must be
    // registered with the runtime so vault_lock can abort it before
    // tearing down the vault. Forgetting one means key material lives
    // past `vault_lock`.
    Ok(I2PRuntime::from_parts(
        manager,
        connection,
        vec![queue_worker, prewarm_worker, room_drain_worker],
    ))
}

/// Pick up to `cap` I2P destinations to prewarm, biased toward contacts
/// whose conversations have most-recent activity. Held only across the
/// parking_lot lock — no `.await` while the lock is held.
///
/// Strategy: take the top 8 by `last_message_at DESC NULLS LAST`, then
/// randomly sample `cap` of them. This avoids the deterministic "every
/// contact every tick" fingerprint while still keeping warm tunnels to
/// the people the user is actually talking with.
fn sample_prewarm_destinations(
    db: &parking_lot::Mutex<crate::db::Database>,
    cap: usize,
) -> Vec<String> {
    let candidates: Vec<String> = {
        let guard = db.lock();
        let mut stmt = match guard.conn.prepare(
            "SELECT c.i2p_destination
             FROM contacts c
             LEFT JOIN conversations conv
                 ON conv.contact_id = c.id AND conv.type = 'direct'
             WHERE c.i2p_destination IS NOT NULL
             ORDER BY conv.last_message_at IS NULL, conv.last_message_at DESC
             LIMIT 8",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("i2p: prewarm query prepare failed: {e}");
                return Vec::new();
            }
        };
        let rows = match stmt.query_map([], |r| r.get::<_, Option<String>>(0)) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("i2p: prewarm query_map failed: {e}");
                return Vec::new();
            }
        };
        rows.flatten()
            .flatten()
            .filter(|d| d.len() >= 400)
            .collect()
    };

    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    let mut shuffled = candidates;
    shuffled.shuffle(&mut rng);
    shuffled.truncate(cap);
    shuffled
}

/// Tear the runtime down. Always called from `vault_lock`. Idempotent —
/// passing an already-shutdown runtime is a no-op.
pub async fn stop(runtime: I2PRuntime) {
    runtime.shutdown().await;
}
