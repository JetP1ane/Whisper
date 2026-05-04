//! `I2PRuntime` — the bundle of long-lived state that the rest of the app
//! holds while the I2P transport is active.
//!
//! Lifecycle (Phase 6):
//!
//! * `start()` runs after `vault_unlock` (we need the unlocked DB to
//!   read the persisted destination key). It spawns i2pd, builds the
//!   master STREAM session, stands up the inbound accept loop, and
//!   spins the persistent send-queue worker.
//! * `stop()` runs from `vault_lock`. Shuts the queue worker, the
//!   inbound loop, all cached outbound streams, the master session,
//!   and finally the i2pd subprocess (graceful SIGTERM with 5 s
//!   timeout, then SIGKILL).
//!
//! The runtime is shared across the app behind an `Arc`. The struct
//! holds three things the rest of the app needs by reference:
//!
//! * `connection: Arc<ConnectionManager>` — outbound `send_blob` and
//!   inbound accept loop. Used by `commands.rs::message_send` (Phase 6
//!   graft) and the queue worker.
//! * `manager: Arc<I2PManager>` — used by the security dashboard
//!   (Phase 11) to render destination + log path + tunnel status.
//! * `queue_worker: JoinHandle<()>` — the background tokio task. The
//!   handle is held so `stop()` can `abort()` it.

use super::connection::ConnectionManager;
use super::manager::{I2pConfig, I2PManager};
use super::I2pResult;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// All I2P-side state that's only valid while the vault is unlocked.
///
/// The fields are public-by-Arc because `commands.rs` send paths and
/// the security dashboard read them; nothing inside is mutable.
pub struct I2PRuntime {
    pub manager: Arc<I2PManager>,
    pub connection: Arc<ConnectionManager>,
    queue_worker: JoinHandle<()>,
}

impl I2PRuntime {
    /// Cheap getter to surface the destination string to the security
    /// dashboard / contact bundle builder without reaching through the
    /// full I2PManager type.
    pub fn destination_pub(&self) -> &str {
        self.manager.destination_pub()
    }
}

/// Inbound frame dispatcher signature. The `lifecycle::start` caller
/// supplies the closure that decides how to feed received frames into
/// `messaging::inbound`. We abstract this here (rather than calling
/// `inbound::process_blob` directly) because `transport/i2p` must not
/// take a hard dependency on the messaging crate's types — they evolve
/// independently and the layering is clearer with a function pointer.
pub type FrameDispatcher = Arc<
    dyn Fn(
            String,
            super::framing::Frame,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = I2pResult<()>> + Send>,
        > + Send
        + Sync,
>;

impl I2PRuntime {
    /// Construct from already-built parts. Used by `lifecycle::start`
    /// after it has spawned i2pd, built the ConnectionManager, started
    /// the inbound loop, and spawned the queue worker. Splitting the
    /// "build" and "construct" steps keeps the lifecycle logic linear
    /// and the runtime struct dumb.
    pub fn from_parts(
        manager: Arc<I2PManager>,
        connection: Arc<ConnectionManager>,
        queue_worker: JoinHandle<()>,
    ) -> Self {
        Self {
            manager,
            connection,
            queue_worker,
        }
    }

    /// Graceful teardown. Always run before dropping the I2PManager.
    pub async fn shutdown(self) {
        // 1. Stop the queue worker first so we don't try to send while
        //    teardown is in progress.
        self.queue_worker.abort();
        let _ = self.queue_worker.await;
        // 2. Stop the inbound accept loop + close cached outbound
        //    streams. ConnectionManager::shutdown_inbound is `&self` so
        //    we can call it through the Arc; the cached connections are
        //    dropped when the last Arc drops.
        self.connection.shutdown_inbound().await;
        // 3. Stop i2pd. We can only call `shutdown` on an owned manager
        //    — if other Arc clones are alive we settle for kill_on_drop
        //    semantics. In normal flow nothing else holds the manager
        //    Arc by the time we get here.
        if let Ok(mgr) = Arc::try_unwrap(self.manager) {
            let _ = mgr.shutdown().await;
        } else {
            tracing::warn!(
                "i2p: I2PManager Arc still has live references at shutdown; \
                 relying on kill_on_drop"
            );
        }
    }
}

/// Convenience: build the standard `I2pConfig` from a profile dir + a
/// transit-opt-in flag. Wraps the otherwise-trivial struct so callers
/// don't need to import the manager type.
pub fn config_for(profile_dir: std::path::PathBuf, enable_transit: bool) -> I2pConfig {
    I2pConfig {
        profile_dir,
        enable_transit,
    }
}
