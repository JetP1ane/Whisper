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
///
/// All long-lived background tasks register their `JoinHandle` here so
/// `shutdown()` can `abort()` every one before we drop the vault. M-19:
/// without this, tasks like the leaseset prewarm and the room-fanout
/// drain — both holding an `Arc<I2PManager>` with a live SQLCipher
/// connection — would keep running across `vault_lock`, contradicting
/// the "lock clears keys from RAM" architectural property.
pub struct I2PRuntime {
    pub manager: Arc<I2PManager>,
    pub connection: Arc<ConnectionManager>,
    background_tasks: Vec<JoinHandle<()>>,
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

/// Called by the queue worker once per message that flips from
/// `queued` to `sent` after I2P delivery. Lets `commands.rs` emit a
/// `message:status` event without the transport layer having to know
/// about Tauri's `AppHandle`.
pub type DeliveredCallback = Arc<dyn Fn(&str) + Send + Sync>;

impl I2PRuntime {
    /// Construct from already-built parts. Used by `lifecycle::start`
    /// after it has spawned i2pd, built the ConnectionManager, started
    /// the inbound loop, and spawned the queue worker. Splitting the
    /// "build" and "construct" steps keeps the lifecycle logic linear
    /// and the runtime struct dumb.
    pub fn from_parts(
        manager: Arc<I2PManager>,
        connection: Arc<ConnectionManager>,
        background_tasks: Vec<JoinHandle<()>>,
    ) -> Self {
        Self {
            manager,
            connection,
            background_tasks,
        }
    }

    /// Graceful teardown. Always run before dropping the I2PManager.
    ///
    /// Order matters:
    /// 1. Abort every background task we own. Each task holds an
    ///    `Arc<I2PManager>` (and through it a live SQLCipher
    ///    `Database` connection); aborting them releases those Arcs
    ///    so the `try_unwrap` below has a chance to succeed and we
    ///    can take ownership of the manager for a clean shutdown.
    /// 2. Stop the inbound accept loop and tear down cached outbound
    ///    streams.
    /// 3. SIGTERM i2pd (or, on Drop, SIGKILL via kill_on_drop).
    pub async fn shutdown(self) {
        for handle in &self.background_tasks {
            handle.abort();
        }
        // Await each task's terminal future so its captured Arcs are
        // dropped before we move on. abort() returns immediately; the
        // task's frame is freed when its future is polled to completion
        // (which `.await` on the JoinHandle does).
        for handle in self.background_tasks {
            let _ = handle.await;
        }

        self.connection.shutdown_inbound().await;

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

/// Convenience: build the standard `I2pConfig` from a profile dir, a
/// transit-opt-in flag, and the user's chosen i2pd source (Bundled or
/// External). Wraps the otherwise-trivial struct so callers don't need
/// to import the manager type.
pub fn config_for(
    profile_dir: std::path::PathBuf,
    enable_transit: bool,
    source: super::manager::I2pSource,
) -> I2pConfig {
    I2pConfig {
        profile_dir,
        enable_transit,
        source,
    }
}

/// Filename for the on-disk i2p-source preference within a profile dir.
/// Plaintext JSON. The setting is not sensitive (it's a transport
/// preference, not a key), and the pre-warm runs before the vault is
/// unlocked so an encrypted store wouldn't be readable at that point.
const I2P_SOURCE_FILE: &str = "i2p_source.json";

/// Read the persisted i2p source from `<profile_dir>/i2p_source.json`.
/// Returns `Bundled` if the file is missing or unparseable — Bundled
/// is the safe, default-trust path.
pub fn read_persisted_source(
    profile_dir: &std::path::Path,
) -> super::manager::I2pSource {
    let path = profile_dir.join(I2P_SOURCE_FILE);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Write the i2p source preference to `<profile_dir>/i2p_source.json`.
/// Used by the `i2p_set_source` Tauri command. Bubbles up filesystem
/// errors so the UI can surface a "couldn't save" state instead of
/// silently dropping the change.
pub fn write_persisted_source(
    profile_dir: &std::path::Path,
    source: &super::manager::I2pSource,
) -> std::io::Result<()> {
    let path = profile_dir.join(I2P_SOURCE_FILE);
    let json = serde_json::to_string_pretty(source)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)
}
