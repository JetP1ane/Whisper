//! Global runtime state. Owned by Tauri's `Manager` and accessed from
//! command handlers via `tauri::State<AppState>`.

use crate::db::Database;
use crate::identity::LoadedIdentity;
use crate::transport::i2p::manager::PreStartedI2pd;
use crate::transport::i2p::runtime::I2PRuntime;
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// In-memory vault state. None ↔ locked.
pub struct VaultRuntime {
    pub dek: Zeroizing<[u8; 32]>,
    pub db: Database,
    pub identity: LoadedIdentity,
    /// Ed25519 seed for the configuration-manifest signer. Lives in process
    /// memory only while the vault is unlocked; zeroed on lock.
    pub manifest_seed: Zeroizing<[u8; 32]>,
}

pub struct AppState {
    pub vault: Mutex<Option<VaultRuntime>>,
    /// I2P transport state. None until i2pd comes up after vault_unlock.
    /// The unlock command spawns a background task that fills this in
    /// once SAM is ready (~5-30 s). Sends issued before this completes
    /// are marked failed (no fallback transport).
    pub i2p: tokio::sync::Mutex<Option<Arc<I2PRuntime>>>,
    /// Pre-warmed i2pd, populated at app launch by a background task.
    /// Holds an i2pd subprocess with SAM bridge up and outbound tunnels
    /// built, but no destination minted and no leaseset published —
    /// none of which expose our identity. `vault_unlock` drains this
    /// slot, mints the destination via the unlocked DB, and creates
    /// the master STREAM session, completing transport startup in
    /// ~3-5 s instead of the 30-90 s cold path. Drops to None after
    /// drain or if the app closes before unlock (kill_on_drop reaps
    /// i2pd in either case).
    pub i2p_prewarm: tokio::sync::Mutex<Option<PreStartedI2pd>>,
    /// Handle to the background pre-warm task. `vault_unlock` awaits
    /// this before deciding "use prewarm" vs "cold start" so the two
    /// can't try to spawn i2pd into the same per-profile datadir at
    /// the same time (which would race on the config file and the
    /// router.info / NetDB state on disk). Stored in a parking_lot
    /// mutex because we only swap the Option in/out, never hold the
    /// lock across `.await`.
    ///
    /// The handle type is `tauri::async_runtime::JoinHandle` because
    /// Tauri 2 wraps tokio's runtime handle in its own newtype — a
    /// bare `tokio::spawn` from the setup callback panics ("no
    /// reactor running") because the runtime hasn't taken over the
    /// thread yet. Tauri's spawn queues onto its already-initialized
    /// runtime correctly.
    pub i2p_prewarm_handle: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Bootstrap retry state — populated by `spawn_i2p_start` while the
    /// transport is being brought up. Surfaced via `i2p_status` so the
    /// banner can show "retrying (attempt N)" instead of a stale
    /// elapsed-time counter when the first attempt fails.
    pub i2p_bootstrap: Mutex<I2pBootstrapState>,
    pub paths: AppPaths,
}

#[derive(Clone, Default)]
pub struct I2pBootstrapState {
    /// 1-based attempt counter. 0 before the first attempt starts.
    pub attempt: u32,
    /// Last error message seen on a failed attempt. Cleared on success.
    pub last_error: Option<String>,
    /// True while a start attempt is currently in flight.
    pub in_flight: bool,
}

#[derive(Clone)]
pub struct AppPaths {
    pub db_file: PathBuf,
}

impl AppState {
    pub fn new(paths: AppPaths) -> Self {
        Self {
            vault: Mutex::new(None),
            i2p: tokio::sync::Mutex::new(None),
            i2p_prewarm: tokio::sync::Mutex::new(None),
            i2p_prewarm_handle: Mutex::new(None),
            i2p_bootstrap: Mutex::new(I2pBootstrapState::default()),
            paths,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.lock().is_some()
    }
}
