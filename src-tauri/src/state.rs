//! Global runtime state. Owned by Tauri's `Manager` and accessed from
//! command handlers via `tauri::State<AppState>`.

use crate::db::Database;
use crate::identity::LoadedIdentity;
use crate::transport::cross_relay_stats::CrossRelayStats;
use crate::transport::i2p::runtime::I2PRuntime;
use crate::transport::relay::RelayClient;
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
    /// I2P transport state. None until the queue worker + i2pd come up
    /// after vault_unlock. The unlock command spawns a background task
    /// that fills this in once SAM is ready (~5-30 s). Sends issued
    /// before this completes go through the relay path or get queued.
    pub i2p: tokio::sync::Mutex<Option<Arc<I2PRuntime>>>,
    pub relay: RelayClient,
    pub cross_relay: Arc<CrossRelayStats>,
    pub paths: AppPaths,
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
            relay: RelayClient::new(),
            cross_relay: CrossRelayStats::new(),
            paths,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.lock().is_some()
    }
}
