//! macOS Keychain glue.
//!
//! We persist three small items as generic-password Keychain entries scoped
//! to our app bundle ID. The values are tiny (≤ 100 bytes), opaque to the
//! Keychain, and protected by the OS user's login session.
//!
//! | Account            | Service                     | Value                                                                    |
//! |--------------------|-----------------------------|---------------------------------------------------------------------------|
//! | `vault_dek`        | `com.noctisprivacy.whisper` | `salt(32) || sealed_dek(60)`                                              |
//! | `db_path_marker`   | `com.noctisprivacy.whisper` | absolute path of the SQLCipher file (string) — lets us survive moves      |
//! | `hw_se_keytag`     | `com.noctisprivacy.whisper` | tag string used to look up the Secure-Enclave-bound EC P-256 binding key  |
//!
//! On non-macOS targets the same logical interface is provided via a sandbox
//! file fallback so the rest of the codebase doesn't need to branch.

use thiserror::Error;

use crate::profile;

/// Profile-scoped Keychain service. `default` uses
/// `com.noctisprivacy.whisper.default`; `NOCTIS_PROFILE=alice` uses
/// `com.noctisprivacy.whisper.alice`. Items in different profiles never
/// share an ACL, so two running instances cannot read each other's vaults.
pub fn service() -> String {
    profile::keychain_service("")
}

pub const ACCOUNT_VAULT_DEK: &str = "vault_dek";
pub const ACCOUNT_DB_PATH: &str = "db_path_marker";

#[derive(Debug, Error)]
pub enum KeychainError {
    #[error("keychain not available: {0}")]
    Unavailable(String),
    #[error("keychain item not found")]
    NotFound,
    #[error("keychain io: {0}")]
    Io(String),
}

pub type KeychainResult<T> = Result<T, KeychainError>;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    pub fn read(account: &str) -> KeychainResult<Vec<u8>> {
        let svc = super::service();
        match get_generic_password(&svc, account) {
            Ok(bytes) => Ok(bytes),
            Err(e) => {
                // security-framework returns errSecItemNotFound (-25300) for missing items.
                if e.code() == -25300 {
                    Err(KeychainError::NotFound)
                } else {
                    Err(KeychainError::Io(e.to_string()))
                }
            }
        }
    }

    pub fn write(account: &str, value: &[u8]) -> KeychainResult<()> {
        let svc = super::service();
        set_generic_password(&svc, account, value)
            .map_err(|e| KeychainError::Io(e.to_string()))
    }

    pub fn delete(account: &str) -> KeychainResult<()> {
        let svc = super::service();
        match delete_generic_password(&svc, account) {
            Ok(_) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()),
            Err(e) => Err(KeychainError::Io(e.to_string())),
        }
    }

    pub fn exists(account: &str) -> bool {
        matches!(read(account), Ok(_))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    //! Non-macOS fallback: store in a sandbox file. Same interface, same semantics.
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn store_path(account: &str) -> PathBuf {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(".noctis-whisper");
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("{}.bin", account))
    }

    pub fn read(account: &str) -> KeychainResult<Vec<u8>> {
        let p = store_path(account);
        match fs::read(&p) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeychainError::NotFound),
            Err(e) => Err(KeychainError::Io(e.to_string())),
        }
    }

    pub fn write(account: &str, value: &[u8]) -> KeychainResult<()> {
        fs::write(store_path(account), value).map_err(|e| KeychainError::Io(e.to_string()))
    }

    pub fn delete(account: &str) -> KeychainResult<()> {
        let p = store_path(account);
        if p.exists() {
            fs::remove_file(p).map_err(|e| KeychainError::Io(e.to_string()))?;
        }
        Ok(())
    }

    pub fn exists(account: &str) -> bool {
        store_path(account).exists()
    }
}

pub fn read(account: &str) -> KeychainResult<Vec<u8>> {
    imp::read(account)
}

pub fn write(account: &str, value: &[u8]) -> KeychainResult<()> {
    imp::write(account, value)
}

pub fn delete(account: &str) -> KeychainResult<()> {
    imp::delete(account)
}

pub fn exists(account: &str) -> bool {
    imp::exists(account)
}

// --- Combined vault blob: salt + sealed DEK + hardware seeds ---
//
// One Keychain item, one ACL prompt at unlock time. The hardware seeds are
// 32 bytes each, generated at vault-setup time, and would otherwise live in
// separate `hwseed/db` and `hwseed/tee` items — three prompts. Folding them
// in has the same security per-item (Keychain protects the bytes either way)
// while paying the prompt cost only once.
//
// Layout (156 bytes):
//   [32 salt][12 nonce][32 dek_ct][16 dek_tag][32 db_seed][32 tee_seed]
//
// The sealed DEK still rides through Argon2id-derived key encryption — the
// merged seeds do not change that. Only the surface for keychain ACL prompts
// is reduced.

use crate::crypto::vault::{DEK_BLOB_LEN, VAULT_SALT_LEN};

const SEED_LEN: usize = 32;
const VAULT_BLOB_LEN: usize = VAULT_SALT_LEN + DEK_BLOB_LEN + SEED_LEN + SEED_LEN + SEED_LEN; // 188

pub struct StoredVaultBlob {
    pub salt: [u8; VAULT_SALT_LEN],
    pub sealed_dek: [u8; DEK_BLOB_LEN],
    pub db_seed: [u8; SEED_LEN],
    pub tee_seed: [u8; SEED_LEN],
    pub manifest_seed: [u8; SEED_LEN],
}

pub fn read_vault_blob() -> KeychainResult<StoredVaultBlob> {
    let raw = read(ACCOUNT_VAULT_DEK)?;
    if raw.len() != VAULT_BLOB_LEN {
        return Err(KeychainError::Io(format!(
            "vault blob has unexpected length {} (expected {})",
            raw.len(),
            VAULT_BLOB_LEN
        )));
    }
    let mut salt = [0u8; VAULT_SALT_LEN];
    let mut sealed = [0u8; DEK_BLOB_LEN];
    let mut db_seed = [0u8; SEED_LEN];
    let mut tee_seed = [0u8; SEED_LEN];
    let mut manifest_seed = [0u8; SEED_LEN];

    let mut off = 0usize;
    salt.copy_from_slice(&raw[off..off + VAULT_SALT_LEN]);
    off += VAULT_SALT_LEN;
    sealed.copy_from_slice(&raw[off..off + DEK_BLOB_LEN]);
    off += DEK_BLOB_LEN;
    db_seed.copy_from_slice(&raw[off..off + SEED_LEN]);
    off += SEED_LEN;
    tee_seed.copy_from_slice(&raw[off..off + SEED_LEN]);
    off += SEED_LEN;
    manifest_seed.copy_from_slice(&raw[off..off + SEED_LEN]);

    Ok(StoredVaultBlob {
        salt,
        sealed_dek: sealed,
        db_seed,
        tee_seed,
        manifest_seed,
    })
}

pub fn write_vault_blob(
    salt: &[u8; VAULT_SALT_LEN],
    sealed_dek: &[u8; DEK_BLOB_LEN],
    db_seed: &[u8; SEED_LEN],
    tee_seed: &[u8; SEED_LEN],
    manifest_seed: &[u8; SEED_LEN],
) -> KeychainResult<()> {
    let mut buf = [0u8; VAULT_BLOB_LEN];
    let mut off = 0usize;
    buf[off..off + VAULT_SALT_LEN].copy_from_slice(salt);
    off += VAULT_SALT_LEN;
    buf[off..off + DEK_BLOB_LEN].copy_from_slice(sealed_dek);
    off += DEK_BLOB_LEN;
    buf[off..off + SEED_LEN].copy_from_slice(db_seed);
    off += SEED_LEN;
    buf[off..off + SEED_LEN].copy_from_slice(tee_seed);
    off += SEED_LEN;
    buf[off..off + SEED_LEN].copy_from_slice(manifest_seed);

    write(ACCOUNT_VAULT_DEK, &buf)?;
    let _ = touch_marker();
    Ok(())
}

/// `vault_initialized` does NOT touch the Keychain — that would trigger an
/// `Allow / Always Allow / Deny` prompt on every status poll for unsigned
/// dev builds. Instead we leave a 0-byte marker file at setup time and check
/// the filesystem here. The marker is non-secret; the real vault material
/// stays in the Keychain (and behind the user's passphrase).
pub fn vault_initialized() -> bool {
    profile::vault_marker_file().exists()
}

fn touch_marker() -> std::io::Result<()> {
    let path = profile::vault_marker_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, b"")?;
    Ok(())
}

/// Remove the marker so a re-installed app sees a clean slate. Used by the
/// duress-wipe path; not currently exposed.
#[allow(dead_code)]
pub fn clear_marker() {
    let _ = std::fs::remove_file(profile::vault_marker_file());
}
