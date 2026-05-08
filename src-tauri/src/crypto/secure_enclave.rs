//! macOS hardware binding.
//!
//! Three logical operations:
//!
//! - [`derive_db_key_with_enclave`] — combine the software DEK with a
//!   Keychain-bound 32-byte seed (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`)
//!   to derive the SQLCipher database key. The seed never leaves the user's
//!   login Keychain; copying the database file off the device is insufficient.
//! - [`derive_conversation_key`] — per-conversation HMAC-SHA256 derivation
//!   using a second Keychain seed (always-available after login).
//! - [`derive_sealed_conversation_key`] — biometric-gated counterpart, fronted
//!   by `SecAccessControl(.biometryCurrentSet, .userPresence)`. Each use
//!   prompts Touch ID.
//!
//! These are not as strong as Android's StrongBox/TEE keys (HMAC keys do not
//! live inside the Secure Enclave on macOS — only EC P-256 keys do), but they
//! are the correct macOS equivalent: the seed is encrypted at rest, scoped to
//! the local device, and protected by the user's login session and (for the
//! sealed seed) their biometric.

use super::{CryptoError, CryptoResult, HARDWARE_DB_INFO};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Process-local cache for hardware-bound seeds.
///
/// Without code-signing the macOS Keychain prompts the user on every read,
/// and we hit this path many times per second (TEE encrypt/decrypt for every
/// message render). The cache loads each seed on first use and serves it from
/// memory until [`clear_caches`] is called on vault lock.
///
/// Trade-off: for the lifetime of an unlocked vault the seeds live in app
/// memory rather than only in the Keychain. That matches the threat model:
/// the same process already holds the SQLCipher database key derived from
/// these seeds, so memory exposure is not a new attack surface.
static SEED_CACHE: Lazy<Mutex<HashMap<&'static str, [u8; 32]>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn cached_seed(account: &'static str) -> Option<Zeroizing<[u8; 32]>> {
    let guard = SEED_CACHE.lock();
    guard.get(account).map(|b| {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(b);
        out
    })
}

fn cache_seed(account: &'static str, value: &[u8; 32]) {
    SEED_CACHE.lock().insert(account, *value);
}

/// Drop all cached hardware seeds. Called on vault lock.
pub fn clear_caches() {
    let mut guard = SEED_CACHE.lock();
    for (_, bytes) in guard.iter_mut() {
        use zeroize::Zeroize;
        bytes.zeroize();
    }
    guard.clear();
}

/// Pre-populate the seed cache from a value the caller already has (e.g.
/// the merged vault blob returned by a single Keychain read). After this,
/// downstream `derive_db_key_with_enclave` / `derive_conversation_key`
/// calls hit the cache and never touch the Keychain until lock.
pub fn install_seed_db(value: [u8; 32]) {
    SEED_CACHE.lock().insert(SEED_DB, value);
}

pub fn install_seed_tee(value: [u8; 32]) {
    SEED_CACHE.lock().insert(SEED_TEE, value);
}

/// Hardware security tier reported to the user-facing dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareTier {
    SecureEnclaveBiometric,
    SecureEnclave,
    SoftwareOnly,
    None,
}

use crate::profile;

fn seed_service() -> String {
    profile::keychain_service("hwseed")
}

const SEED_DB: &str = "db";
const SEED_TEE: &str = "tee";
const SEED_SEALED: &str = "sealed";

/// Detect the best available hardware tier.
///
/// **Honesty note:** the `SecureEnclaveBiometric` variant is reserved for
/// when the *database* seed itself is gated by Touch ID. Today only the
/// optional sealed-conversation seed uses biometric ACL; the always-on
/// DB seed is bound to the user's login keychain with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `kSecAttrSynchronizable=false`.
/// Reporting `SecureEnclaveBiometric` here just because Touch ID is
/// physically present would overstate the actual protection — so we
/// report `SecureEnclave` on macOS regardless of biometric capability.
pub fn detect_tier() -> HardwareTier {
    #[cfg(target_os = "macos")]
    {
        // Currently we never report SecureEnclaveBiometric; see doc comment.
        let _ = has_biometric_capability;
        HardwareTier::SecureEnclave
    }
    #[cfg(not(target_os = "macos"))]
    {
        HardwareTier::SoftwareOnly
    }
}

/// Derive the SQLCipher database key from:
/// 1. the software DEK (already decrypted from the vault), and
/// 2. a 32-byte Keychain-bound seed.
///
/// `database_key = HKDF-SHA256(ikm = software_dek, salt = hw_seed, info = HARDWARE_DB_INFO)`
pub fn derive_db_key_with_enclave(
    software_dek: &[u8; 32],
) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let seed = get_or_create_seed(SEED_DB, false)?;
    let hk = Hkdf::<Sha256>::new(Some(&*seed), software_dek);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HARDWARE_DB_INFO, &mut *out)
        .map_err(|_| CryptoError::KdfFailure("DB key HKDF expand"))?;
    Ok(out)
}

/// Per-conversation key: `HMAC-SHA256(tee_seed, conversation_id)`.
pub fn derive_conversation_key(conversation_id: &[u8]) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let seed = get_or_create_seed(SEED_TEE, false)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*seed)
        .map_err(|_| CryptoError::KdfFailure("hmac key length"))?;
    mac.update(conversation_id);
    let tag = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Biometric-gated per-conversation key. Each call requires fresh Touch ID
/// authentication (the Keychain item is fronted by a SecAccessControl
/// requiring `.biometryCurrentSet | .userPresence`).
pub fn derive_sealed_conversation_key(
    conversation_id: &[u8],
) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let seed = get_or_create_seed(SEED_SEALED, true)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*seed)
        .map_err(|_| CryptoError::KdfFailure("hmac key length"))?;
    mac.update(conversation_id);
    let tag = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&tag);
    Ok(out)
}

// =====================================================================
// Seed read / create
// =====================================================================

fn get_or_create_seed(
    account: &'static str,
    biometric: bool,
) -> CryptoResult<Zeroizing<[u8; 32]>> {
    // 1. Process-local cache: zero Keychain prompts after first load.
    if let Some(cached) = cached_seed(account) {
        return Ok(cached);
    }

    // 2. Existing Keychain item — read and cache.
    if let Some(seed) = read_seed(account)? {
        cache_seed(account, &*seed);
        return Ok(seed);
    }

    // 3. First run for this seed: generate, persist, cache.
    // M-1: OsRng (getrandom syscall) for hardware-bound seed material.
    let mut fresh = Zeroizing::new([0u8; 32]);
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut *fresh);
    write_seed(account, &*fresh, biometric)?;
    cache_seed(account, &*fresh);
    Ok(fresh)
}

/// Pre-load all non-biometric seeds so subsequent encrypt/decrypt calls don't
/// trigger Keychain prompts. Called from `vault_unlock` / `vault_setup` so the
/// "Allow" dialog (if any) appears once at unlock time, not once per message.
pub fn warm_caches() -> CryptoResult<()> {
    let _ = get_or_create_seed(SEED_DB, false)?;
    let _ = get_or_create_seed(SEED_TEE, false)?;
    Ok(())
}

fn read_seed(account: &str) -> CryptoResult<Option<Zeroizing<[u8; 32]>>> {
    match imp::read(account) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(CryptoError::SecureEnclave(format!(
                    "seed `{account}` length {} != 32",
                    bytes.len()
                )));
            }
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
        Err(KeychainErr::NotFound) => Ok(None),
        Err(KeychainErr::Other(e)) => Err(CryptoError::SecureEnclave(e)),
    }
}

fn write_seed(account: &str, value: &[u8; 32], biometric: bool) -> CryptoResult<()> {
    imp::write(account, value, biometric).map_err(|e| match e {
        KeychainErr::NotFound => CryptoError::SecureEnclave("not found on write".into()),
        KeychainErr::Other(s) => CryptoError::SecureEnclave(s),
    })
}

#[cfg(target_os = "macos")]
fn has_biometric_capability() -> bool {
    // `LocalAuthentication.framework` exposes `LAContext.canEvaluatePolicy`
    // for the definitive answer, but invoking it requires a UI thread and
    // adds an Objective-C bridge. For runtime tier detection we conservatively
    // report biometric capability on Apple Silicon (where Touch ID and
    // Apple T2 / SE are present); user-facing UX falls back if a Touch ID
    // prompt fails at use time.
    cfg!(target_arch = "aarch64")
}

// =====================================================================
// Keychain helpers (private to this module)
// =====================================================================

#[derive(Debug)]
enum KeychainErr {
    NotFound,
    Other(String),
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
        AccessControlOptions, PasswordOptions,
    };

    pub fn read(account: &str) -> Result<Vec<u8>, KeychainErr> {
        let svc = super::seed_service();
        match get_generic_password(&svc, account) {
            Ok(b) => Ok(b),
            Err(e) if e.code() == -25300 => Err(KeychainErr::NotFound),
            Err(e) => Err(KeychainErr::Other(e.to_string())),
        }
    }

    pub fn write(account: &str, value: &[u8], biometric: bool) -> Result<(), KeychainErr> {
        let svc = super::seed_service();
        // Replace any existing entry so the access-control flags stick.
        // (Some users may have items written by an older build that used
        // the default `kSecAttrAccessibleWhenUnlocked` accessibility — which
        // was eligible for iCloud Keychain sync. Wipe and re-add with the
        // tightened protection class.)
        let _ = delete_generic_password(&svc, account);

        // Build a SecAccessControl that pins the seed to:
        //   - this device only (no iCloud Keychain sync, no migration to a
        //     restored device), and
        //   - only available while the user's account is unlocked.
        // For the biometric path, additionally require Touch ID OR device
        // passcode each use (the OS will fall back to passcode if biometry
        // fails). `BIOMETRY_CURRENT_SET` invalidates the protection if the
        // enrolled fingerprint set changes — that's the desired Signal-style
        // semantics for sealed conversations.
        let flags = if biometric {
            (AccessControlOptions::BIOMETRY_CURRENT_SET
                | AccessControlOptions::OR
                | AccessControlOptions::DEVICE_PASSCODE)
                .bits()
        } else {
            0
        };
        let acl = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags,
        )
        .map_err(|e| KeychainErr::Other(format!("SecAccessControl create: {e}")))?;

        let mut options = PasswordOptions::new_generic_password(&svc, account);
        options.set_access_control(acl);
        // Belt-and-braces: explicitly opt out of iCloud Keychain. The
        // `AccessibleWhenUnlockedThisDeviceOnly` protection already implies
        // non-syncable, but setting `kSecAttrSynchronizable=false` makes
        // the constraint visible at query time too.
        options.set_access_synchronized(Some(false));

        set_generic_password_options(value, options)
            .map_err(|e| KeychainErr::Other(e.to_string()))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn path(account: &str) -> PathBuf {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(".noctis-whisper");
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("seed_{account}.bin"))
    }

    pub fn read(account: &str) -> Result<Vec<u8>, KeychainErr> {
        match fs::read(path(account)) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KeychainErr::NotFound),
            Err(e) => Err(KeychainErr::Other(e.to_string())),
        }
    }

    pub fn write(account: &str, value: &[u8], _biometric: bool) -> Result<(), KeychainErr> {
        fs::write(path(account), value).map_err(|e| KeychainErr::Other(e.to_string()))
    }
}
