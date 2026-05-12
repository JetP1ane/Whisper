//! Tauri IPC commands — the stable surface exposed to the React frontend.
//!
//! Errors are converted into a string-typed `Result<T, String>` because the
//! frontend handles them as plain strings. Heavy work (Argon2id, network I/O)
//! runs inside `tokio::task::spawn_blocking` where appropriate.

use crate::crypto::bundle;
use crate::crypto::keychain;
use crate::crypto::keys::derive_alias;
use crate::crypto::safety_numbers;
use crate::crypto::secure_enclave::{self, HardwareTier};
use crate::crypto::vault as vault_crypto;
use crate::db::contacts::Contact;
use crate::db::messages::Conversation;
use crate::db::Database;
use crate::identity;
use crate::messaging::{inbound, sender};
use crate::state::{AppState, VaultRuntime};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Hard upper bound on passphrase length accepted at the IPC boundary.
/// Argon2id's work is independent of input length once the input is
/// hashed into the initial state, but accepting arbitrarily-large inputs
/// still hands a free DoS knob to anyone with IPC access — and it's
/// nonsense semantically (no human types a 64 KB passphrase). 1024 bytes
/// covers anything reasonable, including long Diceware-style phrases.
const MAX_PASSPHRASE_BYTES: usize = 1024;

// (Legacy minimum-passphrase-length enforcement was removed: users
// pick their own threat model. The frontend renders a strength
// indicator at vault-setup time so the choice is informed, but the
// IPC layer no longer rejects "too short" — only "too large", which
// is a DoS guard and lives in `check_passphrase_length`.)

/// Per-process counter of consecutive failed passphrase attempts. Reset
/// to zero on any successful unlock or recovery-phrase view. Drives a
/// small ramped sleep to make brute-forcing through the IPC boundary
/// (or by an attacker who has scripted the UI) noticeably costly.
///
/// We deliberately do *not* persist this — a determined attacker can
/// always restart the process. Argon2id's per-attempt cost (≈300-700 ms
/// on Apple Silicon at our parameters) is the actual rate-limiter; the
/// counter is belt-and-braces for the within-process case.
static PASSPHRASE_FAILURES: parking_lot::Mutex<u32> = parking_lot::Mutex::new(0);

fn check_passphrase_length(p: &str) -> Result<(), String> {
    if p.len() > MAX_PASSPHRASE_BYTES {
        return Err(format!(
            "passphrase too long (max {MAX_PASSPHRASE_BYTES} bytes)"
        ));
    }
    Ok(())
}

/// Sleep an amount that ramps with consecutive failures. Capped so the
/// UI still feels responsive after a typo.
async fn passphrase_throttle_sleep() {
    let n = *PASSPHRASE_FAILURES.lock();
    let secs = match n {
        0..=2 => 0,
        3..=5 => 1,
        6..=9 => 3,
        _ => 5,
    };
    if secs > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
    }
}

fn passphrase_record_failure() {
    let mut g = PASSPHRASE_FAILURES.lock();
    *g = g.saturating_add(1);
}

fn passphrase_reset_failures() {
    *PASSPHRASE_FAILURES.lock() = 0;
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Try I2P delivery for a `PreparedSend`. Returns:
///   * `Ok(true)` — delivered via I2P, caller should mark status `sent`
///     and skip the relay path entirely.
///   * `Ok(false)` — I2P not attempted (no runtime, no peer destination,
///     or the peer destination looks invalid). Caller falls through to
///     the relay code.
///   * `Err(_)` — I2P was attempted and failed mid-flight (tunnel error,
///     ACK mismatch, etc.). Caller falls through to relay so a single
///     transient failure doesn't drop the message.
///
/// Centralizing this here keeps each `message_send*` command's I2P
/// graft to a single 3-line decision: try I2P, on `Ok(true)` emit the
/// status event + return, otherwise continue with the existing relay
/// code unchanged.
async fn try_i2p_deliver(
    state: &std::sync::Arc<AppState>,
    contact: &Contact,
    kind: crate::transport::i2p::framing::FrameType,
    blob: &[u8],
) -> CmdResult<bool> {
    let runtime = {
        let slot = state.i2p.lock().await;
        slot.as_ref().cloned()
    };
    let runtime = match runtime {
        Some(r) => r,
        None => return Ok(false),
    };
    if !crate::transport::i2p::dispatch::should_use_i2p(contact, Some(&runtime)) {
        return Ok(false);
    }
    let dest = match contact.i2p_destination.as_deref() {
        Some(d) => d,
        None => return Ok(false),
    };
    let inner = crate::transport::i2p::dispatch::strip_mailbox_prefix(blob)
        .map_err(err)?;

    // First-dial transient failures are common on I2P: leasesets need
    // time to propagate to floodfills, NetDB lookups can miss the first
    // time, tunnels sometimes get reset mid-handshake. Retry up to 3
    // times with progressive backoff before falling back to the relay.
    // The total worst-case delay (~7 s) is bounded by what the user
    // can tolerate before the message visibly stalls; relay fallback
    // after that point keeps the UX responsive.
    let backoffs = [0u64, 3, 5];
    let mut last_err: Option<String> = None;
    for (i, secs) in backoffs.iter().enumerate() {
        if *secs > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(*secs)).await;
        }
        match runtime.connection.send_blob(dest, kind, inner).await {
            Ok(()) => {
                tracing::info!(
                    "i2p: delivered to {} via destination {} (attempt {})",
                    contact.alias,
                    &dest[..16.min(dest.len())],
                    i + 1
                );
                return Ok(true);
            }
            Err(e) => {
                let msg = format!("{e}");
                tracing::debug!(
                    "i2p: attempt {} to {} failed: {msg}",
                    i + 1,
                    contact.alias
                );
                last_err = Some(msg);
            }
        }
    }
    tracing::info!(
        "i2p: send to {} failed after {} attempts ({}); falling back to relay",
        contact.alias,
        backoffs.len(),
        last_err.as_deref().unwrap_or("unknown")
    );
    Ok(false)
}

/// Stamp a message row with its actual delivery transport. The vault
/// guard is taken inside; callers don't need to be holding it. Safe
/// to call before a deposit completes — the transport choice is known
/// at dispatch time.
fn stamp_transport(state: &std::sync::Arc<AppState>, msg_id: &str, transport: &str) {
    let guard = state.vault.lock();
    if let Some(rt) = guard.as_ref() {
        let _ = rt.db.set_message_delivery_transport(msg_id, transport);
    }
}

/// Emit a `message:status` event for the given message id. Used by the
/// I2P path (which has no persistent `Deposited` event from the relay
/// to flip status downstream).
fn emit_message_status_sent(app: &tauri::AppHandle, msg_id: &str) {
    #[derive(Serialize, Clone)]
    struct StatusEvt<'a> {
        message_id: &'a str,
        status: &'a str,
    }
    use tauri::Emitter;
    let _ = app.emit(
        "message:status",
        StatusEvt {
            message_id: msg_id,
            status: "sent",
        },
    );
}

// =====================================================================
// vault
// =====================================================================

#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
    pub hardware_tier: HardwareTier,
}

#[tauri::command]
pub async fn vault_status(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<VaultStatus> {
    Ok(VaultStatus {
        initialized: keychain::vault_initialized(),
        unlocked: state.is_unlocked(),
        hardware_tier: secure_enclave::detect_tier(),
    })
}

#[derive(Serialize)]
pub struct VaultSetupResult {
    /// 12-word BIP39 recovery phrase. Shown to the user once. Persisted
    /// inside the encrypted DB; never returned over IPC again.
    pub recovery_phrase: String,
    pub alias: String,
}

#[tauri::command]
pub async fn vault_setup(
    passphrase: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<VaultSetupResult> {
    setup_or_restore(passphrase, None, state, app).await
}

/// Destructive: blow away the Keychain blob, the SQLCipher DB, and the
/// attachment store so a `setup_or_restore` call can rebuild from
/// scratch. Called only when the user has supplied a known recovery
/// phrase — losing the passphrase is not enough to wipe.
fn wipe_existing_vault(state: &State<'_, std::sync::Arc<AppState>>) -> anyhow::Result<()> {
    // Drop the in-memory runtime first so no stale handles linger.
    *state.vault.lock() = None;
    let _ = keychain::delete(keychain::ACCOUNT_VAULT_DEK);
    let _ = keychain::delete(keychain::ACCOUNT_DB_PATH);
    let db_path = &state.paths.db_file;
    if db_path.exists() {
        std::fs::remove_file(db_path).ok();
    }
    let attachments = crate::profile::data_dir().join("attachments");
    if attachments.exists() {
        let _ = std::fs::remove_dir_all(&attachments);
    }
    secure_enclave::clear_caches();
    Ok(())
}

/// Re-materialize the BIP39 recovery phrase from the encrypted-at-rest
/// entropy. Gated on a fresh passphrase challenge so that anyone with
/// brief access to an unlocked screen can't reveal it. Returns `None` if
/// the entropy column is empty (vault predates BIP39).
#[tauri::command]
pub async fn vault_view_recovery_phrase(
    passphrase: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Option<String>> {
    if !state.is_unlocked() {
        return Err("vault locked".into());
    }
    check_passphrase_length(&passphrase)?;
    passphrase_throttle_sleep().await;
    // Re-verify the passphrase against the stored salted DEK to defeat
    // shoulder-surf reveals and casual access on an unlocked machine.
    let blob = keychain::read_vault_blob().map_err(err)?;
    let dek_check = tokio::task::spawn_blocking({
        let pass = passphrase.into_bytes();
        let salt = blob.salt.clone();
        let sealed = blob.sealed_dek.clone();
        move || -> anyhow::Result<()> {
            let vault_key =
                vault_crypto::derive_vault_key(&pass, &salt).map_err(|e| anyhow!("argon2: {e}"))?;
            let _dek = vault_crypto::open_dek(&vault_key, &sealed)
                .map_err(|_| anyhow!("passphrase incorrect"))?;
            Ok(())
        }
    })
    .await
    .map_err(err)?;
    if let Err(e) = dek_check {
        passphrase_record_failure();
        return Err(err(e));
    }
    passphrase_reset_failures();

    let entropy: Vec<u8> = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        match rt.db.get_identity_seed_entropy().map_err(err)? {
            Some(b) => b,
            None => return Ok(None),
        }
    };
    let arr: [u8; 16] = entropy
        .as_slice()
        .try_into()
        .map_err(|_| "stored entropy not 16 bytes".to_string())?;
    let phrase = crate::crypto::seed::phrase_from_entropy(&arr);
    Ok(Some(phrase))
}

/// Recover a vault from a BIP39 recovery phrase. Re-derives the same
/// Ed25519 + X25519 identity (and therefore the same Whisper alias) the
/// user had on the original device. ML-KEM regenerates fresh — this is
/// transparent to peers because the bundle is republished after recovery.
///
/// M-14: this command is a *silent total wipe* primitive when the
/// vault is already initialized — every existing message, contact, and
/// room is destroyed before the new identity is materialized. We can't
/// require the current passphrase as a gate (the entire point of
/// recovery is "I forgot my passphrase"), so we instead defend with:
///
///   1. An explicit `confirm_destructive_wipe: true` argument, so any
///      caller — including a JS-injection attacker — has to write the
///      flag down. A misnamed-arg call dies before any state changes.
///   2. The passphrase-failure throttle. Repeat wipes in a single
///      process pay the same backoff as repeat unlock failures, so a
///      bot can't burst the IPC.
///   3. A loud `tracing::warn!` and a `security:vault_wiped` event so
///      the UI can surface what happened even if the call originated
///      out-of-band.
#[tauri::command]
pub async fn vault_recover_from_seed(
    passphrase: String,
    recovery_phrase: String,
    confirm_destructive_wipe: bool,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<VaultSetupResult> {
    if keychain::vault_initialized() && !confirm_destructive_wipe {
        return Err(
            "vault_recover_from_seed will wipe the existing vault — \
             call again with confirm_destructive_wipe=true to proceed"
                .into(),
        );
    }
    if keychain::vault_initialized() {
        // Loud signal so the user (or anything watching logs) sees a
        // wipe even if it was driven by a path that bypassed the UI.
        tracing::warn!(
            "vault_recover_from_seed: destructive wipe of an existing vault triggered"
        );
        use tauri::Emitter;
        let _ = app.emit("security:vault_wiped", serde_json::json!({}));
        passphrase_record_failure();
        passphrase_throttle_sleep().await;
    }
    setup_or_restore(passphrase, Some(recovery_phrase), state, app).await
}

async fn setup_or_restore(
    passphrase: String,
    existing_phrase: Option<String>,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<VaultSetupResult> {
    // Recovery from a known seed phrase is also our "I lost my passphrase"
    // recovery path, so we let the caller wipe-and-rebuild when the vault
    // already exists *and* a phrase was supplied. Plain `vault_setup` (no
    // phrase) still bails to avoid clobbering an active vault.
    if keychain::vault_initialized() {
        if existing_phrase.is_none() {
            return Err("vault already initialized".into());
        }
        wipe_existing_vault(&state).map_err(err)?;
    }
    check_passphrase_length(&passphrase)?;
    let passphrase_bytes = passphrase.into_bytes();
    let db_path = state.paths.db_file.clone();

    // Run KDF + key derivation off the Tauri command thread.
    let (runtime, recovery_phrase, alias) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(VaultRuntime, String, String)> {
            use rand::RngCore;

            let salt = vault_crypto::generate_salt();
            let vault_key = vault_crypto::derive_vault_key(&passphrase_bytes, &salt)
                .map_err(|e| anyhow!("argon2: {e}"))?;
            let dek = vault_crypto::generate_dek();
            let sealed = vault_crypto::seal_dek(&vault_key, &dek)
                .map_err(|e| anyhow!("dek seal: {e}"))?;

            let mut db_seed = [0u8; 32];
            let mut tee_seed = [0u8; 32];
            let mut manifest_seed_arr = [0u8; 32];
            // M-1: take all key material from OsRng (getrandom syscall),
            // never thread_rng (a userspace ChaCha PRNG seeded from
            // OsRng but reseeded only via the thread-local RNG path).
            // Belt-and-braces given how cheap a syscall is here.
            rand::rngs::OsRng.fill_bytes(&mut db_seed);
            rand::rngs::OsRng.fill_bytes(&mut tee_seed);
            rand::rngs::OsRng.fill_bytes(&mut manifest_seed_arr);

            keychain::write_vault_blob(&salt, &sealed, &db_seed, &tee_seed, &manifest_seed_arr)
                .map_err(|e| anyhow!("keychain write: {e}"))?;

            secure_enclave::install_seed_db(db_seed);
            secure_enclave::install_seed_tee(tee_seed);

            let db_key = derive_db_key(&dek)?;
            let db = Database::open(&db_path, &*db_key)?;

            let (identity, phrase) = match existing_phrase {
                None => identity::create_and_persist(&db)?,
                Some(p) => {
                    let li = identity::restore_from_phrase(&db, &p)?;
                    (li, p)
                }
            };

            // M-8: persist the manifest's verifying key AND a signature
            // over the live crypto-constants digest. vault_unlock will
            // re-verify, so an attacker who tampers with the SQLite
            // settings table (or any other on-disk artifact that flows
            // into the digest) cannot pass the check without the
            // Keychain-bound manifest signer seed.
            let mfst_pub =
                crate::crypto::config_manifest::verifying_key_from_seed(&manifest_seed_arr);
            db.settings_put("manifest_verifying_key", &hex::encode(mfst_pub))?;
            let mfst_sig =
                crate::crypto::config_manifest::sign_current_hex(&manifest_seed_arr);
            db.settings_put("manifest_signature", &mfst_sig)?;

            let mut manifest_seed = Zeroizing::new([0u8; 32]);
            manifest_seed.copy_from_slice(&manifest_seed_arr);

            let alias = identity.alias.clone();
            Ok((
                VaultRuntime {
                    dek,
                    db,
                    identity,
                    manifest_seed,
                },
                phrase,
                alias,
            ))
        })
        .await
        .map_err(err)?
        .map_err(err)?;

    *state.vault.lock() = Some(runtime);

    // Same as vault_unlock — spawn I2P in the background. Without
    // this, a fresh-install user who completes BIP39 onboarding never
    // brings up i2pd until they lock + unlock.
    let dek_for_i2p: Zeroizing<[u8; 32]> = state
        .vault
        .lock()
        .as_ref()
        .map(|rt| {
            let mut copy = Zeroizing::new([0u8; 32]);
            copy.copy_from_slice(&*rt.dek);
            copy
        })
        .ok_or("vault locked between setup and i2p spawn")?;
    spawn_i2p_start(std::sync::Arc::clone(&state), app, dek_for_i2p);

    Ok(VaultSetupResult {
        recovery_phrase,
        alias,
    })
}

#[tauri::command]
pub async fn vault_unlock(
    passphrase: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    if state.is_unlocked() {
        return Ok(());
    }
    if !keychain::vault_initialized() {
        return Err("vault not initialized".into());
    }
    check_passphrase_length(&passphrase)?;
    // Throttle BEFORE doing the Argon2 work, so a bot can't burst-load
    // the CPU just by retrying. After enough failures it will pay both
    // the throttle and the KDF cost per attempt.
    passphrase_throttle_sleep().await;
    let blob = keychain::read_vault_blob().map_err(err)?;
    let passphrase_bytes = passphrase.into_bytes();
    let db_path = state.paths.db_file.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<VaultRuntime> {
        let vault_key = vault_crypto::derive_vault_key(&passphrase_bytes, &blob.salt)
            .map_err(|e| anyhow!("argon2: {e}"))?;
        let dek = vault_crypto::open_dek(&vault_key, &blob.sealed_dek)
            .map_err(|_| anyhow!("incorrect passphrase"))?;

        // Single Keychain read produced all seeds. Install into the cache
        // before deriving anything that would otherwise trigger another read.
        secure_enclave::install_seed_db(blob.db_seed);
        secure_enclave::install_seed_tee(blob.tee_seed);

        let db_key = derive_db_key(&dek)?;
        let db = Database::open(&db_path, &*db_key)?;

        let identity = identity::load(&db)?
            .ok_or_else(|| anyhow!("vault is initialized but identity row is missing"))?;

        // M-8: verify the on-disk manifest signature still matches the
        // live crypto-constants digest. A row mutated outside the app
        // (or by an attacker who downgraded a binary's HKDF salt
        // without the matching signer seed) will fail this check.
        // Both rows must exist — older vaults that predate manifest
        // wiring will be re-signed on first unlock.
        let mfst_vk = db.settings_get("manifest_verifying_key")?;
        let mfst_sig = db.settings_get("manifest_signature")?;
        match (mfst_vk.as_deref(), mfst_sig.as_deref()) {
            (Some(vk), Some(sig)) => {
                crate::crypto::config_manifest::verify_current_hex(vk, sig)
                    .map_err(|_| anyhow!(
                        "manifest signature mismatch — vault settings table \
                         has been modified or this binary's crypto constants \
                         no longer match what the vault was signed with"
                    ))?;
            }
            (Some(vk), None) => {
                // Pre-M-8 vault: verifying key is present but signature
                // wasn't persisted at setup. Re-sign now under the
                // existing verifying key — the seed is in the keychain,
                // so this is the legitimate owner.
                let derived_vk =
                    crate::crypto::config_manifest::verifying_key_from_seed(
                        &blob.manifest_seed,
                    );
                if hex::encode(derived_vk).as_str() != vk {
                    return Err(anyhow!(
                        "manifest verifying key on disk does not match the \
                         seed in the keychain — refusing to open vault"
                    ));
                }
                let sig_hex = crate::crypto::config_manifest::sign_current_hex(
                    &blob.manifest_seed,
                );
                db.settings_put("manifest_signature", &sig_hex)?;
                tracing::info!("manifest: backfilled signature for pre-M-8 vault");
            }
            (None, _) => {
                // Pre-existing vault from before manifest wiring at all.
                // Backfill both rows from the keychain seed.
                let derived_vk =
                    crate::crypto::config_manifest::verifying_key_from_seed(
                        &blob.manifest_seed,
                    );
                db.settings_put(
                    "manifest_verifying_key",
                    &hex::encode(derived_vk),
                )?;
                let sig_hex = crate::crypto::config_manifest::sign_current_hex(
                    &blob.manifest_seed,
                );
                db.settings_put("manifest_signature", &sig_hex)?;
                tracing::info!(
                    "manifest: initialized verifying key + signature for pre-existing vault"
                );
            }
        }

        let mut manifest_seed = Zeroizing::new([0u8; 32]);
        manifest_seed.copy_from_slice(&blob.manifest_seed);

        Ok(VaultRuntime {
            dek,
            db,
            identity,
            manifest_seed,
        })
    })
    .await
    .map_err(err)?;

    let result = match result {
        Ok(rt) => {
            passphrase_reset_failures();
            rt
        }
        Err(e) => {
            passphrase_record_failure();
            return Err(err(e));
        }
    };

    *state.vault.lock() = Some(result);

    // Bring up the I2P transport in the background. The unlock UX
    // doesn't wait — first-launch reseed + tunnel build can take ~30 s
    // and we don't want to block the user. Sends issued before I2P is
    // ready fall back to the relay path; the queue worker (Phase 6.5)
    // will pick them up once SAM is online.
    let dek_for_i2p: Zeroizing<[u8; 32]> = state
        .vault
        .lock()
        .as_ref()
        .map(|rt| {
            let mut copy = Zeroizing::new([0u8; 32]);
            copy.copy_from_slice(&*rt.dek);
            copy
        })
        .ok_or("vault locked between unlock and i2p spawn")?;
    spawn_i2p_start(std::sync::Arc::clone(&state), app.clone(), dek_for_i2p);

    Ok(())
}

/// Spawn the I2P transport startup in a background task. The task
/// opens its OWN Database handle (sharing the SQLCipher file via WAL)
/// so it never needs to coordinate with the vault parking_lot Mutex
/// for long-running async work. The handle survives until vault_lock.
///
/// Retries indefinitely with exponential backoff (5s → 10s → 20s → 30s
/// cap) until the transport comes up or the vault is locked. Each
/// attempt re-opens its own DB connection because the previous attempt
/// may have moved its handle into a partially-built I2PManager that
/// then dropped on error.
fn spawn_i2p_start(
    state: std::sync::Arc<AppState>,
    app: tauri::AppHandle,
    dek: Zeroizing<[u8; 32]>,
) {
    // M-9: take the DEK as a fixed-size Zeroizing<[u8; 32]> rather than
    // a `Vec<u8>` whose backing allocation outlives any zeroize call we
    // could issue from inside the spawned task. The previous version
    // also had `try_into().unwrap_or([0u8; 32])` here — a length
    // mismatch would have silently substituted a zero DEK and derived
    // a deterministic db_key under the all-zeros input, which is a
    // catastrophic key-confusion failure mode. With a typed `[u8; 32]`
    // the wrong-length branch is unreachable.
    let db_path = state.paths.db_file.clone();
    tokio::spawn(async move {
        // Derive the DB key once; reuse across retries. The original
        // DEK drops at the end of this scope and zeroizes via Zeroizing.
        let db_key = match crate::crypto::secure_enclave::derive_db_key_with_enclave(&dek) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("i2p: derive_db_key_with_enclave failed: {e}");
                return;
            }
        };
        drop(dek);

        let profile_dir = crate::profile::data_dir();
        let mut attempt: u32 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            {
                let mut bs = state.i2p_bootstrap.lock();
                bs.attempt = attempt;
                bs.in_flight = true;
            }

            // If the vault was locked while we were sleeping between
            // retries, bail. vault_lock clears the runtime slot but
            // does not directly notify us, so we poll the vault state
            // here as a cheap cancellation check.
            if !state.is_unlocked() {
                tracing::info!(
                    "i2p: vault locked during bootstrap retry — stopping retries"
                );
                let mut bs = state.i2p_bootstrap.lock();
                bs.in_flight = false;
                return;
            }

            // Re-open the DB on every attempt — the previous attempt
            // may have moved its handle into a partially-built manager
            // that dropped on error.
            let db = match crate::db::Database::open(&db_path, &*db_key) {
                Ok(d) => d,
                Err(e) => {
                    let msg = format!("secondary DB open failed: {e}");
                    tracing::warn!("i2p: {msg}");
                    record_attempt_failure(&state, &msg);
                    sleep_backoff(attempt).await;
                    continue;
                }
            };

            let enable_transit = db
                .settings_get("i2p_enable_transit")
                .ok()
                .flatten()
                .map(|v| v == "1")
                .unwrap_or(false);

            // Inbound dispatcher: rebuilt per-attempt so it captures
            // a fresh AppHandle clone but the same shared AppState.
            let app_handle = app.clone();
            let state_for_dispatch = state.clone();
            let dispatcher: crate::transport::i2p::runtime::FrameDispatcher =
                std::sync::Arc::new(move |peer_dest, frame| {
                    let app = app_handle.clone();
                    let state = state_for_dispatch.clone();
                    Box::pin(async move {
                        use crate::transport::i2p::framing::FrameType;
                        match frame.kind {
                            FrameType::Message | FrameType::FileMetadata => {
                                if let Err(e) =
                                    crate::messaging::inbound::dispatch_i2p_frame(
                                        &app,
                                        &state,
                                        &peer_dest,
                                        &frame.payload,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "i2p: inbound dispatch failed for {}: {e:#}",
                                        &peer_dest[..16.min(peer_dest.len())]
                                    );
                                    return Err(crate::transport::i2p::I2pError::Sam(
                                        format!("dispatch: {e}"),
                                    ));
                                }
                            }
                            FrameType::FileChunk => {
                                tracing::debug!(
                                    "i2p: FileChunk from {} (Phase 7 will handle)",
                                    &peer_dest[..16.min(peer_dest.len())]
                                );
                            }
                            _ => {
                                tracing::debug!(
                                    "i2p: ignoring frame {:?} from {}",
                                    frame.kind,
                                    &peer_dest[..16.min(peer_dest.len())]
                                );
                            }
                        }
                        Ok(())
                    })
                });

            // Queue-worker delivery callback: after the worker drains a
            // queued send, the message row is now `status = 'sent'` and
            // `delivery_transport = 'i2p'`. Notify the frontend so the
            // bubble flips from "Sending…" to "Sent · I2P" without a
            // poll.
            let app_for_queue = app.clone();
            let on_queued_delivered: crate::transport::i2p::runtime::DeliveredCallback =
                std::sync::Arc::new(move |msg_id: &str| {
                    emit_message_status_sent(&app_for_queue, msg_id);
                });

            // Prefer the pre-warm path: phase A may have completed
            // during the unlock dialog, so we just need phase B
            // (mint destination + create master STREAM session ≈ 3-5s).
            // First-attempt-only — if finalize fails on a stale handle
            // we don't want to keep yanking it; subsequent retries do
            // the full cold start.
            //
            // Await the prewarm task before reading the slot. If the
            // pre-warm is still running (user unlocked faster than
            // SAM HELLO came up), we MUST wait for it to either fill
            // the slot or fail — kicking off a parallel cold-start
            // would race on the per-profile datadir + i2pd.conf and
            // corrupt state.
            let prewarmed = if attempt == 1 {
                let task_handle = state.i2p_prewarm_handle.lock().take();
                if let Some(h) = task_handle {
                    let _ = h.await;
                }
                state.i2p_prewarm.lock().await.take()
            } else {
                None
            };

            // Source-mismatch check: the pre-warm captured at app
            // launch is bound to whatever `i2p_source` was persisted
            // at that moment. If the user opened Settings → Security
            // and switched modes while the vault was still locked,
            // the persisted preference now differs from what the
            // pre-warm is running against. Using the stale pre-warm
            // in that case would silently connect to the wrong router
            // (or the bundled one when the user wanted external,
            // wasting their explicit configuration). Detect the
            // mismatch and discard the pre-warm in favor of a fresh
            // cold start that honors the current preference.
            let current_source =
                crate::transport::i2p::runtime::read_persisted_source(&profile_dir);
            let result = match prewarmed {
                Some(pre) if pre.source() == &current_source => {
                    tracing::info!(
                        "i2p: using pre-warmed i2pd (sam={}); finalizing transport",
                        pre.sam_addr()
                    );
                    crate::transport::i2p::lifecycle::finalize(
                        pre,
                        db,
                        dispatcher,
                        on_queued_delivered,
                    )
                    .await
                }
                Some(pre) => {
                    tracing::info!(
                        "i2p: pre-warm source ({:?}) no longer matches user preference \
                         ({:?}) — discarding pre-warm and cold-starting fresh",
                        pre.source(),
                        current_source
                    );
                    pre.shutdown().await;
                    crate::transport::i2p::lifecycle::start(
                        db,
                        profile_dir.clone(),
                        enable_transit,
                        current_source,
                        dispatcher,
                        on_queued_delivered,
                    )
                    .await
                }
                None => {
                    tracing::info!(
                        "i2p: no pre-warm available — running full cold start \
                         (attempt={attempt}, source={})",
                        if current_source.is_bundled() {
                            "bundled"
                        } else {
                            "external"
                        }
                    );
                    crate::transport::i2p::lifecycle::start(
                        db,
                        profile_dir.clone(),
                        enable_transit,
                        current_source,
                        dispatcher,
                        on_queued_delivered,
                    )
                    .await
                }
            };
            match result {
                Ok(runtime) => {
                    let mut slot = state.i2p.lock().await;
                    *slot = Some(std::sync::Arc::new(runtime));
                    tracing::info!(
                        "i2p: transport ready (transit={}, attempt={attempt})",
                        if enable_transit { "on" } else { "off" }
                    );
                    let mut bs = state.i2p_bootstrap.lock();
                    bs.in_flight = false;
                    bs.last_error = None;
                    return;
                }
                Err(e) => {
                    let msg = format!("{e}");
                    tracing::warn!(
                        "i2p: transport failed to start (attempt={attempt}): {msg}"
                    );
                    record_attempt_failure(&state, &msg);
                    sleep_backoff(attempt).await;
                }
            }
        }
    });
}

fn record_attempt_failure(state: &std::sync::Arc<AppState>, msg: &str) {
    let mut bs = state.i2p_bootstrap.lock();
    bs.in_flight = false;
    bs.last_error = Some(msg.to_string());
}

/// Backoff schedule: 5s, 10s, 20s, then capped at 30s. We retry forever
/// until the vault is locked — most failures (stale tunnel set, port
/// race, cert dir not yet copied) clear within one or two retries.
async fn sleep_backoff(attempt: u32) {
    let secs = match attempt {
        1 => 5,
        2 => 10,
        3 => 20,
        _ => 30,
    };
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}

#[tauri::command]
pub async fn vault_lock(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<()> {
    // Tear down the I2P transport first — the queue worker (when wired
    // in Phase 6.5) needs the DB still open while it shuts down. Take
    // the runtime out of the slot under the async lock, then await its
    // graceful shutdown without holding any locks.
    let i2p_runtime = {
        let mut slot = state.i2p.lock().await;
        slot.take()
    };
    if let Some(rt) = i2p_runtime {
        if let Ok(rt_owned) = std::sync::Arc::try_unwrap(rt) {
            crate::transport::i2p::lifecycle::stop(rt_owned).await;
        } else {
            tracing::warn!(
                "i2p: runtime Arc has live references at vault_lock; \
                 i2pd will be reaped on Drop"
            );
        }
    }

    let mut guard = state.vault.lock();
    if let Some(rt) = guard.take() {
        rt.db.close();
    }
    drop(guard);
    *state.i2p_bootstrap.lock() = crate::state::I2pBootstrapState::default();
    secure_enclave::clear_caches();
    Ok(())
}

fn derive_db_key(dek: &[u8; 32]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    secure_enclave::derive_db_key_with_enclave(dek)
        .map_err(|e| anyhow!("hw db key: {e}"))
}

// =====================================================================
// identity
// =====================================================================

#[derive(Serialize)]
pub struct IdentitySummary {
    pub alias: String,
    pub ed25519_public_hex: String,
    pub safety_number_hex_fingerprint: String,
}

#[tauri::command]
pub async fn identity_get(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<IdentitySummary> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let ed_pub = rt.identity.keys.ed25519_verifying().to_bytes();
    Ok(IdentitySummary {
        alias: rt.identity.alias.clone(),
        ed25519_public_hex: hex::encode_upper(ed_pub),
        safety_number_hex_fingerprint: safety_numbers::hex_fingerprint(&ed_pub),
    })
}

#[tauri::command]
pub async fn identity_invite_link(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<String> {
    let bundle = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        identity::build_published_bundle(&rt.db, &rt.identity).map_err(err)?
    };
    Ok(bundle::build_whisper_link(&bundle))
}

/// Local-only bundle build — pre-relay-removal this PUT to the relay's
/// /bundle/{alias} endpoint so other peers could resolve us by alias.
/// With I2P-only transport there is no directory, so the call now just
/// rebuilds the bundle to validate it (and emits a log line for parity
/// with the old flow). The bundle itself travels via QR/whisper:// link
/// at contact-add time.
#[tauri::command]
pub async fn identity_publish_bundle(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<()> {
    let alias = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| "vault locked".to_string())?;
        let _ = identity::build_published_bundle(&rt.db, &rt.identity).map_err(err)?;
        rt.identity.alias.clone()
    };
    tracing::info!("publish_bundle: ok for `{}` (local only)", alias);
    Ok(())
}

// =====================================================================
// contacts
// =====================================================================

#[tauri::command]
pub async fn contact_list(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<Vec<Contact>> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db.list_contacts().map_err(err)
}

/// Alias-based contact add was a relay-directory lookup; with I2P-only
/// transport there is no directory. Returns an explicit error so the
/// frontend can surface "use a whisper:// link or QR" guidance.
#[tauri::command]
pub async fn contact_add_by_alias(
    alias: String,
    _nickname: Option<String>,
    _state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Contact> {
    Err(format!(
        "alias lookup is unavailable in I2P-only mode — ask `{alias}` for a whisper:// link or QR"
    ))
}

#[tauri::command]
pub async fn contact_add_by_link(
    link: String,
    nickname: Option<String>,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Contact> {
    // Outer-bound cap: a real bundle is ~2.2 KB serialized + ~38% base58 overhead,
    // so anything above 8 KB is malformed/oversized. Reject before doing the
    // big-int base58 decode so a malicious link can't burn CPU or RAM.
    if link.len() > 8192 {
        return Err("invite link too large".into());
    }
    let bundle = bundle::parse_whisper_link(&link).map_err(err)?;
    let mut contact = persist_bundle_as_contact(&state, bundle, None)?;
    if let Some(n) = nickname.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        {
            let guard = state.vault.lock();
            let rt = guard.as_ref().ok_or("vault locked")?;
            rt.db.set_contact_nickname(&contact.id, Some(n)).map_err(err)?;
        }
        contact.nickname = Some(n.to_string());
    }
    spawn_announce_retry(std::sync::Arc::clone(&state), contact.clone());
    Ok(contact)
}

/// Build the contact-request envelope synchronously (under the vault
/// lock) and hand it off to a background retry task. The task waits
/// for the I2P runtime to come up and retries `send_blob` with
/// exponential backoff until either delivery succeeds or the deadline
/// (~10 minutes) elapses.
fn spawn_announce_retry(state: std::sync::Arc<AppState>, contact: Contact) {
    use crate::transport::envelopes::wrap_contact_request;

    let dest = match contact.i2p_destination.as_deref() {
        Some(d) if d.len() >= 400 => d.to_string(),
        _ => {
            tracing::info!(
                "announce: `{}` has no i2p_destination — skipping (they'll add us back via their own link)",
                contact.alias
            );
            return;
        }
    };
    let envelope = {
        let guard = state.vault.lock();
        let rt = match guard.as_ref() {
            Some(r) => r,
            None => {
                tracing::warn!("announce: vault locked at enqueue time");
                return;
            }
        };
        let my_bundle = match identity::build_published_bundle(&rt.db, &rt.identity) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("announce: build_published_bundle failed: {e:#}");
                return;
            }
        };
        wrap_contact_request(&bundle::serialize(&my_bundle))
    };

    let alias = contact.alias.clone();
    tokio::spawn(async move {
        // Total retry budget: ~10 min. The first launch's i2pd boot
        // can take 90s; leaseset propagation across the network adds
        // another 30-120s. Beyond that the peer is almost certainly
        // offline; the user can resend by re-pasting the link.
        let backoffs_secs = [3u64, 5, 10, 20, 30, 45, 60, 90, 120, 180];
        let mut last_err = String::from("not attempted");
        for (i, secs) in backoffs_secs.iter().enumerate() {
            tokio::time::sleep(std::time::Duration::from_secs(*secs)).await;
            let i2p_runtime = {
                let slot = state.i2p.lock().await;
                slot.as_ref().cloned()
            };
            let Some(rt) = i2p_runtime else {
                last_err = "i2p runtime not ready".into();
                continue;
            };
            match rt
                .connection
                .send_blob(
                    &dest,
                    crate::transport::i2p::framing::FrameType::Message,
                    &envelope,
                )
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        "announce: contact-request delivered to `{alias}` on attempt {}",
                        i + 1
                    );
                    return;
                }
                Err(e) => {
                    last_err = format!("{e}");
                    tracing::debug!(
                        "announce: attempt {} for `{alias}` failed: {last_err}",
                        i + 1
                    );
                }
            }
        }
        tracing::warn!(
            "announce: gave up on contact-request to `{alias}` after {} attempts: {last_err}",
            backoffs_secs.len()
        );
    });
}

#[allow(dead_code)]
async fn announce_to_new_contact(
    state: &State<'_, std::sync::Arc<AppState>>,
    contact: &Contact,
) -> anyhow::Result<()> {
    use crate::transport::envelopes::wrap_contact_request;

    let dest = match contact.i2p_destination.as_deref() {
        Some(d) if d.len() >= 400 => d,
        _ => {
            tracing::info!(
                "announce_to_new_contact: `{}` has no i2p_destination — skipping",
                contact.alias
            );
            return Ok(());
        }
    };

    let my_bundle_bytes = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
        let my_bundle = identity::build_published_bundle(&rt.db, &rt.identity)?;
        bundle::serialize(&my_bundle)
    };

    let envelope = wrap_contact_request(&my_bundle_bytes);

    let i2p_runtime = {
        let slot = state.i2p.lock().await;
        slot.as_ref().cloned()
    };
    let Some(rt) = i2p_runtime else {
        tracing::warn!(
            "announce_to_new_contact: I2P runtime not ready"
        );
        return Ok(());
    };
    rt.connection
        .send_blob(
            dest,
            crate::transport::i2p::framing::FrameType::Message,
            &envelope,
        )
        .await
        .map_err(|e| anyhow!("i2p contact-request: {e}"))?;
    tracing::info!(
        "contact-request: I2P-delivered {} bytes to `{}`",
        envelope.len(),
        contact.alias
    );
    Ok(())
}

fn persist_bundle_as_contact(
    state: &State<'_, std::sync::Arc<AppState>>,
    bundle: bundle::PublicKeyBundle,
    _fallback_relay_url: Option<String>,
) -> CmdResult<Contact> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let now = now_unix_ms();
    let i2p_destination = if bundle.i2p_destination.is_empty() {
        None
    } else {
        Some(bundle.i2p_destination.clone())
    };
    let contact = Contact {
        id: Uuid::new_v4().to_string(),
        alias: bundle.alias.clone(),
        ed25519_public: bundle.identity_key.to_vec(),
        x25519_public: bundle.x25519_key.to_vec(),
        mlkem_public: bundle.kyber_key.clone(),
        i2p_destination,
        verified: false,
        peer_has_verified_us: false,
        hide_until_verified: false,
        is_sealed: false,
        nickname: None,
        created_at: now,
        updated_at: now,
    };
    rt.db.upsert_contact(&contact).map_err(err)?;
    // Persist the full signed bundle so message_send can ratchet-bootstrap
    // without needing to fetch from a relay registry (which doesn't exist
    // anymore in I2P-only mode). The bundle bytes are already verified by
    // `parse_whisper_link`, so no additional check needed here.
    let bundle_bytes = bundle::serialize(&bundle);
    rt.db
        .set_contact_signed_bundle(&contact.id, &bundle_bytes)
        .map_err(err)?;

    // Initiator's conversation is *not* pending — clicking Add is the
    // explicit user gesture. The recipient's side will be marked pending
    // when the contact-request envelope is processed.
    rt.db
        .upsert_conversation(&Conversation {
            id: contact.id.clone(),
            kind: "direct".into(),
            contact_id: Some(contact.id.clone()),
            contact_alias: None,
            contact_nickname: None,
            room_name: None,
            room_description: None,
            disappear_timer: None,
            is_sealed: false,
            is_pending: false,
            last_message_at: None,
            unread_count: 0,
            created_at: now,
        })
        .map_err(err)?;

    // Cache the bundle bytes inside the contact row's mlkem_public field if
    // we ever need to recover them — for now we serialize it on demand.
    Ok(contact)
}

/// Accept a pending contact request: flip the conversation from pending →
/// active, and send our bundle back so the originator has a fresh OTPK and
/// knows we accepted.
#[tauri::command]
pub async fn contact_accept_request(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let contact = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        rt.db
            .set_conversation_pending(&conversation_id, false)
            .map_err(err)?;
        let conv = rt
            .db
            .list_conversations()
            .map_err(err)?
            .into_iter()
            .find(|c| c.id == conversation_id);
        let contact_id = conv.and_then(|c| c.contact_id);
        contact_id.and_then(|cid| {
            rt.db
                .list_contacts()
                .ok()
                .and_then(|list| list.into_iter().find(|c| c.id == cid))
        })
    };
    if let Some(c) = contact {
        if let Err(e) = announce_to_new_contact(&state, &c).await {
            tracing::warn!("accept reciprocate failed: {e:#}");
        }
    }
    Ok(())
}

/// Decline a pending contact request: remove the conversation + contact rows
/// (CASCADE drops messages and ratchet sessions). The peer is not notified.
#[tauri::command]
pub async fn contact_decline_request(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db
        .delete_conversation_and_contact(&conversation_id)
        .map_err(err)
}

/// Delete a conversation and everything that belongs to it: every message
/// row, every on-disk attachment payload, the linked contact (for direct
/// chats), every room_members row (for rooms), and the cached ratchet
/// session. This is local-only — no leave envelope is sent to peers.
#[tauri::command]
pub async fn conversation_delete(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let profile_dir = crate::profile::data_dir();

    // Collect attachment ids first so we can clean up the files outside the
    // SQL transaction. The cascading DELETE will drop the rows themselves.
    let attachment_ids: Vec<String> = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let mut stmt = rt
            .db
            .conn
            .prepare(
                "SELECT id FROM messages
                 WHERE conversation_id = ?1 AND is_attachment = 1",
            )
            .map_err(err)?;
        let rows: Vec<String> = stmt
            .query_map(rusqlite::params![&conversation_id], |r| {
                r.get::<_, String>(0)
            })
            .map_err(err)?
            .filter_map(|r| r.ok())
            .collect();
        rows
    };

    // Drop the conversation row + any linked contact. CASCADE removes
    // messages, ratchet_sessions, and room_members.
    {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        rt.db
            .delete_conversation_and_contact(&conversation_id)
            .map_err(err)?;
    }

    // Best-effort delete of attachment files. Missing files are fine — the
    // sweeper may have already purged them.
    for id in attachment_ids {
        crate::messaging::attachments::delete(&profile_dir, &id);
    }
    Ok(())
}

#[tauri::command]
pub async fn contact_verify(
    id: String,
    verified: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db.set_contact_verified(&id, verified).map_err(err)
}

/// Set or clear a user-chosen display name for a contact. The wire-level
/// alias is unchanged; this only affects local presentation.
#[tauri::command]
pub async fn contact_set_nickname(
    id: String,
    nickname: Option<String>,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let trimmed = nickname.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db.set_contact_nickname(&id, trimmed).map_err(err)
}

#[derive(Serialize)]
pub struct SafetyNumbers {
    pub digits: [u32; 12],
    pub formatted: String,
    pub hex_fingerprint: String,
}

#[tauri::command]
pub async fn contact_safety_numbers(
    contact_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<SafetyNumbers> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;

    let me = rt.identity.keys.ed25519_verifying().to_bytes();
    let contacts = rt.db.list_contacts().map_err(err)?;
    let peer = contacts
        .into_iter()
        .find(|c| c.id == contact_id)
        .ok_or("unknown contact")?;
    let mut peer_id = [0u8; 32];
    peer_id.copy_from_slice(&peer.ed25519_public[..32]);
    let digits = safety_numbers::safety_numbers(&me, &peer_id);

    Ok(SafetyNumbers {
        digits,
        formatted: safety_numbers::format_safety_numbers(&digits),
        hex_fingerprint: safety_numbers::hex_fingerprint(&peer_id),
    })
}

// =====================================================================
// conversations + messages
// =====================================================================

#[tauri::command]
pub async fn conversation_list(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<Vec<Conversation>> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db.list_conversations().map_err(err)
}

/// Set (or clear) the disappearing-message timer for a conversation.
/// `secs` semantics: `None` = off, `Some(30)` = 30 s, `Some(300)` = 5 min,
/// `Some(3600)` = 1 h, `Some(86400)` = 24 h, `Some(604800)` = 7 d.
#[tauri::command]
pub async fn conversation_set_disappear(
    conversation_id: String,
    secs: Option<i64>,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db
        .set_disappear_timer(&conversation_id, secs)
        .map_err(err)
}

/// Zero out the unread badge for a conversation. Called by the
/// frontend when the user opens (or has open) a conversation that
/// has unread messages, and again whenever a new message arrives in
/// the currently-selected conversation.
#[tauri::command]
pub async fn conversation_mark_read(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    let did_clear = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        rt.db
            .conn
            .execute(
                "UPDATE conversations SET unread_count = 0
                 WHERE id = ?1 AND unread_count > 0",
                rusqlite::params![conversation_id],
            )
            .map_err(err)?
    };
    if did_clear > 0 {
        // Tell the sidebar to re-fetch the conversation list so the
        // green badge disappears immediately.
        use tauri::Emitter;
        let _ = app.emit("conversations:changed", serde_json::json!({}));
    }
    Ok(())
}

#[tauri::command]
pub async fn conversation_open(
    contact_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Conversation> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let conversations = rt.db.list_conversations().map_err(err)?;
    if let Some(c) = conversations.into_iter().find(|c| c.contact_id.as_deref() == Some(&contact_id)) {
        return Ok(c);
    }
    let now = now_unix_ms();
    let c = Conversation {
        id: contact_id.clone(),
        kind: "direct".into(),
        contact_id: Some(contact_id),
        contact_alias: None,
            contact_nickname: None,
        room_name: None,
        room_description: None,
        disappear_timer: None,
        is_sealed: false,
        is_pending: false,
        last_message_at: None,
        unread_count: 0,
        created_at: now,
    };
    rt.db.upsert_conversation(&c).map_err(err)?;
    Ok(c)
}

#[derive(Serialize)]
pub struct DisplayMessage {
    pub id: String,
    pub conversation_id: String,
    pub sender_alias: String,
    /// Optional user-set nickname for the sender, resolved at read time
    /// from the contact's current `nickname` column. Frontend prefers this
    /// over `sender_alias`. `None` for outbound messages or peers we
    /// don't have a nickname set for.
    pub sender_nickname: Option<String>,
    pub is_outbound: bool,
    pub text: Option<String>,
    pub is_attachment: bool,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
    pub status: String,
    /// Unix-ms deadline at which the client should detonate this message
    /// (delete locally). Set when the sender opted in to a self-detonating
    /// envelope or when the conversation has a disappear timer.
    pub disappear_at: Option<i64>,
    /// Which transport carried this outbound message — `"i2p"` or
    /// `"relay"`. None for inbound rows or pre-Phase-6 sends. The
    /// chat bubble renders a small icon distinguishing them.
    pub delivery_transport: Option<String>,
    /// Number of times the I2P send-queue worker has attempted to
    /// deliver this message. None for messages that aren't currently
    /// in the queue (delivered inline, already sent, inbound rows).
    /// Used by the bubble to render "Recipient offline · retrying"
    /// vs "Sending…" vs "Queued · trying" without leaking presence
    /// signals over the wire — purely derived from local outbox state.
    pub attempt_count: Option<i64>,
    /// Unix-ms timestamp of the last delivery attempt, or None if no
    /// attempt has been made yet. Pairs with `attempt_count` for the
    /// stale-queue UX inference.
    pub last_attempt_at: Option<i64>,
    /// Emoji reactions on this message, grouped by emoji with a
    /// per-emoji count and a `mine` flag indicating whether *this*
    /// device contributed. Sorted by descending count then emoji.
    pub reactions: Vec<ReactionGroup>,
    pub created_at: i64,
}

#[derive(Serialize, Clone)]
pub struct ReactionGroup {
    pub emoji: String,
    pub count: i64,
    pub mine: bool,
}

#[derive(Serialize)]
pub struct ConversationSecurity {
    pub conversation_id: String,
    pub peer_alias: Option<String>,
    pub peer_id_hex: Option<String>,
    pub aead: &'static str,        // "ChaCha20-Poly1305"
    pub kex_classical: &'static str, // "X25519"
    pub kex_pq: Option<&'static str>, // "ML-KEM-1024" if PQ was active
    pub kdf: &'static str,         // "HKDF-SHA256"
    pub identity_sig: &'static str, // "Ed25519"
    pub messages_sent: i64,
    pub messages_received: i64,
    pub ratchet_send_chain_n: u32, // messages in current sending chain
    pub ratchet_recv_chain_n: u32, // messages in current receiving chain
    pub ratchet_prev_chain_len: u32,
    pub skipped_keys_cached: usize,
    pub session_established: bool,
    pub is_verified: bool,
    pub peer_has_verified_us: bool,
    pub is_sealed: bool,
    pub disappear_timer_secs: Option<i64>,
    pub hardware_tier: HardwareTier,
    pub safety_numbers: SafetyNumbers,
    /// Peer's I2P destination (base64), or None for legacy contacts.
    /// Truncated for display; the full value lives in the contact row.
    pub peer_i2p_destination: Option<String>,
    /// True iff the local I2P runtime currently has at least one
    /// cached outbound stream to this peer (i.e., a tunnel is hot).
    /// Surfaces "warm route" feedback in the panel without leaking
    /// any signal to the peer.
    pub i2p_tunnel_warm: bool,
}

#[tauri::command]
pub async fn conversation_security_summary(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<ConversationSecurity> {
    use crate::messaging::ratchet_store;

    // Synchronous DB read block — captures everything we need into
    // owned values, then the parking_lot guard drops at the end of
    // the block. The subsequent `.await` (for the I2P tunnel-warm
    // check) must not hold the guard, since `parking_lot::MutexGuard`
    // is not Send.
    struct DbSnapshot {
        conv_id: String,
        conv_kind: String,
        conv_is_sealed: bool,
        conv_disappear_timer: Option<i64>,
        contact_id: Option<String>,
        contact_alias: Option<String>,
        contact_ed25519: Option<Vec<u8>>,
        contact_mlkem_empty: bool,
        contact_verified: bool,
        contact_peer_has_verified_us: bool,
        peer_i2p_destination: Option<String>,
        send_n: u32,
        recv_n: u32,
        prev_n: u32,
        skipped: usize,
        established: bool,
        has_pq: bool,
        messages_sent: i64,
        messages_received: i64,
        me_pub: [u8; 32],
    }

    let snap: DbSnapshot = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;

        let conv = rt
            .db
            .list_conversations()
            .map_err(err)?
            .into_iter()
            .find(|c| c.id == conversation_id)
            .ok_or("unknown conversation")?;

        let contact = match conv.contact_id.as_ref() {
            Some(cid) => rt
                .db
                .list_contacts()
                .map_err(err)?
                .into_iter()
                .find(|c| &c.id == cid),
            None => None,
        };

    // Pull the ratchet state if it exists. Counts give us forward-secrecy
    // progress without disclosing key material.
    let (send_n, recv_n, prev_n, skipped, established, has_pq) = if conv.kind == "room" {
        // Rooms use sender-key broadcast (ChaCha20-Poly1305 + HKDF-SHA256
        // chain). Symmetric AEAD is post-quantum (Grover ⇒ 128-bit
        // security), and each sender-key seed was distributed over the
        // owner's / member's pairwise PQ-X3DH ratchet — ML-KEM-1024
        // protected. So `has_pq=true` for any room with at least one peer
        // sender-key on file.
        let members = rt.db.list_room_members(&conv.id).map_err(err)?;
        let any_peer_seed = members.iter().any(|m| m.sender_key.is_some());
        let contacts_lookup = rt.db.list_contacts().map_err(err)?;
        let all_have_mlkem = members.iter().all(|m| {
            contacts_lookup
                .iter()
                .find(|c| c.id == m.contact_id)
                .map(|c| !c.mlkem_public.is_empty())
                .unwrap_or(true)
        });
        let pq = any_peer_seed && all_have_mlkem;
        // Aggregate send count across the room (we don't track per-member
        // chain numbers here — sender_key state lives behind decode).
        let total: i64 = rt
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1",
                rusqlite::params![&conv.id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (total as u32, 0, 0, 0, any_peer_seed, pq)
    } else {
        match contact
            .as_ref()
            .and_then(|c| ratchet_store::load(&rt.db, &c.id).ok().flatten())
        {
            Some(s) => {
                // If the bundle we used for bootstrap had a kyber public key
                // (mlkem_public non-empty on the contact row), PQ was active.
                let pq = contact
                    .as_ref()
                    .map(|c| !c.mlkem_public.is_empty())
                    .unwrap_or(false);
                (
                    s.send_msg_num,
                    s.recv_msg_num,
                    s.prev_send_len,
                    s.skipped.len(),
                    true,
                    pq,
                )
            }
            None => (0, 0, 0, 0, false, false),
        }
    };

        // Per-direction message counts from the DB.
        let messages_sent: i64 = rt
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1 AND is_outbound = 1",
                rusqlite::params![conversation_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let messages_received: i64 = rt
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1 AND is_outbound = 0",
                rusqlite::params![conversation_id],
                |r| r.get(0),
            )
            .unwrap_or(0);

        DbSnapshot {
            conv_id: conv.id.clone(),
            conv_kind: conv.kind.clone(),
            conv_is_sealed: conv.is_sealed,
            conv_disappear_timer: conv.disappear_timer,
            contact_id: contact.as_ref().map(|c| c.id.clone()),
            contact_alias: contact.as_ref().map(|c| c.alias.clone()),
            contact_ed25519: contact.as_ref().map(|c| c.ed25519_public.clone()),
            contact_mlkem_empty: contact
                .as_ref()
                .map(|c| c.mlkem_public.is_empty())
                .unwrap_or(true),
            contact_verified: contact.as_ref().map(|c| c.verified).unwrap_or(false),
            contact_peer_has_verified_us: contact
                .as_ref()
                .map(|c| c.peer_has_verified_us)
                .unwrap_or(false),
            peer_i2p_destination: contact.as_ref().and_then(|c| c.i2p_destination.clone()),
            send_n,
            recv_n,
            prev_n,
            skipped,
            established,
            has_pq,
            messages_sent,
            messages_received,
            me_pub: rt.identity.keys.ed25519_verifying().to_bytes(),
        }
    }; // parking_lot guard dropped here.

    let i2p_tunnel_warm = if let Some(dest) = snap.peer_i2p_destination.as_deref() {
        let slot = state.i2p.lock().await;
        match slot.as_ref() {
            Some(rt) => rt.connection.has_cached_outbound(dest).await,
            None => false,
        }
    } else {
        false
    };

    let (peer_alias, peer_id_hex, sn) = if let Some(ed_bytes) = snap.contact_ed25519.as_ref() {
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&ed_bytes[..32]);
        let digits = safety_numbers::safety_numbers(&snap.me_pub, &peer);
        let sn = SafetyNumbers {
            digits,
            formatted: safety_numbers::format_safety_numbers(&digits),
            hex_fingerprint: safety_numbers::hex_fingerprint(&peer),
        };
        (snap.contact_alias.clone(), Some(hex::encode_upper(peer)), sn)
    } else {
        (
            None,
            None,
            SafetyNumbers {
                digits: [0u32; 12],
                formatted: String::new(),
                hex_fingerprint: String::new(),
            },
        )
    };
    let _ = snap.contact_id; // suppressed unused-warning; field reserved for future use

    Ok(ConversationSecurity {
        conversation_id,
        peer_alias,
        peer_id_hex,
        aead: "ChaCha20-Poly1305",
        kex_classical: "X25519",
        kex_pq: if snap.has_pq { Some("ML-KEM-1024") } else { None },
        kdf: "HKDF-SHA256",
        identity_sig: "Ed25519",
        messages_sent: snap.messages_sent,
        messages_received: snap.messages_received,
        ratchet_send_chain_n: snap.send_n,
        ratchet_recv_chain_n: snap.recv_n,
        ratchet_prev_chain_len: snap.prev_n,
        skipped_keys_cached: snap.skipped,
        session_established: snap.established,
        is_verified: snap.contact_verified,
        peer_has_verified_us: snap.contact_peer_has_verified_us,
        is_sealed: snap.conv_is_sealed,
        disappear_timer_secs: snap.conv_disappear_timer,
        hardware_tier: secure_enclave::detect_tier(),
        safety_numbers: sn,
        peer_i2p_destination: snap.peer_i2p_destination,
        i2p_tunnel_warm,
    })
}

#[tauri::command]
pub async fn conversation_messages(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Vec<DisplayMessage>> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let rows = rt
        .db
        .load_messages_encrypted(&conversation_id, 500)
        .map_err(err)?;

    // Build alias → nickname map once so each message lookup is O(1).
    use std::collections::HashMap;
    let nickname_by_alias: HashMap<String, String> = rt
        .db
        .list_contacts()
        .map_err(err)?
        .into_iter()
        .filter_map(|c| c.nickname.map(|n| (c.alias, n)))
        .collect();

    // One pass over the I2P send queue, keyed by message_id. Each
    // outbound `queued` message gets its current attempt count + last
    // attempt timestamp so the bubble can render "Sending…" vs
    // "Queued · trying" vs "Recipient offline · retrying" purely from
    // local outbox state — no presence beacons, no wire side-channel.
    let queue_state: HashMap<String, (i64, Option<i64>)> = {
        let mut stmt = rt
            .db
            .conn
            .prepare(
                "SELECT message_id, attempt_count, last_attempt_at
                 FROM i2p_send_queue
                 WHERE status = 'queued'",
            )
            .map_err(err)?;
        let mut map = HashMap::new();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(err)?;
        for row in rows.flatten() {
            map.insert(row.0, (row.1, row.2));
        }
        map
    };

    // One pass over `message_reactions` for this conversation.
    // Group by (message_id, emoji) into counts + a `mine` flag.
    let mut reactions_by_msg: HashMap<String, Vec<ReactionGroup>> = HashMap::new();
    {
        let mut stmt = rt
            .db
            .conn
            .prepare(
                "SELECT mr.message_id, mr.emoji,
                        SUM(CASE WHEN mr.reactor_alias = 'self' THEN 1 ELSE 0 END) AS mine_count,
                        COUNT(*) AS total
                 FROM message_reactions mr
                 JOIN messages m ON m.id = mr.message_id
                 WHERE m.conversation_id = ?1
                 GROUP BY mr.message_id, mr.emoji
                 ORDER BY mr.message_id, total DESC, mr.emoji",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(rusqlite::params![conversation_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(err)?;
        for row in rows.flatten() {
            let (msg_id, emoji, mine, total) = row;
            reactions_by_msg
                .entry(msg_id)
                .or_default()
                .push(ReactionGroup {
                    emoji,
                    count: total,
                    mine: mine > 0,
                });
        }
    }

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let plaintext = if let Some(blob) = r.tee_encrypted_content.as_ref() {
            match crate::crypto::tee_encryption::decrypt_for_conversation(
                conversation_id.as_bytes(),
                blob,
            ) {
                Ok(env) => match crate::crypto::message_crypto::decode_envelope(&env) {
                    Ok(crate::crypto::message_crypto::DecodedEnvelope::Text { text, .. }) => Some(text),
                    Ok(crate::crypto::message_crypto::DecodedEnvelope::DetonatingText { text, .. }) => Some(text),
                    _ => None,
                },
                Err(_) => None,
            }
        } else {
            None
        };
        let sender_nickname = if r.is_outbound {
            None
        } else {
            nickname_by_alias.get(&r.sender_alias).cloned()
        };
        // Only outbound + queued rows are interesting — everything else
        // can't be in the queue. Saves a hashmap lookup per inbound row.
        let queue = if r.is_outbound && r.status == "queued" {
            queue_state.get(&r.id).copied()
        } else {
            None
        };
        let reactions = reactions_by_msg.remove(&r.id).unwrap_or_default();
        out.push(DisplayMessage {
            id: r.id,
            conversation_id: conversation_id.clone(),
            sender_alias: r.sender_alias,
            sender_nickname,
            is_outbound: r.is_outbound,
            text: plaintext,
            is_attachment: r.is_attachment,
            filename: r.filename,
            mime_type: r.mime_type,
            file_size: r.file_size,
            status: r.status,
            disappear_at: r.disappear_at,
            delivery_transport: r.delivery_transport,
            attempt_count: queue.map(|(c, _)| c),
            last_attempt_at: queue.and_then(|(_, t)| t),
            reactions,
            created_at: r.created_at,
        });
    }
    Ok(out)
}

/// Look up the conversation + contact + the cached signed bundle needed
/// to bootstrap the ratchet. Returns `Err` with a clear message when the
/// peer was added under a code path that didn't cache its bundle (e.g.
/// pre-migration row from the old relay-fetch days). The frontend can
/// then prompt the user to re-add the contact.
fn load_send_target(
    state: &State<'_, std::sync::Arc<AppState>>,
    conversation_id: &str,
) -> CmdResult<(Contact, crate::db::messages::Conversation, bundle::PublicKeyBundle)> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let conv = rt
        .db
        .list_conversations()
        .map_err(err)?
        .into_iter()
        .find(|c| c.id == conversation_id)
        .ok_or("unknown conversation")?;
    let contact_id = conv
        .contact_id
        .clone()
        .ok_or("only direct conversations supported in v1")?;
    let contact = rt
        .db
        .list_contacts()
        .map_err(err)?
        .into_iter()
        .find(|c| c.id == contact_id)
        .ok_or("unknown contact")?;
    let bytes = rt
        .db
        .get_contact_signed_bundle(&contact.id)
        .map_err(err)?
        .ok_or_else(|| {
            format!(
                "no cached bundle for {} — re-add this contact via their whisper:// link",
                contact.alias
            )
        })?;
    let parsed = bundle::deserialize(&bytes).map_err(err)?;
    bundle::verify_bundle(&parsed).map_err(err)?;
    Ok((contact, conv, parsed))
}

#[tauri::command]
pub async fn message_send(
    conversation_id: String,
    text: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<String> {
    let (contact, conversation, bundle) = load_send_target(&state, &conversation_id)?;

    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        sender::prepare_send_text(
            &rt.db,
            &rt.identity,
            &contact,
            &bundle,
            &conversation.id,
            &text,
            None,
        )
        .map_err(err)?
    };

    // Spawn dispatch in the background so the command returns immediately.
    // The message row is already inserted (in `queued` status) by
    // `prepare_send_text` above, so the frontend can render the bubble
    // right away. As I2P / relay attempts resolve, we emit
    // `message:status` events that flip the bubble's status indicator.
    let state_clone = std::sync::Arc::clone(&state);
    let app_clone = app.clone();
    let contact_clone = contact.clone();
    let prepared_for_task = PreparedDispatch {
        msg_id: prepared.msg_id.clone(),
        blob: prepared.blob.clone(),
        frame_kind: crate::transport::i2p::framing::FrameType::Message,
    };
    tokio::spawn(async move {
        dispatch_outbound(state_clone, app_clone, contact_clone, prepared_for_task).await;
    });

    Ok(prepared.message.id)
}

/// Inputs the background dispatch task needs to attempt I2P delivery.
/// All fields are owned so the task doesn't borrow command state.
struct PreparedDispatch {
    msg_id: String,
    blob: Vec<u8>,
    /// Which I2P frame type to use. Text/control envelopes are
    /// `Message`; attachments use `FileMetadata`.
    frame_kind: crate::transport::i2p::framing::FrameType,
}

/// Background dispatch: I2P-only.
///
/// Outcomes:
///   * Delivered now → mark `sent` + transport `i2p` + emit status.
///   * Peer has no I2P destination → mark `failed` (will never deliver).
///   * I2P runtime not yet up, or dial failed after internal retries →
///     enqueue in `i2p_send_queue` and leave status `queued`. The queue
///     worker drains these once SAM is online and the peer is reachable.
async fn dispatch_outbound(
    state: std::sync::Arc<AppState>,
    app: tauri::AppHandle,
    contact: Contact,
    prepared: PreparedDispatch,
) {
    match try_i2p_deliver(&state, &contact, prepared.frame_kind, &prepared.blob).await {
        Ok(true) => {
            {
                let guard = state.vault.lock();
                if let Some(rt) = guard.as_ref() {
                    let _ = rt.db.set_message_status(&prepared.msg_id, "sent");
                    let _ = rt
                        .db
                        .set_message_delivery_transport(&prepared.msg_id, "i2p");
                }
            }
            emit_message_status_sent(&app, &prepared.msg_id);
        }
        _ => {
            // Inline-deliver path didn't succeed. Decide between
            // permanent failure (peer has no destination) and durable
            // queueing (transport not yet ready, or peer offline).
            let dest = match contact.i2p_destination.as_deref() {
                Some(d) if d.len() >= 400 => d.to_string(),
                _ => {
                    tracing::warn!(
                        "dispatch_outbound: {} has no I2P destination — marking failed",
                        contact.alias
                    );
                    let guard = state.vault.lock();
                    if let Some(rt) = guard.as_ref() {
                        let _ = rt.db.set_message_status(&prepared.msg_id, "failed");
                    }
                    drop(guard);
                    emit_message_status(&app, &prepared.msg_id, "failed");
                    return;
                }
            };

            // Strip the 32-byte mailbox prefix before persisting — the
            // queue worker calls send_blob with the inner ratchet wire
            // exactly like try_i2p_deliver does.
            let inner = match crate::transport::i2p::dispatch::strip_mailbox_prefix(&prepared.blob)
            {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    tracing::warn!(
                        "dispatch_outbound: cannot strip mailbox prefix for {}: {e}",
                        contact.alias
                    );
                    let guard = state.vault.lock();
                    if let Some(rt) = guard.as_ref() {
                        let _ = rt.db.set_message_status(&prepared.msg_id, "failed");
                    }
                    drop(guard);
                    emit_message_status(&app, &prepared.msg_id, "failed");
                    return;
                }
            };

            let enqueue_res: Result<(), String> = {
                let guard = state.vault.lock();
                match guard.as_ref() {
                    Some(rt) => crate::transport::i2p::queue::enqueue(
                        &rt.db,
                        &contact.id,
                        &prepared.msg_id,
                        &dest,
                        prepared.frame_kind,
                        &inner,
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                    None => Err("vault locked".to_string()),
                }
            };
            match enqueue_res {
                Ok(()) => {
                    tracing::info!(
                        "dispatch_outbound: enqueued message for {} (transport not ready or peer offline) — queue worker will retry",
                        contact.alias
                    );
                    // Status stays `queued`. No transport stamp yet —
                    // queue worker stamps it after success.
                }
                Err(e) => {
                    tracing::warn!(
                        "dispatch_outbound: enqueue failed for {}: {e} — marking failed",
                        contact.alias
                    );
                    let guard = state.vault.lock();
                    if let Some(rt) = guard.as_ref() {
                        let _ = rt.db.set_message_status(&prepared.msg_id, "failed");
                    }
                    drop(guard);
                    emit_message_status(&app, &prepared.msg_id, "failed");
                }
            }
        }
    }
}

/// Generic message:status emitter — the I2P-success path uses
/// `emit_message_status_sent` for the common "sent" case; this
/// is for "failed" or other terminal states.
fn emit_message_status(app: &tauri::AppHandle, msg_id: &str, status: &str) {
    #[derive(Serialize, Clone)]
    struct StatusEvt<'a> {
        message_id: &'a str,
        status: &'a str,
    }
    use tauri::Emitter;
    let _ = app.emit(
        "message:status",
        StatusEvt {
            message_id: msg_id,
            status,
        },
    );
}

/// Self-detonating text variant of `message_send`. The TTL is sealed
/// inside the AEAD envelope so the relay and any network adversary can't
/// strip or extend it. Both client sides set `disappear_at` on the row
/// and the existing sweeper purges them locally; the relay TTL is
/// clamped to `detonate_secs` so the blob also expires server-side.
#[tauri::command]
pub async fn message_send_detonating(
    conversation_id: String,
    text: String,
    detonate_secs: u32,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<String> {
    if detonate_secs == 0 {
        return Err("detonate_secs must be > 0".into());
    }
    let (contact, conversation, bundle) = load_send_target(&state, &conversation_id)?;

    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        sender::prepare_send_detonating_text(
            &rt.db,
            &rt.identity,
            &contact,
            &bundle,
            &conversation.id,
            &text,
            detonate_secs,
            None,
        )
        .map_err(err)?
    };

    // Clamp relay TTL to the detonation window so the blob also disappears
    // server-side. Cap at 24h since that's the relay's max retention. The
    // I2P path doesn't need this — there's no server holding the blob;
    // detonation is enforced by the AEAD-embedded TTL on both clients.
    let relay_ttl = (detonate_secs as u64).min(60 * 60 * 24);

    // Fire-and-forget dispatch — same shape as `message_send`.
    let state_clone = std::sync::Arc::clone(&state);
    let app_clone = app.clone();
    let contact_clone = contact.clone();
    let _ = relay_ttl; // legacy — relay path removed
    let prepared_for_task = PreparedDispatch {
        msg_id: prepared.msg_id.clone(),
        blob: prepared.blob.clone(),
        frame_kind: crate::transport::i2p::framing::FrameType::Message,
    };
    tokio::spawn(async move {
        dispatch_outbound(state_clone, app_clone, contact_clone, prepared_for_task).await;
    });

    Ok(prepared.message.id)
}

/// Create a new group conversation (room) and invite the listed contacts.
/// Steps:
///   1. allocate a fresh 16-byte room_id (UUID),
///   2. persist the local conversation row + a self-row + a member row per
///      invitee, all with the owner's freshly-generated sender-key seed,
///   3. fan out a `RoomInvite` envelope over each invitee's pairwise Double
///      Ratchet, carrying our chain seed and the full member list.
///
/// `member_contact_ids` are the contact-table ids of the people to invite.
#[tauri::command]
pub async fn room_create(
    name: String,
    member_contact_ids: Vec<String>,
    state: State<'_, std::sync::Arc<AppState>>,
    _app: tauri::AppHandle,
) -> CmdResult<String> {
    use crate::crypto::message_crypto::{
        build_aad, build_room_invite_envelope, pack_attachment_wire, pad_pkcs7, RatchetWire,
    };
    use crate::crypto::ratchet;
    use crate::crypto::sender_key::SenderKey;
    use crate::crypto::PAD_BLOCK;
    use crate::db::messages::Conversation;
    use rand::{rngs::OsRng, RngCore};
    use std::time::Duration;
    use uuid::Uuid;

    if name.trim().is_empty() {
        return Err("room name required".into());
    }
    if member_contact_ids.is_empty() {
        return Err("invite at least one member".into());
    }

    let room_id_bytes: [u8; 16] = *Uuid::new_v4().as_bytes();
    let room_id_str = Uuid::from_bytes(room_id_bytes).to_string();
    let now = now_unix_ms();

    let mut owner_seed = [0u8; 32];
    OsRng.fill_bytes(&mut owner_seed);

    // Synchronous prep: persist room + members and prepare ratchet wires
    // for each invitee (we encrypt under the lock so ratchet state is
    // consistent across the fan-out).
    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();

        let invitees = rt
            .db
            .list_contacts()
            .map_err(err)?
            .into_iter()
            .filter(|c| member_contact_ids.contains(&c.id))
            .collect::<Vec<_>>();
        if invitees.len() != member_contact_ids.len() {
            return Err("one or more invitees are not contacts".into());
        }

        // 1+2. Conversation + member rows.
        rt.db
            .upsert_conversation(&Conversation {
                id: room_id_str.clone(),
                kind: "room".into(),
                contact_id: None,
                contact_alias: None,
            contact_nickname: None,
                room_name: Some(name.clone()),
                room_description: None,
                disappear_timer: None,
                is_sealed: false,
                is_pending: false,
                last_message_at: None,
                unread_count: 0,
                created_at: now,
            })
            .map_err(err)?;

        // Persist the owner's sender-key in the dedicated self table — it
        // does not belong in `room_members` because there's no contact row
        // for ourselves to FK against.
        let me_sk = SenderKey::from_seed(owner_seed);
        crate::messaging::room_keys::save_self(&rt.db, &room_id_str, &me_sk).map_err(err)?;

        // Pending member rows for invitees.
        for c in &invitees {
            crate::messaging::room_keys::upsert_member_pending(
                &rt.db,
                &room_id_str,
                &c.id,
                "member",
                now,
            )
            .map_err(err)?;
        }

        // Build the member-bundle list. Owner first, then each invitee.
        // Each member needs every other member's full bundle to bootstrap
        // pairwise ratchets for sender-key sharing — without these,
        // non-owner members can't reach each other.
        let my_bundle_bytes = {
            let my_bundle = identity::build_published_bundle(&rt.db, &rt.identity)
                .map_err(err)?;
            bundle::serialize(&my_bundle)
        };
        let mut member_bundles_owned: Vec<Vec<u8>> = Vec::with_capacity(invitees.len() + 1);
        member_bundles_owned.push(my_bundle_bytes);
        for c in &invitees {
            let bytes = rt
                .db
                .get_contact_signed_bundle(&c.id)
                .map_err(err)?
                .ok_or_else(|| {
                    format!(
                        "no cached bundle for invitee {} — re-add this contact first",
                        c.alias
                    )
                })?;
            member_bundles_owned.push(bytes);
        }
        let member_bundles_refs: Vec<&[u8]> =
            member_bundles_owned.iter().map(|b| b.as_slice()).collect();
        let _ = me_pub; // member identity is now derived from bundles

        // 3. Per-invitee encrypted invite ready for deposit.
        let mut wires: Vec<(Vec<u8>, String, Option<String>)> = Vec::new();
        for c in &invitees {
            let envelope = build_room_invite_envelope(
                now as u64,
                &room_id_bytes,
                &name,
                "",
                &owner_seed,
                &member_bundles_refs,
            )
            .map_err(err)?;
            let padded = pad_pkcs7(&envelope, PAD_BLOCK);

            let mut state_obj = match crate::messaging::ratchet_store::load(&rt.db, &c.id)
                .map_err(err)?
            {
                Some(s) => s,
                None => {
                    return Err(format!(
                        "no ratchet session with `{}` — message them once first",
                        c.alias
                    ))
                }
            };
            let enc =
                ratchet::encrypt_message(&mut state_obj, &padded, build_aad).map_err(err)?;
            // Use the unbounded attachment wire — room invites carry
            // every member's full bundle (~3.5 KB each), which can
            // exceed the 4096-byte cap of pack_text_wire when there are
            // 2+ members.
            let wire = pack_attachment_wire(&RatchetWire {
                ratchet_key: &enc.ratchet_key,
                prev_chain_len: enc.prev_chain_len,
                msg_num: enc.msg_num,
                nonce: &enc.nonce,
                ciphertext: &enc.ciphertext,
                sentinel_digest: None,
            });
            crate::messaging::ratchet_store::save(&rt.db, &c.id, &state_obj).map_err(err)?;

            let sender_mb_hex = crate::transport::mailbox::hex(
                &crate::transport::mailbox::current_mailbox(&me_pub),
            );
            let recipient_mb_hex = crate::transport::mailbox::hex(
                &crate::transport::mailbox::current_mailbox(&c.ed25519_public),
            );
            let mut blob = Vec::with_capacity(32 + wire.len());
            blob.extend_from_slice(sender_mb_hex.as_bytes());
            blob.extend_from_slice(&wire);
            wires.push((
                blob,
                recipient_mb_hex,
                c.i2p_destination.clone(),
            ));
        }
        wires
    };

    // Async fan-out: I2P direct delivery to each invitee. Members
    // without an i2p_destination on file are skipped.
    let i2p_runtime = {
        let slot = state.i2p.lock().await;
        slot.as_ref().cloned()
    };
    for (blob, _recipient_mb_hex, i2p_dest) in prepared {
        let Some(rt) = i2p_runtime.as_ref() else {
            tracing::warn!("room_create: I2P runtime not ready; invite dropped");
            continue;
        };
        let Some(dest) = i2p_dest.as_deref() else {
            tracing::warn!("room_create: invitee has no i2p_destination; skipping");
            continue;
        };
        if dest.len() < 400 {
            continue;
        }
        let Ok(inner) = crate::transport::i2p::dispatch::strip_mailbox_prefix(&blob) else {
            continue;
        };
        if let Err(e) = rt
            .connection
            .send_blob(
                dest,
                crate::transport::i2p::framing::FrameType::Message,
                inner,
            )
            .await
        {
            tracing::warn!("room_create: I2P delivery failed: {e}");
        }
    }
    Ok(room_id_str)
}

/// Send a text message to every member of a room. Encrypts once with our
/// sender key, packs the room wire format, and fans the same ciphertext out
/// to each member's mailbox.
#[tauri::command]
pub async fn room_send(
    room_id: String,
    text: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<String> {
    use crate::crypto::sender_key;
    use crate::db::messages::Message;
    use std::time::Duration;
    use uuid::Uuid;

    if text.trim().is_empty() {
        return Err("empty text".into());
    }

    let room_uuid =
        Uuid::parse_str(&room_id).map_err(|_| "room id not a UUID".to_string())?;
    let room_id_bytes: [u8; 16] = *room_uuid.as_bytes();
    let now = now_unix_ms();
    let msg_id = Uuid::new_v4().to_string();

    // Synchronous prep: encrypt under self sender-key, build per-recipient
    // deposits, persist the local sent-row.
    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();

        let mut sk = crate::messaging::room_keys::load_self(&rt.db, &room_id)
            .map_err(err)?
            .ok_or_else(|| format!("not a member of room {}", room_id))?;

        // Wrap the text in the standard envelope so the receiver can call
        // `decode_envelope` on it (matching direct-message handling).
        use crate::crypto::message_crypto::build_text_envelope;
        let envelope = build_text_envelope(now as u64, &text);
        let padded = crate::crypto::message_crypto::pad_pkcs7(&envelope, crate::crypto::PAD_BLOCK);

        let enc =
            sender_key::encrypt(&mut sk, &room_id_bytes, &me_pub, &padded).map_err(err)?;
        crate::messaging::room_keys::save_self(&rt.db, &room_id, &sk).map_err(err)?;
        let wire = sender_key::pack_room_wire(&room_id_bytes, &me_pub, &enc);

        // Outbound fan-out targets: every other member with a known
        // contact carrying an I2P destination. Each row also carries
        // the peer's contact_id (for the pending-fanout buffer) and
        // a `ready` flag — when false, we buffer the message in
        // `room_pending_fanout` instead of sending right now and
        // wait for the peer's RoomSenderKeyAck before draining.
        let members = rt.db.list_room_members(&room_id).map_err(err)?;
        let contacts = rt.db.list_contacts().map_err(err)?;
        struct Target {
            contact_id: String,
            i2p_destination: Option<String>,
            ed25519_public: [u8; 32],
            ready: bool,
        }
        let mut targets: Vec<Target> = Vec::new();
        for m in members {
            if m.contact_id == "self" {
                continue;
            }
            let Some(c) = contacts.iter().find(|c| c.id == m.contact_id) else {
                continue;
            };
            let pk: [u8; 32] = match c.ed25519_public.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let ready = crate::messaging::room_keys::peer_has_acked_my_key(
                &rt.db, &room_id, &c.id,
            )
            .unwrap_or(false);
            targets.push(Target {
                contact_id: c.id.clone(),
                i2p_destination: c.i2p_destination.clone(),
                ed25519_public: pk,
                ready,
            });
        }

        let me_mb_hex = crate::transport::mailbox::hex(
            &crate::transport::mailbox::current_mailbox(&me_pub),
        );
        // (blob, contact_id, i2p_dest, ready)
        let mut blobs: Vec<(Vec<u8>, String, Option<String>, bool)> = Vec::new();
        for t in targets {
            let _recipient_mb_hex = crate::transport::mailbox::hex(
                &crate::transport::mailbox::current_mailbox(&t.ed25519_public),
            );
            let mut blob = Vec::with_capacity(32 + wire.len());
            blob.extend_from_slice(me_mb_hex.as_bytes());
            blob.extend_from_slice(&wire);
            blobs.push((blob, t.contact_id, t.i2p_destination, t.ready));
        }

        // Persist the local sent row.
        let me_alias = rt.identity.alias.clone();
        let envelope_bytes = envelope;
        let tee = crate::crypto::tee_encryption::encrypt_for_conversation(
            room_id.as_bytes(),
            &envelope_bytes,
        )
        .ok();
        let _ = rt.db.insert_message(
            &Message {
                id: msg_id.clone(),
                conversation_id: room_id.clone(),
                sender_alias: me_alias,
                is_outbound: true,
                plaintext: None,
                is_attachment: false,
                filename: None,
                mime_type: None,
                file_size: None,
                status: "queued".into(),
                disappear_at: rt
                    .db
                    .conversation_disappear_timer(&room_id)
                    .ok()
                    .flatten()
                    .map(|s| now + s.saturating_mul(1000)),
                created_at: now,
            },
            tee.as_deref(),
            None,
            None,
        );

        blobs
    };

    // Buffer first: any recipient who hasn't ACK'd our sender-key share
    // gets the blob persisted in `room_pending_fanout`. The ACK handler
    // (`handle_room_sender_key_ack`) drains them when the ACK arrives.
    // Recipients that are ready get the live fan-out below. Buffering
    // happens inside the vault lock since it's a single quick INSERT.
    let mut to_send_now: Vec<(Vec<u8>, Option<String>)> = Vec::new();
    {
        let guard = state.vault.lock();
        if let Some(rt) = guard.as_ref() {
            for (blob, contact_id, i2p_dest, ready) in prepared {
                if ready {
                    to_send_now.push((blob, i2p_dest));
                } else {
                    let id = uuid::Uuid::new_v4().to_string();
                    if let Err(e) = rt.db.enqueue_room_pending_fanout(
                        &id,
                        &room_id,
                        &contact_id,
                        &msg_id,
                        &blob,
                        now,
                    ) {
                        tracing::warn!(
                            "room_send: enqueue_room_pending_fanout failed for {}: {e}",
                            contact_id
                        );
                    } else {
                        tracing::debug!(
                            "room_send: buffered for {} pending sender-key ACK",
                            contact_id
                        );
                    }
                }
            }
        }
    }

    // Fire-and-forget I2P fan-out so room_send returns immediately
    // and the bubble can render synchronously on the sender's side.
    // Mirrors the message_send pattern. The local row is already
    // persisted (status=queued) above, so the UI shows the bubble in
    // the same tick the user pressed Send. Status flips to `sent`
    // after every ready recipient has had a delivery attempt; the
    // queued/buffered ones drain via the ACK gate. If a send fails
    // mid-flight (peer offline, transient tunnel error), the blob is
    // requeued in `room_pending_fanout` for the next periodic drain.
    let state_clone = std::sync::Arc::clone(&state);
    let app_clone = app.clone();
    let msg_id_clone = msg_id.clone();
    let room_id_clone = room_id.clone();
    // We need (blob, contact_id, dest) for the requeue path on failure.
    let to_send_now_with_ids: Vec<(Vec<u8>, String, Option<String>)> = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let members = rt.db.list_room_members(&room_id).map_err(err)?;
        let contacts = rt.db.list_contacts().map_err(err)?;
        let ready_contacts: Vec<(String, Option<String>)> = members
            .into_iter()
            .filter(|m| m.contact_id != "self")
            .filter_map(|m| {
                contacts
                    .iter()
                    .find(|c| c.id == m.contact_id)
                    .filter(|c| {
                        crate::messaging::room_keys::peer_has_acked_my_key(
                            &rt.db, &room_id, &c.id,
                        )
                        .unwrap_or(false)
                    })
                    .map(|c| (c.id.clone(), c.i2p_destination.clone()))
            })
            .collect();
        // Pair each (blob, dest) with the matching contact_id by
        // dest equality (we only have ready peers in to_send_now).
        to_send_now
            .into_iter()
            .filter_map(|(blob, dest)| {
                let contact_id = ready_contacts
                    .iter()
                    .find(|(_, d)| d == &dest)
                    .map(|(id, _)| id.clone())?;
                Some((blob, contact_id, dest))
            })
            .collect()
    };
    tokio::spawn(async move {
        let i2p_runtime = {
            let slot = state_clone.i2p.lock().await;
            slot.as_ref().cloned()
        };
        for (blob, contact_id, i2p_dest) in to_send_now_with_ids {
            let Some(rt) = i2p_runtime.as_ref() else {
                tracing::warn!(
                    "room_send: I2P runtime not ready; requeueing for {}",
                    contact_id
                );
                requeue_room_blob(
                    &state_clone,
                    &room_id_clone,
                    &contact_id,
                    &msg_id_clone,
                    &blob,
                );
                continue;
            };
            let Some(dest) = i2p_dest.as_deref() else {
                tracing::warn!("room_send: member has no i2p_destination; skipping");
                continue;
            };
            if dest.len() < 400 {
                continue;
            }
            let Ok(inner) = crate::transport::i2p::dispatch::strip_mailbox_prefix(&blob) else {
                continue;
            };
            if let Err(e) = rt
                .connection
                .send_blob(
                    dest,
                    crate::transport::i2p::framing::FrameType::Message,
                    inner,
                )
                .await
            {
                tracing::warn!(
                    "room_send: I2P delivery to {} failed ({e}); requeueing",
                    contact_id
                );
                requeue_room_blob(
                    &state_clone,
                    &room_id_clone,
                    &contact_id,
                    &msg_id_clone,
                    &blob,
                );
            }
        }
        {
            let guard = state_clone.vault.lock();
            if let Some(rt) = guard.as_ref() {
                let _ = rt.db.set_message_status(&msg_id_clone, "sent");
                let _ = rt
                    .db
                    .set_message_delivery_transport(&msg_id_clone, "i2p");
            }
        }
        emit_message_status_sent(&app_clone, &msg_id_clone);
    });
    Ok(msg_id)
}

/// Persist a room message blob in `room_pending_fanout` so the
/// periodic drain task picks it up on the next tick. Used by
/// `room_send`'s background fanout when the live I2P send fails.
fn requeue_room_blob(
    state: &std::sync::Arc<AppState>,
    room_id: &str,
    contact_id: &str,
    msg_id: &str,
    blob: &[u8],
) {
    let guard = state.vault.lock();
    let Some(rt) = guard.as_ref() else { return };
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_unix_ms();
    if let Err(e) =
        rt.db
            .enqueue_room_pending_fanout(&id, room_id, contact_id, msg_id, blob, now)
    {
        tracing::warn!("requeue_room_blob: enqueue failed for {contact_id}: {e}");
    }
}

/// Send a file attachment. Reads the bytes from `source_path`, encrypts +
/// transmits via the same ratchet path as text, and stores the bytes
/// at-rest under `<profile>/attachments/<msg_id>.bin` (TEE-encrypted) so
/// the sender can re-open the file later.
/// Add (or remove) an emoji reaction on a message. Stores the
/// reaction locally + ships a `MessageReaction` envelope to the
/// peer (DM) or every other room member (room) via the existing
/// pairwise Double Ratchets. Reactions reference the target by its
/// `wire_hash` — the same hash the recipient stored when they first
/// processed the original message.
#[tauri::command]
pub async fn message_react(
    message_id: String,
    emoji: String,
    remove: bool,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    use crate::crypto::message_crypto::{
        build_aad, build_message_reaction_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
    };
    use crate::crypto::ratchet;
    use crate::crypto::PAD_BLOCK;

    if emoji.is_empty() || emoji.len() > 64 {
        return Err("emoji must be 1..64 bytes".into());
    }

    // Synchronous prep: look up the message + its wire_hash, persist
    // our own reaction row, build per-recipient encrypted blobs.
    struct Prepared {
        wire_hash: [u8; 32],
        conv_id: String,
        outbound_blobs: Vec<(String, Option<String>, Vec<u8>)>, // (contact_id, dest, blob)
    }
    let prep: Prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;

        // 1. Resolve message_id → conversation_id + wire_hash.
        let row: Option<(String, Option<Vec<u8>>)> = rt
            .db
            .conn
            .query_row(
                "SELECT conversation_id, wire_hash FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .ok();
        let (conv_id, wire_hash_vec) = row.ok_or("unknown message")?;
        let wire_hash_vec = wire_hash_vec
            .ok_or("message has no wire_hash — cannot be referenced by a reaction")?;
        if wire_hash_vec.len() != 32 {
            return Err("wire_hash is not 32 bytes".into());
        }
        let mut wire_hash = [0u8; 32];
        wire_hash.copy_from_slice(&wire_hash_vec);

        // 2. Persist our own reaction row.
        let now = now_unix_ms();
        if remove {
            rt.db
                .conn
                .execute(
                    "DELETE FROM message_reactions
                     WHERE message_id = ?1 AND reactor_alias = 'self' AND emoji = ?2",
                    rusqlite::params![message_id, emoji],
                )
                .map_err(err)?;
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            rt.db
                .conn
                .execute(
                    "INSERT OR IGNORE INTO message_reactions
                        (id, message_id, reactor_alias, emoji, created_at)
                     VALUES (?1, ?2, 'self', ?3, ?4)",
                    rusqlite::params![id, message_id, emoji, now],
                )
                .map_err(err)?;
        }

        // 3. Build the wire envelope ONCE (same for every recipient).
        let envelope = build_message_reaction_envelope(
            now as u64,
            &wire_hash,
            remove,
            &emoji,
        )
        .map_err(err)?;
        let padded = pad_pkcs7(&envelope, PAD_BLOCK);

        // 4. Identify recipients: DM = the single contact; room = every
        //    member with a known contact row (excluding self).
        let conv = rt
            .db
            .list_conversations()
            .map_err(err)?
            .into_iter()
            .find(|c| c.id == conv_id)
            .ok_or("conversation not found")?;
        let recipients: Vec<crate::db::contacts::Contact> = if conv.kind == "room" {
            let members = rt.db.list_room_members(&conv.id).map_err(err)?;
            let contacts = rt.db.list_contacts().map_err(err)?;
            members
                .into_iter()
                .filter(|m| m.contact_id != "self")
                .filter_map(|m| contacts.iter().find(|c| c.id == m.contact_id).cloned())
                .collect()
        } else {
            let cid = conv.contact_id.clone().ok_or("direct conv has no contact_id")?;
            rt.db
                .list_contacts()
                .map_err(err)?
                .into_iter()
                .filter(|c| c.id == cid)
                .collect()
        };

        // 5. Encrypt per recipient under their pairwise ratchet.
        let mut outbound_blobs = Vec::with_capacity(recipients.len());
        for c in recipients {
            let mut ratchet_state = match crate::messaging::ratchet_store::load(&rt.db, &c.id)
                .map_err(err)?
            {
                Some(s) => s,
                None => {
                    tracing::debug!(
                        "react: no pairwise ratchet for {} — skipping (will catch up via room broadcast retry)",
                        c.alias
                    );
                    continue;
                }
            };
            let enc = match ratchet::encrypt_message(&mut ratchet_state, &padded, build_aad) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("react: encrypt for {} failed: {e}", c.alias);
                    continue;
                }
            };
            let wire = match pack_text_wire(&RatchetWire {
                ratchet_key: &enc.ratchet_key,
                prev_chain_len: enc.prev_chain_len,
                msg_num: enc.msg_num,
                nonce: &enc.nonce,
                ciphertext: &enc.ciphertext,
                sentinel_digest: None,
            }) {
                Ok(w) => w,
                Err(_) => continue,
            };
            let _ = crate::messaging::ratchet_store::save(&rt.db, &c.id, &ratchet_state);
            outbound_blobs.push((c.id.clone(), c.i2p_destination.clone(), wire));
        }

        Prepared {
            wire_hash,
            conv_id: conv_id.clone(),
            outbound_blobs,
        }
    };
    let _ = prep.wire_hash;

    // Notify the local UI that this conversation's reactions changed.
    // Without this, the sender's own bubble doesn't update with the
    // new chip until something *else* re-fetches the conversation
    // (e.g., a peer's ack arrives, or the user reselects the chat).
    {
        use tauri::Emitter;
        let _ = app.emit(
            "message:reaction",
            serde_json::json!({ "conversation_id": prep.conv_id }),
        );
    }

    // Async send per recipient. Failures are logged; reactions are
    // best-effort and don't go through the persistent send queue.
    let i2p_runtime = {
        let slot = state.i2p.lock().await;
        slot.as_ref().cloned()
    };
    let Some(rt) = i2p_runtime else {
        tracing::warn!("react: I2P runtime not ready — local reaction stored only");
        return Ok(());
    };
    for (_contact_id, dest, wire) in prep.outbound_blobs {
        let Some(dest) = dest else { continue };
        if dest.len() < 400 {
            continue;
        }
        if let Err(e) = rt
            .connection
            .send_blob(
                &dest,
                crate::transport::i2p::framing::FrameType::Message,
                &wire,
            )
            .await
        {
            tracing::debug!("react: I2P send failed: {e}");
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn message_send_attachment(
    conversation_id: String,
    source_path: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<String> {
    use crate::messaging::attachments;
    let path = std::path::PathBuf::from(&source_path);
    let bytes = std::fs::read(&path).map_err(|e| format!("read attachment: {e}"))?;
    if bytes.len() > crate::crypto::MAX_ATTACHMENT_BYTES {
        return Err(format!(
            "attachment exceeds 10 MB cap ({} bytes)",
            bytes.len()
        ));
    }
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment")
        .to_string();
    let mime = mime_guess(&filename);

    let (contact, conversation, bundle) = load_send_target(&state, &conversation_id)?;

    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        sender::prepare_send_attachment(
            &rt.db,
            &rt.identity,
            &contact,
            &bundle,
            &conversation.id,
            &filename,
            &mime,
            &bytes,
            None,
        )
        .map_err(err)?
    };

    let profile_dir = crate::profile::data_dir();
    if let Err(e) =
        attachments::store(&profile_dir, &prepared.msg_id, &conversation.id, &bytes)
    {
        tracing::warn!("attachment_store (sender side) failed: {e}");
    }

    // Fire-and-forget dispatch — same shape as `message_send`. The
    // local at-rest copy is already on disk (above) so the bubble
    // can render the file preview as soon as we return. Attachments
    // use FrameType::FileMetadata so the inbound side knows this is
    // a single-frame inline file (vs the streaming FileChunk path).
    let state_clone = std::sync::Arc::clone(&state);
    let app_clone = app.clone();
    let contact_clone = contact.clone();
    let prepared_for_task = PreparedDispatch {
        msg_id: prepared.msg_id.clone(),
        blob: prepared.blob.clone(),
        frame_kind: crate::transport::i2p::framing::FrameType::FileMetadata,
    };
    tokio::spawn(async move {
        dispatch_outbound(state_clone, app_clone, contact_clone, prepared_for_task).await;
    });

    Ok(prepared.message.id)
}

fn mime_guess(filename: &str) -> String {
    let lower = filename.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "mov" => "video/quicktime",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Decrypt the attachment for `message_id` and return it as a `data:` URL
/// suitable for embedding in an `<img>` element. Used by the chat UI to
/// render image attachments inline. The bytes never leave the sandboxed
/// container — the URL is consumed by the local webview.
#[tauri::command]
pub async fn attachment_load_data_url(
    message_id: String,
    conversation_id: String,
    mime_type: String,
    _state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<String> {
    use base64::Engine;
    let profile_dir = crate::profile::data_dir();
    let bytes = crate::messaging::attachments::load(&profile_dir, &message_id, &conversation_id)
        .map_err(|e| format!("load attachment: {e}"))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(format!("data:{};base64,{}", mime_type, b64))
}

/// Decrypt the attachment for `message_id` and write it to `dest_path`.
/// The caller picks the destination via the file-save dialog.
#[tauri::command]
pub async fn attachment_save_as(
    message_id: String,
    conversation_id: String,
    dest_path: String,
    _state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let profile_dir = crate::profile::data_dir();
    let bytes = crate::messaging::attachments::load(&profile_dir, &message_id, &conversation_id)
        .map_err(|e| format!("load attachment: {e}"))?;
    std::fs::write(&dest_path, &bytes).map_err(|e| format!("write {}: {}", dest_path, e))?;
    Ok(())
}

// =====================================================================
// relay
// =====================================================================

/// Snapshot of the I2P transport state for the security dashboard.
#[derive(Serialize)]
pub struct I2pStatus {
    /// True iff the I2P runtime is up: i2pd subprocess running, master
    /// session created, inbound accept loop and queue worker active.
    pub ready: bool,
    /// Our public destination (base64). Empty string when not ready —
    /// the frontend renders "—" rather than displaying the empty value.
    pub destination: String,
    /// Master STREAM session ID (uuid). Useful for diagnostics; not
    /// secret. Empty when not ready.
    pub session_id: String,
    /// SAM bridge address (e.g. `127.0.0.1:49243`). Useful for
    /// diagnostics; the random ephemeral port confirms Mod #1 is in
    /// effect. Empty when not ready.
    pub sam_addr: String,
    /// Path to the per-profile i2pd log file. The dashboard renders
    /// this as a clickable open-in-Console link.
    pub log_path: String,
    /// Cached outbound stream count — non-zero means there's at least
    /// one active conversation tunnel held warm for keep-alive.
    pub cached_outbound_streams: usize,
    /// 1-based bootstrap attempt counter. Stays at the final value
    /// after success so the UI can render "ready on attempt 3" if it
    /// wants. 0 before the first attempt has begun.
    pub bootstrap_attempt: u32,
    /// Last bootstrap error seen; cleared on the success of a later
    /// attempt. None when ready or when no failure has occurred yet.
    pub bootstrap_last_error: Option<String>,
    /// True while a bootstrap attempt is currently in flight (i2pd
    /// spawning, SAM probe, session creation, …).
    pub bootstrap_in_flight: bool,
}

/// Opt the user in (or out) of contributing to I2P transit routing.
/// Setting takes effect on the next vault unlock — i2pd has to restart
/// to reconfigure transit. We don't auto-restart here because that's
/// disruptive; the dashboard surfaces a "restart i2pd to apply" hint
/// when this changes.
#[tauri::command]
pub async fn i2p_set_transit_optin(
    enabled: bool,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    rt.db
        .settings_put("i2p_enable_transit", if enabled { "1" } else { "0" })
        .map_err(err)?;
    tracing::info!("i2p: transit opt-in set to {enabled} (effective on next unlock)");
    Ok(())
}

/// Read the user's current transit opt-in preference. `false` until
/// they explicitly toggle it on (Mod #1 default).
#[tauri::command]
pub async fn i2p_get_transit_optin(
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<bool> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    Ok(rt
        .db
        .settings_get("i2p_enable_transit")
        .map_err(err)?
        .map(|v| v == "1")
        .unwrap_or(false))
}

/// Read the persisted i2p-source preference. Defaults to `Bundled`.
/// Vault-lock-state independent: the preference lives in a plaintext
/// JSON in the profile dir so the pre-warm path (which runs before
/// the vault is unlocked) can read it too.
#[tauri::command]
pub async fn i2p_get_source() -> CmdResult<crate::transport::i2p::manager::I2pSource> {
    let profile_dir = crate::profile::data_dir();
    Ok(crate::transport::i2p::runtime::read_persisted_source(&profile_dir))
}

/// Persist a new i2p-source preference. Takes effect on the next vault
/// unlock — i2pd needs to be re-spawned (or, in External mode, the
/// SAM connection needs to be re-established against a different
/// endpoint). The UI tells the user a restart is required.
///
/// Always runs a `test_source` probe first so a user can't lock
/// themselves into an unreachable configuration. The probe runs with a
/// 5s timeout for external (long enough for a healthy local router,
/// short enough to fail fast on a typo'd host); Bundled mode skips the
/// probe — its readiness check happens at spawn time on next unlock.
#[tauri::command]
pub async fn i2p_set_source(
    source: crate::transport::i2p::manager::I2pSource,
) -> CmdResult<()> {
    use crate::transport::i2p::manager::I2pSource;

    if let I2pSource::External { host, port } = &source {
        probe_external_sam(host, *port, std::time::Duration::from_secs(5))
            .await
            .map_err(|e| {
                format!(
                    "cannot reach external SAM bridge at {host}:{port}: {e} \
                     — settings not saved"
                )
            })?;
    }

    let profile_dir = crate::profile::data_dir();
    crate::transport::i2p::runtime::write_persisted_source(&profile_dir, &source)
        .map_err(|e| format!("failed to persist i2p source preference: {e}"))?;
    tracing::info!(
        "i2p: source preference saved ({}) — effective on next vault unlock",
        match &source {
            I2pSource::Bundled => "bundled".to_string(),
            I2pSource::External { host, port } => format!("external {host}:{port}"),
        }
    );
    Ok(())
}

/// Test whether a given i2p source is reachable WITHOUT persisting it.
/// Drives the "Test connection" button in Settings → Security.
/// Bundled mode: verifies the bundled binary exists and passes the
/// integrity pin (the same checks `pre_start` does, minus the actual
/// spawn). External mode: opens a SAM HELLO with a 5s timeout.
#[tauri::command]
pub async fn i2p_test_source(
    source: crate::transport::i2p::manager::I2pSource,
) -> CmdResult<()> {
    use crate::transport::i2p::manager::I2pSource;
    match source {
        I2pSource::Bundled => {
            // We can verify the binary exists + the SHA-256 manifest
            // matches. We don't try to spawn it here — that would be
            // 10-30s of wait for a no-op test button.
            crate::transport::i2p::manager::verify_bundled_for_test()
                .map_err(|e| format!("bundled i2pd integrity check failed: {e}"))?;
            Ok(())
        }
        I2pSource::External { host, port } => {
            probe_external_sam(&host, port, std::time::Duration::from_secs(5))
                .await
                .map_err(|e| format!("SAM probe at {host}:{port} failed: {e}"))
        }
    }
}

/// Connect to a SAM v3 bridge and run HELLO. Internal helper for the
/// set/test commands; bounded by `timeout` so a typo'd host can't hang
/// the UI for the full TCP connect backoff.
async fn probe_external_sam(
    host: &str,
    port: u16,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let addr = format!("{host}:{port}");
    tokio::time::timeout(
        timeout,
        crate::transport::i2p::manager::sam_hello_probe(&addr),
    )
    .await
    .map_err(|_| format!("timed out after {}s", timeout.as_secs()))?
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn i2p_status(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<I2pStatus> {
    let runtime = {
        let slot = state.i2p.lock().await;
        slot.as_ref().cloned()
    };
    let bs = state.i2p_bootstrap.lock().clone();
    match runtime {
        Some(rt) => {
            let cached_outbound_streams = rt.connection.cached_outbound_count().await;
            Ok(I2pStatus {
                ready: true,
                destination: rt.manager.destination_pub().to_string(),
                session_id: rt.manager.session_id().to_string(),
                sam_addr: rt.manager.sam_addr().to_string(),
                log_path: rt
                    .manager
                    .log_path()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                cached_outbound_streams,
                bootstrap_attempt: bs.attempt,
                bootstrap_last_error: bs.last_error,
                bootstrap_in_flight: bs.in_flight,
            })
        }
        None => Ok(I2pStatus {
            ready: false,
            destination: String::new(),
            session_id: String::new(),
            sam_addr: String::new(),
            log_path: String::new(),
            cached_outbound_streams: 0,
            bootstrap_attempt: bs.attempt,
            bootstrap_last_error: bs.last_error,
            bootstrap_in_flight: bs.in_flight,
        }),
    }
}

fn me_pubkey(state: &tauri::State<'_, std::sync::Arc<AppState>>) -> Option<[u8; 32]> {
    let guard = state.vault.lock();
    guard
        .as_ref()
        .map(|rt| rt.identity.keys.ed25519_verifying().to_bytes())
}

/// Tauri's `State<T>` borrows from the manager so it can't outlive the
/// command's lifetime. The pump needs an owned handle to the state, which we
/// get by calling `app.state::<AppState>()` and then upgrading to an `Arc`
/// via Tauri's runtime; until that lands cleanly we just clone enough of the
/// pieces the pump actually needs into a fresh struct. Practical workaround:
/// the `AppState` itself is wrapped in `tauri::State<AppState>` which is
/// internally backed by an `Arc<AppState>` inside Tauri's `StateManager`;
/// `app.state::<AppState>()` returns a fresh handle valid for the lifetime
/// of `app`, which the pump captures into the spawned `tokio::spawn`.
fn state_arc_for_pump(_app: &tauri::AppHandle) -> std::sync::Arc<AppState> {
    SHARED_STATE
        .get()
        .cloned()
        .unwrap_or_else(|| panic!("AppState arc not initialized; call install_shared_state() in setup"))
}

static SHARED_STATE: once_cell::sync::OnceCell<std::sync::Arc<AppState>> =
    once_cell::sync::OnceCell::new();

/// Called from `lib.rs::run` setup hook to install the same `AppState` Tauri
/// is managing into a process-global `Arc` we can hand to background tasks.
pub fn install_shared_state(arc: std::sync::Arc<AppState>) {
    let _ = SHARED_STATE.set(arc);
}

/// Lookup of the shared `AppState` from background tasks (the inbound pump,
/// the room sender-key fan-out). Returns `None` before `install_shared_state`
/// has been called.
pub fn shared_state() -> Option<std::sync::Arc<AppState>> {
    SHARED_STATE.get().cloned()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NotificationPrefs {
    pub enabled: bool,
    pub show_preview: bool,
    pub sound: bool,
}

#[tauri::command]
pub async fn notifications_get(
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<NotificationPrefs> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let read = |k: &str, default_val: bool| -> bool {
        match rt.db.settings_get(k).ok().flatten().as_deref() {
            Some("0") => false,
            Some("1") => true,
            _ => default_val,
        }
    };
    Ok(NotificationPrefs {
        enabled: read("notify_enabled", true),
        show_preview: read("notify_show_preview", true),
        sound: read("notify_sound", true),
    })
}

#[tauri::command]
pub async fn notifications_set(
    prefs: NotificationPrefs,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<()> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let put = |k: &str, v: bool| -> Result<(), String> {
        rt.db
            .settings_put(k, if v { "1" } else { "0" })
            .map_err(err)
    };
    put("notify_enabled", prefs.enabled)?;
    put("notify_show_preview", prefs.show_preview)?;
    put("notify_sound", prefs.sound)?;
    Ok(())
}

/// Fire a test notification so users can confirm OS permissions work.
#[tauri::command]
pub async fn notifications_test(app: tauri::AppHandle) -> CmdResult<()> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title("Whisper")
        .body("Notifications are working.")
        .sound("default")
        .show()
        .map_err(err)
}

/// Snapshot of per-URL transient relay activity. Used by the InfoPanel to
/// show users which non-home relays they've used and whether any of those
/// calls failed.
#[derive(Serialize)]
pub struct MessageHit {
    pub message_id: String,
    pub conversation_id: String,
    pub conversation_label: String,
    pub sender_alias: String,
    pub snippet: String,
    pub created_at: i64,
}

/// Full-text search across decrypted message plaintext. Decrypts each row's
/// TEE-encrypted envelope on the fly and case-insensitively matches the
/// query against the contained text. Attachment-only rows are excluded.
/// Returns up to `limit` hits, newest first.
#[tauri::command]
pub async fn messages_search(
    query: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Vec<MessageHit>> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return Ok(Vec::new());
    }
    let q_lower = q_trim.to_lowercase();
    let limit: usize = 50;

    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let conversations = rt.db.list_conversations().map_err(err)?;

    let mut hits: Vec<MessageHit> = Vec::new();
    for conv in &conversations {
        let label = match conv.kind.as_str() {
            "room" => conv.room_name.clone().unwrap_or_else(|| "Room".into()),
            _ => conv
                .contact_alias
                .clone()
                .unwrap_or_else(|| "Direct message".into()),
        };
        let rows = rt
            .db
            .load_messages_encrypted(&conv.id, 1_000)
            .map_err(err)?;
        for r in rows {
            if r.is_attachment {
                continue;
            }
            let Some(blob) = r.tee_encrypted_content.as_ref() else {
                continue;
            };
            let env = match crate::crypto::tee_encryption::decrypt_for_conversation(
                conv.id.as_bytes(),
                blob,
            ) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let text = match crate::crypto::message_crypto::decode_envelope(&env) {
                Ok(crate::crypto::message_crypto::DecodedEnvelope::Text { text, .. }) => text,
                Ok(crate::crypto::message_crypto::DecodedEnvelope::DetonatingText { text, .. }) => {
                    text
                }
                _ => continue,
            };
            if !text.to_lowercase().contains(&q_lower) {
                continue;
            }
            let snippet = build_snippet(&text, &q_lower);
            hits.push(MessageHit {
                message_id: r.id,
                conversation_id: conv.id.clone(),
                conversation_label: label.clone(),
                sender_alias: r.sender_alias,
                snippet,
                created_at: r.created_at,
            });
        }
    }
    hits.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    hits.truncate(limit);
    Ok(hits)
}

/// Tight context around the first match: roughly 30 chars before and 60 after.
fn build_snippet(text: &str, query_lower: &str) -> String {
    let lower = text.to_lowercase();
    let Some(idx) = lower.find(query_lower) else {
        return text.chars().take(120).collect();
    };
    // Convert byte index to character-aligned bounds.
    let start_byte = idx.saturating_sub(30);
    let end_byte = (idx + query_lower.len() + 60).min(text.len());
    let start = floor_char_boundary(text, start_byte);
    let end = floor_char_boundary(text, end_byte);
    let prefix = if start > 0 { "…" } else { "" };
    let suffix = if end < text.len() { "…" } else { "" };
    format!("{}{}{}", prefix, &text[start..end], suffix)
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

// =====================================================================
// dashboard
// =====================================================================

#[derive(Serialize)]
pub struct SecurityStatus {
    pub vault_unlocked: bool,
    pub hardware_tier: HardwareTier,
}

#[tauri::command]
pub async fn security_status(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<SecurityStatus> {
    Ok(SecurityStatus {
        vault_unlocked: state.is_unlocked(),
        hardware_tier: secure_enclave::detect_tier(),
    })
}

/// Enumerate the network sockets owned by the Whisper process and
/// classify each as expected (loopback to our SAM bridge) or
/// unexpected (anything else).  The expected count is always exactly
/// one when the I2P runtime is up and idle: a single TCP stream from
/// us to `127.0.0.1:<sam_port>`.  Anything beyond that is worth
/// investigating — surface this view in Settings → Security.
#[tauri::command]
pub async fn egress_audit(
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<crate::security::egress::EgressAudit> {
    let (sam_addr, i2pd_pid) = {
        let slot = state.i2p.lock().await;
        match slot.as_ref() {
            Some(rt) => (
                Some(rt.manager.sam_addr().to_string()),
                rt.manager.child_pid(),
            ),
            None => (None, None),
        }
    };
    let audit = crate::security::egress::audit_self(sam_addr.as_deref(), i2pd_pid);
    Ok(audit)
}

// Suppress unused-import warnings while the rest of the surface settles.
#[allow(dead_code)]
const _ALIAS: fn(&[u8; 32]) -> String = derive_alias;
