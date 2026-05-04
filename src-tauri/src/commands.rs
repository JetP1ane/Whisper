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
use crate::transport::bundle_registry;
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

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Look up the stored TLS SPKI pin for a given relay URL. `None` means
/// either the URL is plaintext (`ws://`) or we have not yet performed a
/// TOFU handshake with this relay.
fn lookup_relay_pin(
    state: &tauri::State<'_, std::sync::Arc<AppState>>,
    relay_url: &str,
) -> Option<[u8; 32]> {
    let guard = state.vault.lock();
    let rt = guard.as_ref()?;
    let hex_str = rt
        .db
        .settings_get(&crate::transport::relay::pin_settings_key(relay_url))
        .ok()
        .flatten()?;
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

/// Record the outcome of a transient deposit into per-relay stats so the
/// UI can show users which relays they've actually been hitting and
/// whether any of those calls failed.
fn record_transient_deposit(
    state: &tauri::State<'_, std::sync::Arc<AppState>>,
    relay_url: &str,
    result: &crate::transport::TransportResult<Option<[u8; 32]>>,
) {
    use crate::transport::cross_relay_stats::{classify_transport_error, RelayCallStatus};
    let status = match result {
        Ok(_) => RelayCallStatus::Ok,
        Err(e) => classify_transport_error(e),
    };
    state.cross_relay.record_deposit(relay_url, status);
}

/// Persist the captured pin for a relay URL only when no pin was stored
/// before this call. Mismatch cases never reach this path because the
/// rustls verifier rejects the handshake before we observe a captured pin.
fn persist_relay_pin_if_new(
    state: &tauri::State<'_, std::sync::Arc<AppState>>,
    relay_url: &str,
    expected_pin: Option<[u8; 32]>,
    captured_pin: Option<[u8; 32]>,
) {
    if expected_pin.is_some() {
        return;
    }
    let Some(pin) = captured_pin else { return };
    let guard = state.vault.lock();
    if let Some(rt) = guard.as_ref() {
        let _ = rt.db.settings_put(
            &crate::transport::relay::pin_settings_key(relay_url),
            &hex::encode(pin),
        );
        tracing::info!(
            "TOFU pin captured for transient relay {}: {}…",
            relay_url,
            &hex::encode(pin)[..16]
        );
    }
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
) -> CmdResult<VaultSetupResult> {
    setup_or_restore(passphrase, None, state).await
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
                .map_err(|e| anyhow!("passphrase incorrect"))?;
            Ok(())
        }
    })
    .await
    .map_err(err)?;
    dek_check.map_err(err)?;

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
#[tauri::command]
pub async fn vault_recover_from_seed(
    passphrase: String,
    recovery_phrase: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<VaultSetupResult> {
    setup_or_restore(passphrase, Some(recovery_phrase), state).await
}

async fn setup_or_restore(
    passphrase: String,
    existing_phrase: Option<String>,
    state: State<'_, std::sync::Arc<AppState>>,
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
    if passphrase.len() < 8 {
        return Err("passphrase too short".into());
    }
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
            rand::thread_rng().fill_bytes(&mut db_seed);
            rand::thread_rng().fill_bytes(&mut tee_seed);
            rand::thread_rng().fill_bytes(&mut manifest_seed_arr);

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

            let mfst_pub =
                crate::crypto::config_manifest::verifying_key_from_seed(&manifest_seed_arr);
            db.settings_put("manifest_verifying_key", &hex::encode(mfst_pub))?;

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
    Ok(VaultSetupResult {
        recovery_phrase,
        alias,
    })
}

#[tauri::command]
pub async fn vault_unlock(passphrase: String, state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<()> {
    if state.is_unlocked() {
        return Ok(());
    }
    if !keychain::vault_initialized() {
        return Err("vault not initialized".into());
    }
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
    .map_err(err)?
    .map_err(err)?;

    *state.vault.lock() = Some(result);
    Ok(())
}

#[tauri::command]
pub async fn vault_lock(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<()> {
    let mut guard = state.vault.lock();
    if let Some(rt) = guard.take() {
        rt.db.close();
    }
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

#[tauri::command]
pub async fn identity_publish_bundle(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<()> {
    let (alias, bytes, relay_url) = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| {
            tracing::warn!("publish_bundle: vault locked");
            "vault locked".to_string()
        })?;
        let bundle = identity::build_published_bundle(&rt.db, &rt.identity).map_err(|e| {
            tracing::error!("publish_bundle: build_published_bundle failed: {e}");
            err(e)
        })?;
        let alias = rt.identity.alias.clone();
        let url = state.relay.current_url().ok_or_else(|| {
            tracing::warn!("publish_bundle: no relay configured");
            "no relay configured".to_string()
        })?;
        (alias, bundle::serialize(&bundle), url)
    };
    tracing::info!(
        "publish_bundle: PUT {} bytes to relay {} for alias `{}`",
        bytes.len(),
        relay_url,
        alias
    );
    bundle_registry::put_bundle(&relay_url, &alias, &bytes)
        .await
        .map_err(|e| {
            tracing::error!("publish_bundle: PUT failed: {e}");
            err(e)
        })?;
    tracing::info!("publish_bundle: success for `{}`", alias);
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

#[tauri::command]
pub async fn contact_add_by_alias(
    alias: String,
    nickname: Option<String>,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Contact> {
    let relay_url = state.relay.current_url().ok_or("no relay configured")?;
    let bundle = bundle_registry::get_bundle(&relay_url, &alias)
        .await
        .map_err(err)?
        .ok_or_else(|| format!("no bundle for alias `{alias}`"))?;
    let mut contact = persist_bundle_as_contact(&state, bundle, Some(relay_url))?;
    if let Some(n) = nickname.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        {
            let guard = state.vault.lock();
            let rt = guard.as_ref().ok_or("vault locked")?;
            rt.db.set_contact_nickname(&contact.id, Some(n)).map_err(err)?;
        }
        contact.nickname = Some(n.to_string());
    }
    if let Err(e) = announce_to_new_contact(&state, &contact).await {
        tracing::warn!("contact-request announce failed: {e:#}");
    }
    Ok(contact)
}

#[tauri::command]
pub async fn contact_add_by_link(
    link: String,
    nickname: Option<String>,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Contact> {
    let bundle = bundle::parse_whisper_link(&link).map_err(err)?;
    let mut contact = persist_bundle_as_contact(&state, bundle, state.relay.current_url())?;
    if let Some(n) = nickname.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        {
            let guard = state.vault.lock();
            let rt = guard.as_ref().ok_or("vault locked")?;
            rt.db.set_contact_nickname(&contact.id, Some(n)).map_err(err)?;
        }
        contact.nickname = Some(n.to_string());
    }
    if let Err(e) = announce_to_new_contact(&state, &contact).await {
        tracing::warn!("contact-request announce failed: {e:#}");
    }
    Ok(contact)
}

/// Deposit a contact-request envelope (`[0xCF,0xC0,0xDE,0x01] || my_bundle`)
/// on the new contact's mailbox, prefixed with our sender mailbox so they
/// can identify it. Routes to the contact's home relay when it differs from
/// our own (cross-relay messaging). Best-effort — failures are logged.
async fn announce_to_new_contact(
    state: &State<'_, std::sync::Arc<AppState>>,
    contact: &Contact,
) -> anyhow::Result<()> {
    use crate::transport::envelopes::wrap_contact_request;
    use crate::transport::mailbox;

    let (my_bundle_bytes, sender_mb_hex, recipient_mb_hex) = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or_else(|| anyhow!("vault locked"))?;
        let my_bundle = identity::build_published_bundle(&rt.db, &rt.identity)?;
        let bytes = bundle::serialize(&my_bundle);

        let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
        let sender = mailbox::hex(&mailbox::current_mailbox(&me_pub));
        let recipient = mailbox::hex(&mailbox::current_mailbox(&contact.ed25519_public));
        (bytes, sender, recipient)
    };

    let envelope = wrap_contact_request(&my_bundle_bytes);
    let mut blob = Vec::with_capacity(32 + envelope.len());
    blob.extend_from_slice(sender_mb_hex.as_bytes());
    blob.extend_from_slice(&envelope);

    let msg_id = Uuid::new_v4().to_string();
    let home = state.relay.current_url();
    let target = match contact.relay_url.as_deref() {
        Some(c) if !c.is_empty() && Some(c) != home.as_deref() => Some(c.to_string()),
        _ => None,
    };

    match target {
        Some(url) => {
            tracing::info!(
                "contact-request: cross-relay deposit to {} for `{}`",
                url,
                contact.alias
            );
            let pin = lookup_relay_pin(&state, &url);
            let result = crate::transport::relay::transient_deposit(
                &url,
                &recipient_mb_hex,
                &blob,
                60 * 60 * 24,
                std::time::Duration::from_secs(10),
                pin,
            )
            .await;
            record_transient_deposit(&state, &url, &result);
            let captured = result.map_err(|e| anyhow!("transient deposit: {e}"))?;
            persist_relay_pin_if_new(&state, &url, pin, captured);
        }
        None => {
            state
                .relay
                .deposit(recipient_mb_hex.clone(), &blob, 60 * 60 * 24, msg_id)
                .map_err(|e| anyhow!("deposit contact request: {e}"))?;
        }
    }
    tracing::info!(
        "contact-request: deposited {} bytes for `{}` (mailbox `{}`)",
        blob.len(),
        contact.alias,
        recipient_mb_hex
    );
    Ok(())
}

fn persist_bundle_as_contact(
    state: &State<'_, std::sync::Arc<AppState>>,
    bundle: bundle::PublicKeyBundle,
    fallback_relay_url: Option<String>,
) -> CmdResult<Contact> {
    let guard = state.vault.lock();
    let rt = guard.as_ref().ok_or("vault locked")?;
    let now = now_unix_ms();
    // Prefer the relay URL the bundle owner *signed*; fall back only when
    // the bundle predates v2 or has an empty value.
    let relay_url = if bundle.relay_url.is_empty() {
        fallback_relay_url
    } else {
        Some(bundle.relay_url.clone())
    };
    let contact = Contact {
        id: Uuid::new_v4().to_string(),
        alias: bundle.alias.clone(),
        ed25519_public: bundle.identity_key.to_vec(),
        x25519_public: bundle.x25519_key.to_vec(),
        mlkem_public: bundle.kyber_key.clone(),
        relay_url,
        verified: false,
        peer_has_verified_us: false,
        hide_until_verified: false,
        is_sealed: false,
        nickname: None,
        created_at: now,
        updated_at: now,
    };
    rt.db.upsert_contact(&contact).map_err(err)?;

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
    pub created_at: i64,
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
}

#[tauri::command]
pub async fn conversation_security_summary(
    conversation_id: String,
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<ConversationSecurity> {
    use crate::messaging::ratchet_store;

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

    // Safety numbers + peer fingerprint.
    let me_pub = rt.identity.keys.ed25519_verifying().to_bytes();
    let (peer_alias, peer_id_hex, sn) = if let Some(c) = contact.as_ref() {
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&c.ed25519_public[..32]);
        let digits = safety_numbers::safety_numbers(&me_pub, &peer);
        let sn = SafetyNumbers {
            digits,
            formatted: safety_numbers::format_safety_numbers(&digits),
            hex_fingerprint: safety_numbers::hex_fingerprint(&peer),
        };
        (Some(c.alias.clone()), Some(hex::encode_upper(peer)), sn)
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

    Ok(ConversationSecurity {
        conversation_id,
        peer_alias,
        peer_id_hex,
        aead: "ChaCha20-Poly1305",
        kex_classical: "X25519",
        kex_pq: if has_pq { Some("ML-KEM-1024") } else { None },
        kdf: "HKDF-SHA256",
        identity_sig: "Ed25519",
        messages_sent,
        messages_received,
        ratchet_send_chain_n: send_n,
        ratchet_recv_chain_n: recv_n,
        ratchet_prev_chain_len: prev_n,
        skipped_keys_cached: skipped,
        session_established: established,
        is_verified: contact.as_ref().map(|c| c.verified).unwrap_or(false),
        peer_has_verified_us: contact
            .as_ref()
            .map(|c| c.peer_has_verified_us)
            .unwrap_or(false),
        is_sealed: conv.is_sealed,
        disappear_timer_secs: conv.disappear_timer,
        hardware_tier: secure_enclave::detect_tier(),
        safety_numbers: sn,
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
            created_at: r.created_at,
        });
    }
    Ok(out)
}

#[tauri::command]
pub async fn message_send(
    conversation_id: String,
    text: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<String> {
    let (contact, conversation, contact_bundle) = {
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
        // Reconstruct a minimal bundle for ratchet bootstrap. For accuracy we
        // need to fetch the peer's full bundle the first time we message them
        // (cached after first send). For now, hit the relay every time.
        let relay_url = contact
            .relay_url
            .clone()
            .or_else(|| state.relay.current_url())
            .ok_or("no relay URL")?;
        (contact, conv, relay_url)
    };

    // Fetch the bundle outside the vault lock (network I/O) — we only need
    // it on the first message, but reusing it is harmless.
    let bundle = bundle_registry::get_bundle(&contact_bundle, &contact.alias)
        .await
        .map_err(err)?
        .ok_or_else(|| format!("no bundle for {}", contact.alias))?;

    // Prepare the encrypted blob synchronously (DB writes), then deposit
    // either via the home relay (fast path) or via a transient WebSocket to
    // the contact's home relay (cross-relay).
    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let home = state.relay.current_url();
        sender::prepare_send_text(
            &rt.db,
            &rt.identity,
            &contact,
            &bundle,
            &conversation.id,
            &text,
            home.as_deref(),
        )
        .map_err(err)?
    };

    match prepared.target_relay_url.as_deref() {
        Some(target) => {
            tracing::info!(
                "message_send: cross-relay deposit to {} for {}",
                target,
                contact.alias
            );
            let pin = lookup_relay_pin(&state, target);
            let result = crate::transport::relay::transient_deposit(
                target,
                &prepared.mailbox_hex,
                &prepared.blob,
                60 * 60 * 24,
                std::time::Duration::from_secs(10),
                pin,
            )
            .await;
            record_transient_deposit(&state, target, &result);
            let captured = result.map_err(err)?;
            persist_relay_pin_if_new(&state, target, pin, captured);
            // Cross-relay deposits have no persistent home `Deposited`
            // event, so flip status to `sent` directly here.
            {
                let guard = state.vault.lock();
                let rt = guard.as_ref().ok_or("vault locked")?;
                let _ = rt.db.set_message_status(&prepared.msg_id, "sent");
            }
            #[derive(Serialize, Clone)]
            struct StatusEvt<'a> {
                message_id: &'a str,
                status: &'a str,
            }
            use tauri::Emitter;
            let _ = app.emit(
                "message:status",
                StatusEvt {
                    message_id: &prepared.msg_id,
                    status: "sent",
                },
            );
        }
        None => {
            // Same-relay fast path: ride the persistent home connection.
            let _ = state.relay.deposit(
                prepared.mailbox_hex.clone(),
                &prepared.blob,
                60 * 60 * 24,
                prepared.msg_id.clone(),
            );
        }
    }

    Ok(prepared.message.id)
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
    let (contact, conversation, contact_bundle) = {
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
        let relay_url = contact
            .relay_url
            .clone()
            .or_else(|| state.relay.current_url())
            .ok_or("no relay URL")?;
        (contact, conv, relay_url)
    };

    let bundle = bundle_registry::get_bundle(&contact_bundle, &contact.alias)
        .await
        .map_err(err)?
        .ok_or_else(|| format!("no bundle for {}", contact.alias))?;

    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let home = state.relay.current_url();
        sender::prepare_send_detonating_text(
            &rt.db,
            &rt.identity,
            &contact,
            &bundle,
            &conversation.id,
            &text,
            detonate_secs,
            home.as_deref(),
        )
        .map_err(err)?
    };

    // Clamp relay TTL to the detonation window so the blob also disappears
    // server-side. Cap at 24h since that's the relay's max retention.
    let relay_ttl = (detonate_secs as u64).min(60 * 60 * 24);

    match prepared.target_relay_url.as_deref() {
        Some(target) => {
            tracing::info!(
                "message_send_detonating: cross-relay deposit to {} for {} (ttl={}s)",
                target,
                contact.alias,
                relay_ttl
            );
            let pin = lookup_relay_pin(&state, target);
            let result = crate::transport::relay::transient_deposit(
                target,
                &prepared.mailbox_hex,
                &prepared.blob,
                relay_ttl,
                std::time::Duration::from_secs(10),
                pin,
            )
            .await;
            record_transient_deposit(&state, target, &result);
            let captured = result.map_err(err)?;
            persist_relay_pin_if_new(&state, target, pin, captured);
            {
                let guard = state.vault.lock();
                let rt = guard.as_ref().ok_or("vault locked")?;
                let _ = rt.db.set_message_status(&prepared.msg_id, "sent");
            }
            #[derive(Serialize, Clone)]
            struct StatusEvt<'a> {
                message_id: &'a str,
                status: &'a str,
            }
            use tauri::Emitter;
            let _ = app.emit(
                "message:status",
                StatusEvt {
                    message_id: &prepared.msg_id,
                    status: "sent",
                },
            );
        }
        None => {
            let _ = state.relay.deposit(
                prepared.mailbox_hex.clone(),
                &prepared.blob,
                relay_ttl,
                prepared.msg_id.clone(),
            );
        }
    }

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
        build_aad, build_room_invite_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
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

        // Build the member-list pubkey vector for the invite payload.
        let mut member_pubs: Vec<[u8; 32]> = Vec::with_capacity(invitees.len() + 1);
        member_pubs.push(me_pub);
        for c in &invitees {
            let arr: [u8; 32] = c
                .ed25519_public
                .as_slice()
                .try_into()
                .map_err(|_| "contact ed25519 not 32 bytes".to_string())?;
            member_pubs.push(arr);
        }

        // 3. Per-invitee encrypted invite ready for deposit.
        let mut wires: Vec<(Vec<u8>, String, Option<String>)> = Vec::new();
        for c in &invitees {
            let envelope = build_room_invite_envelope(
                now as u64,
                &room_id_bytes,
                &name,
                "",
                &owner_seed,
                &member_pubs,
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
            let wire = pack_text_wire(&RatchetWire {
                ratchet_key: &enc.ratchet_key,
                prev_chain_len: enc.prev_chain_len,
                msg_num: enc.msg_num,
                nonce: &enc.nonce,
                ciphertext: &enc.ciphertext,
                sentinel_digest: None,
            })
            .map_err(err)?;
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
            wires.push((blob, recipient_mb_hex, c.relay_url.clone()));
        }
        wires
    };

    // Async fan-out: deposit each invite either via the home WS or a
    // transient connection to the invitee's relay.
    let home = state.relay.current_url();
    for (blob, recipient_mb_hex, target) in prepared {
        let cross = match (target.as_deref(), home.as_deref()) {
            (Some(t), Some(h)) if !t.is_empty() && t != h => Some(t.to_string()),
            (Some(t), None) if !t.is_empty() => Some(t.to_string()),
            _ => None,
        };
        match cross {
            Some(url) => {
                let pin = lookup_relay_pin(&state, &url);
                let result = crate::transport::relay::transient_deposit(
                    &url,
                    &recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    Duration::from_secs(10),
                    pin,
                )
                .await;
                record_transient_deposit(&state, &url, &result);
                if let Ok(captured) = result {
                    persist_relay_pin_if_new(&state, &url, pin, captured);
                }
            }
            None => {
                let _ = state.relay.deposit(
                    recipient_mb_hex.clone(),
                    &blob,
                    60 * 60 * 24,
                    uuid::Uuid::new_v4().to_string(),
                );
            }
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
    _app: tauri::AppHandle,
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

        // Outbound fan-out targets: every other member with a known contact.
        let members = rt.db.list_room_members(&room_id).map_err(err)?;
        let contacts = rt.db.list_contacts().map_err(err)?;
        let mut targets: Vec<(String, Option<String>, [u8; 32])> = Vec::new();
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
            targets.push((c.id.clone(), c.relay_url.clone(), pk));
        }

        let me_mb_hex = crate::transport::mailbox::hex(
            &crate::transport::mailbox::current_mailbox(&me_pub),
        );
        let mut blobs: Vec<(Vec<u8>, String, Option<String>)> = Vec::new();
        for (_cid, target_relay, peer_pub) in targets {
            let recipient_mb_hex = crate::transport::mailbox::hex(
                &crate::transport::mailbox::current_mailbox(&peer_pub),
            );
            let mut blob = Vec::with_capacity(32 + wire.len());
            blob.extend_from_slice(me_mb_hex.as_bytes());
            blob.extend_from_slice(&wire);
            blobs.push((blob, recipient_mb_hex, target_relay));
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

    let home = state.relay.current_url();
    for (blob, recipient_mb_hex, target) in prepared {
        let cross = match (target.as_deref(), home.as_deref()) {
            (Some(t), Some(h)) if !t.is_empty() && t != h => Some(t.to_string()),
            (Some(t), None) if !t.is_empty() => Some(t.to_string()),
            _ => None,
        };
        match cross {
            Some(url) => {
                let pin = lookup_relay_pin(&state, &url);
                let result = crate::transport::relay::transient_deposit(
                    &url,
                    &recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    Duration::from_secs(10),
                    pin,
                )
                .await;
                record_transient_deposit(&state, &url, &result);
                if let Ok(captured) = result {
                    persist_relay_pin_if_new(&state, &url, pin, captured);
                }
            }
            None => {
                let _ = state.relay.deposit(
                    recipient_mb_hex.clone(),
                    &blob,
                    60 * 60 * 24,
                    uuid::Uuid::new_v4().to_string(),
                );
            }
        }
    }

    {
        let guard = state.vault.lock();
        if let Some(rt) = guard.as_ref() {
            let _ = rt.db.set_message_status(&msg_id, "sent");
        }
    }
    Ok(msg_id)
}

/// Send a file attachment. Reads the bytes from `source_path`, encrypts +
/// transmits via the same ratchet path as text, and stores the bytes
/// at-rest under `<profile>/attachments/<msg_id>.bin` (TEE-encrypted) so
/// the sender can re-open the file later.
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

    let (contact, conversation, contact_relay) = {
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
        let relay_url = contact
            .relay_url
            .clone()
            .or_else(|| state.relay.current_url())
            .ok_or("no relay URL")?;
        (contact, conv, relay_url)
    };
    let bundle = bundle_registry::get_bundle(&contact_relay, &contact.alias)
        .await
        .map_err(err)?
        .ok_or_else(|| format!("no bundle for {}", contact.alias))?;

    let prepared = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let home = state.relay.current_url();
        sender::prepare_send_attachment(
            &rt.db,
            &rt.identity,
            &contact,
            &bundle,
            &conversation.id,
            &filename,
            &mime,
            &bytes,
            home.as_deref(),
        )
        .map_err(err)?
    };

    let profile_dir = crate::profile::data_dir();
    if let Err(e) =
        attachments::store(&profile_dir, &prepared.msg_id, &conversation.id, &bytes)
    {
        tracing::warn!("attachment_store (sender side) failed: {e}");
    }

    match prepared.target_relay_url.as_deref() {
        Some(target) => {
            let pin = lookup_relay_pin(&state, target);
            let result = crate::transport::relay::transient_deposit(
                target,
                &prepared.mailbox_hex,
                &prepared.blob,
                60 * 60 * 24,
                std::time::Duration::from_secs(15),
                pin,
            )
            .await;
            record_transient_deposit(&state, target, &result);
            let captured = result.map_err(err)?;
            persist_relay_pin_if_new(&state, target, pin, captured);
            {
                let guard = state.vault.lock();
                let rt = guard.as_ref().ok_or("vault locked")?;
                let _ = rt.db.set_message_status(&prepared.msg_id, "sent");
            }
            use tauri::Emitter;
            let _ = app.emit(
                "message:status",
                serde_json::json!({ "message_id": &prepared.msg_id, "status": "sent" }),
            );
        }
        None => {
            let _ = state.relay.deposit(
                prepared.mailbox_hex.clone(),
                &prepared.blob,
                60 * 60 * 24,
                prepared.msg_id.clone(),
            );
        }
    }
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

#[derive(Serialize)]
pub struct RelayStatus {
    pub url: Option<String>,
    pub connected: bool,
    pub frame_counters: crate::transport::frame_accounting::Snapshot,
}

#[tauri::command]
pub async fn relay_status(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<RelayStatus> {
    Ok(RelayStatus {
        url: state.relay.current_url(),
        connected: state.relay.current_url().is_some(),
        frame_counters: state.relay.counters().snapshot(),
    })
}

/// Change the home relay URL: persist, re-sign manifest, reconnect, and
/// broadcast `relay_update` envelopes to every contact so they route future
/// deposits to the new URL. Records the previous URL to enable 14-day
/// grace-period polling.
#[tauri::command]
pub async fn relay_change_url(
    new_url: String,
    state: State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    if !(new_url.starts_with("ws://") || new_url.starts_with("wss://")) {
        return Err("relay URL must start with ws:// or wss://".into());
    }
    relay_connect(new_url.clone(), state.clone(), app.clone()).await?;
    if let Err(e) = identity_publish_bundle(state.clone()).await {
        tracing::warn!("relay_change_url: bundle republish failed: {e}");
    }

    use crate::crypto::message_crypto::{
        build_aad, build_relay_update_envelope, pack_text_wire, pad_pkcs7, RatchetWire,
    };
    use crate::crypto::ratchet;
    use crate::crypto::PAD_BLOCK;
    use crate::messaging::ratchet_store;
    use crate::transport::mailbox;
    use std::time::Duration;

    let now_ms = now_unix_ms();
    let (contacts, me_pub) = {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        (
            rt.db.list_contacts().map_err(err)?,
            rt.identity.keys.ed25519_verifying().to_bytes(),
        )
    };
    let sender_mb_hex = mailbox::hex(&mailbox::current_mailbox(&me_pub));

    for contact in contacts {
        let envelope = build_relay_update_envelope(now_ms as u64, &new_url);
        let padded = pad_pkcs7(&envelope, PAD_BLOCK);

        let prepared = {
            let guard = state.vault.lock();
            let rt = match guard.as_ref() {
                Some(rt) => rt,
                None => break,
            };
            let mut ratchet_state = match ratchet_store::load(&rt.db, &contact.id).ok().flatten() {
                Some(s) => s,
                None => continue,
            };
            let enc = match ratchet::encrypt_message(&mut ratchet_state, &padded, build_aad) {
                Ok(e) => e,
                Err(_) => continue,
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
            let _ = ratchet_store::save(&rt.db, &contact.id, &ratchet_state);

            let recipient_mb_hex =
                mailbox::hex(&mailbox::current_mailbox(&contact.ed25519_public));
            let mut blob = Vec::with_capacity(32 + wire.len());
            blob.extend_from_slice(sender_mb_hex.as_bytes());
            blob.extend_from_slice(&wire);
            (blob, recipient_mb_hex, contact.relay_url.clone())
        };

        let (blob, recipient_mb_hex, target) = prepared;
        let home = state.relay.current_url();
        let cross = match (target.as_deref(), home.as_deref()) {
            (Some(t), Some(h)) if !t.is_empty() && t != h => Some(t.to_string()),
            (Some(t), None) if !t.is_empty() => Some(t.to_string()),
            _ => None,
        };
        match cross {
            Some(url) => {
                let pin = lookup_relay_pin(&state, &url);
                let result = crate::transport::relay::transient_deposit(
                    &url,
                    &recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    Duration::from_secs(10),
                    pin,
                )
                .await;
                record_transient_deposit(&state, &url, &result);
                if let Ok(captured) = result {
                    persist_relay_pin_if_new(&state, &url, pin, captured);
                }
            }
            None => {
                let _ = state.relay.deposit(
                    recipient_mb_hex,
                    &blob,
                    60 * 60 * 24,
                    uuid::Uuid::new_v4().to_string(),
                );
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn relay_set_url(url: String, _state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<()> {
    // Minimal: accept any ws/wss URL. The signed-manifest flow is layered on
    // later when Secure Enclave signing lands.
    if !(url.starts_with("ws://") || url.starts_with("wss://")) {
        return Err("relay URL must start with ws:// or wss://".into());
    }
    keychain::write(keychain::ACCOUNT_DB_PATH, url.as_bytes()).map_err(err)?;
    Ok(())
}

#[tauri::command]
pub async fn relay_connect(
    url: String,
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
) -> CmdResult<()> {
    tracing::info!("relay_connect: connecting to {}", url);

    // ===== Record this URL as the home relay (drives bundle.relay_url). =====
    // Detect URL change vs. previously-stored home: if it changed, kick off
    // the 14-day grace-period polling of the old relay so messages contacts
    // deposited there before they processed our `relay_update` aren't lost.
    {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let prior = rt.db.settings_get("home_relay_url").ok().flatten();
        if let Some(prev) = prior.as_deref() {
            if prev != url {
                rt.db
                    .settings_put("previous_relay_url", prev)
                    .map_err(err)?;
                rt.db
                    .settings_put(
                        "relay_migration_started_at",
                        &now_unix_ms().to_string(),
                    )
                    .map_err(err)?;
                tracing::info!(
                    "relay_connect: home relay changed from {} to {} — grace period started",
                    prev,
                    url
                );
            }
        }
        rt.db.settings_put("home_relay_url", &url).map_err(err)?;
    }

    // ===== Configuration manifest verification =====
    // Compute the manifest digest for this URL (binding the stored TLS pin
    // when present) and either verify a stored signature or install a TOFU
    // one signed with our manifest signer. Refuse to connect if a stored
    // signature exists but doesn't verify — that's a tampering signal.
    {
        let guard = state.vault.lock();
        let rt = guard.as_ref().ok_or("vault locked")?;
        let stored_pin_for_digest = rt
            .db
            .settings_get(&crate::transport::relay::pin_settings_key(&url))
            .ok()
            .flatten()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        let digest = crate::crypto::config_manifest::manifest_digest(
            &url,
            stored_pin_for_digest.as_ref().map(|p| p.as_slice()),
        );

        let stored_sig_hex = rt.db.settings_get("manifest_signature").map_err(err)?;
        let stored_url = rt.db.settings_get("manifest_relay_url").map_err(err)?;
        let pubkey_hex = rt
            .db
            .settings_get("manifest_verifying_key")
            .map_err(err)?
            .ok_or("manifest verifying key missing")?;
        let pubkey_bytes: [u8; 32] = hex::decode(&pubkey_hex)
            .map_err(|_| "manifest verifying key not hex".to_string())?
            .try_into()
            .map_err(|_| "manifest verifying key not 32 bytes".to_string())?;

        match (stored_sig_hex, stored_url) {
            (Some(sig_hex), Some(stored_url)) if stored_url == url => {
                let sig_bytes: [u8; 64] = hex::decode(&sig_hex)
                    .map_err(|_| "manifest signature not hex".to_string())?
                    .try_into()
                    .map_err(|_| "manifest signature not 64 bytes".to_string())?;
                if let Err(e) = crate::crypto::config_manifest::verify(
                    &pubkey_bytes,
                    &digest,
                    &sig_bytes,
                ) {
                    tracing::error!("relay_connect: MANIFEST TAMPERED — refusing connect: {e}");
                    use tauri::Emitter;
                    let _ = app.emit(
                        "security:manifest_tampered",
                        serde_json::json!({ "url": url }),
                    );
                    return Err("config manifest signature failed to verify".into());
                }
                tracing::info!("relay_connect: manifest verified ✓");
            }
            _ => {
                // First connect (TOFU) or URL change. Sign the new manifest
                // with the in-memory signer and persist.
                let sig =
                    crate::crypto::config_manifest::sign(&rt.manifest_seed, &digest);
                rt.db
                    .settings_put("manifest_signature", &hex::encode(sig))
                    .map_err(err)?;
                rt.db
                    .settings_put("manifest_relay_url", &url)
                    .map_err(err)?;
                tracing::info!("relay_connect: manifest signed (TOFU/url-change)");
            }
        }
    }

    let stored_pin = lookup_relay_pin(&state, &url);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let tx_for_periodic = tx.clone();
    match state.relay.connect(url.clone(), stored_pin, tx).await {
        Ok(captured_pin) => {
            tracing::info!("relay_connect: ws connected to {}", url);
            // TOFU: first time we see this URL, persist the pin and re-sign
            // the manifest digest so future verifies cover the TLS identity.
            if let Some(pin) = captured_pin {
                if stored_pin.is_none() {
                    let guard = state.vault.lock();
                    if let Some(rt) = guard.as_ref() {
                        let _ = rt.db.settings_put(
                            &crate::transport::relay::pin_settings_key(&url),
                            &hex::encode(pin),
                        );
                        let new_digest = crate::crypto::config_manifest::manifest_digest(
                            &url,
                            Some(&pin),
                        );
                        let new_sig = crate::crypto::config_manifest::sign(
                            &rt.manifest_seed,
                            &new_digest,
                        );
                        let _ = rt
                            .db
                            .settings_put("manifest_signature", &hex::encode(new_sig));
                        tracing::info!(
                            "relay_connect: TOFU pin captured, manifest re-signed with TLS pin"
                        );
                    }
                }
            }
            let state_arc = state_arc_for_pump(&app);
            inbound::spawn_pump(app.clone(), state_arc.clone(), state.relay.clone(), rx);

            // Periodic background tasks: fallback retrieve every 30 s and
            // frame-accounting reconciliation every 60 s. The pump receives
            // the responses and runs the verdict.
            if let Some(me_pk) = me_pubkey(&state) {
                let client = state.relay.clone();
                tokio::spawn(crate::transport::relay::run_periodic_tasks(
                    client,
                    me_pk.to_vec(),
                    state_arc.clone(),
                    tx_for_periodic,
                    app.clone(),
                ));
            }

            // Kick off an immediate retrieve so anything the relay still
            // has for us shows up without waiting for the next notify.
            if let Some(me_pk) = me_pubkey(&state) {
                let real = crate::transport::mailbox::current_mailbox(&me_pk);
                let batch = crate::transport::mailbox::build_retrieve_batch(&real);
                let hex: Vec<String> = batch.iter().map(crate::transport::mailbox::hex).collect();
                let _ = state.relay.retrieve(hex);
            }
            Ok(())
        }
        Err(e) => {
            tracing::error!("relay_connect: connect failed: {e}");
            if matches!(e, crate::transport::TransportError::TlsPinMismatch) {
                use tauri::Emitter;
                let _ = app.emit(
                    "security:tls_pin_mismatch",
                    serde_json::json!({ "url": url }),
                );
            }
            Err(err(e))
        }
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

#[tauri::command]
pub async fn cross_relay_stats(
    state: State<'_, std::sync::Arc<AppState>>,
) -> CmdResult<Vec<crate::transport::cross_relay_stats::RelayUsage>> {
    Ok(state.cross_relay.snapshot())
}

// =====================================================================
// dashboard
// =====================================================================

#[derive(Serialize)]
pub struct SecurityStatus {
    pub vault_unlocked: bool,
    pub hardware_tier: HardwareTier,
    pub relay_connected: bool,
    pub relay_url: Option<String>,
    pub frame_counters: crate::transport::frame_accounting::Snapshot,
    pub manifest_verified: bool,
    pub manifest_signed_url: Option<String>,
    /// Hex-encoded SHA-256 of the home relay's leaf certificate SPKI, if a
    /// pin has been captured. `None` for plaintext (`ws://`) relays or
    /// before the first successful TOFU handshake.
    pub tls_pin_hex: Option<String>,
}

#[tauri::command]
pub async fn security_status(state: State<'_, std::sync::Arc<AppState>>) -> CmdResult<SecurityStatus> {
    let url = state.relay.current_url();
    let (manifest_verified, manifest_signed_url, tls_pin_hex) = {
        let guard = state.vault.lock();
        match guard.as_ref() {
            None => (false, None, None),
            Some(rt) => {
                let (mv, msu) = verify_manifest_for(rt, url.as_deref());
                let pin = url.as_deref().and_then(|u| {
                    rt.db
                        .settings_get(&crate::transport::relay::pin_settings_key(u))
                        .ok()
                        .flatten()
                });
                (mv, msu, pin)
            }
        }
    };
    Ok(SecurityStatus {
        vault_unlocked: state.is_unlocked(),
        hardware_tier: secure_enclave::detect_tier(),
        relay_connected: url.is_some(),
        relay_url: url,
        frame_counters: state.relay.counters().snapshot(),
        manifest_verified,
        manifest_signed_url,
        tls_pin_hex,
    })
}

fn verify_manifest_for(
    rt: &VaultRuntime,
    url: Option<&str>,
) -> (bool, Option<String>) {
    let signed_url = rt.db.settings_get("manifest_relay_url").ok().flatten();
    let target = match url {
        Some(u) => u,
        None => return (false, signed_url),
    };
    let stored_sig = rt.db.settings_get("manifest_signature").ok().flatten();
    let pubkey_hex = rt.db.settings_get("manifest_verifying_key").ok().flatten();
    let (Some(sig_hex), Some(pk_hex), Some(stored)) = (stored_sig, pubkey_hex, signed_url.clone())
    else {
        return (false, signed_url);
    };
    if stored != target {
        return (false, signed_url);
    }
    let Ok(sig_bytes) = hex::decode(&sig_hex) else {
        return (false, signed_url);
    };
    let Ok(pk_bytes) = hex::decode(&pk_hex) else {
        return (false, signed_url);
    };
    let (Ok(sig_arr), Ok(pk_arr)) = (
        TryInto::<[u8; 64]>::try_into(sig_bytes),
        TryInto::<[u8; 32]>::try_into(pk_bytes),
    ) else {
        return (false, signed_url);
    };
    let stored_pin = rt
        .db
        .settings_get(&crate::transport::relay::pin_settings_key(target))
        .ok()
        .flatten()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    let digest = crate::crypto::config_manifest::manifest_digest(
        target,
        stored_pin.as_ref().map(|p| p.as_slice()),
    );
    (
        crate::crypto::config_manifest::verify(&pk_arr, &digest, &sig_arr).is_ok(),
        signed_url,
    )
}

// Suppress unused-import warnings while the rest of the surface settles.
#[allow(dead_code)]
const _ALIAS: fn(&[u8; 32]) -> String = derive_alias;
