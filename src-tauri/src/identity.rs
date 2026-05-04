//! Identity bootstrap: generate-on-setup, load-on-unlock, publish-on-create.
//!
//! Called from the vault setup/unlock pipeline so the identity is always in
//! place by the time the first frontend command runs.

use crate::crypto::bundle::{
    build_signed_bundle, OneTimePrekeyPublic, PublicKeyBundle, SignedPrekeyPublic,
};
use crate::crypto::keys::{
    derive_alias, generate_identity, generate_one_time_prekeys, generate_signed_prekey,
    IdentityKeys, OneTimePrekey, SignedPrekey,
};
use crate::db::identity::{IdentityRow, OneTimePrekeyRow, SignedPrekeyRow};
use crate::db::Database;
use ed25519_dalek::SigningKey as EdSigningKey;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

pub const SPK_INITIAL_ID: u32 = 1;
pub const OTPK_INITIAL_BATCH: usize = 10;

/// Persisted identity owned by the runtime. Holds public material on the
/// outside and private secrets on the inside; the `keys` field is the same
/// `IdentityKeys` value the crypto helpers expect.
pub struct LoadedIdentity {
    pub keys: IdentityKeys,
    pub alias: String,
    pub display_name: Option<String>,
    pub created_at: i64,
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// First-run identity creation. Persists identity + signed prekey + the
/// initial OTPK batch into `db`.
///
/// Returns the LoadedIdentity AND the 12-word BIP39 phrase used to seed
/// it. The caller is responsible for showing the phrase to the user
/// exactly once and not persisting it in plaintext.
pub fn create_and_persist(db: &Database) -> anyhow::Result<(LoadedIdentity, String)> {
    create_and_persist_inner(db, None)
}

/// Restore identity from an existing BIP39 phrase. Bails if the phrase's
/// checksum is invalid. The Ed25519 + X25519 identity keys come out
/// identical to the original setup; ML-KEM regenerates fresh.
pub fn restore_from_phrase(
    db: &Database,
    phrase: &str,
) -> anyhow::Result<LoadedIdentity> {
    let entropy = crate::crypto::seed::entropy_from_phrase(phrase)
        .map_err(|e| anyhow::anyhow!("seed phrase: {e}"))?;
    let (li, _phrase_again) = create_and_persist_inner(db, Some(entropy))?;
    Ok(li)
}

fn create_and_persist_inner(
    db: &Database,
    existing_entropy: Option<[u8; 16]>,
) -> anyhow::Result<(LoadedIdentity, String)> {
    use crate::crypto::keys::generate_identity_from_seeds;
    use crate::crypto::seed;

    let now = now_unix_ms();

    // 1. BIP39 seed → master → per-key seeds → identity.
    let (entropy, phrase) = match existing_entropy {
        Some(e) => {
            let p = seed::phrase_from_entropy(&e);
            (zeroize::Zeroizing::new(e), p)
        }
        None => seed::generate(),
    };
    let master = seed::master_from_phrase(&phrase, "");
    let seeds = seed::derive_identity_seeds(&master);
    let ik = generate_identity_from_seeds(&seeds);
    let ed_pub = ik.ed25519_verifying().to_bytes();
    let alias = derive_alias(&ed_pub);

    // 2. Signed prekey.
    let spk = generate_signed_prekey(SPK_INITIAL_ID, &ik);
    let spk_x_pub = XPublicKey::from(&spk.x25519_secret);

    // 3. One-time prekeys.
    let otpks = generate_one_time_prekeys(OTPK_INITIAL_BATCH, 1);

    // --- Persist ---
    // ORDER MATTERS: upsert_identity must run before set_identity_seed_entropy.
    // The latter touches the same row; running it first would create a stub
    // with empty secret BLOBs and the ON CONFLICT clause below would leave
    // those empty (it only updates alias/display_name).
    let identity_row = IdentityRow {
        id: "self".into(),
        ed25519_public: ed_pub.to_vec(),
        ed25519_secret: ik.ed25519_signing.to_bytes().to_vec(),
        x25519_public: ik.x25519_public().to_bytes().to_vec(),
        x25519_secret: ik.x25519_secret.to_bytes().to_vec(),
        mlkem_public: ik.mlkem_public.clone(),
        mlkem_secret: ik.mlkem_secret.clone(),
        alias: alias.clone(),
        display_name: None,
        created_at: now,
    };
    db.upsert_identity(&identity_row)?;

    // Persist the entropy (16 bytes) so the user can view / re-derive the
    // phrase later. Stored inside the SQLCipher-encrypted identity row.
    db.set_identity_seed_entropy(&entropy[..])?;

    let spk_row = SignedPrekeyRow {
        id: spk.id,
        x25519_public: spk_x_pub.to_bytes().to_vec(),
        x25519_secret: spk.x25519_secret.to_bytes().to_vec(),
        mlkem_public: spk.mlkem_public.clone(),
        mlkem_secret: spk.mlkem_secret.clone(),
        signature: spk.signature.to_vec(),
        created_at: now,
        rotated_at: None,
    };
    db.insert_signed_prekey(&spk_row)?;

    for otpk in &otpks {
        let otpk_x_pub = XPublicKey::from(&otpk.x25519_secret);
        db.insert_one_time_prekey(&OneTimePrekeyRow {
            id: otpk.id,
            x25519_public: otpk_x_pub.to_bytes().to_vec(),
            x25519_secret: otpk.x25519_secret.to_bytes().to_vec(),
            mlkem_public: otpk.mlkem_public.clone(),
            mlkem_secret: otpk.mlkem_secret.clone(),
            consumed: false,
            created_at: now,
        })?;
    }

    Ok((
        LoadedIdentity {
            keys: ik,
            alias,
            display_name: None,
            created_at: now,
        },
        phrase,
    ))
}

/// Load identity from the unlocked database. Returns `Ok(None)` when no
/// identity row exists yet (vault present but no `self`).
pub fn load(db: &Database) -> anyhow::Result<Option<LoadedIdentity>> {
    let row = match db.load_identity()? {
        Some(r) => r,
        None => return Ok(None),
    };

    let ed_secret: [u8; 32] = row
        .ed25519_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519 secret length"))?;
    let ed25519_signing = EdSigningKey::from_bytes(&ed_secret);

    let x_secret: [u8; 32] = row
        .x25519_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 secret length"))?;
    let x25519_secret = XStaticSecret::from(x_secret);

    let keys = IdentityKeys {
        ed25519_signing,
        x25519_secret,
        mlkem_secret: row.mlkem_secret,
        mlkem_public: row.mlkem_public,
    };

    Ok(Some(LoadedIdentity {
        keys,
        alias: row.alias,
        display_name: row.display_name,
        created_at: row.created_at,
    }))
}

/// Build the signed `PublicKeyBundle` for sharing.
///
/// **Compact form**: the OTPK ML-KEM public key is omitted (empty `Vec`) so
/// the serialized size fits inside the relay's 4 KB cap.
///
/// **Relay URL**: included in the signed payload (v2 bundle field). Other
/// clients deposit messages destined for this owner to this URL, enabling
/// cross-relay messaging. `relay_url` is read from the `settings` table
/// (`home_relay_url` key) — empty string when not set yet.
pub fn build_published_bundle(db: &Database, id: &LoadedIdentity) -> anyhow::Result<PublicKeyBundle> {
    let spk = db
        .current_signed_prekey()?
        .ok_or_else(|| anyhow::anyhow!("no active signed prekey"))?;
    let otpk = db
        .next_unused_one_time_prekey()?
        .ok_or_else(|| anyhow::anyhow!("no unused OTPK to publish"))?;

    let spk_pub = SignedPrekeyPublic {
        id: spk.id,
        x25519_pub: vec_to_32(&spk.x25519_public)?,
        kyber_pub: spk.mlkem_public,
        signature: vec_to_64(&spk.signature)?,
    };
    let otpk_pub = OneTimePrekeyPublic {
        id: otpk.id,
        x25519_pub: vec_to_32(&otpk.x25519_public)?,
        // Compact form for relay publishing: omit OTPK ML-KEM. The peer's
        // initiator code treats this as "no kem2" via the existing Option path.
        kyber_pub: Vec::new(),
    };

    let relay_url = db
        .settings_get("home_relay_url")
        .ok()
        .flatten()
        .unwrap_or_default();
    let bundle = build_signed_bundle(
        &id.keys.ed25519_signing,
        id.keys.ed25519_verifying().to_bytes(),
        id.keys.x25519_public().to_bytes(),
        id.keys.mlkem_public.clone(),
        spk_pub,
        otpk_pub,
        id.alias.clone(),
        id.display_name.clone(),
        relay_url,
    );
    Ok(bundle)
}

fn vec_to_32(v: &[u8]) -> anyhow::Result<[u8; 32]> {
    v.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}
fn vec_to_64(v: &[u8]) -> anyhow::Result<[u8; 64]> {
    v.try_into().map_err(|_| anyhow::anyhow!("expected 64 bytes"))
}

// Suppress dead-code warning until the messaging layer pulls these in.
#[allow(dead_code)]
fn _unused_imports(_: SignedPrekey, _: OneTimePrekey) {}
