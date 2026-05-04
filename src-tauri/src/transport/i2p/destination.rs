//! Persistent I2P destination key management.
//!
//! Mod #3 in the design proposal: the I2P destination key is **not**
//! derived from the Ed25519 identity. Instead it's an independent
//! ed25519/x25519 keypair the SAM bridge mints for us via `DEST GENERATE`,
//! stored in the SQLCipher-encrypted vault alongside the identity. That
//! decoupling means we can rotate a destination (because it got
//! fingerprinted, spam-flagged, or just feels old) without rotating the
//! Whisper identity itself — and vice versa.
//!
//! Lifecycle:
//!
//! 1. **First launch after vault unlock** — if no destination is stored
//!    yet, call [`mint_and_store`] which talks to a *running* SAM bridge
//!    via `DEST GENERATE`, then writes both the public (b64) and full
//!    private (b64) blobs to the `identity` row.
//! 2. **Subsequent launches** — load the existing private blob and pass
//!    it as `DESTINATION=` on `SESSION CREATE`. Same destination, same
//!    .i2p address every time.
//! 3. **Rotation** — call [`rotate`] to mint a fresh keypair and replace
//!    both columns. Existing contacts will need a `destination_update`
//!    control message before they can reach us at the new address (Phase
//!    6 will wire that).
//!
//! All bytes here are I2P-format base64 (alphabet `A–Z a–z 0–9 - ~`,
//! padded with `=`), produced and consumed verbatim by i2pd's SAM bridge.

use super::sam;
use super::I2pResult;
use crate::db::{DbResult, Database};
use rusqlite::params;

/// One persisted I2P destination row.
#[derive(Debug, Clone)]
pub struct PersistedDestination {
    /// Base64 public destination (what we share with peers, ~516 chars).
    pub pub_b64: String,
    /// Base64 private destination blob (full keypair + cert, what
    /// `SESSION CREATE DESTINATION=` accepts; ~880-908 chars).
    pub priv_b64: String,
}

/// Read the stored destination, if any. Returns `Ok(None)` when the
/// identity row exists but the i2p columns are still NULL (i.e. we
/// haven't minted yet — first run after the I2P migration).
pub fn load(db: &Database) -> DbResult<Option<PersistedDestination>> {
    let mut stmt = db.conn.prepare(
        "SELECT i2p_dest_pub, i2p_dest_priv FROM identity WHERE id = 'self' LIMIT 1",
    )?;
    let mut rows = stmt.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let pub_b64: Option<String> = row.get(0)?;
    let priv_blob: Option<Vec<u8>> = row.get(1)?;
    match (pub_b64, priv_blob) {
        (Some(p), Some(s)) if !p.is_empty() && !s.is_empty() => {
            let priv_b64 = String::from_utf8(s)
                .map_err(|e| {
                    super::super::super::db::DbError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    ))
                })?;
            Ok(Some(PersistedDestination { pub_b64: p, priv_b64 }))
        }
        _ => Ok(None),
    }
}

/// Persist (or replace) the destination on the `self` identity row.
pub fn store(db: &Database, dest: &PersistedDestination) -> DbResult<()> {
    let updated = db.conn.execute(
        "UPDATE identity SET i2p_dest_pub = ?1, i2p_dest_priv = ?2 WHERE id = 'self'",
        params![dest.pub_b64, dest.priv_b64.as_bytes()],
    )?;
    if updated == 0 {
        return Err(crate::db::DbError::Sqlite(
            rusqlite::Error::QueryReturnedNoRows,
        ));
    }
    Ok(())
}

/// Mint a fresh destination via the SAM bridge and store it. The DB is
/// behind a `parking_lot::Mutex` because `Database` (rusqlite Connection)
/// is `Send` but not `Sync`; holding `&Database` across `.await` would
/// make any wrapping future non-`Send`. The Mutex is `Sync` and we drop
/// its guard before each await, so the resulting future *is* `Send`.
pub async fn mint_and_store(
    db: &parking_lot::Mutex<Database>,
    sam_addr: &str,
) -> I2pResult<PersistedDestination> {
    let (pub_b64, priv_b64) = sam::dest_generate_oneshot(sam_addr).await?;
    let dest = PersistedDestination { pub_b64, priv_b64 };
    {
        let guard = db.lock();
        store(&guard, &dest).map_err(|e| {
            super::I2pError::Sam(format!("persist destination: {e}"))
        })?;
    }
    Ok(dest)
}

/// Load if present; otherwise mint and store. Same async-Send rationale
/// as [`mint_and_store`] for the Mutex wrapper.
pub async fn load_or_mint(
    db: &parking_lot::Mutex<Database>,
    sam_addr: &str,
) -> I2pResult<PersistedDestination> {
    let cached = {
        let guard = db.lock();
        load(&guard).map_err(|e| {
            super::I2pError::Sam(format!("load destination: {e}"))
        })?
    };
    if let Some(existing) = cached {
        return Ok(existing);
    }
    mint_and_store(db, sam_addr).await
}

/// Replace the existing destination with a freshly minted one. After
/// rotation, contacts reach the *new* destination only after a
/// `destination_update` control message is delivered to them — Phase 6.
pub async fn rotate(
    db: &parking_lot::Mutex<Database>,
    sam_addr: &str,
) -> I2pResult<PersistedDestination> {
    mint_and_store(db, sam_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Database {
        // In-memory SQLCipher-less DB is fine for these structural tests
        // — we're only exercising the schema + UPDATE/SELECT logic.
        let db = Database::open_in_memory_for_tests();
        crate::db::schema::apply(&db.conn).expect("apply schema");
        // Insert a stub identity row so the UPDATE in `store` finds it.
        db.conn
            .execute(
                "INSERT INTO identity
                    (id, ed25519_public, ed25519_secret, x25519_public, x25519_secret,
                     mlkem_public, mlkem_secret, alias, display_name, created_at)
                 VALUES ('self', x'', x'', x'', x'', x'', x'', 'a-b-c', NULL, 0)",
                [],
            )
            .expect("seed identity");
        db
    }

    #[test]
    fn load_returns_none_before_mint() {
        let db = fresh_db();
        let got = load(&db).unwrap();
        assert!(got.is_none(), "expected None on fresh row, got {got:?}");
    }

    #[test]
    fn store_then_load_round_trips() {
        let db = fresh_db();
        let dest = PersistedDestination {
            pub_b64: "PUB_PLACEHOLDER".into(),
            priv_b64: "PRIV_PLACEHOLDER".into(),
        };
        store(&db, &dest).unwrap();
        let got = load(&db).unwrap().expect("destination should be present");
        assert_eq!(got.pub_b64, dest.pub_b64);
        assert_eq!(got.priv_b64, dest.priv_b64);
    }

    #[test]
    fn store_overwrites_previous() {
        let db = fresh_db();
        store(
            &db,
            &PersistedDestination {
                pub_b64: "OLD_PUB".into(),
                priv_b64: "OLD_PRIV".into(),
            },
        )
        .unwrap();
        store(
            &db,
            &PersistedDestination {
                pub_b64: "NEW_PUB".into(),
                priv_b64: "NEW_PRIV".into(),
            },
        )
        .unwrap();
        let got = load(&db).unwrap().unwrap();
        assert_eq!(got.pub_b64, "NEW_PUB");
        assert_eq!(got.priv_b64, "NEW_PRIV");
    }

    #[test]
    fn store_errors_when_no_identity_row() {
        let db = Database::open_in_memory_for_tests();
        crate::db::schema::apply(&db.conn).expect("apply schema");
        let err = store(
            &db,
            &PersistedDestination {
                pub_b64: "P".into(),
                priv_b64: "S".into(),
            },
        )
        .unwrap_err();
        match err {
            crate::db::DbError::Sqlite(rusqlite::Error::QueryReturnedNoRows) => {}
            other => panic!("expected QueryReturnedNoRows, got {other:?}"),
        }
    }
}
