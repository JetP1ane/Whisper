//! Identity, signed prekey, and one-time prekey persistence.

use super::{DbResult, Database};
use rusqlite::params;

#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub id: String,
    pub ed25519_public: Vec<u8>,
    pub ed25519_secret: Vec<u8>,
    pub x25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub mlkem_secret: Vec<u8>,
    pub alias: String,
    pub display_name: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct SignedPrekeyRow {
    pub id: u32,
    pub x25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub mlkem_secret: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at: i64,
    pub rotated_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct OneTimePrekeyRow {
    pub id: u32,
    pub x25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub mlkem_secret: Vec<u8>,
    pub consumed: bool,
    pub created_at: i64,
}

impl Database {
    pub fn upsert_identity(&self, r: &IdentityRow) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO identity (
                id, ed25519_public, ed25519_secret, x25519_public, x25519_secret,
                mlkem_public, mlkem_secret, alias, display_name, created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET
                alias        = excluded.alias,
                display_name = excluded.display_name",
            params![
                r.id,
                r.ed25519_public,
                r.ed25519_secret,
                r.x25519_public,
                r.x25519_secret,
                r.mlkem_public,
                r.mlkem_secret,
                r.alias,
                r.display_name,
                r.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn load_identity(&self) -> DbResult<Option<IdentityRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ed25519_public, ed25519_secret, x25519_public, x25519_secret,
                    mlkem_public, mlkem_secret, alias, display_name, created_at
             FROM identity WHERE id = 'self' LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(r) = rows.next()? {
            Ok(Some(IdentityRow {
                id: r.get(0)?,
                ed25519_public: r.get(1)?,
                ed25519_secret: r.get(2)?,
                x25519_public: r.get(3)?,
                x25519_secret: r.get(4)?,
                mlkem_public: r.get(5)?,
                mlkem_secret: r.get(6)?,
                alias: r.get(7)?,
                display_name: r.get(8)?,
                created_at: r.get(9)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Persist the 16-byte BIP39 entropy on the identity row. Stored
    /// inside SQLCipher's encrypted DB so a vault dump without the
    /// passphrase reveals nothing.
    ///
    /// Caller MUST call this AFTER `upsert_identity` — never before, or the
    /// secrets columns won't yet exist on the row.
    pub fn set_identity_seed_entropy(&self, entropy: &[u8]) -> DbResult<()> {
        let updated = self.conn.execute(
            "UPDATE identity SET seed_entropy = ?1 WHERE id = 'self'",
            params![entropy],
        )?;
        if updated == 0 {
            return Err(super::DbError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        }
        Ok(())
    }

    pub fn get_identity_seed_entropy(&self) -> DbResult<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT seed_entropy FROM identity WHERE id = 'self'")?;
        let mut rows = stmt.query([])?;
        if let Some(r) = rows.next()? {
            Ok(r.get(0)?)
        } else {
            Ok(None)
        }
    }

    pub fn insert_signed_prekey(&self, r: &SignedPrekeyRow) -> DbResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO signed_prekeys (
                id, x25519_public, x25519_secret, mlkem_public, mlkem_secret,
                signature, created_at, rotated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                r.id,
                r.x25519_public,
                r.x25519_secret,
                r.mlkem_public,
                r.mlkem_secret,
                r.signature,
                r.created_at,
                r.rotated_at,
            ],
        )?;
        Ok(())
    }

    pub fn current_signed_prekey(&self) -> DbResult<Option<SignedPrekeyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, x25519_public, x25519_secret, mlkem_public, mlkem_secret,
                    signature, created_at, rotated_at
             FROM signed_prekeys
             WHERE rotated_at IS NULL
             ORDER BY created_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(r) = rows.next()? {
            Ok(Some(SignedPrekeyRow {
                id: r.get(0)?,
                x25519_public: r.get(1)?,
                x25519_secret: r.get(2)?,
                mlkem_public: r.get(3)?,
                mlkem_secret: r.get(4)?,
                signature: r.get(5)?,
                created_at: r.get(6)?,
                rotated_at: r.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn insert_one_time_prekey(&self, r: &OneTimePrekeyRow) -> DbResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO one_time_prekeys (
                id, x25519_public, x25519_secret, mlkem_public, mlkem_secret,
                consumed, created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                r.id,
                r.x25519_public,
                r.x25519_secret,
                r.mlkem_public,
                r.mlkem_secret,
                r.consumed as i64,
                r.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn next_unused_one_time_prekey(&self) -> DbResult<Option<OneTimePrekeyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, x25519_public, x25519_secret, mlkem_public, mlkem_secret,
                    consumed, created_at
             FROM one_time_prekeys
             WHERE consumed = 0
             ORDER BY id ASC LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(r) = rows.next()? {
            Ok(Some(OneTimePrekeyRow {
                id: r.get(0)?,
                x25519_public: r.get(1)?,
                x25519_secret: r.get(2)?,
                mlkem_public: r.get(3)?,
                mlkem_secret: r.get(4)?,
                consumed: r.get::<_, i64>(5)? != 0,
                created_at: r.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn one_time_prekey_by_id(&self, id: u32) -> DbResult<Option<OneTimePrekeyRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, x25519_public, x25519_secret, mlkem_public, mlkem_secret,
                    consumed, created_at
             FROM one_time_prekeys WHERE id = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(OneTimePrekeyRow {
                id: r.get(0)?,
                x25519_public: r.get(1)?,
                x25519_secret: r.get(2)?,
                mlkem_public: r.get(3)?,
                mlkem_secret: r.get(4)?,
                consumed: r.get::<_, i64>(5)? != 0,
                created_at: r.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Mark a one-time prekey as consumed AND erase its secret material
    /// from the row. Once a peer has used it for PQ-X3DH key agreement,
    /// the long-lived secret has done its job and serves only as a
    /// liability — keeping it on disk lets a future vault compromise
    /// retroactively unmask all sessions established under it. We
    /// preserve the row (as a cheap bloom filter against an attacker
    /// reusing the same OTPK id twice) but zero the secret blobs.
    pub fn mark_one_time_prekey_consumed(&self, id: u32) -> DbResult<()> {
        self.conn.execute(
            "UPDATE one_time_prekeys
                SET consumed = 1,
                    x25519_secret = zeroblob(0),
                    mlkem_secret = zeroblob(0)
                WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn count_unused_one_time_prekeys(&self) -> DbResult<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE consumed = 0",
            [],
            |r| r.get(0),
        )?;
        Ok(count)
    }
}
