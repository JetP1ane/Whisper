//! Contact CRUD.

use super::{DbResult, Database};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub alias: String,
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
    pub mlkem_public: Vec<u8>,
    pub relay_url: Option<String>,
    /// Peer's I2P destination (base64). Captured from the v3+ signed
    /// bundle on contact add. None for legacy v1/v2 bundles. The send
    /// queue / connection manager uses this as the dial target.
    pub i2p_destination: Option<String>,
    pub verified: bool,
    pub peer_has_verified_us: bool,
    pub hide_until_verified: bool,
    pub is_sealed: bool,
    /// Optional user-set display name. Local-only — never sent over the
    /// wire. The wire-level identifier remains `alias`.
    pub nickname: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Database {
    pub fn upsert_contact(&self, c: &Contact) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO contacts (
                id, alias, ed25519_public, x25519_public, mlkem_public, relay_url,
                i2p_destination, verified, peer_has_verified_us, hide_until_verified,
                is_sealed, created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(id) DO UPDATE SET
                alias                = excluded.alias,
                ed25519_public       = excluded.ed25519_public,
                x25519_public        = excluded.x25519_public,
                mlkem_public         = excluded.mlkem_public,
                relay_url            = excluded.relay_url,
                i2p_destination      = excluded.i2p_destination,
                verified             = excluded.verified,
                peer_has_verified_us = excluded.peer_has_verified_us,
                hide_until_verified  = excluded.hide_until_verified,
                is_sealed            = excluded.is_sealed,
                updated_at           = excluded.updated_at",
            params![
                c.id,
                c.alias,
                c.ed25519_public,
                c.x25519_public,
                c.mlkem_public,
                c.relay_url,
                c.i2p_destination,
                c.verified as i64,
                c.peer_has_verified_us as i64,
                c.hide_until_verified as i64,
                c.is_sealed as i64,
                c.created_at,
                c.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn list_contacts(&self) -> DbResult<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, alias, ed25519_public, x25519_public, mlkem_public, relay_url,
                    i2p_destination,
                    verified, peer_has_verified_us, hide_until_verified, is_sealed,
                    nickname, created_at, updated_at
             FROM contacts
             ORDER BY COALESCE(nickname, alias) ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Contact {
                    id: r.get(0)?,
                    alias: r.get(1)?,
                    ed25519_public: r.get(2)?,
                    x25519_public: r.get(3)?,
                    mlkem_public: r.get(4)?,
                    relay_url: r.get(5)?,
                    i2p_destination: r.get(6)?,
                    verified: r.get::<_, i64>(7)? != 0,
                    peer_has_verified_us: r.get::<_, i64>(8)? != 0,
                    hide_until_verified: r.get::<_, i64>(9)? != 0,
                    is_sealed: r.get::<_, i64>(10)? != 0,
                    nickname: r.get(11)?,
                    created_at: r.get(12)?,
                    updated_at: r.get(13)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Set or clear the user-chosen display name for a contact.
    pub fn set_contact_nickname(&self, id: &str, nickname: Option<&str>) -> DbResult<()> {
        self.conn.execute(
            "UPDATE contacts SET nickname = ?1, updated_at = ?2 WHERE id = ?3",
            params![nickname, now_unix_ms(), id],
        )?;
        Ok(())
    }

    pub fn set_contact_relay_url(&self, id: &str, relay_url: &str) -> DbResult<()> {
        self.conn.execute(
            "UPDATE contacts SET relay_url = ?1, updated_at = ?2 WHERE id = ?3",
            params![relay_url, now_unix_ms(), id],
        )?;
        Ok(())
    }

    pub fn set_contact_verified(&self, id: &str, verified: bool) -> DbResult<()> {
        self.conn.execute(
            "UPDATE contacts SET verified = ?1, updated_at = ?2 WHERE id = ?3",
            params![verified as i64, now_unix_ms(), id],
        )?;
        Ok(())
    }
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
