//! Persist / load `RatchetState` keyed by `contact_id`.
//!
//! Format is `bincode` (compact binary). Kept inside the SQLCipher database.

use crate::crypto::ratchet::RatchetState;
use crate::db::Database;
use anyhow::Result;
use rusqlite::params;

pub fn save(db: &Database, contact_id: &str, state: &RatchetState) -> Result<()> {
    let bytes = bincode::serialize(state)?;
    let now = now_unix_ms();
    db.conn.execute(
        "INSERT INTO ratchet_sessions (contact_id, session_data, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(contact_id) DO UPDATE SET
            session_data = excluded.session_data,
            updated_at   = excluded.updated_at",
        params![contact_id, bytes, now],
    )?;
    Ok(())
}

pub fn load(db: &Database, contact_id: &str) -> Result<Option<RatchetState>> {
    let mut stmt = db
        .conn
        .prepare("SELECT session_data FROM ratchet_sessions WHERE contact_id = ?1 LIMIT 1")?;
    let mut rows = stmt.query(params![contact_id])?;
    if let Some(r) = rows.next()? {
        let bytes: Vec<u8> = r.get(0)?;
        let state: RatchetState = bincode::deserialize(&bytes)?;
        Ok(Some(state))
    } else {
        Ok(None)
    }
}

pub fn delete(db: &Database, contact_id: &str) -> Result<()> {
    db.conn.execute(
        "DELETE FROM ratchet_sessions WHERE contact_id = ?1",
        params![contact_id],
    )?;
    Ok(())
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
