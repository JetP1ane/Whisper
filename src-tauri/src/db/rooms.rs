//! Room (group conversation) member management.

use super::{DbResult, Database};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMember {
    pub room_id: String,
    pub contact_id: String,
    pub role: String, // 'owner' | 'member'
    pub sender_key: Option<Vec<u8>>,
    pub joined_at: i64,
}

impl Database {
    pub fn add_room_member(&self, m: &RoomMember) -> DbResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO room_members (room_id, contact_id, role, sender_key, joined_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![m.room_id, m.contact_id, m.role, m.sender_key, m.joined_at],
        )?;
        Ok(())
    }

    pub fn list_room_members(&self, room_id: &str) -> DbResult<Vec<RoomMember>> {
        let mut stmt = self.conn.prepare(
            "SELECT room_id, contact_id, role, sender_key, joined_at
             FROM room_members
             WHERE room_id = ?1
             ORDER BY joined_at ASC",
        )?;
        let rows = stmt
            .query_map(params![room_id], |r| {
                Ok(RoomMember {
                    room_id: r.get(0)?,
                    contact_id: r.get(1)?,
                    role: r.get(2)?,
                    sender_key: r.get(3)?,
                    joined_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn remove_room_member(&self, room_id: &str, contact_id: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM room_members WHERE room_id = ?1 AND contact_id = ?2",
            params![room_id, contact_id],
        )?;
        Ok(())
    }

    /// Update just the `sender_key` BLOB for a (room, contact) row. Used when
    /// the sender-key state advances (encrypt or decrypt step) so the chain
    /// is persistent across vault restarts.
    pub fn update_room_member_sender_key(
        &self,
        room_id: &str,
        contact_id: &str,
        sender_key: &[u8],
    ) -> DbResult<()> {
        self.conn.execute(
            "UPDATE room_members SET sender_key = ?1
             WHERE room_id = ?2 AND contact_id = ?3",
            params![sender_key, room_id, contact_id],
        )?;
        Ok(())
    }

    /// Read the user's own sender-key for a room.
    pub fn get_self_room_key(&self, room_id: &str) -> DbResult<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT sender_key FROM room_self_keys WHERE room_id = ?1")?;
        let mut rows = stmt.query(params![room_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(r.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Insert or update the user's own sender-key for a room.
    pub fn put_self_room_key(&self, room_id: &str, sender_key: &[u8]) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO room_self_keys (room_id, sender_key) VALUES (?1, ?2)
             ON CONFLICT(room_id) DO UPDATE SET sender_key = excluded.sender_key",
            params![room_id, sender_key],
        )?;
        Ok(())
    }

    /// Look up one room member's row.
    pub fn room_member(
        &self,
        room_id: &str,
        contact_id: &str,
    ) -> DbResult<Option<RoomMember>> {
        let mut stmt = self.conn.prepare(
            "SELECT room_id, contact_id, role, sender_key, joined_at
             FROM room_members
             WHERE room_id = ?1 AND contact_id = ?2",
        )?;
        let mut rows = stmt.query(params![room_id, contact_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(RoomMember {
                room_id: r.get(0)?,
                contact_id: r.get(1)?,
                role: r.get(2)?,
                sender_key: r.get(3)?,
                joined_at: r.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }
}
