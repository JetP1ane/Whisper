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
        // ON CONFLICT DO UPDATE — NOT `INSERT OR REPLACE`. Replace
        // would drop the `peer_acked_my_key_at` column (and any other
        // columns we add in the future) back to its default, breaking
        // the room sender-key ACK gate the moment the same `(room,
        // contact)` row is touched twice (e.g. once on invite as a
        // pending member, again when the peer's seed arrives).
        // Sender_key updates only when the new row carries a Some
        // value so a re-invite without a seed doesn't wipe an
        // already-known seed either.
        self.conn.execute(
            "INSERT INTO room_members (room_id, contact_id, role, sender_key, joined_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(room_id, contact_id) DO UPDATE SET
                role        = excluded.role,
                sender_key  = COALESCE(excluded.sender_key, room_members.sender_key),
                joined_at   = excluded.joined_at",
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

    // --- room_pending_fanout: per-(room, contact) outbound buffer for
    // room messages we couldn't fan out yet because the recipient
    // hadn't ACK'd our sender-key share. Drained on ACK. ---

    pub fn enqueue_room_pending_fanout(
        &self,
        id: &str,
        room_id: &str,
        contact_id: &str,
        msg_id: &str,
        blob: &[u8],
        created_at: i64,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO room_pending_fanout (id, room_id, contact_id, msg_id, blob, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, room_id, contact_id, msg_id, blob, created_at],
        )?;
        Ok(())
    }

    /// All currently-buffered room fanout rows where the recipient's
    /// peer_acked_my_key_at is non-null (i.e., the ACK gate is open
    /// for this peer, so we have permission to send). Used by the
    /// periodic drain worker; rows are returned but NOT deleted
    /// (caller deletes after a confirmed I2P send via `delete_room_pending_fanout_row`).
    pub fn list_drainable_room_fanout(
        &self,
    ) -> DbResult<Vec<(String, String, String, String, Vec<u8>)>> {
        // (id, room_id, contact_id, msg_id, blob)
        let mut stmt = self.conn.prepare(
            "SELECT rpf.id, rpf.room_id, rpf.contact_id, rpf.msg_id, rpf.blob
             FROM room_pending_fanout rpf
             JOIN room_members rm
                ON rm.room_id = rpf.room_id AND rm.contact_id = rpf.contact_id
             WHERE rm.peer_acked_my_key_at IS NOT NULL
             ORDER BY rpf.created_at ASC",
        )?;
        let rows: Vec<(String, String, String, String, Vec<u8>)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a single fanout row by id. Called after successful send.
    pub fn delete_room_pending_fanout_row(&self, id: &str) -> DbResult<()> {
        self.conn.execute(
            "DELETE FROM room_pending_fanout WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Take all pending fanout rows for `(room_id, contact_id)`, oldest
    /// first, and delete them from the table. Caller fans out the
    /// returned blobs over I2P. Returns `(msg_id, blob)` pairs.
    pub fn drain_room_pending_fanout(
        &self,
        room_id: &str,
        contact_id: &str,
    ) -> DbResult<Vec<(String, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, msg_id, blob FROM room_pending_fanout
             WHERE room_id = ?1 AND contact_id = ?2
             ORDER BY created_at ASC",
        )?;
        let rows: Vec<(String, String, Vec<u8>)> = stmt
            .query_map(params![room_id, contact_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (id, _, _) in &rows {
            self.conn.execute(
                "DELETE FROM room_pending_fanout WHERE id = ?1",
                params![id],
            )?;
        }
        Ok(rows.into_iter().map(|(_, msg, blob)| (msg, blob)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    fn fresh_db_with_room(room_id: &str, contact_ids: &[&str]) -> Database {
        let db = Database::open_in_memory_for_tests();
        crate::db::schema::apply(&db.conn).expect("apply schema");
        // Seed minimum rows for FK validity (contacts + conversation).
        for cid in contact_ids {
            db.conn
                .execute(
                    "INSERT INTO contacts
                        (id, alias, ed25519_public, x25519_public, mlkem_public,
                         created_at, updated_at)
                     VALUES (?1, 'test-alias', x'', x'', x'', 0, 0)",
                    params![cid],
                )
                .unwrap();
        }
        db.conn
            .execute(
                "INSERT INTO conversations (id, type, created_at)
                 VALUES (?1, 'room', 0)",
                params![room_id],
            )
            .unwrap();
        db
    }

    #[test]
    fn add_room_member_preserves_peer_acked_my_key_at() {
        // Regression: with INSERT OR REPLACE, a second add_room_member
        // call (e.g. when a peer's RoomSenderKey envelope arrives and
        // we upsert the seed onto an existing pending row) wiped the
        // ACK timestamp, breaking the room_send gate.
        let db = fresh_db_with_room("room-1", &["bob"]);
        // Initial pending insert.
        db.add_room_member(&RoomMember {
            room_id: "room-1".into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 100,
        })
        .unwrap();
        // ACK arrives — bob acked our key share.
        db.conn
            .execute(
                "UPDATE room_members SET peer_acked_my_key_at = ?1
                 WHERE room_id = ?2 AND contact_id = ?3",
                params![777_i64, "room-1", "bob"],
            )
            .unwrap();
        // Bob's RoomSenderKey arrives, seed gets stored via add_room_member.
        db.add_room_member(&RoomMember {
            room_id: "room-1".into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: Some(vec![0xAA; 32]),
            joined_at: 200,
        })
        .unwrap();
        // ACK timestamp must survive.
        let ts: Option<i64> = db
            .conn
            .query_row(
                "SELECT peer_acked_my_key_at FROM room_members
                 WHERE room_id='room-1' AND contact_id='bob'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ts, Some(777));
        // And the seed is now stored.
        let key: Option<Vec<u8>> = db
            .conn
            .query_row(
                "SELECT sender_key FROM room_members
                 WHERE room_id='room-1' AND contact_id='bob'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(key, Some(vec![0xAA; 32]));
    }

    #[test]
    fn add_room_member_does_not_clobber_seed_with_none() {
        // If a re-invite arrives without a seed, the existing seed
        // must NOT be wiped. This is the defensive arm of
        // COALESCE(excluded.sender_key, room_members.sender_key).
        let db = fresh_db_with_room("room-2", &["bob"]);
        db.add_room_member(&RoomMember {
            room_id: "room-2".into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: Some(vec![0xBB; 32]),
            joined_at: 100,
        })
        .unwrap();
        // Re-add as pending (sender_key=None).
        db.add_room_member(&RoomMember {
            room_id: "room-2".into(),
            contact_id: "bob".into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 200,
        })
        .unwrap();
        let key: Option<Vec<u8>> = db
            .conn
            .query_row(
                "SELECT sender_key FROM room_members
                 WHERE room_id='room-2' AND contact_id='bob'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(key, Some(vec![0xBB; 32]));
    }

    #[test]
    fn pending_fanout_drain_returns_oldest_first_and_deletes() {
        let db = fresh_db_with_room("room-3", &["bob"]);
        // Insert a real message FK target so the optional FK validates.
        // (room_pending_fanout has FK on contact_id only via room_members?)
        // Actually FK is to contacts(id) and conversations(id) — both
        // already exist from fresh_db_with_room.
        db.enqueue_room_pending_fanout(
            "q1",
            "room-3",
            "bob",
            "msg-A",
            b"first",
            10,
        )
        .unwrap();
        db.enqueue_room_pending_fanout(
            "q2",
            "room-3",
            "bob",
            "msg-B",
            b"second",
            20,
        )
        .unwrap();
        let drained = db.drain_room_pending_fanout("room-3", "bob").unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, "msg-A");
        assert_eq!(drained[1].0, "msg-B");
        // Re-drain returns nothing — rows were deleted.
        let again = db.drain_room_pending_fanout("room-3", "bob").unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn pending_fanout_drain_isolates_by_contact() {
        let db = fresh_db_with_room("room-4", &["bob", "carol"]);
        db.enqueue_room_pending_fanout("q1", "room-4", "bob", "m1", b"x", 10)
            .unwrap();
        db.enqueue_room_pending_fanout("q2", "room-4", "carol", "m2", b"y", 11)
            .unwrap();
        let bob_drained = db.drain_room_pending_fanout("room-4", "bob").unwrap();
        assert_eq!(bob_drained.len(), 1);
        // carol's row is untouched.
        let carol_drained = db.drain_room_pending_fanout("room-4", "carol").unwrap();
        assert_eq!(carol_drained.len(), 1);
        assert_eq!(carol_drained[0].0, "m2");
    }
}
