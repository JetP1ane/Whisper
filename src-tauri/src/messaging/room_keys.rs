//! Persistence helpers for per-(room, member) sender-key state.
//!
//! Each `room_members` row owns a single `sender_key` BLOB column. We
//! serialize `SenderKey { chain_key, counter }` with bincode for compact
//! storage. The chain key sits at rest inside SQLCipher (vault DEK),
//! mirroring how pairwise ratchet state is stored.

use crate::crypto::sender_key::SenderKey;
use crate::db::rooms::RoomMember;
use crate::db::Database;
use anyhow::{anyhow, Result};

/// Encode a sender-key state for the `sender_key` column.
pub fn encode(sk: &SenderKey) -> Result<Vec<u8>> {
    bincode::serialize(sk).map_err(|e| anyhow!("encode SenderKey: {e}"))
}

/// Decode a sender-key state from the `sender_key` column. `None` ⇒ row
/// has no key yet (e.g., a member we invited but who hasn't shared their
/// key back yet).
pub fn decode(blob: Option<&[u8]>) -> Result<Option<SenderKey>> {
    match blob {
        None => Ok(None),
        Some(b) => bincode::deserialize::<SenderKey>(b)
            .map(Some)
            .map_err(|e| anyhow!("decode SenderKey: {e}")),
    }
}

/// Save a sender-key snapshot back to the row.
pub fn save(db: &Database, room_id: &str, contact_id: &str, sk: &SenderKey) -> Result<()> {
    let blob = encode(sk)?;
    db.update_room_member_sender_key(room_id, contact_id, &blob)
        .map_err(|e| anyhow!("update sender_key: {e}"))
}

/// Insert or upsert a member with an attached sender-key seed.
pub fn upsert_member_with_seed(
    db: &Database,
    room_id: &str,
    contact_id: &str,
    role: &str,
    chain_seed: &[u8; 32],
    joined_at: i64,
) -> Result<()> {
    let sk = SenderKey::from_seed(*chain_seed);
    let blob = encode(&sk)?;
    db.add_room_member(&RoomMember {
        room_id: room_id.into(),
        contact_id: contact_id.into(),
        role: role.into(),
        sender_key: Some(blob),
        joined_at,
    })
    .map_err(|e| anyhow!("add room member: {e}"))
}

/// Persist the user's own sender-key state for a room.
pub fn save_self(db: &Database, room_id: &str, sk: &SenderKey) -> Result<()> {
    let blob = encode(sk)?;
    db.put_self_room_key(room_id, &blob)
        .map_err(|e| anyhow!("put_self_room_key: {e}"))
}

/// Load the user's own sender-key state for a room.
pub fn load_self(db: &Database, room_id: &str) -> Result<Option<SenderKey>> {
    let blob = db
        .get_self_room_key(room_id)
        .map_err(|e| anyhow!("get_self_room_key: {e}"))?;
    decode(blob.as_deref())
}

/// Insert a member row without a known sender key yet (e.g., placeholder
/// for an invited peer who hasn't sent us their seed yet).
pub fn upsert_member_pending(
    db: &Database,
    room_id: &str,
    contact_id: &str,
    role: &str,
    joined_at: i64,
) -> Result<()> {
    db.add_room_member(&RoomMember {
        room_id: room_id.into(),
        contact_id: contact_id.into(),
        role: role.into(),
        sender_key: None,
        joined_at,
    })
    .map_err(|e| anyhow!("add room member: {e}"))
}

/// Mark `(room, contact)` as having ACK'd our sender-key share. Used by
/// `handle_room_sender_key_ack` to flip the gate that lets `room_send`
/// fan out future messages to this peer immediately.
pub fn mark_peer_acked_my_key(
    db: &Database,
    room_id: &str,
    contact_id: &str,
    when_ms: i64,
) -> Result<()> {
    db.conn
        .execute(
            "UPDATE room_members SET peer_acked_my_key_at = ?1
             WHERE room_id = ?2 AND contact_id = ?3",
            rusqlite::params![when_ms, room_id, contact_id],
        )
        .map_err(|e| anyhow!("update peer_acked_my_key_at: {e}"))?;
    Ok(())
}

/// Has `contact_id` ACK'd our sender-key share for `room_id`?
pub fn peer_has_acked_my_key(
    db: &Database,
    room_id: &str,
    contact_id: &str,
) -> Result<bool> {
    let mut stmt = db
        .conn
        .prepare(
            "SELECT peer_acked_my_key_at FROM room_members
             WHERE room_id = ?1 AND contact_id = ?2",
        )
        .map_err(|e| anyhow!("prepare peer_has_acked: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::params![room_id, contact_id])
        .map_err(|e| anyhow!("query peer_has_acked: {e}"))?;
    match rows.next().map_err(|e| anyhow!("next: {e}"))? {
        Some(r) => {
            let ts: Option<i64> = r.get(0).map_err(|e| anyhow!("col: {e}"))?;
            Ok(ts.is_some())
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::rooms::RoomMember;
    use rusqlite::params;

    fn fresh_db_with_room_member(room_id: &str, contact_id: &str) -> Database {
        let db = Database::open_in_memory_for_tests();
        crate::db::schema::apply(&db.conn).expect("apply schema");
        db.conn
            .execute(
                "INSERT INTO contacts (id, alias, ed25519_public, x25519_public, mlkem_public, created_at, updated_at)
                 VALUES (?1, 'a', x'', x'', x'', 0, 0)",
                params![contact_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO conversations (id, type, created_at) VALUES (?1, 'room', 0)",
                params![room_id],
            )
            .unwrap();
        db.add_room_member(&RoomMember {
            room_id: room_id.into(),
            contact_id: contact_id.into(),
            role: "member".into(),
            sender_key: None,
            joined_at: 0,
        })
        .unwrap();
        db
    }

    #[test]
    fn peer_has_acked_starts_false() {
        let db = fresh_db_with_room_member("r", "c");
        assert!(!peer_has_acked_my_key(&db, "r", "c").unwrap());
    }

    #[test]
    fn mark_then_query_round_trip() {
        let db = fresh_db_with_room_member("r", "c");
        mark_peer_acked_my_key(&db, "r", "c", 12345).unwrap();
        assert!(peer_has_acked_my_key(&db, "r", "c").unwrap());
    }

    #[test]
    fn unknown_contact_returns_false_not_error() {
        let db = fresh_db_with_room_member("r", "c");
        // Querying for a contact not in the room must not panic.
        assert!(!peer_has_acked_my_key(&db, "r", "nope").unwrap());
    }
}
