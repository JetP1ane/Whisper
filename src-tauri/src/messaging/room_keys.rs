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
