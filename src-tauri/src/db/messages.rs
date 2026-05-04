//! Message + conversation CRUD.

use super::{DbResult, Database};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub kind: String, // 'direct' | 'room'
    pub contact_id: Option<String>,
    /// Resolved peer alias for direct conversations (joined from contacts).
    /// `None` for rooms or until the contact row is missing.
    pub contact_alias: Option<String>,
    /// Optional user-set display name for the peer. Frontend prefers this
    /// over `contact_alias` when set.
    pub contact_nickname: Option<String>,
    pub room_name: Option<String>,
    pub room_description: Option<String>,
    pub disappear_timer: Option<i64>,
    pub is_sealed: bool,
    pub is_pending: bool,
    pub last_message_at: Option<i64>,
    pub unread_count: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub conversation_id: String,
    pub sender_alias: String,
    pub is_outbound: bool,
    /// Decrypted plaintext body. We hold the on-disk row encrypted, and only
    /// populate this field on read paths after Secure-Enclave decryption.
    pub plaintext: Option<String>,
    pub is_attachment: bool,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
    pub status: String,
    pub disappear_at: Option<i64>,
    pub created_at: i64,
}

impl Database {
    pub fn list_conversations(&self) -> DbResult<Vec<Conversation>> {
        // LEFT JOIN to surface the contact alias + nickname for direct
        // conversations.
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.type, c.contact_id, k.alias, k.nickname,
                    c.room_name, c.room_description, c.disappear_timer,
                    c.is_sealed, c.is_pending, c.last_message_at,
                    c.unread_count, c.created_at
             FROM conversations c
             LEFT JOIN contacts k ON k.id = c.contact_id
             ORDER BY c.last_message_at DESC NULLS LAST, c.created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Conversation {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    contact_id: r.get(2)?,
                    contact_alias: r.get(3)?,
                    contact_nickname: r.get(4)?,
                    room_name: r.get(5)?,
                    room_description: r.get(6)?,
                    disappear_timer: r.get(7)?,
                    is_sealed: r.get::<_, i64>(8)? != 0,
                    is_pending: r.get::<_, i64>(9)? != 0,
                    last_message_at: r.get(10)?,
                    unread_count: r.get(11)?,
                    created_at: r.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn upsert_conversation(&self, c: &Conversation) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO conversations (
                id, type, contact_id, room_name, room_description, disappear_timer,
                is_sealed, is_pending, last_message_at, unread_count, created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(id) DO UPDATE SET
                contact_id        = excluded.contact_id,
                room_name         = excluded.room_name,
                room_description  = excluded.room_description,
                disappear_timer   = excluded.disappear_timer,
                is_sealed         = excluded.is_sealed,
                is_pending        = excluded.is_pending,
                last_message_at   = excluded.last_message_at,
                unread_count      = excluded.unread_count",
            params![
                c.id,
                c.kind,
                c.contact_id,
                c.room_name,
                c.room_description,
                c.disappear_timer,
                c.is_sealed as i64,
                c.is_pending as i64,
                c.last_message_at,
                c.unread_count,
                c.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn set_conversation_pending(&self, id: &str, pending: bool) -> DbResult<()> {
        self.conn.execute(
            "UPDATE conversations SET is_pending = ?1 WHERE id = ?2",
            params![pending as i64, id],
        )?;
        Ok(())
    }

    pub fn delete_conversation_and_contact(&self, id: &str) -> DbResult<()> {
        // Drop the conversation and the linked contact row (CASCADE on
        // foreign key removes ratchet sessions + messages).
        let contact_id: Option<String> = self
            .conn
            .query_row(
                "SELECT contact_id FROM conversations WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .ok();
        self.conn
            .execute("DELETE FROM conversations WHERE id = ?1", params![id])?;
        if let Some(cid) = contact_id {
            self.conn
                .execute("DELETE FROM contacts WHERE id = ?1", params![cid])?;
        }
        Ok(())
    }

    pub fn set_message_status(&self, id: &str, status: &str) -> DbResult<()> {
        self.conn.execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    /// Record which transport carried this outbound message — "i2p" or
    /// "relay". Pre-Phase-6 rows have NULL here. The bubble UI renders
    /// a small icon distinguishing the two so the user can see at a
    /// glance which path each send actually took.
    pub fn set_message_delivery_transport(
        &self,
        id: &str,
        transport: &str,
    ) -> DbResult<()> {
        self.conn.execute(
            "UPDATE messages SET delivery_transport = ?1 WHERE id = ?2",
            params![transport, id],
        )?;
        Ok(())
    }

    /// Insert a message row. Caller passes the TEE-encrypted body. For
    /// outbound messages, `wire_hash` is the SHA-256 of the deposited blob
    /// (so inbound delivery receipts can match it back).
    pub fn insert_message(
        &self,
        m: &Message,
        tee_encrypted_content: Option<&[u8]>,
        sealed_content: Option<&[u8]>,
        wire_hash: Option<&[u8]>,
    ) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO messages (
                id, conversation_id, sender_alias, is_outbound,
                tee_encrypted_content, sealed_content,
                is_attachment, filename, mime_type, file_size,
                status, wire_hash, disappear_at, created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                m.id,
                m.conversation_id,
                m.sender_alias,
                m.is_outbound as i64,
                tee_encrypted_content,
                sealed_content,
                m.is_attachment as i64,
                m.filename,
                m.mime_type,
                m.file_size,
                m.status,
                wire_hash,
                m.disappear_at,
                m.created_at,
            ],
        )?;
        Ok(())
    }

    /// Flip an outbound message's status to `delivered` by matching the
    /// SHA-256 of the original deposited wire blob. Returns the row id if
    /// we found and updated it.
    pub fn mark_delivered_by_wire_hash(&self, wire_hash: &[u8]) -> DbResult<Option<String>> {
        let id: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM messages
                 WHERE wire_hash = ?1 AND is_outbound = 1
                 ORDER BY created_at DESC LIMIT 1",
                params![wire_hash],
                |r| r.get(0),
            )
            .ok();
        if let Some(ref id) = id {
            self.conn.execute(
                "UPDATE messages SET status = 'delivered' WHERE id = ?1",
                params![id],
            )?;
        }
        Ok(id)
    }

    pub fn settings_get(&self, key: &str) -> DbResult<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(r) = rows.next()? {
            Ok(Some(r.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn settings_put(&self, key: &str, value: &str) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn settings_delete(&self, key: &str) -> DbResult<()> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Look up the disappearing-message timer (in seconds) for a single
    /// conversation, if one is configured. Used by the send/receive paths
    /// to compute each message row's `disappear_at` deadline.
    pub fn conversation_disappear_timer(
        &self,
        conversation_id: &str,
    ) -> DbResult<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT disappear_timer FROM conversations WHERE id = ?1")?;
        let mut rows = stmt.query(params![conversation_id])?;
        if let Some(r) = rows.next()? {
            Ok(r.get::<_, Option<i64>>(0)?)
        } else {
            Ok(None)
        }
    }

    /// Delete every message whose `disappear_at` deadline has passed.
    /// Returns the number of rows removed.
    pub fn purge_expired_messages(&self, now_ms: i64) -> DbResult<usize> {
        let n = self.conn.execute(
            "DELETE FROM messages
             WHERE disappear_at IS NOT NULL AND disappear_at <= ?1",
            params![now_ms],
        )?;
        Ok(n)
    }

    /// Set the disappearing-message timer (or clear it with `None`).
    pub fn set_disappear_timer(&self, conversation_id: &str, secs: Option<i64>) -> DbResult<()> {
        self.conn.execute(
            "UPDATE conversations SET disappear_timer = ?1 WHERE id = ?2",
            params![secs, conversation_id],
        )?;
        Ok(())
    }

    /// Load encrypted rows for a conversation. Plaintext decryption happens above this layer.
    pub fn load_messages_encrypted(
        &self,
        conversation_id: &str,
        limit: i64,
    ) -> DbResult<Vec<EncryptedRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender_alias, is_outbound,
                    tee_encrypted_content, sealed_content,
                    is_attachment, filename, mime_type, file_size,
                    status, disappear_at, delivery_transport, created_at
             FROM messages
             WHERE conversation_id = ?1
             ORDER BY created_at ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![conversation_id, limit], |r| {
                Ok(EncryptedRow {
                    id: r.get(0)?,
                    sender_alias: r.get(1)?,
                    is_outbound: r.get::<_, i64>(2)? != 0,
                    tee_encrypted_content: r.get(3)?,
                    sealed_content: r.get(4)?,
                    is_attachment: r.get::<_, i64>(5)? != 0,
                    filename: r.get(6)?,
                    mime_type: r.get(7)?,
                    file_size: r.get(8)?,
                    status: r.get(9)?,
                    disappear_at: r.get(10)?,
                    delivery_transport: r.get(11)?,
                    created_at: r.get(12)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedRow {
    pub id: String,
    pub sender_alias: String,
    pub is_outbound: bool,
    pub tee_encrypted_content: Option<Vec<u8>>,
    pub sealed_content: Option<Vec<u8>>,
    pub is_attachment: bool,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
    pub status: String,
    pub disappear_at: Option<i64>,
    /// "i2p" / "relay" / NULL — see `set_message_delivery_transport`.
    pub delivery_transport: Option<String>,
    pub created_at: i64,
}
