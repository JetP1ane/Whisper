//! Schema definition + migrations.
//!
//! Migration policy: schema_version row in a `schema_meta` table; each
//! migration is an idempotent `CREATE TABLE IF NOT EXISTS` plus any column
//! additions with `ALTER TABLE`. Drop columns by recreating the table.

use rusqlite::Connection;
use super::DbResult;

pub const CURRENT_VERSION: u32 = 1;

const SQL_V1: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Long-term identity (one row, id = 'self'). Secret bytes live alongside
-- public bytes in the same row — SQLCipher provides at-rest encryption and
-- the row is only visible while the vault is unlocked.
CREATE TABLE IF NOT EXISTS identity (
    id              TEXT PRIMARY KEY,
    ed25519_public  BLOB NOT NULL,
    ed25519_secret  BLOB NOT NULL,
    x25519_public   BLOB NOT NULL,
    x25519_secret   BLOB NOT NULL,
    mlkem_public    BLOB NOT NULL,
    mlkem_secret    BLOB NOT NULL,
    alias           TEXT NOT NULL,
    display_name    TEXT,
    seed_entropy    BLOB,                   -- 16-byte BIP39 entropy (recovery)
    created_at      INTEGER NOT NULL
);

-- Signed prekey (rotates periodically). Currently a single active row;
-- past rotations remain for inflight decryptions during transition.
CREATE TABLE IF NOT EXISTS signed_prekeys (
    id              INTEGER PRIMARY KEY,
    x25519_public   BLOB NOT NULL,
    x25519_secret   BLOB NOT NULL,
    mlkem_public    BLOB NOT NULL,
    mlkem_secret    BLOB NOT NULL,
    signature       BLOB NOT NULL,
    created_at      INTEGER NOT NULL,
    rotated_at      INTEGER
);

-- One-time prekeys. Consumed (deleted) when used by an incoming session.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id              INTEGER PRIMARY KEY,
    x25519_public   BLOB NOT NULL,
    x25519_secret   BLOB NOT NULL,
    mlkem_public    BLOB NOT NULL,
    mlkem_secret    BLOB NOT NULL,
    consumed        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
);

-- Contacts.
CREATE TABLE IF NOT EXISTS contacts (
    id                    TEXT PRIMARY KEY,
    alias                 TEXT NOT NULL,
    ed25519_public        BLOB NOT NULL,
    x25519_public         BLOB NOT NULL,
    mlkem_public          BLOB NOT NULL,
    relay_url             TEXT,
    verified              INTEGER NOT NULL DEFAULT 0,
    peer_has_verified_us  INTEGER NOT NULL DEFAULT 0,
    hide_until_verified   INTEGER NOT NULL DEFAULT 0,
    is_sealed             INTEGER NOT NULL DEFAULT 0,
    sealed_salt           BLOB,
    nickname              TEXT,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contacts_alias ON contacts(alias);

-- Conversations.
-- `is_pending = 1` means this is an unaccepted contact request (inbound from
-- another peer). The conversation is hidden from the main list and shown in
-- the dedicated "Requests" UI until the user accepts or declines.
CREATE TABLE IF NOT EXISTS conversations (
    id                TEXT PRIMARY KEY,
    type              TEXT NOT NULL,           -- 'direct' | 'room'
    contact_id        TEXT,                    -- direct only
    room_name         TEXT,                    -- room only
    room_description  TEXT,
    disappear_timer   INTEGER,                 -- seconds, NULL = off
    is_sealed         INTEGER NOT NULL DEFAULT 0,
    is_pending        INTEGER NOT NULL DEFAULT 0,
    sealed_salt       BLOB,
    last_message_at   INTEGER,
    unread_count      INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_conv_last ON conversations(last_message_at DESC);

-- Messages.
-- `wire_hash` is SHA-256 of the deposited blob bytes (sender mailbox prefix
-- + ratchet wire), kept on outbound rows so we can match incoming delivery
-- receipts back to the original message and flip status `sent` → `delivered`.
CREATE TABLE IF NOT EXISTS messages (
    id                     TEXT PRIMARY KEY,
    conversation_id        TEXT NOT NULL,
    sender_alias           TEXT NOT NULL,
    is_outbound            INTEGER NOT NULL,
    tee_encrypted_content  BLOB,
    sealed_content         BLOB,
    is_attachment          INTEGER NOT NULL DEFAULT 0,
    filename               TEXT,
    mime_type              TEXT,
    file_size              INTEGER,
    status                 TEXT NOT NULL DEFAULT 'queued', -- queued|sent|delivered|failed
    wire_hash              BLOB,
    disappear_at           INTEGER,
    created_at             INTEGER NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_msg_disappear ON messages(disappear_at) WHERE disappear_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_msg_wire_hash ON messages(wire_hash) WHERE wire_hash IS NOT NULL;

-- Ratchet sessions (one per peer; rooms use sender keys, not pairwise ratchets).
CREATE TABLE IF NOT EXISTS ratchet_sessions (
    contact_id   TEXT PRIMARY KEY,
    session_data BLOB NOT NULL,
    updated_at   INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- Room members (sender-key state). One row per peer; the owner's own key
-- lives separately in `room_self_keys` because it does not point at a
-- contact row.
CREATE TABLE IF NOT EXISTS room_members (
    room_id     TEXT NOT NULL,
    contact_id  TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member', -- 'owner'|'member'
    sender_key  BLOB,
    joined_at   INTEGER NOT NULL,
    PRIMARY KEY (room_id, contact_id),
    FOREIGN KEY (room_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

-- The current user's per-room sender key. Separate from `room_members`
-- because we don't have a contact row for ourselves.
CREATE TABLE IF NOT EXISTS room_self_keys (
    room_id     TEXT PRIMARY KEY,
    sender_key  BLOB NOT NULL,
    FOREIGN KEY (room_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Pending blobs (crash-safe receive queue: blob is decoded post-restart).
CREATE TABLE IF NOT EXISTS pending_blobs (
    id           TEXT PRIMARY KEY,
    blob_data    BLOB NOT NULL,
    received_at  INTEGER NOT NULL
);

-- Settings (key/value, opaque).
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

pub fn apply(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(SQL_V1)?;
    // Tolerant ALTERs for columns added after the initial v1 schema. SQLite
    // has no `IF NOT EXISTS` for ADD COLUMN, so we ignore the "duplicate
    // column name" error and let it be a no-op on already-migrated DBs.
    let _ = conn.execute("ALTER TABLE contacts ADD COLUMN nickname TEXT", []);
    let _ = conn.execute("ALTER TABLE identity ADD COLUMN seed_entropy BLOB", []);
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?1)",
        [CURRENT_VERSION.to_string()],
    )?;
    Ok(())
}
