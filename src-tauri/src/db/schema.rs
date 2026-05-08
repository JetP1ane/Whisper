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
    -- I2P destination is independent from the Ed25519 identity so it can
    -- be rotated without rotating identity (Mod #3). `i2p_dest_pub` is the
    -- base64 public destination shared with peers; `i2p_dest_priv` is the
    -- full private blob i2pd's SAM `SESSION CREATE DESTINATION=` accepts.
    i2p_dest_pub    TEXT,
    i2p_dest_priv   BLOB,
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
    -- I2P destination of the contact (base64). Populated from the signed
    -- contact bundle exchange. The legacy relay_url column was dropped
    -- when the desktop client went I2P-only.
    i2p_destination       TEXT,
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

-- I2P send queue. Outbound message blobs that haven't been ACK'd by the
-- peer yet. The queue worker walks this on a backoff schedule and retries
-- delivery via ConnectionManager::send_blob. Rows expire after 30 days.
CREATE TABLE IF NOT EXISTS i2p_send_queue (
    id                  TEXT PRIMARY KEY,        -- random UUID for the queue entry
    contact_id          TEXT NOT NULL,
    message_id          TEXT NOT NULL,           -- ref. into messages table for status updates
    contact_destination TEXT NOT NULL,           -- peer's i2p_destination (b64) at enqueue time
    frame_kind          INTEGER NOT NULL,        -- FrameType code (0x01 message, 0x02 file metadata, etc.)
    encrypted_blob      BLOB NOT NULL,           -- ratchet-encrypted bytes already framed-payload-ready
    created_at          INTEGER NOT NULL,        -- ms since epoch
    last_attempt_at     INTEGER,                 -- ms since epoch; NULL means not yet attempted
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'queued',  -- queued|delivered|expired|failed
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_i2p_send_queue_status ON i2p_send_queue(status, last_attempt_at);
CREATE INDEX IF NOT EXISTS idx_i2p_send_queue_contact ON i2p_send_queue(contact_id, status);

-- Per-room outbound buffer for messages we couldn't fan out to a member
-- yet because they haven't ACK'd our sender-key share. Drained by
-- `messaging::inbound::handle_room_sender_key_ack` when the missing
-- ACK arrives. Closes the race where the very first room message
-- could arrive at a fresh co-participant before our pairwise ratchet
-- bootstrap completed and they'd silently drop the ciphertext.
CREATE TABLE IF NOT EXISTS room_pending_fanout (
    id           TEXT PRIMARY KEY,
    room_id      TEXT NOT NULL,
    contact_id   TEXT NOT NULL,
    msg_id       TEXT NOT NULL,
    blob         BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (room_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_room_pending_fanout_target
  ON room_pending_fanout(room_id, contact_id, created_at);

-- Per-message emoji reactions. Both local and remote reactions land
-- here; `reactor_alias` is "self" for our own reactions and the
-- peer's alias for inbound ones. A given (message_id, reactor_alias,
-- emoji) tuple is unique — re-reacting with the same emoji is a
-- no-op, and removing a reaction is `DELETE WHERE …`.
CREATE TABLE IF NOT EXISTS message_reactions (
    id              TEXT PRIMARY KEY,
    message_id      TEXT NOT NULL,
    reactor_alias   TEXT NOT NULL,
    emoji           TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    UNIQUE (message_id, reactor_alias, emoji),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_message_reactions_msg
  ON message_reactions(message_id);
"#;

pub fn apply(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(SQL_V1)?;
    // Tolerant ALTERs for columns added after the initial v1 schema. SQLite
    // has no `IF NOT EXISTS` for ADD COLUMN, so we ignore the "duplicate
    // column name" error and let it be a no-op on already-migrated DBs.
    let _ = conn.execute("ALTER TABLE contacts ADD COLUMN nickname TEXT", []);
    let _ = conn.execute("ALTER TABLE identity ADD COLUMN seed_entropy BLOB", []);
    let _ = conn.execute("ALTER TABLE identity ADD COLUMN i2p_dest_pub TEXT", []);
    let _ = conn.execute("ALTER TABLE identity ADD COLUMN i2p_dest_priv BLOB", []);
    let _ = conn.execute("ALTER TABLE contacts ADD COLUMN i2p_destination TEXT", []);
    // delivery_transport on outbound message rows: "i2p" if the I2P
    // dispatch path delivered, "relay" if the legacy relay fallback
    // carried it, NULL for inbound rows or pre-migration messages.
    // Surfaced in the chat bubble as a small icon so the user can see
    // which transport actually moved each byte.
    let _ = conn.execute("ALTER TABLE messages ADD COLUMN delivery_transport TEXT", []);
    // Cached serialized v3 bundle for the contact (signed, full prekey
    // material). Required so message_send can bootstrap a ratchet on
    // first message without going to a relay registry — that path is
    // gone in I2P-only mode.
    let _ = conn.execute("ALTER TABLE contacts ADD COLUMN signed_bundle BLOB", []);
    // Drop legacy relay_url column on existing DBs. Tolerant of the
    // "no such column" error so it's a no-op on fresh DBs that never
    // had the column, and on DBs that have already been migrated.
    let _ = conn.execute("ALTER TABLE contacts DROP COLUMN relay_url", []);
    // Per-(room, peer) timestamp recording when that peer ACK'd our
    // sender-key share for that room. Used by `room_send` to decide
    // whether to fan out immediately or buffer in `room_pending_fanout`.
    let _ = conn.execute(
        "ALTER TABLE room_members ADD COLUMN peer_acked_my_key_at INTEGER",
        [],
    );
    conn.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?1)",
        [CURRENT_VERSION.to_string()],
    )?;
    Ok(())
}
