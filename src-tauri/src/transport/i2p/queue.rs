//! Persistent send queue.
//!
//! Bridges the gap between "user hits Send" (synchronous) and "peer is
//! reachable through I2P right now" (asynchronous, may be hours later).
//! The queue:
//!
//! 1. Holds the ratchet-encrypted blob in SQLCipher so a crash doesn't
//!    drop the message.
//! 2. Walks pending rows on a backoff schedule, calling
//!    [`connection::ConnectionManager::send_blob`] for each.
//! 3. On success, marks the row `delivered` + flips the user-visible
//!    message row's `status` from `queued` → `delivered`.
//! 4. On failure, bumps `attempt_count`, records `last_attempt_at`, and
//!    leaves the row `queued` for the next backoff tick.
//! 5. Expires rows after 30 days of un-ACK'd retries.
//!
//! The queue worker is started on vault-unlock and stopped on
//! vault-lock. It's intentionally a single tokio task — the inner SAM
//! `stream_connect` parallelism comes for free because each `send_blob`
//! opens its own short-lived connection (or reuses the cached one).

use super::connection::ConnectionManager;
use super::framing::FrameType;
use super::I2pResult;
use crate::db::{DbResult, Database};
use rusqlite::params;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Maximum age of a queue entry before we give up and mark it expired.
const QUEUE_TTL_SECS: i64 = 30 * 24 * 3600;

/// Backoff between attempts. Matches the design proposal §4 schedule.
fn backoff_for_attempt(n: u32) -> Duration {
    match n {
        0 => Duration::from_secs(0),
        1 => Duration::from_secs(5),
        2 => Duration::from_secs(15),
        3 => Duration::from_secs(30),
        4 => Duration::from_secs(60),
        _ => Duration::from_secs(300),
    }
}

#[derive(Debug, Clone)]
pub struct QueuedSend {
    pub id: String,
    pub contact_id: String,
    pub message_id: String,
    pub contact_destination: String,
    pub frame_kind: u8,
    pub encrypted_blob: Vec<u8>,
    pub created_at: i64,
    pub last_attempt_at: Option<i64>,
    pub attempt_count: u32,
    pub status: String,
}

/// Enqueue a new outbound message. Returns the row id. Idempotent in the
/// sense that re-enqueuing the same blob just creates a new row — the
/// caller's `message_id` stays stable so the messages table tracks one
/// logical message.
pub fn enqueue(
    db: &Database,
    contact_id: &str,
    message_id: &str,
    contact_destination: &str,
    frame_kind: FrameType,
    encrypted_blob: &[u8],
) -> DbResult<String> {
    let id = Uuid::new_v4().to_string();
    let now = now_unix_ms();
    db.conn.execute(
        "INSERT INTO i2p_send_queue
            (id, contact_id, message_id, contact_destination, frame_kind,
             encrypted_blob, created_at, last_attempt_at, attempt_count, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, 0, 'queued')",
        params![
            id,
            contact_id,
            message_id,
            contact_destination,
            frame_kind.code() as i64,
            encrypted_blob,
            now,
        ],
    )?;
    Ok(id)
}

/// Fetch all rows still in `queued` state. Ordered oldest first so
/// retries respect the original send order.
pub fn list_queued(db: &Database) -> DbResult<Vec<QueuedSend>> {
    let mut stmt = db.conn.prepare(
        "SELECT id, contact_id, message_id, contact_destination, frame_kind,
                encrypted_blob, created_at, last_attempt_at, attempt_count, status
         FROM i2p_send_queue
         WHERE status = 'queued'
         ORDER BY created_at ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(QueuedSend {
                id: r.get(0)?,
                contact_id: r.get(1)?,
                message_id: r.get(2)?,
                contact_destination: r.get(3)?,
                frame_kind: r.get::<_, i64>(4)? as u8,
                encrypted_blob: r.get(5)?,
                created_at: r.get(6)?,
                last_attempt_at: r.get(7)?,
                attempt_count: r.get::<_, i64>(8)? as u32,
                status: r.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Mark a row delivered + propagate status to the messages table.
pub fn mark_delivered(db: &Database, queue_id: &str, message_id: &str) -> DbResult<()> {
    db.conn.execute(
        "UPDATE i2p_send_queue SET status = 'delivered' WHERE id = ?1",
        params![queue_id],
    )?;
    db.conn.execute(
        "UPDATE messages SET status = 'delivered' WHERE id = ?1",
        params![message_id],
    )?;
    Ok(())
}

/// Mark a row expired + propagate status. Called when a row exceeds
/// `QUEUE_TTL_SECS`.
pub fn mark_expired(db: &Database, queue_id: &str, message_id: &str) -> DbResult<()> {
    db.conn.execute(
        "UPDATE i2p_send_queue SET status = 'expired' WHERE id = ?1",
        params![queue_id],
    )?;
    db.conn.execute(
        "UPDATE messages SET status = 'failed' WHERE id = ?1",
        params![message_id],
    )?;
    Ok(())
}

/// Bump attempt counters after a failed delivery. Status stays `queued`
/// so the next worker tick picks it up after the backoff.
pub fn record_attempt(db: &Database, queue_id: &str) -> DbResult<()> {
    let now = now_unix_ms();
    db.conn.execute(
        "UPDATE i2p_send_queue
         SET last_attempt_at = ?1, attempt_count = attempt_count + 1
         WHERE id = ?2",
        params![now, queue_id],
    )?;
    Ok(())
}

/// Outcome of a single send attempt by the worker. Returned by the
/// async send half (`try_send`) so the sync record-keeping half
/// (`record_outcome`) can update the DB without holding a reference
/// across the await.
#[derive(Debug, Clone, Copy)]
enum Attempt {
    Delivered,
    Failed,
}

/// Sync half: peek at the queue under the DB lock, decide which rows
/// are due (by age + backoff), expire any past their TTL, and return
/// the rows to attempt this tick. The DB lock is dropped before the
/// caller does any await — that's the whole point of the split.
fn take_due_rows(db: &Database, now_ms: i64) -> Vec<QueuedSend> {
    let pending = match list_queued(db) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("i2p: list_queued failed: {e}");
            return Vec::new();
        }
    };
    let mut due = Vec::new();
    for row in pending {
        if (now_ms - row.created_at) / 1000 > QUEUE_TTL_SECS {
            let _ = mark_expired(db, &row.id, &row.message_id);
            tracing::warn!(
                "i2p: send queue row {} expired after {}d",
                row.id,
                (now_ms - row.created_at) / 1000 / 86400
            );
            continue;
        }
        if let Some(last) = row.last_attempt_at {
            let waited = Duration::from_millis((now_ms - last) as u64);
            let needed = backoff_for_attempt(row.attempt_count);
            if waited < needed {
                continue;
            }
        }
        due.push(row);
    }
    due
}

/// Async half: actually issue the send. Holds no DB reference.
async fn try_send(conn: &ConnectionManager, row: &QueuedSend) -> Attempt {
    let kind = FrameType::from_code(row.frame_kind);
    match conn
        .send_blob(&row.contact_destination, kind, &row.encrypted_blob)
        .await
    {
        Ok(()) => {
            tracing::info!(
                "i2p: delivered queued message {} to {}",
                row.message_id,
                &row.contact_destination[..16.min(row.contact_destination.len())]
            );
            Attempt::Delivered
        }
        Err(e) => {
            tracing::debug!(
                "i2p: send attempt {} for {} failed: {e}",
                row.attempt_count + 1,
                row.message_id
            );
            Attempt::Failed
        }
    }
}

/// Sync half: write back the outcome. Re-acquires the DB lock.
fn record_outcome(db: &Database, row: &QueuedSend, outcome: Attempt) {
    match outcome {
        Attempt::Delivered => {
            let _ = mark_delivered(db, &row.id, &row.message_id);
        }
        Attempt::Failed => {
            let _ = record_attempt(db, &row.id);
        }
    }
}

/// One pass of the queue worker — useful for tests that drive a single
/// tick without spawning the long-running worker. Returns the number of
/// rows that were marked delivered this pass.
pub async fn process_once(
    db_holder: &parking_lot::Mutex<Option<Database>>,
    conn: &ConnectionManager,
) -> I2pResult<usize> {
    let now = now_unix_ms();
    let due = {
        let guard = db_holder.lock();
        match guard.as_ref() {
            Some(db) => take_due_rows(db, now),
            None => Vec::new(),
        }
    };
    let mut delivered = 0;
    for row in due {
        let outcome = try_send(conn, &row).await;
        if matches!(outcome, Attempt::Delivered) {
            delivered += 1;
        }
        let guard = db_holder.lock();
        if let Some(db) = guard.as_ref() {
            record_outcome(db, &row, outcome);
        }
    }
    Ok(delivered)
}

/// Long-running worker: process the queue on a fixed cadence. Cancelled
/// when the owning `JoinHandle` is dropped (or via `abort()`).
///
/// The cadence here is the *outer* loop — the per-row backoff inside
/// `take_due_rows` gates whether each individual row is actually
/// retried on this tick.
pub async fn run_worker(
    db: Arc<parking_lot::Mutex<Option<Database>>>,
    conn: Arc<ConnectionManager>,
) {
    let tick = Duration::from_secs(5);
    loop {
        tokio::time::sleep(tick).await;
        let _ = process_once(&db, &conn).await;
    }
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db_with_message(message_id: &str, contact_id: &str) -> Database {
        let db = Database::open_in_memory_for_tests();
        crate::db::schema::apply(&db.conn).expect("apply schema");
        // Seed minimum rows that the queue's foreign keys need.
        db.conn
            .execute(
                "INSERT INTO contacts
                    (id, alias, ed25519_public, x25519_public, mlkem_public,
                     created_at, updated_at)
                 VALUES (?1, 'test-alias', x'', x'', x'', 0, 0)",
                params![contact_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO conversations (id, type, contact_id, created_at)
                 VALUES (?1, 'direct', ?1, 0)",
                params![contact_id],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO messages
                    (id, conversation_id, sender_alias, is_outbound, status, created_at)
                 VALUES (?1, ?2, 'self', 1, 'queued', 0)",
                params![message_id, contact_id],
            )
            .unwrap();
        db
    }

    #[test]
    fn enqueue_then_list_returns_one_row() {
        let db = fresh_db_with_message("msg-1", "contact-1");
        enqueue(
            &db,
            "contact-1",
            "msg-1",
            "PEER_DEST_PLACEHOLDER",
            FrameType::Message,
            b"encrypted-bytes",
        )
        .unwrap();
        let rows = list_queued(&db).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, "msg-1");
        assert_eq!(rows[0].frame_kind, FrameType::Message.code());
        assert_eq!(rows[0].encrypted_blob, b"encrypted-bytes");
        assert_eq!(rows[0].status, "queued");
        assert_eq!(rows[0].attempt_count, 0);
        assert!(rows[0].last_attempt_at.is_none());
    }

    #[test]
    fn record_attempt_increments_count_and_stamp() {
        let db = fresh_db_with_message("msg-2", "contact-2");
        let id = enqueue(
            &db,
            "contact-2",
            "msg-2",
            "PEER",
            FrameType::Message,
            b"x",
        )
        .unwrap();
        record_attempt(&db, &id).unwrap();
        record_attempt(&db, &id).unwrap();
        let rows = list_queued(&db).unwrap();
        assert_eq!(rows[0].attempt_count, 2);
        assert!(rows[0].last_attempt_at.is_some());
    }

    #[test]
    fn mark_delivered_propagates_to_messages_table() {
        let db = fresh_db_with_message("msg-3", "contact-3");
        let id = enqueue(
            &db,
            "contact-3",
            "msg-3",
            "PEER",
            FrameType::Message,
            b"x",
        )
        .unwrap();
        mark_delivered(&db, &id, "msg-3").unwrap();
        // Queue row gone from `queued` state.
        let queued = list_queued(&db).unwrap();
        assert!(queued.is_empty());
        // messages.status flipped.
        let s: String = db
            .conn
            .query_row(
                "SELECT status FROM messages WHERE id = 'msg-3'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, "delivered");
    }

    #[test]
    fn mark_expired_flips_message_to_failed() {
        let db = fresh_db_with_message("msg-4", "contact-4");
        let id = enqueue(
            &db,
            "contact-4",
            "msg-4",
            "PEER",
            FrameType::Message,
            b"x",
        )
        .unwrap();
        mark_expired(&db, &id, "msg-4").unwrap();
        let s: String = db
            .conn
            .query_row(
                "SELECT status FROM messages WHERE id = 'msg-4'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, "failed");
    }

    #[test]
    fn backoff_schedule_grows_then_caps_at_5_minutes() {
        assert_eq!(backoff_for_attempt(0), Duration::from_secs(0));
        assert_eq!(backoff_for_attempt(1), Duration::from_secs(5));
        assert_eq!(backoff_for_attempt(4), Duration::from_secs(60));
        assert_eq!(backoff_for_attempt(5), Duration::from_secs(300));
        assert_eq!(backoff_for_attempt(100), Duration::from_secs(300));
    }
}
