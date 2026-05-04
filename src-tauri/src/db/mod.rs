//! SQLCipher-backed local store.
//!
//! - The database file lives in the app's sandbox container.
//! - The key is derived in the crypto layer
//!   (`HKDF(software_dek, salt = AES_CBC(SE_key, software_dek), info = HARDWARE_DB_INFO)`).
//! - We open the connection with `PRAGMA key = "x'<hex>'";` so SQLCipher
//!   uses the raw 32-byte key directly (no second KDF pass).

pub mod contacts;
pub mod identity;
pub mod messages;
pub mod rooms;
pub mod schema;

use rusqlite::Connection;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlcipher: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid db key length")]
    InvalidKeyLen,
}

pub type DbResult<T> = Result<T, DbError>;

pub struct Database {
    pub conn: Connection,
}

impl Database {
    /// Open (or create) the SQLCipher database at `path` using `db_key`.
    /// `db_key` must be 32 bytes; it is hex-encoded into the PRAGMA only and
    /// zeroized immediately afterwards.
    pub fn open(path: &Path, db_key: &[u8]) -> DbResult<Self> {
        if db_key.len() != 32 {
            return Err(DbError::InvalidKeyLen);
        }
        let conn = Connection::open(path)?;

        // Use SQLCipher's raw-key form: x'<64 hex chars>'.
        let mut hex_key = String::with_capacity(64);
        for b in db_key {
            use std::fmt::Write;
            let _ = write!(&mut hex_key, "{:02x}", b);
        }
        let pragma = format!("PRAGMA key = \"x'{}'\";", hex_key);
        conn.execute_batch(&pragma)?;
        hex_key.zeroize();

        // SQLCipher 4 defaults are fine; tighten cipher settings if we ever
        // need to harden against downgrade.
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;

        schema::apply(&conn)?;
        Ok(Self { conn })
    }

    /// Close + zeroize. The `Connection` itself doesn't expose the key, so
    /// dropping is sufficient.
    pub fn close(self) {
        drop(self.conn);
    }

    /// Open an in-memory database for tests. Skips the SQLCipher PRAGMA
    /// dance (in-memory SQLite is process-private already) and does not
    /// run the schema migration — callers do that explicitly so they can
    /// layer additional fixtures around it.
    ///
    /// Always-public so integration tests under `tests/` can reach it;
    /// production callers must use [`open`] which goes through SQLCipher.
    #[doc(hidden)]
    pub fn open_in_memory_for_tests() -> Self {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("pragma");
        Self { conn }
    }
}
