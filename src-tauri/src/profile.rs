//! Profile scoping — lets multiple instances of the desktop app run
//! side-by-side for multi-user testing.
//!
//! Selection: read once at startup from the `NOCTIS_PROFILE` env var
//! (e.g. `alice`, `bob`, `test1`). Defaults to `default` when unset, so
//! existing single-user installs keep working.
//!
//! Scopes:
//!
//! - Data directory: `~/Library/Application Support/com.noctisprivacy.whisper/<profile>/`
//! - SQLCipher file: `<profile>/whisper.db`
//! - Vault marker:   `<profile>/vault_marker`
//! - Keychain items: service tagged with the profile name

use once_cell::sync::Lazy;
use std::path::PathBuf;

/// Active profile name. Sanitized to ASCII alphanumerics, dashes, and
/// underscores so we never inject odd characters into Keychain service
/// names or filesystem paths.
pub static PROFILE: Lazy<String> = Lazy::new(|| {
    let raw = std::env::var("NOCTIS_PROFILE").unwrap_or_else(|_| "default".to_string());
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase()
});

pub fn name() -> &'static str {
    &PROFILE
}

/// `~/Library/Application Support/com.noctisprivacy.whisper/<profile>`
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Library/Application Support/com.noctisprivacy.whisper")
        .join(name());
    let _ = std::fs::create_dir_all(&base);
    base
}

pub fn db_file() -> PathBuf {
    data_dir().join("whisper.db")
}

pub fn vault_marker_file() -> PathBuf {
    data_dir().join("vault_marker")
}

/// Keychain Service base + per-purpose suffix, scoped to the profile.
/// e.g. `com.noctisprivacy.whisper.alice` for the vault DEK,
///      `com.noctisprivacy.whisper.alice.hwseed` for hardware seeds.
pub fn keychain_service(suffix: &str) -> String {
    if suffix.is_empty() {
        format!("com.noctisprivacy.whisper.{}", name())
    } else {
        format!("com.noctisprivacy.whisper.{}.{}", name(), suffix)
    }
}
