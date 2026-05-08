//! Outbound dispatch helpers used by `commands.rs` to decide whether
//! a contact is reachable over I2P and to peel the legacy 32-byte
//! mailbox prefix off a `PreparedSend.blob` before handing it to the
//! `ConnectionManager`.
//!
//! Older revisions of this module also contained a relay-fallback
//! dispatcher; that path was removed when the desktop client went
//! I2P-only. The two functions below are the only pieces that survived.

use super::runtime::I2PRuntime;
use super::I2pError;
use crate::db::contacts::Contact;
use crate::transport::mailbox::MAILBOX_PREFIX_LEN;

/// Returns `true` iff we should attempt I2P delivery for this contact
/// right now: the contact has a real-looking I2P destination and an
/// I2P runtime is available.
pub fn should_use_i2p(contact: &Contact, i2p: Option<&I2PRuntime>) -> bool {
    let dest = match contact.i2p_destination.as_deref() {
        Some(d) if !d.is_empty() => d,
        _ => return false,
    };
    if i2p.is_none() {
        return false;
    }
    // A destination shorter than ~400 chars is definitely malformed
    // (real I2P destinations are 516+ chars b64). Reject obvious junk
    // before bothering the SAM bridge.
    dest.len() >= 400
}

/// Strip the 32-byte sender mailbox prefix that `prepare_send_text`
/// glues onto the front of `PreparedSend.blob` for the legacy relay
/// layout. I2P destination routing makes that prefix meaningless.
pub fn strip_mailbox_prefix(blob: &[u8]) -> Result<&[u8], I2pError> {
    if blob.len() < MAILBOX_PREFIX_LEN {
        return Err(I2pError::Encoding(format!(
            "blob too short to strip mailbox prefix (have {}, need >= {})",
            blob.len(),
            MAILBOX_PREFIX_LEN
        )));
    }
    Ok(&blob[MAILBOX_PREFIX_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact_with(dest: Option<&str>) -> Contact {
        Contact {
            id: "c1".into(),
            alias: "abc".into(),
            ed25519_public: vec![0u8; 32],
            x25519_public: vec![0u8; 32],
            mlkem_public: vec![],
            i2p_destination: dest.map(String::from),
            verified: false,
            peer_has_verified_us: false,
            hide_until_verified: false,
            is_sealed: false,
            nickname: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn should_use_i2p_requires_destination_runtime_and_min_length() {
        let with_dest = contact_with(Some(&"A".repeat(500)));
        let no_dest = contact_with(None);
        let short_dest = contact_with(Some("ABCD"));
        // No runtime: never use I2P.
        assert!(!should_use_i2p(&with_dest, None));
        assert!(!should_use_i2p(&no_dest, None));
        assert!(!should_use_i2p(&short_dest, None));
    }

    #[test]
    fn strip_mailbox_prefix_drops_first_32_bytes() {
        let mut blob = b"00112233445566778899aabbccddeeff".to_vec();
        blob.extend_from_slice(b"INNER_WIRE_PAYLOAD");
        let inner = strip_mailbox_prefix(&blob).unwrap();
        assert_eq!(inner, b"INNER_WIRE_PAYLOAD");
    }

    #[test]
    fn strip_mailbox_prefix_rejects_short_blobs() {
        let too_short = b"only-five".to_vec();
        let err = strip_mailbox_prefix(&too_short).unwrap_err();
        assert!(matches!(err, I2pError::Encoding(_)));
    }
}
