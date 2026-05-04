//! Magic-byte envelopes that share the deposit channel with ratchet messages.
//!
//! These are not encrypted — they are framing hints. The receiver uses the
//! prefix to dispatch without attempting ratchet decryption first. Magic bytes
//! are NOT a security boundary; cryptographic verification (Ed25519 bundle
//! signature, ratchet AEAD) happens independently.
//!
//! Layouts match the Android client byte-for-byte
//! (`ContactRequestEnvelope.kt`, `SessionRequestEnvelope.kt`).

/// `[0xCF, 0xC0, 0xDE, 0x01] || compact_bundle_bytes`
pub const CONTACT_REQUEST_MAGIC: [u8; 4] = [0xCF, 0xC0, 0xDE, 0x01];

/// `[0xCF, 0xC0, 0x5E, 0x01] || 8B big-endian unix-millis timestamp`
/// Always exactly 12 bytes — distinguishable from the 4096-byte ratchet
/// message and the (>4096) first-message payload by size alone.
pub const SESSION_REQUEST_MAGIC: [u8; 4] = [0xCF, 0xC0, 0x5E, 0x01];

pub fn wrap_contact_request(bundle_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bundle_bytes.len());
    out.extend_from_slice(&CONTACT_REQUEST_MAGIC);
    out.extend_from_slice(bundle_bytes);
    out
}

pub fn unwrap_contact_request(wire: &[u8]) -> Option<&[u8]> {
    if wire.len() <= 4 {
        return None;
    }
    if wire[..4] == CONTACT_REQUEST_MAGIC {
        Some(&wire[4..])
    } else {
        None
    }
}

pub fn build_session_request(timestamp_ms: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&SESSION_REQUEST_MAGIC);
    out[4..].copy_from_slice(&timestamp_ms.to_be_bytes());
    out
}

pub fn is_session_request(wire: &[u8]) -> bool {
    wire.len() >= 4 && wire[..4] == SESSION_REQUEST_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_request_round_trip() {
        let bundle = b"hello bundle";
        let wrapped = wrap_contact_request(bundle);
        assert_eq!(&wrapped[..4], &CONTACT_REQUEST_MAGIC);
        assert_eq!(unwrap_contact_request(&wrapped), Some(&bundle[..]));
    }

    #[test]
    fn session_request_is_twelve_bytes() {
        let r = build_session_request(0x1122_3344_5566_7788);
        assert_eq!(r.len(), 12);
        assert_eq!(&r[..4], &SESSION_REQUEST_MAGIC);
        assert_eq!(&r[4..], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert!(is_session_request(&r));
    }

    #[test]
    fn unrelated_bytes_are_not_envelopes() {
        let v = [0u8; 4096];
        assert!(unwrap_contact_request(&v).is_none());
        assert!(!is_session_request(&v));
    }
}
