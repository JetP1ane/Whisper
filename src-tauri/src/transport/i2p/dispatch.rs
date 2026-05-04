//! Outbound dispatch: pick I2P or relay for a given contact.
//!
//! Each `commands.rs` send path used to call `state.relay.deposit(...)`
//! directly. Phase 6 wraps that single hard-coded transport in a
//! decision: if the contact has an I2P destination AND the I2P runtime
//! is up, send via I2P; otherwise fall back to the relay path. The
//! relay code path is unchanged — it's only the choice that's new.
//!
//! The contract here is intentionally narrow: a contact + the
//! ratchet-encrypted bytes (the wire format produced by
//! `messaging::sender::PreparedSend.blob`). The dispatcher unwraps the
//! Whisper relay-format prefix when going via I2P (the 32-byte sender
//! mailbox prefix is meaningless on a destination-routed transport)
//! and frames just the inner ratchet wire.

use super::framing::FrameType;
use super::runtime::I2PRuntime;
use super::I2pError;
use crate::db::contacts::Contact;
use crate::transport::mailbox::MAILBOX_PREFIX_LEN;

/// Outcome of a dispatch attempt. Both arms tell the caller what to do
/// with the message status row in `messages` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Sent over I2P and the peer ACK'd at the wire level. Caller
    /// flips `messages.status` from `queued` → `sent`. Once the inner
    /// ratchet delivery receipt arrives later, the existing inbound
    /// pipeline flips `sent` → `delivered`.
    DeliveredViaI2p,
    /// Sent via relay using the legacy path. Caller emits the existing
    /// `Deposited` status flow.
    DeliveredViaRelay,
    /// Recipient is not reachable via I2P and has no relay URL. The
    /// caller has already enqueued via `queue::enqueue` and the worker
    /// will retry. Status stays `queued`.
    Queued,
}

/// The decision-only half: returns `true` iff we should attempt I2P
/// for this contact right now. Public so the live integration tests
/// can sanity-check the routing without exercising the full send.
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
/// glues onto the front of `PreparedSend.blob` for the relay layout.
/// I2P destination routing makes that prefix meaningless — it identifies
/// a *mailbox*, and there are no mailboxes on I2P. Returns the inner
/// ratchet wire bytes.
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

/// One-shot send. Tries I2P direct first. If the peer isn't reachable
/// (CANT_REACH_PEER, tunnel build failed, etc.) and a relay URL is on
/// file, falls back to the caller-supplied `relay_send` closure. If
/// neither path works, returns `Outcome::Queued` and the caller is
/// responsible for having already inserted a `i2p_send_queue` row.
///
/// The relay closure is a `Fn` rather than a direct call into
/// `transport::relay` to keep this module's deps narrow — the relay
/// transport may eventually live behind a feature flag.
pub async fn dispatch_send<RF, RFFut>(
    contact: &Contact,
    i2p: Option<&I2PRuntime>,
    kind: FrameType,
    blob: &[u8],
    relay_send: RF,
) -> Result<Outcome, I2pError>
where
    RF: FnOnce() -> RFFut,
    RFFut: std::future::Future<Output = Result<(), String>>,
{
    if should_use_i2p(contact, i2p) {
        let dest = contact.i2p_destination.as_deref().unwrap_or_default();
        let runtime = i2p.expect("checked by should_use_i2p");
        let inner = strip_mailbox_prefix(blob)?;
        match runtime.connection.send_blob(dest, kind, inner).await {
            Ok(()) => return Ok(Outcome::DeliveredViaI2p),
            Err(e) => {
                tracing::info!(
                    "i2p: direct send to {} failed ({e}); falling back",
                    &dest[..16.min(dest.len())]
                );
                // Fall through to relay attempt below.
            }
        }
    }
    if contact.relay_url.is_some() {
        match relay_send().await {
            Ok(()) => return Ok(Outcome::DeliveredViaRelay),
            Err(e) => {
                tracing::info!("relay: deposit failed ({e}); message will be queued");
            }
        }
    }
    Ok(Outcome::Queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact_with(dest: Option<&str>, relay: Option<&str>) -> Contact {
        Contact {
            id: "c1".into(),
            alias: "abc".into(),
            ed25519_public: vec![0u8; 32],
            x25519_public: vec![0u8; 32],
            mlkem_public: vec![],
            relay_url: relay.map(String::from),
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
        let with_dest = contact_with(Some(&"A".repeat(500)), None);
        let no_dest = contact_with(None, Some("wss://relay/ws"));
        let short_dest = contact_with(Some("ABCD"), None);
        // No runtime: never use I2P.
        assert!(!should_use_i2p(&with_dest, None));
        assert!(!should_use_i2p(&no_dest, None));
        assert!(!should_use_i2p(&short_dest, None));
    }

    #[test]
    fn strip_mailbox_prefix_drops_first_32_bytes() {
        let mut blob = b"00112233445566778899aabbccddeeff".to_vec(); // 32 bytes
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
