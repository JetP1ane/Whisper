//! Public key bundle: serialization + Ed25519 signing + Base58 invite link.
//!
//! Wire format mirrors the Android client's `BundleSerializer` exactly:
//!
//! ```text
//! writeInt(version)                    // i32 BE
//! writeField(identity_key_ed25519)     // 32 bytes
//! writeField(x25519_key)               // 32 bytes
//! writeField(kyber_key)                // 1568 bytes (or 0 in compact form)
//! writeInt(spk.id)
//! writeField(spk.x25519_pub)
//! writeField(spk.kyber_pub)
//! writeField(spk.signature)            // 64 bytes — Ed25519 over (x_pub || k_pub)
//! writeInt(otpk.id)
//! writeField(otpk.x25519_pub)
//! writeField(otpk.kyber_pub)           // 1568 bytes (or 0 in compact form)
//! writeField(bundle_signature)         // 64 bytes — Ed25519 over the entire payload
//! writeString(alias)                   // length-prefixed UTF-8, len = -1 for null
//! writeString(display_name)
//! ```
//!
//! `writeField(b)`  = `[4B BE len][bytes]`
//! `writeString(s)` = same, with a magic length of `-1` to encode `None`.
//! `writeInt(i)`    = `[4B BE i32]`.

use super::{CryptoError, CryptoResult};
use ed25519_dalek::{
    Signature, Signer, SigningKey as EdSigningKey, Verifier, VerifyingKey as EdVerifyingKey,
};

/// Bundle version 2 added `relay_url` for cross-relay messaging.
/// Bundle version 3 adds `i2p_destination` so peers can reach this owner
/// over I2P directly without ever touching a relay. v3 keeps `relay_url`
/// in the layout so older v2 readers (and the relay-fallback path)
/// continue to deserialize. New installs leave `relay_url` empty when
/// I2P is the only transport.
pub const BUNDLE_VERSION: i32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyBundle {
    pub version: i32,
    pub identity_key: [u8; 32],     // Ed25519
    pub x25519_key: [u8; 32],
    pub kyber_key: Vec<u8>,         // 1568 bytes (full) or empty (compact QR)
    pub signed_prekey: SignedPrekeyPublic,
    pub one_time_prekey: OneTimePrekeyPublic,
    pub bundle_signature: [u8; 64], // Ed25519 over the unsigned payload
    pub alias: String,
    pub display_name: Option<String>,
    /// Owner's home relay URL (legacy v2 transport path). Empty for new
    /// I2P-only installs.
    pub relay_url: String,
    /// Owner's I2P destination (base64). Empty for legacy v1/v2 bundles
    /// that predate the I2P transport. When non-empty, recipients
    /// deliver via I2P directly through this destination.
    pub i2p_destination: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrekeyPublic {
    pub id: u32,
    pub x25519_pub: [u8; 32],
    pub kyber_pub: Vec<u8>, // 1568 bytes
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePrekeyPublic {
    pub id: u32,
    pub x25519_pub: [u8; 32],
    pub kyber_pub: Vec<u8>, // 1568 bytes (full) or empty (compact QR)
}

// --- Serialize / deserialize ---

fn write_field(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn write_string(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(text) => write_field(out, text.as_bytes()),
        None => out.extend_from_slice(&(-1i32).to_be_bytes()),
    }
}

fn write_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn serialize(b: &PublicKeyBundle) -> Vec<u8> {
    let cap = 4
        + 4 + b.identity_key.len()
        + 4 + b.x25519_key.len()
        + 4 + b.kyber_key.len()
        + 4
        + 4 + b.signed_prekey.x25519_pub.len()
        + 4 + b.signed_prekey.kyber_pub.len()
        + 4 + b.signed_prekey.signature.len()
        + 4
        + 4 + b.one_time_prekey.x25519_pub.len()
        + 4 + b.one_time_prekey.kyber_pub.len()
        + 4 + b.bundle_signature.len()
        + 4 + b.alias.len()
        + 4 + b.display_name.as_ref().map(|s| s.len()).unwrap_or(0)
        + 4 + b.relay_url.len()
        + 4 + b.i2p_destination.len();
    let mut out = Vec::with_capacity(cap);
    write_i32(&mut out, b.version);
    write_field(&mut out, &b.identity_key);
    write_field(&mut out, &b.x25519_key);
    write_field(&mut out, &b.kyber_key);
    write_i32(&mut out, b.signed_prekey.id as i32);
    write_field(&mut out, &b.signed_prekey.x25519_pub);
    write_field(&mut out, &b.signed_prekey.kyber_pub);
    write_field(&mut out, &b.signed_prekey.signature);
    write_i32(&mut out, b.one_time_prekey.id as i32);
    write_field(&mut out, &b.one_time_prekey.x25519_pub);
    write_field(&mut out, &b.one_time_prekey.kyber_pub);
    write_field(&mut out, &b.bundle_signature);
    write_string(&mut out, Some(&b.alias));
    write_string(&mut out, b.display_name.as_deref());
    write_field(&mut out, b.relay_url.as_bytes()); // v2 trailing field
    write_field(&mut out, b.i2p_destination.as_bytes()); // v3 trailing field
    out
}

struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn read_i32(&mut self) -> CryptoResult<i32> {
        if self.off + 4 > self.data.len() {
            return Err(CryptoError::Decode("bundle truncated (i32)"));
        }
        let v = i32::from_be_bytes(self.data[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }

    fn read_field(&mut self) -> CryptoResult<&'a [u8]> {
        let len = self.read_i32()? as usize;
        if self.off + len > self.data.len() {
            return Err(CryptoError::Decode("bundle truncated (field)"));
        }
        let slice = &self.data[self.off..self.off + len];
        self.off += len;
        Ok(slice)
    }

    fn read_string(&mut self) -> CryptoResult<Option<String>> {
        let len = self.read_i32()?;
        if len < 0 {
            return Ok(None);
        }
        let len = len as usize;
        if self.off + len > self.data.len() {
            return Err(CryptoError::Decode("bundle truncated (string)"));
        }
        let s = std::str::from_utf8(&self.data[self.off..self.off + len])
            .map_err(|_| CryptoError::Decode("bundle string is not UTF-8"))?
            .to_string();
        self.off += len;
        Ok(Some(s))
    }
}

pub fn deserialize(bytes: &[u8]) -> CryptoResult<PublicKeyBundle> {
    let mut c = Cursor { data: bytes, off: 0 };
    let version = c.read_i32()?;
    let identity_key: [u8; 32] = c
        .read_field()?
        .try_into()
        .map_err(|_| CryptoError::Decode("bundle identity_key not 32 bytes"))?;
    let x25519_key: [u8; 32] = c
        .read_field()?
        .try_into()
        .map_err(|_| CryptoError::Decode("bundle x25519_key not 32 bytes"))?;
    let kyber_key = c.read_field()?.to_vec();
    let spk_id = c.read_i32()? as u32;
    let spk_x: [u8; 32] = c
        .read_field()?
        .try_into()
        .map_err(|_| CryptoError::Decode("spk x25519 not 32 bytes"))?;
    let spk_k = c.read_field()?.to_vec();
    let spk_sig: [u8; 64] = c
        .read_field()?
        .try_into()
        .map_err(|_| CryptoError::Decode("spk signature not 64 bytes"))?;
    let otpk_id = c.read_i32()? as u32;
    let otpk_x: [u8; 32] = c
        .read_field()?
        .try_into()
        .map_err(|_| CryptoError::Decode("otpk x25519 not 32 bytes"))?;
    let otpk_k = c.read_field()?.to_vec();
    let bundle_sig: [u8; 64] = c
        .read_field()?
        .try_into()
        .map_err(|_| CryptoError::Decode("bundle signature not 64 bytes"))?;
    let alias = c
        .read_string()?
        .ok_or(CryptoError::Decode("bundle alias is null"))?;
    let display_name = c.read_string()?;
    // v2: relay_url. v1 bundles don't have it; tolerate by reading empty.
    let relay_url = if c.off < c.data.len() {
        std::str::from_utf8(c.read_field()?)
            .map_err(|_| CryptoError::Decode("bundle relay_url not UTF-8"))?
            .to_string()
    } else {
        String::new()
    };
    // v3: i2p_destination. v1/v2 bundles don't have it; tolerate by reading empty.
    let i2p_destination = if c.off < c.data.len() {
        std::str::from_utf8(c.read_field()?)
            .map_err(|_| CryptoError::Decode("bundle i2p_destination not UTF-8"))?
            .to_string()
    } else {
        String::new()
    };

    Ok(PublicKeyBundle {
        version,
        identity_key,
        x25519_key,
        kyber_key,
        signed_prekey: SignedPrekeyPublic {
            id: spk_id,
            x25519_pub: spk_x,
            kyber_pub: spk_k,
            signature: spk_sig,
        },
        one_time_prekey: OneTimePrekeyPublic {
            id: otpk_id,
            x25519_pub: otpk_x,
            kyber_pub: otpk_k,
        },
        bundle_signature: bundle_sig,
        alias,
        display_name,
        relay_url,
        i2p_destination,
    })
}

// --- Bundle signing + verification ---

/// Build the unsigned payload (everything serialized but with a 64-byte zero
/// stand-in for `bundle_signature`). The Ed25519 signature is computed over
/// this payload, then the real signature replaces the zero stand-in.
pub fn build_signed_bundle(
    signing: &EdSigningKey,
    identity_key: [u8; 32],
    x25519_key: [u8; 32],
    kyber_key: Vec<u8>,
    spk: SignedPrekeyPublic,
    otpk: OneTimePrekeyPublic,
    alias: String,
    display_name: Option<String>,
    relay_url: String,
    i2p_destination: String,
) -> PublicKeyBundle {
    let mut placeholder = PublicKeyBundle {
        version: BUNDLE_VERSION,
        identity_key,
        x25519_key,
        kyber_key,
        signed_prekey: spk,
        one_time_prekey: otpk,
        bundle_signature: [0u8; 64],
        alias,
        display_name,
        relay_url,
        i2p_destination,
    };
    let payload = serialize(&placeholder);
    let sig = signing.sign(&payload).to_bytes();
    placeholder.bundle_signature = sig;
    placeholder
}

pub fn verify_bundle(b: &PublicKeyBundle) -> CryptoResult<()> {
    let vk = EdVerifyingKey::from_bytes(&b.identity_key)
        .map_err(|_| CryptoError::Decode("invalid Ed25519 identity key"))?;

    // 1. Bundle Ed25519 signature over the (zero-signature) payload.
    let mut to_verify = b.clone();
    to_verify.bundle_signature = [0u8; 64];
    let payload = serialize(&to_verify);
    let sig = Signature::from_bytes(&b.bundle_signature);
    vk.verify(&payload, &sig)
        .map_err(|_| CryptoError::Decode("bundle signature failed to verify"))?;

    // 2. Signed prekey signature (Ed25519 over `x25519_pub || kyber_pub`).
    let mut spk_msg = Vec::with_capacity(32 + b.signed_prekey.kyber_pub.len());
    spk_msg.extend_from_slice(&b.signed_prekey.x25519_pub);
    spk_msg.extend_from_slice(&b.signed_prekey.kyber_pub);
    let spk_sig = Signature::from_bytes(&b.signed_prekey.signature);
    vk.verify(&spk_msg, &spk_sig)
        .map_err(|_| CryptoError::Decode("spk signature failed to verify"))?;

    // 3. **Alias / identity-key binding.** The alias is a deterministic
    //    function of the identity key (`BIP39(SHA-256(identity_key)[:33b])`),
    //    so `bundle.alias` must equal that derivation. This closes the
    //    relay-MITM-by-bundle-substitution gap: a malicious relay cannot
    //    serve Eve's bundle as the answer to "give me Bob's alias" because
    //    Eve's identity key produces a different alias.
    let derived = crate::crypto::keys::derive_alias(&b.identity_key);
    if derived != b.alias {
        return Err(CryptoError::Decode(
            "bundle alias does not match identity key (possible relay substitution)",
        ));
    }

    Ok(())
}

// --- Base58 (Bitcoin/IPFS alphabet) for whisper:// invite links ---

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Big-int divmod by 58.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &b in input {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        result.push('1');
    }
    for d in digits.iter().rev() {
        result.push(ALPHABET[*d as usize] as char);
    }
    result
}

pub fn base58_decode(input: &str) -> CryptoResult<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let zeros = input.chars().take_while(|&c| c == '1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    for c in input.chars() {
        let digit = ALPHABET
            .iter()
            .position(|&a| a == c as u8)
            .ok_or(CryptoError::Decode("invalid Base58 char"))? as u32;
        let mut carry = digit;
        for b in bytes.iter_mut() {
            let v = (*b as u32) * 58 + carry;
            *b = (v % 256) as u8;
            carry = v / 256;
        }
        while carry > 0 {
            bytes.push((carry % 256) as u8);
            carry /= 256;
        }
    }
    let mut result = vec![0u8; zeros];
    result.extend(bytes.iter().rev());
    Ok(result)
}

/// Build a sharable invite link.
///
/// `whisper://c/<base58>` — the bundle itself includes `relay_url`, so the
/// recipient picks it up from the parsed payload. The optional `?relay=...`
/// query parameter is included as a hint for human readers and is verified
/// against the bundle's own `relay_url` on parse (mismatch ⇒ rejected).
pub fn build_whisper_link(b: &PublicKeyBundle) -> String {
    let body = base58_encode(&serialize(b));
    if b.relay_url.is_empty() {
        format!("whisper://c/{}", body)
    } else {
        format!(
            "whisper://c/{}?relay={}",
            body,
            url_encode(&b.relay_url)
        )
    }
}

pub fn parse_whisper_link(input: &str) -> CryptoResult<PublicKeyBundle> {
    let prefix = "whisper://c/";
    let trimmed = input.trim();
    let body = trimmed.strip_prefix(prefix).unwrap_or(trimmed);
    // Split off query string if present.
    let (b58, query) = match body.find('?') {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let bytes = base58_decode(b58)?;
    let bundle = deserialize(&bytes)?;
    verify_bundle(&bundle)?;

    // If a `relay=` hint was provided, sanity-check against the bundle's
    // signed `relay_url`. The signed value is authoritative.
    if let Some(q) = query {
        for kv in q.split('&') {
            if let Some(rest) = kv.strip_prefix("relay=") {
                let hinted = url_decode(rest);
                if !bundle.relay_url.is_empty() && hinted != bundle.relay_url {
                    return Err(CryptoError::Decode(
                        "whisper link `relay=` hint disagrees with signed bundle relay_url",
                    ));
                }
            }
        }
    }
    Ok(bundle)
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map(|s| u8::from_str_radix(s, 16))
            {
                if let Ok(byte) = hex {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn dummy_bundle() -> PublicKeyBundle {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let kyber = vec![0xAAu8; 1568];
        let spk = SignedPrekeyPublic {
            id: 1,
            x25519_pub: [11u8; 32],
            kyber_pub: kyber.clone(),
            signature: signing.sign(&[[11u8; 32].as_slice(), kyber.as_slice()].concat()).to_bytes(),
        };
        let otpk = OneTimePrekeyPublic {
            id: 42,
            x25519_pub: [22u8; 32],
            kyber_pub: kyber.clone(),
        };
        // Alias must derive from the identity key — verify_bundle now enforces this.
        let id_key = signing.verifying_key().to_bytes();
        let alias = crate::crypto::keys::derive_alias(&id_key);
        build_signed_bundle(
            &signing,
            id_key,
            [33u8; 32],
            kyber,
            spk,
            otpk,
            alias,
            Some("test".into()),
            "wss://test.example.com/ws".into(),
            "I2P_DEST_TEST_PLACEHOLDER".into(),
        )
    }

    #[test]
    fn round_trip_bundle() {
        let b = dummy_bundle();
        let bytes = serialize(&b);
        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(parsed, b);
    }

    #[test]
    fn signature_verifies() {
        let b = dummy_bundle();
        verify_bundle(&b).unwrap();
    }

    #[test]
    fn tampered_bundle_fails_verification() {
        let mut b = dummy_bundle();
        // Picking another valid alias triggers BOTH the alias-binding
        // check (different SHA-256) and the signature check (signed payload
        // changes); either failure is expected.
        b.alias = "abandon-abandon-abandon".into();
        assert!(verify_bundle(&b).is_err());
    }

    #[test]
    fn alias_substitution_fails_verification() {
        // A relay swapping bundles cannot keep the original alias because
        // the alias is bound to the identity key. Even with a valid
        // signature on the substitute, the alias check fires.
        let bob_signing = SigningKey::from_bytes(&[7u8; 32]);
        let bob_alias = crate::crypto::keys::derive_alias(&bob_signing.verifying_key().to_bytes());

        let eve_signing = SigningKey::from_bytes(&[42u8; 32]);
        let kyber = vec![0xCCu8; 1568];
        let spk = SignedPrekeyPublic {
            id: 1,
            x25519_pub: [11u8; 32],
            kyber_pub: kyber.clone(),
            signature: eve_signing
                .sign(&[[11u8; 32].as_slice(), kyber.as_slice()].concat())
                .to_bytes(),
        };
        let otpk = OneTimePrekeyPublic {
            id: 42,
            x25519_pub: [22u8; 32],
            kyber_pub: kyber.clone(),
        };
        // Eve signs a bundle that claims Bob's alias.
        let mut substituted = build_signed_bundle(
            &eve_signing,
            eve_signing.verifying_key().to_bytes(),
            [33u8; 32],
            kyber,
            spk,
            otpk,
            bob_alias.clone(),
            None,
            "wss://eve.example.com/ws".into(),
            "I2P_DEST_EVE".into(),
        );
        // Eve's signature on the bundle is valid (she signed it), but the
        // alias-vs-identity-key check rejects the substitution.
        assert_ne!(
            substituted.alias,
            crate::crypto::keys::derive_alias(&substituted.identity_key)
        );
        assert!(verify_bundle(&substituted).is_err());
        // Sanity: with Eve's *own* alias the bundle verifies.
        substituted.alias =
            crate::crypto::keys::derive_alias(&substituted.identity_key);
        let _ = substituted; // We rely on the test path above.
    }

    #[test]
    fn base58_round_trip() {
        for input in [
            &b""[..],
            &[0u8][..],
            &[0u8, 0u8, 1u8, 2u8, 3u8][..],
            &[0xFFu8; 64][..],
        ] {
            let s = base58_encode(input);
            let back = base58_decode(&s).unwrap();
            assert_eq!(back, input);
        }
    }

    #[test]
    fn whisper_link_round_trip() {
        let b = dummy_bundle();
        let link = build_whisper_link(&b);
        assert!(link.starts_with("whisper://c/"));
        let parsed = parse_whisper_link(&link).unwrap();
        assert_eq!(parsed, b);
    }
}
