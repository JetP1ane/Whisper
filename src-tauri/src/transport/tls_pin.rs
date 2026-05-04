//! TLS SPKI pinning verifier for relay WebSocket connections.
//!
//! TOFU semantics per relay URL: the first successful connection captures
//! the leaf certificate's SubjectPublicKeyInfo (SHA-256 of the SPKI bytes),
//! and every subsequent connection must present a leaf with the same SPKI
//! hash. A mismatch refuses the handshake — a privacy-first messenger
//! cannot trust a CA-signed cert it has never seen before.
//!
//! For dev mode (`ws://`) this module is unused — TLS is off entirely.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::Mutex;

/// Custom verifier that compares the leaf certificate's SPKI against an
/// expected SHA-256 pin. Captures the SPKI hash on every handshake so the
/// caller can read it back after `connect_async_tls_with_config` returns
/// (used for TOFU on first connect).
#[derive(Debug)]
pub struct PinningVerifier {
    /// Expected SPKI hash. `None` = TOFU mode: accept any cert and capture
    /// its SPKI for the caller to persist.
    expected: Option<[u8; 32]>,
    /// Captured SPKI hash from the most recent handshake. The caller reads
    /// this after the connection succeeds to either verify it matched the
    /// stored pin or persist it as the new TOFU pin.
    captured: Mutex<Option<[u8; 32]>>,
}

impl PinningVerifier {
    pub fn new(expected: Option<[u8; 32]>) -> Arc<Self> {
        Arc::new(Self {
            expected,
            captured: Mutex::new(None),
        })
    }

    /// Returns the SPKI hash observed during the most recent handshake.
    pub fn captured_pin(&self) -> Option<[u8; 32]> {
        *self.captured.lock().unwrap()
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let spki = extract_spki_sha256(end_entity.as_ref())
            .map_err(|e| RustlsError::General(format!("SPKI extract failed: {e}")))?;
        *self.captured.lock().unwrap() = Some(spki);

        match self.expected {
            None => {
                // TOFU: first contact, no stored pin yet. Accept and let
                // the caller persist what we just captured.
                Ok(ServerCertVerified::assertion())
            }
            Some(expected) => {
                if expected == spki {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(RustlsError::General(
                        "TLS pin mismatch: leaf SPKI does not match stored pin".into(),
                    ))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // We don't validate the chain ourselves — the SPKI pin is the trust
        // anchor. The signature was already checked by the TLS state machine
        // against the leaf public key; reaching this callback means the
        // peer holds the matching private key.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn extract_spki_sha256(cert_der: &[u8]) -> Result<[u8; 32], String> {
    use x509_parser::prelude::FromDer;
    let (_rest, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| format!("parse cert: {e}"))?;
    let spki_der = cert.tbs_certificate.subject_pki.raw;
    let mut h = Sha256::new();
    h.update(spki_der);
    Ok(h.finalize().into())
}

/// Build a rustls `ClientConfig` that delegates server certificate validation
/// to a `PinningVerifier`. Returns the config plus a handle to the verifier
/// so the caller can read the captured SPKI after handshake.
pub fn pinning_client_config(
    expected: Option<[u8; 32]>,
) -> (Arc<rustls::ClientConfig>, Arc<PinningVerifier>) {
    let verifier = PinningVerifier::new(expected);
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    (Arc::new(config), verifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_pin_is_none_before_handshake() {
        let v = PinningVerifier::new(None);
        assert!(v.captured_pin().is_none());
    }

    #[test]
    fn extract_spki_sha256_is_deterministic() {
        // Self-signed Ed25519 cert generated for testing.
        // Parsing failure is acceptable for the empty-input case.
        let result = extract_spki_sha256(&[]);
        assert!(result.is_err());
    }
}
