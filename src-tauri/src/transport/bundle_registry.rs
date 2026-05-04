//! Bundle registry — HTTP `PUT` / `GET /bundle/{alias}` against the relay.
//!
//! Wire body is the raw byte serialization from [`crate::crypto::bundle`]
//! (≤ 4 KB, plain `application/octet-stream`). Always run the result through
//! [`crate::crypto::bundle::verify_bundle`] before trusting it.

use super::TransportError;
use crate::crypto::bundle;
use reqwest::StatusCode;

const PATH_PREFIX: &str = "/bundle/";
const MAX_BUNDLE_BYTES: usize = 4096;

fn alias_pattern_ok(alias: &str) -> bool {
    let parts: Vec<&str> = alias.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| {
        let len = p.chars().count();
        len >= 2 && len <= 12 && p.chars().all(|c| c.is_ascii_lowercase())
    })
}

fn registry_url(relay_ws_url: &str, alias: &str) -> Result<String, TransportError> {
    if !alias_pattern_ok(alias) {
        return Err(TransportError::Encoding(format!("invalid alias `{alias}`")));
    }
    // Convert the WebSocket URL to its HTTP origin.
    // wss://host[:port][/...]   →  https://host[:port]
    //  ws://host[:port][/...]   →  http://host[:port]
    let origin = if let Some(rest) = relay_ws_url.strip_prefix("wss://") {
        format!("https://{}", strip_path(rest))
    } else if let Some(rest) = relay_ws_url.strip_prefix("ws://") {
        format!("http://{}", strip_path(rest))
    } else if relay_ws_url.starts_with("https://") || relay_ws_url.starts_with("http://") {
        let mut s = relay_ws_url.to_string();
        if let Some(idx) = s[8..].find('/') {
            s.truncate(8 + idx);
        }
        s
    } else {
        return Err(TransportError::Encoding(
            "relay URL must start with ws:// or wss://".into(),
        ));
    };
    Ok(format!("{}{}{}", origin, PATH_PREFIX, alias))
}

fn strip_path(s: &str) -> String {
    match s.find('/') {
        Some(i) => s[..i].to_string(),
        None => s.to_string(),
    }
}

pub async fn put_bundle(
    relay_ws_url: &str,
    alias: &str,
    bundle_bytes: &[u8],
) -> Result<(), TransportError> {
    if bundle_bytes.len() > MAX_BUNDLE_BYTES {
        return Err(TransportError::Encoding(format!(
            "bundle too large ({} > {} bytes)",
            bundle_bytes.len(),
            MAX_BUNDLE_BYTES
        )));
    }
    let url = registry_url(relay_ws_url, alias)?;
    let resp = reqwest::Client::builder()
        .build()
        .map_err(|e| TransportError::Ws(e.to_string()))?
        .put(url)
        .header("Content-Type", "application/octet-stream")
        .body(bundle_bytes.to_vec())
        .send()
        .await
        .map_err(|e| TransportError::Ws(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(TransportError::Protocol("bundle PUT rejected"));
    }
    Ok(())
}

pub async fn get_bundle(
    relay_ws_url: &str,
    alias: &str,
) -> Result<Option<bundle::PublicKeyBundle>, TransportError> {
    let url = registry_url(relay_ws_url, alias)?;
    let resp = reqwest::Client::builder()
        .build()
        .map_err(|e| TransportError::Ws(e.to_string()))?
        .get(url)
        .send()
        .await
        .map_err(|e| TransportError::Ws(e.to_string()))?;
    match resp.status() {
        StatusCode::OK => {
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| TransportError::Ws(e.to_string()))?;
            let parsed = bundle::deserialize(&bytes).map_err(|_| {
                TransportError::Protocol("bundle deserialization failed")
            })?;
            bundle::verify_bundle(&parsed)
                .map_err(|_| TransportError::Protocol("bundle signature failed"))?;
            Ok(Some(parsed))
        }
        StatusCode::NOT_FOUND => Ok(None),
        s => Err(TransportError::Protocol(match s.as_u16() {
            400 => "bundle GET: invalid alias",
            500 => "bundle GET: relay error",
            _ => "bundle GET: unexpected status",
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_validation() {
        assert!(alias_pattern_ok("amber-falcon-seven"));
        assert!(alias_pattern_ok("ab-cd-ef"));
        assert!(!alias_pattern_ok("amber-falcon"));
        assert!(!alias_pattern_ok("amber-falcon-"));
        assert!(!alias_pattern_ok("Amber-falcon-seven"));
        assert!(!alias_pattern_ok("amber-falcon-thisistoolongtolongsorry"));
    }

    #[test]
    fn registry_url_construction() {
        assert_eq!(
            registry_url("wss://relay.example.com/ws", "amber-falcon-seven").unwrap(),
            "https://relay.example.com/bundle/amber-falcon-seven"
        );
        assert_eq!(
            registry_url("ws://127.0.0.1:8080/ws", "amber-falcon-seven").unwrap(),
            "http://127.0.0.1:8080/bundle/amber-falcon-seven"
        );
    }
}
