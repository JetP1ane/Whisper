//! SAM v3.3 client — talks to a local `i2pd` SAM bridge.
//!
//! SAM is a line-oriented ASCII control protocol that, after a handshake on
//! a single TCP connection, can either (a) stay in control mode for issuing
//! more commands, or (b) be flipped to a raw byte-stream after a successful
//! `STREAM CONNECT` / `STREAM ACCEPT`. Each I2P "stream" is therefore one
//! TCP connection from us to i2pd.
//!
//! References:
//!   - <https://geti2p.net/spec/sam-v3>
//!   - i2pd source: `libi2pd_client/SAM.cpp`
//!
//! This module is intentionally transport-generic: every helper takes
//! anything implementing `AsyncRead + AsyncWrite` so we can run the same
//! protocol over TCP today and Unix domain sockets tomorrow if we end up
//! patching i2pd.

use super::{I2pError, I2pResult, SAM_MAX_VERSION, SAM_MIN_VERSION};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// One parsed `KEY=VALUE` line from the SAM bridge. The bridge always sends
/// a verb (e.g. `HELLO REPLY`, `SESSION STATUS`) followed by k/v pairs.
#[derive(Debug, Clone)]
pub struct SamReply {
    pub verb: String,
    pub kv: HashMap<String, String>,
}

impl SamReply {
    pub fn result(&self) -> Option<&str> {
        self.kv.get("RESULT").map(String::as_str)
    }
    pub fn ok(&self) -> bool {
        self.result() == Some("OK")
    }
    pub fn message(&self) -> Option<&str> {
        self.kv.get("MESSAGE").map(String::as_str)
    }
}

/// Read a single CRLF-or-LF-terminated line from `r` and parse it into a
/// `SamReply`. Lines are short (rarely > 1 KB) so a single allocation here
/// is fine; for the actual stream payload we drop into `r` directly after
/// the handshake completes.
pub async fn read_reply<R>(r: &mut BufReader<R>) -> I2pResult<SamReply>
where
    R: AsyncRead + Unpin,
{
    let mut line = String::new();
    let n = r.read_line(&mut line).await?;
    if n == 0 {
        return Err(I2pError::Disconnected);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    parse_reply(trimmed)
}

/// Parse a SAM reply line. SAM uses two-word verbs (`HELLO REPLY`,
/// `SESSION STATUS`, `STREAM STATUS`, `DEST REPLY`, `NAMING REPLY`),
/// followed by space-separated `KEY=VALUE` pairs. Values may be quoted
/// (rare) — we accept simple unquoted forms which cover everything i2pd
/// emits for our use cases.
pub fn parse_reply(line: &str) -> I2pResult<SamReply> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next().ok_or_else(|| I2pError::Sam("empty reply".into()))?;
    let second = tokens.next().ok_or_else(|| I2pError::Sam("reply missing verb tail".into()))?;
    let verb = format!("{first} {second}");
    let mut kv = HashMap::new();
    for tok in tokens {
        if let Some(eq) = tok.find('=') {
            let (k, v) = tok.split_at(eq);
            kv.insert(k.to_string(), v[1..].to_string());
        }
    }
    Ok(SamReply { verb, kv })
}

/// Send a SAM command line. SAM lines must terminate with `\n`; we don't
/// emit `\r\n` because i2pd accepts plain `\n` and we save a byte.
pub async fn send_line<W>(w: &mut W, line: &str) -> I2pResult<()>
where
    W: AsyncWrite + Unpin,
{
    if line.contains('\n') {
        return Err(I2pError::Sam(
            "internal: SAM command line contained newline".into(),
        ));
    }
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.flush().await?;
    Ok(())
}

/// Perform the `HELLO VERSION` handshake. Returns the negotiated version
/// the bridge picked (e.g. `"3.3"`). Errors if the bridge can't meet our
/// minimum.
pub async fn hello<RW>(rw: &mut BufReader<RW>) -> I2pResult<String>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let cmd = format!("HELLO VERSION MIN={SAM_MIN_VERSION} MAX={SAM_MAX_VERSION}");
    send_line(rw.get_mut(), &cmd).await?;
    let reply = read_reply(rw).await?;
    if reply.verb != "HELLO REPLY" {
        return Err(I2pError::Sam(format!(
            "expected HELLO REPLY, got `{}`",
            reply.verb
        )));
    }
    if !reply.ok() {
        return Err(I2pError::Sam(format!(
            "HELLO failed: {} (msg={:?})",
            reply.result().unwrap_or("?"),
            reply.message()
        )));
    }
    let version = reply
        .kv
        .get("VERSION")
        .cloned()
        .ok_or_else(|| I2pError::Sam("HELLO REPLY missing VERSION".into()))?;
    Ok(version)
}

/// `DEST GENERATE` — ask the SAM bridge to mint a fresh destination
/// keypair without creating a session. Used once at first launch so we
/// can persist the private key in the vault, then later create sessions
/// that adopt this same destination via `SESSION CREATE DESTINATION=…`.
///
/// Returns `(pub_b64, priv_b64)` where `priv_b64` is the full I2P private
/// destination format (signing key + crypto key + cert), the same blob
/// `SESSION CREATE DESTINATION=` accepts.
pub async fn dest_generate<RW>(rw: &mut BufReader<RW>) -> I2pResult<(String, String)>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    // 7 = EdDSA_SHA512_Ed25519 (SAM 3.1+ default but i2pd 2.60 only
    // accepts the numeric form on DEST GENERATE).
    send_line(rw.get_mut(), "DEST GENERATE SIGNATURE_TYPE=7").await?;
    let reply = read_reply(rw).await?;
    if reply.verb != "DEST REPLY" {
        return Err(I2pError::Sam(format!(
            "expected DEST REPLY, got `{}`",
            reply.verb
        )));
    }
    let pub_b64 = reply
        .kv
        .get("PUB")
        .cloned()
        .ok_or_else(|| I2pError::Sam("DEST REPLY missing PUB".into()))?;
    let priv_b64 = reply
        .kv
        .get("PRIV")
        .cloned()
        .ok_or_else(|| I2pError::Sam("DEST REPLY missing PRIV".into()))?;
    Ok((pub_b64, priv_b64))
}

/// Tunnel-quality knobs we attach to every `SESSION CREATE`. Two hops
/// inbound + outbound is the I2P default and gives a reasonable
/// latency/anonymity tradeoff. Encrypted leasesets (Mod #2 in the
/// design proposal) prevent random I2P participants from discovering
/// that our destination exists.
pub fn default_session_options() -> Vec<(&'static str, &'static str)> {
    vec![
        // 7 = EdDSA_SHA512_Ed25519. SAM accepts numeric form universally;
        // symbolic names are spotty between i2pd versions.
        ("SIGNATURE_TYPE", "7"),
        ("inbound.length", "2"),
        ("outbound.length", "2"),
        ("inbound.quantity", "3"),
        ("outbound.quantity", "3"),
        ("i2cp.leaseSetType", "5"),
        ("i2cp.leaseSetEncType", "4"),
    ]
}

/// `SESSION CREATE STYLE=STREAM` — stand up a session that ties the
/// supplied private destination key to a session ID. After this returns
/// OK, separate SAM sockets can `STREAM CONNECT` / `STREAM ACCEPT`
/// against `session_id`.
///
/// `dest_priv` should be either:
/// - `"TRANSIENT"` for a throwaway destination (tests), or
/// - the base64 PRIV blob from a prior `DEST GENERATE` (production)
pub async fn session_create_stream<RW>(
    rw: &mut BufReader<RW>,
    session_id: &str,
    dest_priv: &str,
    extra_opts: &[(&str, &str)],
) -> I2pResult<String>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let mut cmd = format!(
        "SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={dest_priv}"
    );
    for (k, v) in default_session_options().iter().chain(extra_opts.iter()) {
        cmd.push(' ');
        cmd.push_str(k);
        cmd.push('=');
        cmd.push_str(v);
    }
    send_line(rw.get_mut(), &cmd).await?;
    let reply = read_reply(rw).await?;
    if reply.verb != "SESSION STATUS" {
        return Err(I2pError::Sam(format!(
            "expected SESSION STATUS, got `{}`",
            reply.verb
        )));
    }
    if !reply.ok() {
        let msg = reply.message().unwrap_or("");
        if reply.result() == Some("DUPLICATED_ID") || msg.contains("already taken") {
            return Err(I2pError::SessionTaken(session_id.into()));
        }
        return Err(I2pError::Sam(format!(
            "SESSION CREATE failed: {} ({})",
            reply.result().unwrap_or("?"),
            msg
        )));
    }
    let dest = reply
        .kv
        .get("DESTINATION")
        .cloned()
        .ok_or_else(|| I2pError::Sam("SESSION STATUS missing DESTINATION".into()))?;
    Ok(dest)
}

/// `STREAM CONNECT` — open a new SAM socket, hello, then ask the bridge
/// to dial `peer_dest`. After SAM responds `STREAM STATUS RESULT=OK` the
/// remaining bytes on this socket are the raw end-to-end byte stream
/// (which Whisper layers its own length-prefixed frames over).
///
/// This always opens a *fresh* TCP connection to the SAM bridge — SAM
/// requires one socket per stream — so we accept the bridge address
/// rather than an already-open socket.
pub async fn stream_connect(
    bridge_addr: &str,
    session_id: &str,
    peer_dest: &str,
) -> I2pResult<TcpStream> {
    let tcp = TcpStream::connect(bridge_addr).await?;
    let mut buf = BufReader::new(tcp);
    let _version = hello(&mut buf).await?;
    let cmd = format!(
        "STREAM CONNECT ID={session_id} DESTINATION={peer_dest} SILENT=false"
    );
    send_line(buf.get_mut(), &cmd).await?;
    let reply = read_reply(&mut buf).await?;
    if reply.verb != "STREAM STATUS" {
        return Err(I2pError::Sam(format!(
            "expected STREAM STATUS, got `{}`",
            reply.verb
        )));
    }
    if !reply.ok() {
        return Err(I2pError::Sam(format!(
            "STREAM CONNECT failed: {} ({})",
            reply.result().unwrap_or("?"),
            reply.message().unwrap_or("")
        )));
    }
    // `into_inner` returns the TCP stream with the buffered reader's
    // internal buffer discarded. SAM doesn't push any bytes between
    // STREAM STATUS and the start of the user payload, so this is
    // safe — but we double-check there's nothing buffered before
    // tearing down to catch protocol drift early.
    if !buf.buffer().is_empty() {
        return Err(I2pError::Sam(
            "SAM bridge sent unexpected bytes after STREAM STATUS".into(),
        ));
    }
    Ok(buf.into_inner())
}

/// `STREAM ACCEPT` — open a new SAM socket and tell the bridge we're
/// ready to receive *one* inbound connection on `session_id`. When a
/// remote peer dials our destination, the bridge writes a single line
/// `<peer_b64_destination>\n` and then the raw payload follows.
///
/// Returns `(tcp_stream, peer_destination_b64)`. The caller is then in
/// raw-bytes mode and should layer their own framing on top.
pub async fn stream_accept(
    bridge_addr: &str,
    session_id: &str,
) -> I2pResult<(TcpStream, String)> {
    let tcp = TcpStream::connect(bridge_addr).await?;
    let mut buf = BufReader::new(tcp);
    let _version = hello(&mut buf).await?;
    let cmd = format!("STREAM ACCEPT ID={session_id} SILENT=false");
    send_line(buf.get_mut(), &cmd).await?;
    let status = read_reply(&mut buf).await?;
    if status.verb != "STREAM STATUS" {
        return Err(I2pError::Sam(format!(
            "expected STREAM STATUS, got `{}`",
            status.verb
        )));
    }
    if !status.ok() {
        return Err(I2pError::Sam(format!(
            "STREAM ACCEPT failed: {} ({})",
            status.result().unwrap_or("?"),
            status.message().unwrap_or("")
        )));
    }
    // i2pd now blocks until a peer connects, then writes one line:
    // the peer's full base64 destination, terminated by `\n`. After
    // that the socket is raw bytes.
    let mut peer_line = String::new();
    let n = buf.read_line(&mut peer_line).await?;
    if n == 0 {
        return Err(I2pError::Disconnected);
    }
    let peer_dest = peer_line.trim_end_matches(['\r', '\n']).to_string();
    if peer_dest.is_empty() {
        return Err(I2pError::Sam("empty peer destination on accept".into()));
    }
    if !buf.buffer().is_empty() {
        // The peer may have already sent payload by the time we read
        // the destination line. Drain whatever's buffered so the caller
        // doesn't lose it. We return that byte slice alongside the
        // socket via a small framing trick: prepend it onto the inner
        // TcpStream by way of a `Chain`-style adapter.
        //
        // For now, fail loudly — Phase 3 (ConnectionManager) will use a
        // BufReader-aware accept variant. Worth catching this early.
        return Err(I2pError::Sam(
            "peer sent payload before we entered read loop (Phase 3 fix needed)"
                .into(),
        ));
    }
    Ok((buf.into_inner(), peer_dest))
}

/// `NAMING LOOKUP` — resolve a short name (e.g. `whisper.alice.i2p`) to a
/// full destination via i2pd's local address book. We don't *use* this
/// for Whisper today (contacts always exchange the full destination via
/// the signed bundle) but it's cheap to keep around for diagnostics.
pub async fn naming_lookup<RW>(
    rw: &mut BufReader<RW>,
    name: &str,
) -> I2pResult<String>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    let cmd = format!("NAMING LOOKUP NAME={name}");
    send_line(rw.get_mut(), &cmd).await?;
    let reply = read_reply(rw).await?;
    if reply.verb != "NAMING REPLY" {
        return Err(I2pError::Sam(format!(
            "expected NAMING REPLY, got `{}`",
            reply.verb
        )));
    }
    if !reply.ok() {
        return Err(I2pError::Sam(format!(
            "NAMING LOOKUP failed: {} ({})",
            reply.result().unwrap_or("?"),
            reply.message().unwrap_or("")
        )));
    }
    reply
        .kv
        .get("VALUE")
        .cloned()
        .ok_or_else(|| I2pError::Sam("NAMING REPLY missing VALUE".into()))
}

/// Drain bytes from `r` into a buffer until `r` returns 0 (peer closed)
/// or we hit `cap` bytes. Used for tests + for short-message receive
/// paths where we don't care about framing yet.
pub async fn read_to_cap<R>(r: &mut R, cap: usize) -> I2pResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    while buf.len() < cap {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        let take = n.min(cap - buf.len());
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hello_reply_ok() {
        let r = parse_reply("HELLO REPLY RESULT=OK VERSION=3.3").unwrap();
        assert_eq!(r.verb, "HELLO REPLY");
        assert!(r.ok());
        assert_eq!(r.kv.get("VERSION").unwrap(), "3.3");
    }

    #[test]
    fn parse_session_status_failure() {
        let r = parse_reply(
            "SESSION STATUS RESULT=DUPLICATED_ID MESSAGE=\"already_taken\"",
        )
        .unwrap();
        assert_eq!(r.verb, "SESSION STATUS");
        assert!(!r.ok());
        assert_eq!(r.result(), Some("DUPLICATED_ID"));
    }

    #[test]
    fn parse_dest_reply() {
        let r = parse_reply(
            "DEST REPLY PUB=AAAA-PUB-KEY-PLACEHOLDER PRIV=BBBB-PRIV-KEY-PLACEHOLDER",
        )
        .unwrap();
        assert_eq!(r.verb, "DEST REPLY");
        assert_eq!(r.kv.get("PUB").unwrap(), "AAAA-PUB-KEY-PLACEHOLDER");
        assert_eq!(r.kv.get("PRIV").unwrap(), "BBBB-PRIV-KEY-PLACEHOLDER");
    }

    #[test]
    fn parse_reply_missing_verb_tail_errors() {
        let err = parse_reply("HELLO").unwrap_err();
        match err {
            I2pError::Sam(_) => {}
            other => panic!("expected Sam error, got {other:?}"),
        }
    }

    #[test]
    fn parse_reply_with_unknown_kv_keeps_extras() {
        let r = parse_reply("STREAM STATUS RESULT=OK FOO=bar BAZ=qux").unwrap();
        assert!(r.ok());
        assert_eq!(r.kv.get("FOO").unwrap(), "bar");
        assert_eq!(r.kv.get("BAZ").unwrap(), "qux");
    }

    #[test]
    fn default_session_options_includes_encrypted_leaseset() {
        let opts = default_session_options();
        let m: std::collections::HashMap<_, _> = opts.into_iter().collect();
        assert_eq!(m.get("i2cp.leaseSetType"), Some(&"5"));
        assert_eq!(m.get("i2cp.leaseSetEncType"), Some(&"4"));
        assert_eq!(m.get("SIGNATURE_TYPE"), Some(&"7"));
    }
}
