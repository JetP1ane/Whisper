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

/// Open a TCP connection to the SAM bridge with TCP_NODELAY set. SAM is
/// extremely sensitive to write batching: with Nagle enabled, our second
/// command (sent right after reading HELLO REPLY) can sit in the kernel
/// for up to ~40 ms while i2pd is happy to half-close the socket if it
/// thinks we've gone away. Disabling Nagle costs us nothing — every line
/// we send is a deliberate command, never a small fragment of a larger
/// stream — and eliminates a class of "Disconnected" bugs that took an
/// hour to find the first time.
pub async fn connect(bridge_addr: &str) -> I2pResult<BufReader<TcpStream>> {
    let tcp = TcpStream::connect(bridge_addr).await?;
    tcp.set_nodelay(true).ok();
    Ok(BufReader::new(tcp))
}

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
/// followed by space-separated `KEY=VALUE` pairs. `MESSAGE` values are
/// often double-quoted because they contain spaces (e.g.
/// `MESSAGE="Can't reach peer"`). We honor that.
pub fn parse_reply(line: &str) -> I2pResult<SamReply> {
    // Pull off the two-word verb first.
    let mut rest = line.trim_start();
    let (first, r1) = split_word(rest)?;
    rest = r1;
    let (second, r2) = split_word(rest)?;
    rest = r2.trim_start();
    let verb = format!("{first} {second}");

    let mut kv = HashMap::new();
    while !rest.is_empty() {
        let (k, after_eq) = match rest.find('=') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => break,
        };
        let (v, tail) = if after_eq.starts_with('"') {
            // Quoted value: read up to closing quote. SAM doesn't escape
            // quotes inside the value, so a simple find suffices.
            let body = &after_eq[1..];
            match body.find('"') {
                Some(end) => (&body[..end], &body[end + 1..]),
                None => (body, ""),
            }
        } else {
            // Unquoted: read up to next whitespace.
            match after_eq.find(char::is_whitespace) {
                Some(i) => (&after_eq[..i], &after_eq[i..]),
                None => (after_eq, ""),
            }
        };
        kv.insert(k.to_string(), v.to_string());
        rest = tail.trim_start();
    }
    Ok(SamReply { verb, kv })
}

/// True iff every byte of `s` is in the I2P base64 alphabet
/// (`A-Z`, `a-z`, `0-9`, `-`, `~`) or is `=` padding. SAM commands are
/// newline-and-space-delimited; a destination or id string that carries
/// any other character can either inject a follow-on SAM command or
/// confuse the bridge's tokenizer. This is the choke-point used by
/// `stream_connect` and friends to validate caller-supplied tokens.
fn is_safe_sam_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'-' || b == b'~' || b == b'='
        })
}

fn split_word(s: &str) -> I2pResult<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(I2pError::Sam("empty reply".into()));
    }
    Ok(match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], &s[i..]),
        None => return Err(I2pError::Sam("reply missing verb tail".into())),
    })
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
/// keypair without creating a session. Returns `(pub_b64, priv_b64)`.
///
/// Stateless SAM commands (DEST GENERATE, NAMING LOOKUP, RAW SEND) MUST
/// run on their own dedicated short-lived socket per the SAM v3.3 idiom:
/// HELLO + one verb per socket, bridge closes after the reply. Mixing
/// these onto a control socket that's already done HELLO causes i2pd to
/// half-close the connection and we read EOF before the reply arrives.
/// `dest_generate_oneshot` opens, hellos, asks, parses, and tears down
/// in a single call — which is also how Whisper actually uses it
/// (we mint a destination once at first launch and persist it).
pub async fn dest_generate_oneshot(bridge_addr: &str) -> I2pResult<(String, String)> {
    let mut buf = connect(bridge_addr).await?;
    let _v = hello(&mut buf).await?;
    // 7 = EdDSA_SHA512_Ed25519 (SAM 3.1+ default but i2pd 2.60 only
    // accepts the numeric form on DEST GENERATE).
    send_line(buf.get_mut(), "DEST GENERATE SIGNATURE_TYPE=7").await?;
    let reply = read_reply(&mut buf).await?;
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
/// latency/anonymity tradeoff. The inbound/outbound *quantity* of 8
/// (up from i2pd's default of 5) trades a bit of CPU + bandwidth for
/// resilience: when one router on a tunnel path is slow, having
/// several spare tunnels already built means the next send can pick a
/// fresh one instead of waiting for a build cycle. With 8 tunnels in
/// each direction, the probability that *every* tunnel is unavailable
/// at the moment of send drops sharply.
pub fn default_session_options() -> Vec<(&'static str, &'static str)> {
    vec![
        // 7 = EdDSA_SHA512_Ed25519. SAM accepts numeric form universally;
        // symbolic names are spotty between i2pd versions.
        ("SIGNATURE_TYPE", "7"),
        ("inbound.length", "2"),
        ("outbound.length", "2"),
        ("inbound.quantity", "8"),
        ("outbound.quantity", "8"),
        // LS2 (type 3) with ECIES-X25519-AEAD on-wire encryption.
        //
        // Encrypted LS2 (type 5) with per-client DH auth was attempted
        // but rejected by i2pd's SAM bridge when the auth list is empty
        // (fresh install with no contacts). Making encrypted leasesets
        // work properly requires cycling the session on every contact-
        // add so the auth list updates — that's session-restart machinery
        // we haven't built yet. Until then we use LS2: anyone who knows
        // our destination can resolve us. Practical exposure stays
        // small because destinations are only ever shared via signed
        // bundles (QR / whisper:// link), never a public directory.
        ("i2cp.leaseSetType", "3"),
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
    // Defensive: any embedded whitespace in the destination would
    // truncate the SESSION CREATE line on the SAM bridge side and
    // cause "Malformed message" + a socket close. We trim on read in
    // `destination::load` already, but fail fast here too so a future
    // regression is loud.
    if dest_priv != "TRANSIENT"
        && dest_priv.chars().any(|c| c.is_whitespace())
    {
        return Err(I2pError::InvalidDestination(
            "destination contains whitespace; SAM line would be truncated".into(),
        ));
    }
    if session_id.chars().any(|c| c.is_whitespace()) {
        return Err(I2pError::Sam(
            "session_id contains whitespace".into(),
        ));
    }
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

/// Build the encrypted-leaseset DH-auth options for a SESSION CREATE.
///
/// Returns the options as owned strings (caller will reborrow as
/// `&[(&str, &str)]` for `session_create_stream`'s `extra_opts`). The
/// pair list is:
///
///   `i2cp.leaseSetPrivKey`           = `<our_x25519_priv_b64>`
///   `i2cp.leaseSetClient.0.dh`       = `<contact_0_x25519_pub_b64>`
///   `i2cp.leaseSetClient.1.dh`       = `<contact_1_x25519_pub_b64>`
///   ...
///
/// Both keys use standard base64 (`+/=`) — that's what i2pd's SAM
/// accepts for these I2CP options. The destination format itself uses
/// I2P's `-~` alphabet but those are negotiated via DEST GENERATE /
/// SESSION CREATE, not via these per-client options.
///
/// `our_x25519_priv` is our identity X25519 secret (32 bytes). Reusing
/// it from PQ-X3DH means we don't need a new key class, and contact
/// bundles already carry the matching public key for the auth list on
/// the other side. The trade-off is that this single key proves both
/// "I'm the owner of this Whisper identity" and "I can decrypt
/// leaseset metadata for sessions that authorized me" — fine for our
/// threat model (both usages are bound to the same vault).
///
/// `contact_x25519_pubs` is the list of contact public keys that should
/// be authorized to resolve our leaseset. Order doesn't matter; the
/// helper assigns indices automatically.
pub fn encrypted_leaseset_options(
    our_x25519_priv: &[u8; 32],
    contact_x25519_pubs: &[[u8; 32]],
) -> Vec<(String, String)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut opts = Vec::with_capacity(1 + contact_x25519_pubs.len());
    opts.push((
        "i2cp.leaseSetPrivKey".to_string(),
        STANDARD.encode(our_x25519_priv),
    ));
    for (i, pubkey) in contact_x25519_pubs.iter().enumerate() {
        opts.push((
            format!("i2cp.leaseSetClient.{i}.dh"),
            STANDARD.encode(pubkey),
        ));
    }
    opts
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
    // M-15: SAM is a newline-delimited line protocol; embedding a peer
    // destination directly into the command line is unsafe if the
    // destination string carries `\n`, `\r`, or whitespace. A signed
    // bundle's `i2p_destination` field is UTF-8 so a malicious peer
    // could otherwise inject a follow-on SAM command (e.g. swap the
    // session, request the destination's private key). I2P's base64
    // alphabet is `A-Za-z0-9-~` plus `=` padding; reject anything
    // outside that. Same for the session id we generated locally —
    // belt-and-braces in case it ever flows from less-trusted state.
    if !is_safe_sam_token(peer_dest) {
        return Err(I2pError::Sam(format!(
            "peer destination contains characters outside the I2P base64 alphabet — refusing to send to SAM"
        )));
    }
    if !is_safe_sam_token(session_id) {
        return Err(I2pError::Sam(format!(
            "session id contains unsafe characters — refusing to send to SAM"
        )));
    }
    let mut buf = connect(bridge_addr).await?;
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
    if !is_safe_sam_token(session_id) {
        return Err(I2pError::Sam(
            "session id contains unsafe characters — refusing to send to SAM"
                .into(),
        ));
    }
    let mut buf = connect(bridge_addr).await?;
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
/// full destination via i2pd's local address book. Stateless one-shot,
/// same socket pattern as [`dest_generate_oneshot`]. We don't *use* this
/// for Whisper today (contacts always exchange the full destination via
/// the signed bundle) but it's kept around for diagnostics + the special
/// `ME` query which returns our own session destination.
pub async fn naming_lookup_oneshot(bridge_addr: &str, name: &str) -> I2pResult<String> {
    let mut buf = connect(bridge_addr).await?;
    let _v = hello(&mut buf).await?;
    let cmd = format!("NAMING LOOKUP NAME={name}");
    send_line(buf.get_mut(), &cmd).await?;
    let reply = read_reply(&mut buf).await?;
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
    fn is_safe_sam_token_accepts_valid_destinations() {
        assert!(is_safe_sam_token(
            "AbCdEf0123456789-~==~--abcdefghijklmnopqrstuvwxyz"
        ));
        assert!(is_safe_sam_token("session-id-42"));
    }

    #[test]
    fn is_safe_sam_token_rejects_injection_attempts() {
        // M-15 regression: any whitespace, newline, control char, or
        // non-base64 character must be rejected so a malicious peer
        // destination cannot inject a follow-on SAM command.
        assert!(!is_safe_sam_token(""));
        assert!(!is_safe_sam_token("ok\nDESTROY"));
        assert!(!is_safe_sam_token("ok\rwhatever"));
        assert!(!is_safe_sam_token("has space"));
        assert!(!is_safe_sam_token("has\ttab"));
        assert!(!is_safe_sam_token("plus+is+not+I2P+base64"));
        assert!(!is_safe_sam_token("slash/also/not"));
        assert!(!is_safe_sam_token("nul\0byte"));
    }

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
        assert_eq!(r.message(), Some("already_taken"));
    }

    #[test]
    fn parse_quoted_message_with_spaces() {
        // Real i2pd reply format — MESSAGE is quoted because the human
        // text contains spaces.
        let r = parse_reply(
            "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"Can't reach peer\"",
        )
        .unwrap();
        assert!(!r.ok());
        assert_eq!(r.result(), Some("CANT_REACH_PEER"));
        assert_eq!(r.message(), Some("Can't reach peer"));
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
    fn default_session_options_use_ls2_with_ecies() {
        let opts = default_session_options();
        let m: std::collections::HashMap<_, _> = opts.into_iter().collect();
        // LS2 (type 3) with ECIES-X25519-AEAD (encType 4). Encrypted
        // leasesets (type 5 + authType 1) are deferred until we wire
        // session-cycling on contact-add.
        assert_eq!(m.get("i2cp.leaseSetType"), Some(&"3"));
        assert_eq!(m.get("i2cp.leaseSetEncType"), Some(&"4"));
        assert!(m.get("i2cp.leaseSetAuthType").is_none());
        assert_eq!(m.get("SIGNATURE_TYPE"), Some(&"7"));
        // 8/8 tunnel pool (resilience boost over i2pd's default of 5).
        assert_eq!(m.get("inbound.quantity"), Some(&"8"));
        assert_eq!(m.get("outbound.quantity"), Some(&"8"));
    }

    #[test]
    fn encrypted_leaseset_options_layout() {
        let our_priv = [0x11u8; 32];
        let contact_a = [0xAAu8; 32];
        let contact_b = [0xBBu8; 32];
        let opts = encrypted_leaseset_options(&our_priv, &[contact_a, contact_b]);
        // First entry must be our priv key (i2pd reads it before scanning
        // the per-client list).
        assert_eq!(opts[0].0, "i2cp.leaseSetPrivKey");
        // Per-client entries indexed from 0.
        assert_eq!(opts[1].0, "i2cp.leaseSetClient.0.dh");
        assert_eq!(opts[2].0, "i2cp.leaseSetClient.1.dh");
        // Values are base64-encoded 32-byte keys.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        assert_eq!(STANDARD.decode(&opts[0].1).unwrap(), our_priv.to_vec());
        assert_eq!(STANDARD.decode(&opts[1].1).unwrap(), contact_a.to_vec());
        assert_eq!(STANDARD.decode(&opts[2].1).unwrap(), contact_b.to_vec());
    }

    #[test]
    fn encrypted_leaseset_options_handles_zero_contacts() {
        // Bootstrapping case: no contacts yet. The session still gets
        // our priv key so we can dial others; auth list is empty so
        // the leaseset accepts no incoming dials. (Caller may decide
        // to defer session creation until at least one contact exists.)
        let opts = encrypted_leaseset_options(&[0u8; 32], &[]);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].0, "i2cp.leaseSetPrivKey");
    }
}
