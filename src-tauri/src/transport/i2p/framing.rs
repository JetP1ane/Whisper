//! Wire framing for an I2P stream.
//!
//! After a SAM `STREAM CONNECT` or `STREAM ACCEPT` succeeds, the socket
//! becomes a raw byte pipe between two destinations. Whisper layers a
//! tiny framing protocol on top so a single connection can carry
//! multiple distinct messages, ACKs, and keepalives:
//!
//! ```text
//!  ┌────────────┬────────┬───────────────────────┐
//!  │ length(BE) │ type   │ payload (length bytes)│
//!  │  4 bytes   │ 1 byte │       N bytes         │
//!  └────────────┴────────┴───────────────────────┘
//!     N = length, can be 0 for ACK / keepalive
//! ```
//!
//! Length is **payload bytes only** (does not include the 5-byte header).
//! Type codes mirror §3 of the design proposal:
//!
//! | code | meaning |
//! |------|---------|
//! | 0x01 | ratchet-encrypted message blob (text/control envelope inside)|
//! | 0x02 | ratchet-encrypted file metadata (filename + thumbnail) |
//! | 0x03 | ratchet-encrypted file chunk |
//! | 0x04 | ACK — payload is 32-byte SHA-256 of the blob being ack'd |
//! | 0x05 | keepalive ping — payload empty |
//! | 0x06 | keepalive pong — payload empty |
//!
//! The framing is intentionally simple: it's a TCP-style stream multiplex,
//! not a request/response RPC. Higher layers (`connection`, `queue`)
//! decide how to use it.

use super::{I2pError, I2pResult, MAX_FRAME_PAYLOAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// All defined frame types. Unknown codes on read are tolerated by
/// upgrading to [`FrameType::Unknown`] so future protocol versions can
/// introduce new frame types without breaking older clients (they just
/// ignore frames they can't decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Message,
    FileMetadata,
    FileChunk,
    Ack,
    KeepalivePing,
    KeepalivePong,
    Unknown(u8),
}

impl FrameType {
    pub fn code(self) -> u8 {
        match self {
            FrameType::Message => 0x01,
            FrameType::FileMetadata => 0x02,
            FrameType::FileChunk => 0x03,
            FrameType::Ack => 0x04,
            FrameType::KeepalivePing => 0x05,
            FrameType::KeepalivePong => 0x06,
            FrameType::Unknown(c) => c,
        }
    }
    pub fn from_code(code: u8) -> Self {
        match code {
            0x01 => FrameType::Message,
            0x02 => FrameType::FileMetadata,
            0x03 => FrameType::FileChunk,
            0x04 => FrameType::Ack,
            0x05 => FrameType::KeepalivePing,
            0x06 => FrameType::KeepalivePong,
            other => FrameType::Unknown(other),
        }
    }
}

/// One decoded frame. Owns its payload so the caller can drop the read
/// buffer freely.
#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: FrameType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameType, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            payload: payload.into(),
        }
    }
    pub fn ack(blob_hash: [u8; 32]) -> Self {
        Self {
            kind: FrameType::Ack,
            payload: blob_hash.to_vec(),
        }
    }
    pub fn ping() -> Self {
        Self {
            kind: FrameType::KeepalivePing,
            payload: Vec::new(),
        }
    }
    pub fn pong() -> Self {
        Self {
            kind: FrameType::KeepalivePong,
            payload: Vec::new(),
        }
    }
}

/// Serialize a frame onto the wire. `flush` is the caller's
/// responsibility — for a series of frames in flight, the caller can
/// batch them and flush once.
pub async fn write_frame<W>(w: &mut W, frame: &Frame) -> I2pResult<()>
where
    W: AsyncWrite + Unpin,
{
    if frame.payload.len() > MAX_FRAME_PAYLOAD {
        return Err(I2pError::Encoding(format!(
            "frame payload {} > max {}",
            frame.payload.len(),
            MAX_FRAME_PAYLOAD
        )));
    }
    let mut header = [0u8; 5];
    header[..4].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    header[4] = frame.kind.code();
    w.write_all(&header).await?;
    if !frame.payload.is_empty() {
        w.write_all(&frame.payload).await?;
    }
    Ok(())
}

/// Read exactly one frame from the wire. Returns `Disconnected` on EOF
/// before the header is complete — the caller treats that as a clean
/// connection close.
pub async fn read_frame<R>(r: &mut R) -> I2pResult<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(I2pError::Disconnected);
        }
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
    let kind = FrameType::from_code(header[4]);
    if len > MAX_FRAME_PAYLOAD {
        return Err(I2pError::Encoding(format!(
            "inbound frame length {len} exceeds cap {MAX_FRAME_PAYLOAD}"
        )));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await?;
    }
    Ok(Frame { kind, payload })
}

/// Read frames until EOF or error, yielding each via the closure. Used
/// by the inbound accept loop (Phase 3 ConnectionManager); a peer can
/// send multiple frames over one stream and we process each as it
/// arrives.
pub async fn read_frames_loop<R, F, Fut>(mut r: R, mut handler: F) -> I2pResult<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(Frame) -> Fut,
    Fut: std::future::Future<Output = I2pResult<()>>,
{
    loop {
        match read_frame(&mut r).await {
            Ok(frame) => handler(frame).await?,
            Err(I2pError::Disconnected) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: Frame) -> Frame {
        let mut out = Vec::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            write_frame(&mut out, &frame).await.unwrap();
            let mut cur = std::io::Cursor::new(out);
            read_frame(&mut cur).await.unwrap()
        })
    }

    #[test]
    fn round_trip_message_frame() {
        let payload = b"hello whisper".to_vec();
        let got = round_trip(Frame::new(FrameType::Message, payload.clone()));
        assert_eq!(got.kind, FrameType::Message);
        assert_eq!(got.payload, payload);
    }

    #[test]
    fn round_trip_ack_frame_carries_hash() {
        let hash = [0xABu8; 32];
        let got = round_trip(Frame::ack(hash));
        assert_eq!(got.kind, FrameType::Ack);
        assert_eq!(got.payload, hash.to_vec());
    }

    #[test]
    fn round_trip_keepalive_has_empty_payload() {
        let p = round_trip(Frame::ping());
        assert_eq!(p.kind, FrameType::KeepalivePing);
        assert!(p.payload.is_empty());
        let q = round_trip(Frame::pong());
        assert_eq!(q.kind, FrameType::KeepalivePong);
        assert!(q.payload.is_empty());
    }

    #[test]
    fn unknown_frame_type_decodes_to_unknown_variant() {
        // Hand-roll a frame with an unknown type byte and verify we
        // tolerate it (forward-compat).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3u32.to_be_bytes()); // payload len
        bytes.push(0xFE); // unknown type
        bytes.extend_from_slice(b"foo");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut cur = std::io::Cursor::new(bytes);
        let frame = rt.block_on(read_frame(&mut cur)).unwrap();
        assert_eq!(frame.kind, FrameType::Unknown(0xFE));
        assert_eq!(frame.payload, b"foo");
    }

    #[test]
    fn oversized_payload_rejected_on_write() {
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut out = Vec::new();
        let err =
            rt.block_on(write_frame(&mut out, &Frame::new(FrameType::Message, big))).unwrap_err();
        assert!(matches!(err, I2pError::Encoding(_)));
    }

    #[test]
    fn oversized_length_header_rejected_on_read() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes()));
        bytes.push(0x01);
        // No payload — read should bail on the length check before any
        // bulk read.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut cur = std::io::Cursor::new(bytes);
        let err = rt.block_on(read_frame(&mut cur)).unwrap_err();
        assert!(matches!(err, I2pError::Encoding(_)));
    }

    #[test]
    fn truncated_header_returns_disconnected() {
        // Only 3 bytes of the 5-byte header — peer hung up mid-frame.
        let bytes = vec![0u8, 0u8, 0u8];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut cur = std::io::Cursor::new(bytes);
        let err = rt.block_on(read_frame(&mut cur)).unwrap_err();
        assert!(matches!(err, I2pError::Disconnected));
    }

    #[test]
    fn read_frames_loop_handles_multiple_frames_then_eof() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut out = Vec::new();
            write_frame(&mut out, &Frame::new(FrameType::Message, b"first".to_vec()))
                .await
                .unwrap();
            write_frame(&mut out, &Frame::ack([7u8; 32])).await.unwrap();
            write_frame(&mut out, &Frame::ping()).await.unwrap();

            // Channel out the observed frame types so the test closure
            // doesn't have to capture a mutable Vec across `.await`.
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let cur = std::io::Cursor::new(out);
            read_frames_loop(cur, move |f| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(f.kind);
                    Ok(())
                }
            })
            .await
            .unwrap();
            let mut seen = Vec::new();
            while let Some(k) = rx.recv().await {
                seen.push(k);
            }
            assert_eq!(
                seen,
                vec![FrameType::Message, FrameType::Ack, FrameType::KeepalivePing]
            );
        });
    }
}
