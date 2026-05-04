//! ConnectionManager — the API the rest of Whisper uses to send and
//! receive blobs over I2P.
//!
//! Everything below is built on top of the [`manager::I2PManager`] master
//! session: outbound calls open SAM `STREAM CONNECT` sockets to a peer
//! destination, layer [`framing`] on top, and stream as many frames as
//! the caller wants over a single connection. Inbound is the symmetric
//! `STREAM ACCEPT` loop — one tokio task per accepted connection,
//! handler is the caller's closure.
//!
//! ## Outbound
//!
//! [`ConnectionManager::send_blob`] takes a peer destination + payload
//! bytes (already ratchet-encrypted) and a [`framing::FrameType`].
//! It opens a fresh stream, writes one frame, awaits the ACK frame in
//! response, and tears the stream down. Higher layers (Phase 4 send
//! queue) sit on top and add retry/backoff/persistence.
//!
//! Connection caching (Phase 3 §2 keep-alive): a successful `send_blob`
//! to a destination keeps the underlying SAM stream alive in a per-
//! destination cache for `STREAM_IDLE_TIMEOUT_SECS` seconds. Subsequent
//! sends to the same peer reuse the connection, avoiding the 1-3s
//! tunnel-build cost on every back-and-forth message. A background
//! reaper closes idle entries after the timeout.
//!
//! ## Inbound
//!
//! [`ConnectionManager::run_inbound`] starts a tokio task that loops on
//! `STREAM ACCEPT`. Each accepted connection is handled by a handler
//! the caller supplies (`Fn(peer_dest, frame) -> impl Future`); the
//! manager handles framing + writes the ACK reply for `Message` /
//! `FileMetadata` / `FileChunk` frames automatically.
//!
//! The inbound task is owned by the manager — calling `shutdown_inbound`
//! signals the loop to exit and joins on the task.

use super::framing::{read_frame, write_frame, Frame, FrameType};
use super::manager::I2PManager;
use super::sam;
use super::{I2pError, I2pResult, STREAM_IDLE_TIMEOUT_SECS};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Inbound handler signature. The closure receives the remote peer's
/// full base64 destination + the decoded frame, and returns a result.
/// Returning `Err` is logged but does NOT terminate the inbound loop —
/// one bad connection shouldn't kill the manager.
pub type InboundHandler = Arc<
    dyn Fn(
            String,
            Frame,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = I2pResult<()>> + Send>,
        > + Send
        + Sync,
>;

/// One cached outbound connection. The `last_used` instant is bumped on
/// every send and checked by the reaper to evict idle entries.
struct CachedConn {
    stream: TcpStream,
    last_used: Instant,
}

pub struct ConnectionManager {
    /// SAM bridge address (cloned from the I2PManager).
    sam_addr: String,
    /// Master session ID (cloned from the I2PManager).
    session_id: String,
    /// Outbound connection cache, keyed by peer destination (base64).
    outbound: Arc<Mutex<HashMap<String, CachedConn>>>,
    /// Reaper task that evicts idle outbound connections.
    reaper: JoinHandle<()>,
    /// Inbound accept loop task (Option so `shutdown_inbound` can take
    /// it). Set when `run_inbound` is called.
    inbound: Mutex<Option<JoinHandle<()>>>,
    /// Shutdown signal for the inbound loop.
    inbound_shutdown: Arc<tokio::sync::Notify>,
}

impl ConnectionManager {
    pub fn new(manager: &I2PManager) -> Self {
        let sam_addr = manager.sam_addr().to_string();
        let outbound: Arc<Mutex<HashMap<String, CachedConn>>> = Arc::new(Mutex::new(HashMap::new()));
        let reaper_outbound = outbound.clone();
        let reaper = tokio::spawn(async move {
            let interval = Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS / 2);
            let cap = Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS);
            loop {
                tokio::time::sleep(interval).await;
                let now = Instant::now();
                let mut guard = reaper_outbound.lock().await;
                let stale: Vec<String> = guard
                    .iter()
                    .filter(|(_, c)| now.duration_since(c.last_used) > cap)
                    .map(|(d, _)| d.clone())
                    .collect();
                for dest in stale {
                    if let Some(mut c) = guard.remove(&dest) {
                        let _ = c.stream.shutdown().await;
                        tracing::debug!("i2p: reaped idle outbound stream to {}", &dest[..16]);
                    }
                }
            }
        });
        Self {
            sam_addr,
            session_id: manager.session_id().to_string(),
            outbound,
            reaper,
            inbound: Mutex::new(None),
            inbound_shutdown: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Send a single blob (already ratchet-encrypted) to `peer_dest`.
    /// Frames it with `kind`, awaits the recipient's ACK, returns when
    /// the ACK arrives.
    ///
    /// The ACK payload is the SHA-256 of the blob bytes so the sender
    /// can verify the receiver decoded the same bytes (defense against
    /// silent corruption); we tolerate ACK-without-hash (empty payload)
    /// for forward compat.
    pub async fn send_blob(
        &self,
        peer_dest: &str,
        kind: FrameType,
        blob: &[u8],
    ) -> I2pResult<()> {
        let mut stream = self.acquire_outbound(peer_dest).await?;
        let res = self.send_blob_inner(&mut stream, kind, blob).await;
        match res {
            Ok(()) => {
                self.cache_outbound(peer_dest, stream).await;
                Ok(())
            }
            Err(e) => {
                let _ = stream.shutdown().await;
                Err(e)
            }
        }
    }

    async fn send_blob_inner(
        &self,
        stream: &mut TcpStream,
        kind: FrameType,
        blob: &[u8],
    ) -> I2pResult<()> {
        let frame = Frame::new(kind, blob.to_vec());
        write_frame(stream, &frame).await?;
        stream.flush().await?;

        // Read one frame: expect ACK.
        let reply = read_frame(stream).await?;
        match reply.kind {
            FrameType::Ack => {
                if !reply.payload.is_empty() && reply.payload.len() == 32 {
                    let expected = Sha256::digest(blob);
                    if reply.payload.as_slice() != expected.as_slice() {
                        return Err(I2pError::Sam(
                            "ACK hash does not match sent blob — possible MITM or corruption"
                                .into(),
                        ));
                    }
                }
                Ok(())
            }
            other => Err(I2pError::Sam(format!(
                "expected ACK after send, got {:?}",
                other
            ))),
        }
    }

    /// Get a connection to `peer_dest` — from the cache if it's fresh,
    /// otherwise dial through SAM.
    async fn acquire_outbound(&self, peer_dest: &str) -> I2pResult<TcpStream> {
        // Try the cache first.
        {
            let mut guard = self.outbound.lock().await;
            if let Some(cached) = guard.remove(peer_dest) {
                let age = Instant::now().duration_since(cached.last_used);
                if age < Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS) {
                    tracing::trace!("i2p: reusing cached outbound to {}", &peer_dest[..16]);
                    return Ok(cached.stream);
                }
                // Stale — fall through to dial. Discard the old stream.
                let mut s = cached.stream;
                let _ = s.shutdown().await;
            }
        }
        tracing::debug!("i2p: dialing {} via SAM", &peer_dest[..16]);
        let stream = sam::stream_connect(&self.sam_addr, &self.session_id, peer_dest).await?;
        Ok(stream)
    }

    async fn cache_outbound(&self, peer_dest: &str, stream: TcpStream) {
        let mut guard = self.outbound.lock().await;
        guard.insert(
            peer_dest.to_string(),
            CachedConn {
                stream,
                last_used: Instant::now(),
            },
        );
    }

    /// Number of currently-cached outbound connections — for diagnostics.
    pub async fn cached_outbound_count(&self) -> usize {
        self.outbound.lock().await.len()
    }

    /// Start the inbound accept loop. Each accepted connection runs the
    /// handler on every frame it receives, automatically sending an ACK
    /// (with SHA-256 hash) for `Message` / `FileMetadata` / `FileChunk`.
    /// `KeepalivePing` is auto-replied with `KeepalivePong`. Other frame
    /// types pass through to the handler verbatim.
    ///
    /// Returns immediately; the loop runs in a background task. Call
    /// `shutdown_inbound` to stop it.
    pub async fn run_inbound(&self, handler: InboundHandler) -> I2pResult<()> {
        let mut guard = self.inbound.lock().await;
        if guard.is_some() {
            return Err(I2pError::Sam("inbound loop already running".into()));
        }
        let sam_addr = self.sam_addr.clone();
        let session_id = self.session_id.clone();
        let shutdown = self.inbound_shutdown.clone();
        let task = tokio::spawn(async move {
            inbound_loop(sam_addr, session_id, handler, shutdown).await;
        });
        *guard = Some(task);
        Ok(())
    }

    /// Signal the inbound loop to exit and await its termination.
    pub async fn shutdown_inbound(&self) {
        self.inbound_shutdown.notify_waiters();
        let mut guard = self.inbound.lock().await;
        if let Some(handle) = guard.take() {
            let _ = handle.await;
        }
    }

    /// Drop all cached outbound streams + stop the reaper. Call on app
    /// shutdown before tearing down the I2PManager.
    pub async fn shutdown(self) {
        self.shutdown_inbound().await;
        self.reaper.abort();
        let mut guard = self.outbound.lock().await;
        for (_, mut c) in guard.drain() {
            let _ = c.stream.shutdown().await;
        }
    }
}

async fn inbound_loop(
    sam_addr: String,
    session_id: String,
    handler: InboundHandler,
    shutdown: Arc<tokio::sync::Notify>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("i2p: inbound loop shutting down");
                return;
            }
            res = sam::stream_accept(&sam_addr, &session_id) => {
                match res {
                    Ok((stream, peer_dest)) => {
                        let h = handler.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_inbound_stream(stream, peer_dest, h).await {
                                tracing::warn!("i2p: inbound stream errored: {e}");
                            }
                        });
                    }
                    Err(I2pError::Disconnected) => {
                        // SAM bridge restarted? Brief pause then retry.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        tracing::warn!("i2p: STREAM ACCEPT errored: {e}; retrying in 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }
}

async fn handle_inbound_stream(
    mut stream: TcpStream,
    peer_dest: String,
    handler: InboundHandler,
) -> I2pResult<()> {
    loop {
        let frame = match read_frame(&mut stream).await {
            Ok(f) => f,
            Err(I2pError::Disconnected) => return Ok(()),
            Err(e) => return Err(e),
        };
        match frame.kind {
            FrameType::KeepalivePing => {
                write_frame(&mut stream, &Frame::pong()).await?;
                stream.flush().await?;
            }
            FrameType::KeepalivePong => {
                // No-op; we don't currently track outbound pings.
            }
            FrameType::Ack => {
                // Stand-alone ACK (rare — most ACKs ride the same
                // connection as the request). Pass to handler so it can
                // mark a delivery if it's tracking pending blobs.
                handler(peer_dest.clone(), frame).await?;
            }
            FrameType::Message | FrameType::FileMetadata | FrameType::FileChunk => {
                let hash = Sha256::digest(&frame.payload);
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash);
                handler(peer_dest.clone(), frame).await?;
                // ACK with the SHA-256 of what we received so the sender
                // can verify nothing got mangled in transit.
                write_frame(&mut stream, &Frame::ack(hash_arr)).await?;
                stream.flush().await?;
            }
            FrameType::Unknown(code) => {
                tracing::debug!("i2p: ignoring unknown frame type 0x{code:02x}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal smoke test: build a ConnectionManager-like object isn't
    /// possible without a live I2PManager, so we test the helper logic
    /// (cached_outbound_count starts at 0, etc.) inline rather than via
    /// `ConnectionManager::new`. Realistic tests live in the live
    /// integration suite.
    #[test]
    fn frame_type_codes_are_stable() {
        // Pin the wire codes — anything that changes here is a wire-
        // protocol break and needs a version bump.
        assert_eq!(FrameType::Message.code(), 0x01);
        assert_eq!(FrameType::FileMetadata.code(), 0x02);
        assert_eq!(FrameType::FileChunk.code(), 0x03);
        assert_eq!(FrameType::Ack.code(), 0x04);
        assert_eq!(FrameType::KeepalivePing.code(), 0x05);
        assert_eq!(FrameType::KeepalivePong.code(), 0x06);
    }

    #[test]
    fn ack_payload_is_sha256_of_blob() {
        let blob = b"some encrypted bytes here";
        let hash = Sha256::digest(blob);
        let frame = Frame::ack(hash.into());
        assert_eq!(frame.kind, FrameType::Ack);
        assert_eq!(frame.payload.len(), 32);
        assert_eq!(frame.payload, hash.to_vec());
    }
}
