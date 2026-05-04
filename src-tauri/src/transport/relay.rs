//! WebSocket relay client.
//!
//! - One persistent WS connection per relay URL
//! - Notification-driven retrieval (relay broadcasts `notify` on every deposit;
//!   client immediately issues a retrieve with 8 mailboxes — 2 real + 6 decoy)
//! - 30-second fallback poll
//! - 60-second frame accounting reconciliation
//! - FIFO deposit acknowledgments via per-mailbox queues
//!
//! The actual cryptographic operations (ratchet encrypt / decrypt) happen in
//! the layer above; this module only concerns itself with reliable, ordered
//! transport of opaque blobs.

use super::control_messages::{ClientToRelay, DeliveryMailbox, RelayToClient};
use super::frame_accounting::FrameCounters;
use super::{TransportError, TransportResult};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async, connect_async_tls_with_config,
    tungstenite::protocol::Message as WsMessage, Connector,
};
use url::Url;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Clone)]
pub struct RelayClient {
    inner: Arc<RelayState>,
}

struct RelayState {
    /// Outgoing message queue (to the writer task).
    tx: Mutex<Option<mpsc::UnboundedSender<WsMessage>>>,
    /// Per-mailbox FIFO of pending message IDs awaiting `deposited` ack.
    pending: Mutex<HashMap<String, VecDeque<String>>>,
    /// Running frame counters.
    counters: FrameCounters,
    /// Current relay URL.
    url: Mutex<Option<String>>,
    /// Latest known TLS SPKI pin (SHA-256, hex).
    spki_pin: Mutex<Option<String>>,
}

#[derive(Debug)]
pub enum InboundEvent {
    Notify,
    Delivery(Vec<DeliveryMailbox>),
    Deposited { message_id: String, ok: bool },
    AccountingResponse(super::frame_accounting::RelayCounters),
    Error(String),
}

impl RelayClient {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RelayState {
                tx: Mutex::new(None),
                pending: Mutex::new(HashMap::new()),
                counters: FrameCounters::new(),
                url: Mutex::new(None),
                spki_pin: Mutex::new(None),
            }),
        }
    }

    pub fn counters(&self) -> &FrameCounters {
        &self.inner.counters
    }

    pub fn current_url(&self) -> Option<String> {
        self.inner.url.lock().clone()
    }

    pub fn set_pin(&self, pin: Option<String>) {
        *self.inner.spki_pin.lock() = pin;
    }

    /// Connect (or reconnect) to the given relay URL. Spawns a reader task that
    /// emits inbound events to `events_tx`.
    ///
    /// `expected_pin`: SHA-256 of the leaf cert's SPKI we require the relay
    /// to present. `None` means TOFU — accept any cert and capture its pin
    /// for the caller to persist. For `ws://` URLs no TLS is involved and
    /// the returned pin is always `None`.
    ///
    /// Returns the SPKI pin observed during the handshake (if any).
    pub async fn connect(
        &self,
        url: String,
        expected_pin: Option<[u8; 32]>,
        events_tx: mpsc::UnboundedSender<InboundEvent>,
    ) -> TransportResult<Option<[u8; 32]>> {
        let parsed = Url::parse(&url).map_err(|e| TransportError::Encoding(e.to_string()))?;
        let scheme = parsed.scheme();
        if scheme != "wss" && scheme != "ws" {
            return Err(TransportError::Encoding(
                "relay URL must be ws:// or wss://".into(),
            ));
        }

        let (ws, captured_pin) = if scheme == "wss" {
            let (config, verifier) = super::tls_pin::pinning_client_config(expected_pin);
            let connector = Connector::Rustls(config);
            let (ws, _resp) = connect_async_tls_with_config(&url, None, false, Some(connector))
                .await
                .map_err(|e| {
                    if e.to_string().contains("TLS pin mismatch") {
                        TransportError::TlsPinMismatch
                    } else {
                        TransportError::Ws(e.to_string())
                    }
                })?;
            (ws, verifier.captured_pin())
        } else {
            let (ws, _resp) = connect_async(&url)
                .await
                .map_err(|e| TransportError::Ws(e.to_string()))?;
            (ws, None)
        };

        let (mut ws_write, mut ws_read) = ws.split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsMessage>();
        *self.inner.tx.lock() = Some(out_tx);
        *self.inner.url.lock() = Some(url);

        let counters_writer = self.inner.clone();
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let n = msg.len();
                if ws_write.send(msg).await.is_err() {
                    break;
                }
                counters_writer.counters.observe_send(n);
            }
        });

        let counters_reader = self.inner.clone();
        let pending_reader = self.inner.clone();
        tokio::spawn(async move {
            while let Some(frame) = ws_read.next().await {
                let frame = match frame {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let bytes = match &frame {
                    WsMessage::Text(t) => t.len(),
                    WsMessage::Binary(b) => b.len(),
                    WsMessage::Ping(b) | WsMessage::Pong(b) => b.len(),
                    WsMessage::Close(_) => 0,
                    WsMessage::Frame(_) => 0,
                };

                // Count every inbound frame, including `accounting_response`.
                // The relay snapshots its `framesSentToClient` counter BEFORE
                // writing the response and increments after the write, so its
                // reported value is one less than its actual count at the
                // moment we receive the frame. We compensate in `reconcile`
                // by tolerating a +1 difference on the receive side.
                counters_reader.counters.observe_recv(bytes);
                if let WsMessage::Text(text) = &frame {
                    let evt = parse_inbound(text, &pending_reader);
                    if events_tx.send(evt).is_err() {
                        break;
                    }
                }
            }
            let _ = events_tx.send(InboundEvent::Error("reader closed".into()));
        });

        if let Some(pin) = captured_pin {
            *self.inner.spki_pin.lock() = Some(hex::encode(pin));
        }
        Ok(captured_pin)
    }

    /// Send a deposit. Returns immediately; callers should await the matching
    /// `Deposited` event to confirm.
    pub fn deposit(
        &self,
        mailbox_hex: String,
        blob: &[u8],
        ttl_secs: u64,
        message_id: String,
    ) -> TransportResult<()> {
        // Enqueue for FIFO ack matching.
        self.inner
            .pending
            .lock()
            .entry(mailbox_hex.clone())
            .or_default()
            .push_back(message_id);
        let cmd = ClientToRelay::Deposit {
            mailbox: mailbox_hex,
            blob: B64.encode(blob),
            ttl: ttl_secs,
        };
        self.send_json(&cmd)
    }

    /// Send a retrieve for the provided mailbox batch (already shuffled).
    pub fn retrieve(&self, mailboxes_hex: Vec<String>) -> TransportResult<()> {
        let cmd = ClientToRelay::Retrieve {
            mailboxes: mailboxes_hex,
        };
        self.send_json(&cmd)
    }

    /// Send a cover-traffic frame. The relay silently ignores these. Used to
    /// keep on-wire packet cadence independent of message activity.
    pub fn send_padding(&self) -> TransportResult<()> {
        self.send_json(&ClientToRelay::Padding)
    }

    /// Send a frame accounting request.
    pub fn request_accounting(&self) -> TransportResult<()> {
        let s = self.inner.counters.snapshot();
        let cmd = ClientToRelay::AccountingRequest {
            frames_sent: s.frames_sent,
            frames_received: s.frames_received,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            ts: now_unix_ms(),
        };
        self.send_json(&cmd)
    }

    fn send_json(&self, cmd: &ClientToRelay) -> TransportResult<()> {
        let body = serde_json::to_string(cmd).map_err(|e| TransportError::Encoding(e.to_string()))?;
        let tx = self.inner.tx.lock();
        let tx = tx.as_ref().ok_or(TransportError::Disconnected)?;
        tx.send(WsMessage::Text(body))
            .map_err(|_| TransportError::Disconnected)?;
        Ok(())
    }
}

fn parse_inbound(text: &str, state: &Arc<RelayState>) -> InboundEvent {
    let parsed: Result<RelayToClient, _> = serde_json::from_str(text);
    match parsed {
        Ok(RelayToClient::Notify) => InboundEvent::Notify,
        Ok(RelayToClient::Delivery { mailboxes }) => InboundEvent::Delivery(mailboxes),
        Ok(RelayToClient::Deposited { mailbox, ok }) => {
            // Pop the head of this mailbox's FIFO queue to find the message id.
            let id = state
                .pending
                .lock()
                .get_mut(&mailbox)
                .and_then(|q| q.pop_front())
                .unwrap_or_default();
            InboundEvent::Deposited {
                message_id: id,
                ok,
            }
        }
        Ok(RelayToClient::AccountingResponse {
            frames_received_from_client,
            frames_sent_to_client,
            bytes_received_from_client,
            bytes_sent_to_client,
            ..
        }) => InboundEvent::AccountingResponse(super::frame_accounting::RelayCounters {
            frames_received_from_client,
            frames_sent_to_client,
            bytes_received_from_client,
            bytes_sent_to_client,
        }),
        Ok(RelayToClient::Error { message }) => InboundEvent::Error(message),
        Err(e) => InboundEvent::Error(format!("malformed relay msg: {}", e)),
    }
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One-shot deposit to a different relay than our home WebSocket.
///
/// Used for cross-relay messaging: when Alice's contact `bob` lives on
/// `wss://relay-b.com/ws` and Alice's home connection is on
/// `wss://relay-a.com/ws`, Alice opens a transient connection to relay-b,
/// deposits a single blob, waits for the `deposited` ack (10 s timeout),
/// closes the connection. No frame accounting on transient connections —
/// the home connection's accounting is the trust boundary.
pub async fn transient_deposit(
    relay_url: &str,
    mailbox_hex: &str,
    blob: &[u8],
    ttl_secs: u64,
    timeout: std::time::Duration,
    expected_pin: Option<[u8; 32]>,
) -> TransportResult<Option<[u8; 32]>> {
    use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

    let parsed = url::Url::parse(relay_url).map_err(|e| TransportError::Encoding(e.to_string()))?;
    let scheme = parsed.scheme();
    if scheme != "wss" && scheme != "ws" {
        return Err(TransportError::Encoding(
            "transient deposit URL must be ws:// or wss://".into(),
        ));
    }

    let (ws, captured_pin) = if scheme == "wss" {
        let (config, verifier) = super::tls_pin::pinning_client_config(expected_pin);
        let connector = Connector::Rustls(config);
        let connect_fut =
            connect_async_tls_with_config(relay_url, None, false, Some(connector));
        let pair = match tokio::time::timeout(timeout, connect_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                if e.to_string().contains("TLS pin mismatch") {
                    return Err(TransportError::TlsPinMismatch);
                }
                return Err(TransportError::Ws(e.to_string()));
            }
            Err(_) => {
                return Err(TransportError::Ws(
                    "transient deposit: connect timed out".into(),
                ))
            }
        };
        (pair.0, verifier.captured_pin())
    } else {
        let connect_fut = connect_async(relay_url);
        let pair = match tokio::time::timeout(timeout, connect_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(TransportError::Ws(e.to_string())),
            Err(_) => {
                return Err(TransportError::Ws(
                    "transient deposit: connect timed out".into(),
                ))
            }
        };
        (pair.0, None)
    };

    let (mut tx, mut rx) = ws.split();
    let cmd = ClientToRelay::Deposit {
        mailbox: mailbox_hex.to_string(),
        blob: B64.encode(blob),
        ttl: ttl_secs,
    };
    let body =
        serde_json::to_string(&cmd).map_err(|e| TransportError::Encoding(e.to_string()))?;
    tx.send(WsMessage::Text(body))
        .await
        .map_err(|e| TransportError::Ws(e.to_string()))?;

    // Wait for `{"type":"deposited","mailbox":"<hex>","ok":true}`.
    let ack_fut = async {
        while let Some(frame) = rx.next().await {
            let frame = match frame {
                Ok(f) => f,
                Err(e) => return Err(TransportError::Ws(e.to_string())),
            };
            if let WsMessage::Text(text) = frame {
                if let Ok(parsed) = serde_json::from_str::<RelayToClient>(&text) {
                    if let RelayToClient::Deposited { mailbox, ok } = parsed {
                        if mailbox == mailbox_hex && ok {
                            return Ok(());
                        }
                        return Err(TransportError::Protocol(
                            "transient deposit: relay rejected",
                        ));
                    }
                }
            }
        }
        Err(TransportError::Ws("transient deposit: stream closed".into()))
    };

    let result = tokio::time::timeout(timeout, ack_fut).await;
    let _ = tx.close().await;
    match result {
        Ok(Ok(())) => Ok(captured_pin),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(TransportError::Ws("transient deposit: ack timed out".into())),
    }
}

/// One-shot retrieve from a different relay. Used during the 14-day
/// grace-period after a home-relay change to drain messages that peers
/// deposited there before they processed our `relay_update` envelope.
/// Decoded `Delivery` frames are forwarded to `events_tx` so the inbound
/// pump processes them through its normal path.
pub async fn transient_retrieve(
    relay_url: &str,
    mailboxes_hex: Vec<String>,
    timeout: std::time::Duration,
    events_tx: mpsc::UnboundedSender<InboundEvent>,
    expected_pin: Option<[u8; 32]>,
) -> TransportResult<Option<[u8; 32]>> {
    use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

    let parsed = url::Url::parse(relay_url).map_err(|e| TransportError::Encoding(e.to_string()))?;
    let scheme = parsed.scheme();
    if scheme != "wss" && scheme != "ws" {
        return Err(TransportError::Encoding(
            "transient retrieve URL must be ws:// or wss://".into(),
        ));
    }

    let (ws, captured_pin) = if scheme == "wss" {
        let (config, verifier) = super::tls_pin::pinning_client_config(expected_pin);
        let connector = Connector::Rustls(config);
        let connect_fut =
            connect_async_tls_with_config(relay_url, None, false, Some(connector));
        let pair = match tokio::time::timeout(timeout, connect_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                if e.to_string().contains("TLS pin mismatch") {
                    return Err(TransportError::TlsPinMismatch);
                }
                return Err(TransportError::Ws(e.to_string()));
            }
            Err(_) => {
                return Err(TransportError::Ws(
                    "transient retrieve: connect timed out".into(),
                ))
            }
        };
        (pair.0, verifier.captured_pin())
    } else {
        let connect_fut = connect_async(relay_url);
        let pair = match tokio::time::timeout(timeout, connect_fut).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(TransportError::Ws(e.to_string())),
            Err(_) => {
                return Err(TransportError::Ws(
                    "transient retrieve: connect timed out".into(),
                ))
            }
        };
        (pair.0, None)
    };

    let (mut tx, mut rx) = ws.split();
    let cmd = ClientToRelay::Retrieve {
        mailboxes: mailboxes_hex,
    };
    let body =
        serde_json::to_string(&cmd).map_err(|e| TransportError::Encoding(e.to_string()))?;
    tx.send(WsMessage::Text(body))
        .await
        .map_err(|e| TransportError::Ws(e.to_string()))?;

    // Wait for the matching `delivery` response, then close.
    let recv_fut = async {
        while let Some(frame) = rx.next().await {
            let frame = match frame {
                Ok(f) => f,
                Err(e) => return Err(TransportError::Ws(e.to_string())),
            };
            if let WsMessage::Text(text) = frame {
                if let Ok(parsed) = serde_json::from_str::<RelayToClient>(&text) {
                    if let RelayToClient::Delivery { mailboxes } = parsed {
                        let _ = events_tx.send(InboundEvent::Delivery(mailboxes));
                        return Ok(());
                    }
                }
            }
        }
        Err(TransportError::Ws("transient retrieve: stream closed".into()))
    };

    let result = tokio::time::timeout(timeout, recv_fut).await;
    let _ = tx.close().await;
    match result {
        Ok(Ok(())) => Ok(captured_pin),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(TransportError::Ws("transient retrieve: timed out".into())),
    }
}

/// 14-day grace period for home-relay migration. Peers learn the new URL
/// from a `relay_update` envelope after their next decrypt of any message
/// from us — until then they may still deposit on the old URL.
const GRACE_PERIOD_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Background task: every `FALLBACK_POLL_SECS`, fire a retrieve (home + any
/// previous relay still inside the 14-day grace window) and every
/// `FRAME_RECONCILE_SECS`, fire an accounting request.
///
/// This is wired up by the application layer once the relay client is connected.
pub async fn run_periodic_tasks(
    client: RelayClient,
    recipient_pubkey: Vec<u8>,
    state: Arc<crate::state::AppState>,
    events_tx: mpsc::UnboundedSender<InboundEvent>,
    app: tauri::AppHandle,
) {
    let mut poll = tokio::time::interval(Duration::from_secs(super::FALLBACK_POLL_SECS));
    let mut recon = tokio::time::interval(Duration::from_secs(super::FRAME_RECONCILE_SECS));
    let mut sweep =
        tokio::time::interval(Duration::from_secs(super::DISAPPEAR_SWEEP_SECS));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    recon.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = sweep.tick() => {
                let removed = sweep_expired_messages(&state);
                tracing::debug!("disappearing: sweep tick removed {} row(s)", removed);
                if removed > 0 {
                    tracing::info!("disappearing: purged {} expired message(s)", removed);
                    use tauri::Emitter;
                    let _ = app.emit("messages:purged", removed);
                }
            }
            _ = poll.tick() => {
                let real = super::mailbox::current_mailbox(&recipient_pubkey);
                let batch = super::mailbox::build_retrieve_batch(&real);
                let hex: Vec<String> = batch.iter().map(super::mailbox::hex).collect();
                let _ = client.retrieve(hex.clone());

                // Grace-period sweep of the previously-known home relay.
                let grace = read_grace_period(&state);
                if let Some((prev_url, started_at)) = grace {
                    let now_ms = now_unix_ms();
                    let elapsed = now_ms.saturating_sub(started_at);
                    if elapsed >= GRACE_PERIOD_MS {
                        clear_grace_period(&state);
                        tracing::info!(
                            "grace-period: cleared previous_relay_url after {} ms",
                            elapsed
                        );
                    } else {
                        let url = prev_url.clone();
                        let mailboxes = hex.clone();
                        let tx = events_tx.clone();
                        let pin = read_relay_pin(&state, &url);
                        tokio::spawn(async move {
                            if let Err(e) = transient_retrieve(
                                &url,
                                mailboxes,
                                Duration::from_secs(10),
                                tx,
                                pin,
                            )
                            .await
                            {
                                tracing::debug!(
                                    "grace-period transient_retrieve from {} failed: {}",
                                    url,
                                    e
                                );
                            }
                        });
                    }
                }
            }
            _ = recon.tick() => {
                let _ = client.request_accounting();
            }
        }
    }
}

fn read_grace_period(state: &Arc<crate::state::AppState>) -> Option<(String, u64)> {
    let guard = state.vault.lock();
    let rt = guard.as_ref()?;
    let url = rt.db.settings_get("previous_relay_url").ok().flatten()?;
    if url.is_empty() {
        return None;
    }
    let started = rt
        .db
        .settings_get("relay_migration_started_at")
        .ok()
        .flatten()?;
    let started_ms: u64 = started.parse().ok()?;
    Some((url, started_ms))
}

fn clear_grace_period(state: &Arc<crate::state::AppState>) {
    let guard = state.vault.lock();
    if let Some(rt) = guard.as_ref() {
        let _ = rt.db.settings_delete("previous_relay_url");
        let _ = rt.db.settings_delete("relay_migration_started_at");
    }
}

fn sweep_expired_messages(state: &Arc<crate::state::AppState>) -> usize {
    let now_ms = now_unix_ms() as i64;
    let profile_dir = crate::profile::data_dir();
    let guard = state.vault.lock();
    let Some(rt) = guard.as_ref() else { return 0 };
    // Collect ids of attachments about to be purged so we can also delete
    // their on-disk payloads.
    let attachment_ids: Vec<String> = rt
        .db
        .conn
        .prepare(
            "SELECT id FROM messages
             WHERE disappear_at IS NOT NULL AND disappear_at <= ?1
               AND is_attachment = 1",
        )
        .ok()
        .and_then(|mut stmt| {
            stmt.query_map(rusqlite::params![now_ms], |r| r.get::<_, String>(0))
                .ok()
                .map(|rows| rows.flatten().collect())
        })
        .unwrap_or_default();
    let removed = rt.db.purge_expired_messages(now_ms).unwrap_or(0);
    for id in attachment_ids {
        crate::messaging::attachments::delete(&profile_dir, &id);
    }
    removed
}

/// Settings key prefix for stored TLS SPKI pins, scoped per relay URL.
pub fn pin_settings_key(relay_url: &str) -> String {
    format!("relay_pin:{}", relay_url)
}

fn read_relay_pin(
    state: &Arc<crate::state::AppState>,
    relay_url: &str,
) -> Option<[u8; 32]> {
    let guard = state.vault.lock();
    let rt = guard.as_ref()?;
    let hex = rt.db.settings_get(&pin_settings_key(relay_url)).ok().flatten()?;
    let bytes = hex::decode(hex).ok()?;
    bytes.try_into().ok()
}
