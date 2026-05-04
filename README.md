# Noctis Whisper Desktop

Tauri v2 desktop client for the Noctis Whisper private messenger. Wire-compatible
with the Android client — same PQ-X3DH key exchange, Double Ratchet, padded wire
format, and BLAKE2b mailbox addressing.

## Relay

This client speaks to the existing **`whisper-relay`** Go server (in
`~/Documents/whisper-relay`) — same one the Android app uses. No relay changes
are needed for desktop. The wire protocol the desktop client emits is
verified against the relay's exact JSON tags by unit tests in
`transport/control_messages.rs`:

- type tags: `deposit`, `retrieve`, `delivery`, `deposited`, `notify`,
  `padding`, `error`, `accounting_request`, `accounting_response`
- accounting field names are **camelCase** (`framesSent`,
  `framesReceivedFromClient`, …)
- retrieve batch is exactly 8 mailboxes (2 real + 6 decoy, shuffled)
- deposit blobs ≤ 10.5 MB, TTL ≤ 48 h, mailbox is 32-char lowercase hex

For local end-to-end testing, run the relay in dev mode:

```sh
cd ~/Documents/whisper-relay
go run ./cmd/relay -dev -dev-addr :8080
```

Then point the desktop client at `ws://127.0.0.1:8080/ws` in Settings → Relay.

## Stack

- **Backend:** Rust (Tauri v2) — crypto, transport, SQLCipher, Secure Enclave glue
- **Frontend:** React + TypeScript + Tailwind, single window, dark-only
- **Database:** SQLCipher via `rusqlite` with `bundled-sqlcipher`
- **Crypto:**
  - X25519 (`x25519-dalek`), Ed25519 (`ed25519-dalek`)
  - ML-KEM-1024 (`pqcrypto-mlkem`) for post-quantum
  - ChaCha20-Poly1305 (`chacha20poly1305`)
  - HKDF-SHA256 (`hkdf` + `sha2`), BLAKE2b (`blake2`), Argon2id (`argon2`)
  - All key buffers wrapped in `zeroize`

## Layout

```
src-tauri/src/
  crypto/        keys, vault, pqx3dh, ratchet, message_crypto, sealed,
                 tee_encryption, secure_enclave, safety_numbers
  transport/     mailbox, relay (WS), frame_accounting, control_messages
  db/            schema, contacts, messages, rooms
  state.rs       AppState (vault runtime + relay client)
  commands.rs    Tauri IPC surface
src/
  components/    layout (Sidebar/ChatView/InfoPanel/TitleBar),
                 chat, contacts, rooms, vault, settings, shared
  hooks/         useCrypto, useKeyboard, useVault, useMessages, useWebSocket
  stores/        appStore, conversationStore (Zustand)
```

## Development

```sh
npm install
npm run tauri:dev
```

Requires:

- Rust 1.77+ (`cargo`)
- Node 22+ (`npm`)
- Xcode Command Line Tools

## Open work

The scaffold ships protocol-level wire format, ratchet state, mailbox addressing,
safety numbers, and the SQLCipher schema. The pieces still to be wired up before
first launch:

- Persistence of the sealed DEK (Keychain item or sandboxed file)
- Identity + prekey persistence on first run, served by `vault_setup`
- `vault_unlock` end-to-end: Argon2id → DEK → Secure-Enclave → DB key → SQLCipher
- Real Secure Enclave AES-CBC and HMAC-SHA256 calls
  (`security-framework` `SecKeyCreateSignature` + `SecAccessControl`)
- Bundle GET / PUT against the relay (`/bundle/{alias}` endpoint)
- Ratchet wiring at the message layer (encrypt + deposit, retrieve + decrypt)
- Frame accounting reconciliation alarm + dashboard surfacing
- Sender-key group protocol for rooms

These are explicitly marked with `TODO` in the source.
