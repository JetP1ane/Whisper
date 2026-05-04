# Android ↔ Desktop Interop Reference

Source of truth: the Android client at `~/Documents/main` and the relay at
`~/Documents/whisper-relay`. Every byte-level wire detail in this file has
been read directly from those sources.

## Already aligned (verified by tests)

- **Mailbox addressing** — `BLAKE2b(output_len = 16, input = pubkey || epoch_day_be)`. **Not** BLAKE2b-512 truncated. (`mailbox.rs::compute`)
- **Retrieve batch** — exactly 8 mailboxes: 1 real + 7 random decoys, shuffled. Yesterday's mailbox is fetched separately, not included in every batch. (`mailbox.rs::build_retrieve_batch`)
- **Relay JSON wire** — type tags `deposit / retrieve / delivery / deposited / notify / padding / error / accounting_request / accounting_response`; accounting field names are camelCase. (`control_messages.rs`, unit-tested)
- **Magic-byte envelopes** — `[0xCF,0xC0,0xDE,0x01]` (contact request, variable length), `[0xCF,0xC0,0x5E,0x01]` (session request, exactly 12 bytes incl. 8-byte BE timestamp). (`envelopes.rs`)
- **Three-word alias** — SHA-256 → first 5 bytes, three 11-bit indices into BIP39 English wordlist. (`keys.rs::derive_alias`)
- **Hex fingerprint** — uppercase hex in 4-char (2-byte) groups, 16 groups for a 32-byte key. (`safety_numbers.rs::hex_fingerprint`)
- **PQ-X3DH** — `IKM = dh1||dh2||dh3||dh4||kem1_secret||kem2_secret`; OTPK X25519 always required, only OTPK kyber portion optional; `salt = "NoctisWhisper_v1"`, `info = "NoctisWhisper_PQX3DH_v1"`. (`pqx3dh.rs`)
- **Double Ratchet** — root KDF `HKDF(salt = root_key, ikm = dh, info = "NoctisWhisper_RootChain_v1")`; chain KDF `HKDF(salt = 32 zero bytes ≡ None, ikm = chain_key, info = "NoctisWhisper_ChainKey_v1")`; both expand 64 bytes split into `(new_root|new_chain, message_key)`. AAD = `ratchet_key(32) || prev_chain_len_be(4) || msg_num_be(4)` = 40 bytes. (`ratchet.rs`)
- **Plaintext envelope** — `[8B ts BE][1B type 0x00|0x01][...]`. Backward-compat: byte 8 not in {0x00, 0x01} ⇒ treat tail as UTF-8 text. (`message_crypto.rs::decode_envelope`)
- **PKCS#7 padding** — block ≤ 256, pad byte = `(pad & 0xFF)`. **Lenient unpad**: trailing 0 ⇒ no trim; invalid pad ⇒ no trim. Block-aligned input ⇒ trailing zero block is preserved through the round-trip (matches Android quirk). (`message_crypto.rs`)
- **Ratchet wire format** — `[4B rk_len][rk][4B prev_chain_len][4B msg_num][12B nonce][4B ct_len][ct][1B sentinel_flag][optional 32B digest]`. (`message_crypto.rs::pack_text_wire`)
- **First-message wrapper** — `[4B session_init_len][session_init_bytes][4096B encrypted_message]`; total > 4096 ⇒ first message; total = 4096 ⇒ regular ratchet message. (`pqx3dh.rs::pack_first_message`)
- **Session-init binary layout** — `writeField(initiator_x25519_pub) || writeField(initiator_ephemeral_pub) || writeField(kem1_ct) || writeField(kem2_ct) || writeInt(used_otpk_id_be)`. The first field is Alice's **X25519** key, not her Ed25519 identity key. (`pqx3dh.rs::pack_session_init`)

## Still to implement (documented for the desktop port)

### 1. Bundle binary serialization
`PublicKeyBundle` has the on-the-wire form below (Android `BundleSerializer.serialize`). Needs a Rust counterpart:

```text
writeInt(version)                           // i32 BE
writeField(identity_key_ed25519)            // 32 bytes
writeField(x25519_key)                      // 32 bytes
writeField(kyber_key)                       // 1568 bytes (full) or empty (compact QR)
writeInt(spk.id)
writeField(spk.x25519_pub)                  // 32 bytes
writeField(spk.kyber_pub)                   // 1568 bytes
writeField(spk.signature)                   // 64 bytes Ed25519 over (x25519_pub || kyber_pub)
writeInt(otpk.id)
writeField(otpk.x25519_pub)                 // 32 bytes
writeField(otpk.kyber_pub)                  // 1568 bytes (full) or empty (compact QR)
writeField(bundle_signature)                // 64 bytes Ed25519 over the entire bundle
writeString(alias)                          // length-prefixed UTF-8, len -1 = null
writeString(display_name)                   // length-prefixed UTF-8, len -1 = null
```

The relay accepts ≤ 4096 bytes per `PUT /bundle/{alias}` (alias regex `^[a-z]{2,12}-[a-z]{2,12}-[a-z]{2,12}$`), so compact QR-friendly bundles omit the 1568-byte ML-KEM blobs.

The bundle has **one** OTPK at a time. The other 9 are kept locally; each new contact request uses a fresh OTPK and rotates the published bundle.

### 2. `whisper://` invite link
Format: `whisper://c/<base58-encoded bundle>`. Base58 alphabet is the Bitcoin/IPFS standard. Parser must verify the Ed25519 bundle signature before accepting; tampered bundles are silently dropped.

### 3. Ratchet-state serialization
On Android the ratchet state is serialized via `RatchetSerializer.serialize(state)` (length-prefixed binary, fields in order: root_key, sending_chain, receiving_chain, sending_pub, sending_priv, receiving_pub, send_msg_num, receive_msg_num, prev_send_len, skipped_count, then `[bytes(hex_pub), int(msg_num), bytes(message_key)]` for each skipped key). For pure desktop interop this format only matters if state is exported between platforms (e.g. backup/restore). Within-device, my Rust `RatchetState` uses `serde` to JSON or bincode — incompatible with the Android format but never crosses the wire.

### 4. Ratchet bootstrap detail
- Initiator (Alice): `DoubleRatchet::initAsInitiator(masterSecret, peerRatchetKey = Bob.spk.x25519_pub)`. Alice's first DH ratchet uses her freshly-generated ratchet keypair against Bob's SPK X25519 — *not* against any ephemeral key.
- Responder (Bob): `DoubleRatchet::initAsResponder(masterSecret, myRatchetKey = Bob.spk.x25519_pair)`. Bob's ratchet keypair is his own SPK; the receiving chain is established when Alice's first message arrives carrying her ephemeral as the "ratchet key."
- After this, both sides ratchet normally.

### 5. Frame accounting nuance
`accounting_response` is **not** counted as a received frame on the client side ("meta-protocol, would always cause a +1 mismatch"). Mirror this on desktop.

### 6. Sentinel digest
Every 10th outbound message attaches a 32-byte SHA-256 digest of the sender's active Sentinel threat types (set by `MessageRepository.sendCounter % 10 == 0`). Desktop ships without Sentinel EDR, so we always send `sentinelDigest = None`. Receiving side just stores it as informational.

### 7. Disappearing timer semantics
Short timers (≤ 1 hour) start on **read** (set `disappearAt` only when message is first displayed). Long timers (> 1 hour) start on **receive** (`disappearAt = now + timer` at insert).

### 8. Message-status state machine
`SENDING → DEPOSITED → DELIVERED → READ`, plus `FAILED` for relay errors. Desktop uses the same column values to keep DB-level interop possible if we ever do cross-device export.

## Things I won't match

- **Sentinel EDR layers 1-6** — desktop ships without; out of scope per the desktop spec.
- **Local SQLCipher schema** — only the schema labels matter inside the desktop binary; rows never leave the device, so we can diverge freely.
- **Prefs storage layout** — Android uses SharedPreferences XML; desktop uses macOS Keychain + sandboxed plist. No reason to keep these compatible.

## Verification plan

Once the desktop client has identity generation + ratchet wired end-to-end, write a cross-platform test fixture:

1. Generate a deterministic identity from a fixed PRNG seed on Android, dump bundle + ratchet state to JSON.
2. Replay on desktop, confirm alias, safety numbers, hex fingerprint, and mailbox addresses byte-match.
3. Have Android Alice send a known plaintext to desktop Bob via the dev relay and round-trip it back.

Test vectors should live in a shared `interop/` directory committed to both repos.
