# Noctis Whisper

A private, post-quantum, peer-to-peer messenger.

---

## What it is

Noctis Whisper is a desktop messenger with no central server, hybrid post-quantum end-to-end encryption, and on-device hardware-anchored key storage. It runs on the I2P overlay network: messages traverse a chain of intermediate routers between the two endpoints, so passive network observers see neither message contents nor - under typical conditions - the social graph that most messengers leak.

This document is a description of the architecture, not a security proof. We separate cryptographic guarantees (provable from primitive assumptions and a correct implementation) from architectural properties (true by design, observable in code) from best-effort behaviors (depend on network conditions and resist most but not all adversaries). The boundaries are stated explicitly throughout.

---

## What makes it different

Three architectural choices, taken together, distinguish Whisper from most "private" messengers:

1. **No relay, no directory, no operator infrastructure.** The app does not connect to a server we run. There is no place to subpoena, compromise, or unplug.
2. **The transport layer hides metadata that other E2E messengers leak.** End-to-end encryption protects message contents; the I2P overlay also obscures *who is talking to whom* from passive observers and from any single point of network observation. (This is a meaningful protection, not a perfect one - see *Threat model and limitations*.)
3. **The crypto is hybrid post-quantum.** Today's ciphertexts are protected against an adversary that records traffic now and decrypts decades later when a sufficiently large quantum computer exists.

---

## Identity and prekeys

Each user is a long-term Ed25519 keypair, generated locally during the first-launch BIP39 setup. The 12-word recovery phrase is the seed of an HKDF-driven derivation that produces all long-term identity material on the device. The same phrase, restored on a new device, reproduces the identity bit-for-bit.

The Ed25519 public key produces:

- A **Whisper ID alias** - a deterministic three-word phrase like `patrol-ozone-brick`, derived by indexing the BIP39 word list against `SHA-256(identity_pub)`. The alias is human-readable but not human-chosen, so it cannot be squatted, and every alias maps to exactly one identity key. A fingerprint collision in the alias word-space is approximately 33 bits - useful for casual recognition, **not** sufficient for verification (see *Verification*).
- A **safety-number digit fingerprint**, used for out-of-band verification.

### Prekey lifecycle

X3DH (and our PQ-X3DH extension) requires the recipient to publish prekeys ahead of time so a sender can complete the handshake without an interactive round-trip. With no central server to host these, the prekeys ride **inline inside the recipient's whisper:// invite link** - a Base58-encoded signed bundle the user shares out-of-band.

The bundle published in each link contains:

- **Signed prekey (SPK)** - an X25519 public key plus an ML-KEM-1024 public key, signed by the identity key. Re-used across multiple incoming sessions until rotated (see below).
- **One-time prekey (OTPK)** - a single-use X25519 + ML-KEM keypair. The whisper:// link minted at moment T consumes one OTPK from the local pool and embeds its public component in the bundle. When a remote peer runs X3DH against that link, they reference this specific OTPK by ID, and on the recipient's side it is marked consumed and deleted.

We pre-mint a pool of 20 OTPKs at vault setup; when the count drops below a threshold, the app generates a fresh batch in the background. Generating a new whisper:// link **always** consumes a fresh OTPK - every link is paired with exactly one one-time key.

### Asynchronous first-message mechanics

There is no online responder during X3DH. The handshake happens entirely against the recipient's *bundle*:

1. Alice opens Bob's whisper:// link, deserializes and signature-verifies the bundle.
2. Alice generates an ephemeral X25519 keypair and an ML-KEM-1024 encapsulation against Bob's published SPK + OTPK Kyber keys.
3. Alice mixes the ephemeral and KEM outputs through HKDF-SHA256 into a master secret.
4. Alice sends her first ratchet message wrapped with a session-init blob containing her ephemeral pub keys, KEM ciphertexts, and the OTPK ID she consumed.
5. Bob receives the wrapped first message at any later time, looks up the OTPK by ID in his local DB (it is still there until consumed), and runs the responder side of PQ-X3DH to derive the same master secret.

The OTPK is then deleted on Bob's side.

**Invite links are single-use by design.** Every whisper:// link embeds exactly one OTPK. If the same link is shared with multiple people - e.g., posted in a group chat, screenshotted and forwarded - only the first peer to successfully complete the X3DH handshake consumes the embedded OTPK. Subsequent peers who try the same link will run their initiator side successfully but Bob's responder will fail to find the OTPK secret, and no session is established. The user-visible mitigation is to mint a fresh link per recipient; the app does not currently warn on this case, which is a known UX gap.

**Retransmission of the same first message is distinct from replay.** When Alice's first message reaches Bob, Bob runs the responder bootstrap, decrypts the message, and records the SHA-256 hash of the deposited blob alongside the persisted message. A duplicate of the same first message - for example, retransmitted by the send queue when the original delivery times out - matches the recorded hash at the dispatch layer and is treated idempotently: Bob re-emits the delivery receipt without re-running the responder bootstrap. The bootstrap would error in any case, because the consumed OTPK's secret blob has been zeroed in place and is no longer usable. An attacker replaying a *different* peer's first message against Bob - or replaying Alice's first message before Bob has ever seen it - matches no recorded hash, falls through to the responder bootstrap, and fails at the consumed-OTPK check. Honest retransmission converges on the previously delivered state via the wire-blob hash; replay does not.

### Signed prekey rotation

The schema supports SPK versioning (`signed_prekeys.id`, `rotated_at`); the SPK in any new whisper:// link reflects whichever SPK is currently active. Periodic SPK rotation is a planned operation but not currently automated - at present the SPK rotates only when the user manually re-mints their identity. We document the gap honestly and flag it as a limitation: a user with a static SPK enjoys slightly weaker forward secrecy on the X3DH handshake itself than one rotating SPKs every few weeks. The Double Ratchet's per-message rotation is unaffected - that's where the bulk of the forward-secrecy guarantee actually comes from.

---

## Encryption layer

Every conversation is protected by a **PQ-X3DH key agreement** followed by a **Double Ratchet** for ongoing message-by-message rekeying.

### Key agreement: PQ-X3DH

X3DH is Signal's well-studied initial handshake. We extend it with **ML-KEM-1024**, the NIST-standardized lattice-based key encapsulation mechanism (formerly Kyber):

- The classical X25519 ECDH legs run unchanged.
- A parallel ML-KEM-1024 encapsulation runs against the recipient's published Kyber public key.
- Both shared secrets are mixed into the Double Ratchet's root key via HKDF-SHA256.

This is a **hybrid** construction - the master secret is safe as long as either X25519 *or* ML-KEM-1024 holds. An adversary capturing today's traffic and breaking elliptic-curve cryptography in 2040 still gets nothing without also breaking the lattice.

### Per-message keys: Double Ratchet

Subsequent messages use Signal's Double Ratchet. Each message advances a chain key (HKDF-SHA256). Each pair-of-direction-changes advances the root key by a fresh Diffie-Hellman ratchet step. This produces:

- **Forward secrecy.** Past chain keys are deleted as they advance; compromise of today's session keys does not retroactively decrypt yesterday's messages, provided the deleted keys are not recoverable from the device's storage.
- **Future secrecy (post-compromise security).** A snapshot of an active session does not by itself yield future messages - the next DH ratchet step advances the root and heals the chain, *if and only if* the compromise is one-time. Continuous attacker presence in the session defeats this.

### Symmetric AEAD: ChaCha20-Poly1305

Message ciphertext is encrypted under a chain-derived key with **ChaCha20-Poly1305**, a high-margin AEAD with 256-bit symmetric security (128-bit residual security against quantum search per Grover, comfortably above the 2030 NIST recommendation).

---

## Group chats

Rooms use a **sender-key** model. Each member generates a chain seed, encrypts their own messages with their own chain (advancing per message, HKDF-SHA256), and shares their seed with every other member via the pairwise Double Ratchet established above. Only the sender's chain seed is needed to decrypt their messages. There is no shared group key.

The bootstrap of pairwise channels uses **deterministic X3DH role assignment**: the member with the smaller Ed25519 public key initiates; the larger waits and runs responder X3DH on the first message that arrives. This avoids the simultaneous-initiate race where both sides produce different master secrets and silently desync.

### Membership changes and rekeying

Group membership changes have two axes worth being explicit about.

**Adding a member to an existing room.** The owner mints a fresh `RoomInvite` envelope containing every member's bundle (including the new member's) and sends it to the new joiner over their pairwise channel. The new member auto-persists every other member as a contact, broadcasts their own sender-key seed via the pairwise channels, and existing members receive that seed via the smaller-pubkey-initiates handshake described above.

**Removing a member.** This is where the sender-key model trades simplicity for an explicit limitation: **the current build does not automatically rekey on removal.** A removed member retains the chain seeds of everyone else in the room, which means they can continue decrypting future room messages until every remaining member generates a fresh chain seed and re-broadcasts.

Two consequences:

1. The product UI does not currently expose a "remove member" action. A room is effectively append-only by design choice - we'd rather not ship a button whose effect is partial.
2. If a participant's device is lost or known-compromised, the practical recovery is to abandon the room and create a new one with fresh seeds among the trusted subset. The rooms feature is appropriate for collaboration among parties whose trust is stable for the room's lifetime; it is not appropriate when membership is expected to churn under adversarial conditions. This trade-off is the same one Signal made before MLS; a future MLS-based group protocol would address it but adds substantial complexity that we have not yet committed to.

The sender-key model itself is well-suited to chat (no per-message group key agreement, simple offline catch-up). The limitation is the membership-revocation story, not the per-message security.

---

## At-rest protection

Three layers protect the local database.

### Layer 1: SQLCipher 4

The database file is encrypted by SQLCipher 4 with **AES-256-CBC**, with a **per-page HMAC-SHA512** providing authenticated encryption at the page granularity. Each 4 KB page has an independent IV and HMAC tag, so substitution or corruption of any single page is detectable on read.

We bypass SQLCipher's built-in PBKDF2 by passing a pre-derived 32-byte raw key via `PRAGMA key = "x'<hex>'"`. The key path is:

```
user passphrase
  → Argon2id (memory-hard, ~256 MiB / 3 iter)
    → vault-key (32 B)
      → unwraps the sealed DEK from the local macOS Keychain blob
        → DEK (32 B)
          → HKDF mixing with the hardware-anchored Keychain seed
            → final SQLCipher key (32 B)
```

The hardware-anchored seed is what makes a cloned disk insufficient on its own: a different device's filesystem does not contain the local user's Keychain in a form that the new device's hardware can decrypt.

### Layer 2: Hardware-anchored Keychain seed

A 32-byte random seed is stored in the macOS login Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. **What this is and isn't, precisely:**

- The seed is a symmetric byte value stored as a Keychain item. It is **not** an opaque SE key handle. When the app needs it, the Keychain returns the 32 plaintext bytes into the app's process memory.
- On Apple Silicon and T2 Macs, the **Keychain's** master encryption key is itself bound to the Secure Enclave. That is what makes the Keychain blob unrecoverable from a stolen disk image without the original hardware. The seed inherits this protection at rest, not in use.
- During an unlocked-vault session the seed lives in process memory (cached for performance), so an attacker with code-execution on the running process can read it. The same is true of every other key the app actively uses - this is normal in any Keychain-based design and not specific to Whisper.
- We never claim, and the implementation does not provide, "the seed never leaves the chip." It leaves the Keychain into RAM the first time the vault is unlocked. What the design provides is **hardware-bound key storage at rest** - strong protection against off-device disk attacks, not a protection against compromise of the live process.

This is the conventional macOS pattern for app-side key storage. It is weaker than Android's StrongBox or iOS's hardware-key cryptographic operations (which expose only opaque handles), and the Rust module that implements it is candid about that fact.

In practice, the protection adds up to:

- **Disk clone (Time Machine, forensic image, cloud backup)** - cannot decrypt the database. The Keychain blob is encrypted by a key that is itself hardware-bound on the original device.
- **Disk clone + guessed vault passphrase** - still cannot decrypt. The Argon2id-derived vault-key is one ingredient; the Keychain seed is another, and that one is on hardware the attacker doesn't have.
- **Original device stolen, locked** - protection depends on macOS account security, FileVault, Keychain access control, biometric/passcode policy, and the vault passphrase. The Whisper-specific portion of this stack guarantees that brute-forcing the vault passphrase against a captured database file from a *different* device is fruitless. On the *original* device the attacker has the hardware that will participate in the unwrap, so the chain is only as strong as the next link up - macOS account password and the vault passphrase are both required.
- **Original device stolen, unlocked** - keys are in RAM. `⌘L` (lock vault) clears them and seals the database; until then the messaging session is fully accessible.

### Layer 3: Per-conversation TEE keys (biometric-gated)

A second Keychain seed, fronted by `SecAccessControl(.biometryCurrentSet, .userPresence)`, gates the per-conversation message-body key. **This** is the Touch-ID-protected path: every retrieval of the sealed seed prompts the user. Even on the original device, even with macOS unlocked, even with the vault unlocked, sensitive operations (reading the recovery phrase, viewing safety numbers) require a fresh biometric. The seed is still a symmetric value that lands in process memory after the prompt succeeds - but the gate is per-operation, not per-session.

This layer is defense-in-depth: it means a malicious process that somehow joined an active vault session still cannot trigger the operations that matter most without a user-visible biometric prompt the user can refuse.

---

## Transport: I2P, not Tor

Whisper does not connect to a server. Both endpoints exist on the I2P overlay as **destinations** - cryptographic identifiers (~516-byte base64 strings) bound to a router that holds an inbound tunnel to the destination. Sending a message means encrypting it under the recipient's destination keys, garlic-routing it through your outbound tunnel, and watching it traverse 2-3 more hops on the recipient's side before they decrypt it.

### Why I2P, not Tor

Tor is excellent. It's designed for a different problem.

| | Tor | I2P |
|---|---|---|
| Original design goal | Anonymous outbound browsing | Anonymous bidirectional services |
| Hidden services | Onion services added to a network originally optimized for anonymous client-to-public-server browsing | Hidden destinations are the primary concept (no separate "client" vs "service" mode) |
| Routing pattern | Single circuit per request | Garlic: multiple messages per onion bundle |
| Directory model | Centralized authorities (~10 nodes) | Decentralized DHT (NetDB) |
| Network role | Most users only consume bandwidth | Every router contributes (opt-in transit) |
| Typical end-to-end latency for hidden services | 2-5 s | 0.5-2 s after tunnel warmup |
| Exit nodes | Yes (and they see plaintext for non-HTTPS) | None - traffic stays on overlay |

For chat, two of these matter most:

1. **Bidirectional symmetry.** Both endpoints need to be reachable, and both want anonymity. Tor's strength is the asymmetric case (anonymous client, public server). I2P treats both sides identically.
2. **Latency under load.** Garlic routing batches multiple frames per onion, which suits the small-frequent-message pattern of chat better than Tor's per-request circuits. After our pre-warming task primes the leaseset cache, typical message latency on Whisper is 800ms-2s.

A subtler win: I2P's **decentralized NetDB** means there is no list of "I2P directory authorities" an adversary could subpoena to enumerate routers globally. Tor's directory consensus is public (by necessary design - that's how clients agree on relays); I2P leaks no equivalent authoritative global view. This is not zero-leakage - see *Limitations* - but it raises the bar.

### What we ship

The app bundles `i2pd` v2.60 (the C++ I2P daemon) inside `Contents/Resources/i2pd-bundle/`. On launch:

- We verify the bundled binary's SHA-256 against a pin embedded at build time.
- We spawn `i2pd` as a sandboxed subprocess on randomized loopback ports.
- We open a SAM (Simple Anonymous Messaging) session against the local daemon.
- We mint or load the user's persistent destination keypair from the encrypted DB.

Each instance has its own isolated I2P router, with its own NetDB cache, its own tunnels, its own leaseset.

### Tunnel parameters

We negotiate **2-hop tunnels in each direction**, with **8 inbound + 8 outbound** tunnels per pool. End-to-end, a message traverses 4 routers (2 outbound on the sender, 2 inbound on the recipient), each performing one layer of garlic decryption. The 8/8 pool size gives substantial resilience: if one router slows, the next send picks a different tunnel automatically.

### Pre-warming and durability

Two background tasks shape the experience:

- **Leaseset pre-warm** - every 3 minutes, the app opens a brief stream to each known contact's destination, refreshing their leaseset in our local NetDB.
- **Persistent send queue** - outbound messages that fail (peer offline, transient tunnel error) are persisted in an encrypted queue and retried on a backoff schedule for up to 30 days.

---

## Bootstrap and verification

Whisper IDs are exchanged via **whisper:// links** - Base58-encoded signed bundles containing identity key + prekeys + I2P destination + alias. The link is shared out-of-band.

Two cryptographic invariants are enforced when a link is added:

1. **Bundle signature verification.** The bundle is signed by the identity key it contains.
2. **Alias-key binding.** The alias is the deterministic BIP39 derivation of the identity key. A bundle that claims a different alias than its identity key produces is rejected.

But the **channel that delivered the link** can still be adversarial. If alice sends bob a whisper:// link via a service the attacker controls, the attacker could replace the link with one of their own bundles. The signed bundle is internally consistent, the alias-key binding holds - but the alias is the attacker's, not alice's.

This is where **safety numbers** come in. The Verification section of the contact's info panel shows a 60-digit fingerprint derived from both parties' identity keys. Reading those digits aloud over a phone call you trust - or comparing in person - confirms with cryptographic certainty that the keys both sides hold are unmodified. Marking the contact verified records that comparison locally; if either side later shows a different safety number, the UI flags the discrepancy.

This is the same MITM defense Signal uses, applied to the same kind of attack.

---

## Compromise scenarios and key rotation

Specific failure cases, with what is and is not recoverable.

**Recovery phrase leaked, device intact.** An attacker with the 12-word phrase can re-derive the same identity keys on a new device. They cannot decrypt the original device's database (the SQLCipher key path requires the original device's SE seed, which is hardware-bound). They can attempt to re-pair as the user with the user's contacts, but contacts who have safety-number-verified the original keypair will see no change in the safety number - the attacker holds the same keys, but they hold them on a different device. There is no built-in "this identity moved" notification; the next message both devices send will simply confuse the recipient until one of them stops.

The mitigation is to treat the recovery phrase like a password: store it offline, do not photograph it, do not paste it anywhere a clipboard manager will retain it.

**Device stolen while locked.** Two distinct cases:

- *Disk image only* (Time Machine, forensic image, cloud backup, cloned drive in another machine). A guessed vault passphrase is insufficient because the hardware-anchored Keychain seed is not present in the cloned filesystem in a usable form - it is encrypted by a key that is itself hardware-bound on the original device.
- *Original physical device, attacker has hands on it.* The Keychain seed will participate in the unwrap on the original hardware once macOS is unlocked. Protection in this case depends on the layers macOS provides in front of the Keychain: account login security (FileVault, login password, lockout), Keychain access control on the specific items, biometric or passcode policy on the device, **and** the Whisper vault passphrase (Argon2id, ~256 MiB / 3 iter). Whisper hardens its own slice of the chain; it relies on the OS for the rest. A recovered device with a weak macOS password or no FileVault is, in practice, a different and broader threat than what any application-layer defense can carry alone.

**Device stolen while unlocked.** All current-session keys are in process memory. Past messages persisted to disk are accessible until the vault is locked. Forward secrecy of older messages depends on whether their per-message ratchet keys have already advanced past - they have, so messages with chain index ≪ current index cannot be decrypted from in-memory state alone, but the database holds the ratchet root key from which past chain keys can be re-derived if the attacker reads them out before the user notices. The mitigation is `⌘L` (lock vault) immediately on any incident, which clears in-memory keys and seals the database.

**Identity key compromise.** Identity keys are not currently rotatable in the app - the BIP39 phrase produces them deterministically, and there's no in-app "rotate identity" action. A user who suspects their identity is compromised must mint a new vault from a fresh phrase and notify contacts to re-pair. This is a known gap and an explicit roadmap item; for now, users with high-stakes threat models should treat the seed phrase with the same operational discipline as a hardware-backed PGP key.

**Signed prekey compromise.** SPKs can be rotated by re-publishing the bundle (the schema supports versioning by `signed_prekeys.id`); we do not currently rotate them automatically. The Double Ratchet's per-message rotation is unaffected and continues to provide forward secrecy on the message stream, regardless of SPK age.

**One-time prekey leak before consumption.** If a whisper:// link is observed but never used, the OTPK it carries is sitting in the user's database awaiting consumption. An attacker who steals the OTPK secret could mount one X3DH responder run against an unsuspecting initiator - but they would also need the SPK secret, the identity key secret, and the X25519 secret, none of which travel with the link. A leaked OTPK alone is insufficient.

---

## Hardening the binary

Cryptography only matters if the binary running it isn't compromised. Whisper applies the standard macOS hardening stack:

- **Hardened Runtime + library validation.** Only Apple-signed dylibs or dylibs signed under our Team ID can load. `DYLD_INSERT_LIBRARIES`-style injection is blocked at the OS level.
- **App Sandbox.** Filesystem access is namespaced to `~/Library/Containers/com.noctisprivacy.whisper/Data/`.
- **Hardened Runtime entitlements** - `allow-jit`, `allow-unsigned-executable-memory`, `disable-library-validation`, `allow-dyld-environment-variables`, `disable-executable-page-protection`, and `debugger` are all explicitly **denied**.
- **Bundled `i2pd` SHA-256 pin.** A swapped binary refuses to start.
- **Webview CSP.** Locked to `connect-src 'self' ipc:` - no outbound HTTP from the UI is possible.
- **Live egress audit.** Settings → Security exposes a panel that enumerates every TCP socket the Whisper process holds open, classified expected/unexpected. The user can verify in real time that nothing is phoning home.

---

## Threat model and limitations

Honest claims, separated by the strength of the guarantee.

### Cryptographic guarantees (strong, conditional on primitives + correct implementation)

- Message confidentiality against any party other than sender and intended recipient(s), assuming the security of ChaCha20-Poly1305, X25519, ML-KEM-1024, Ed25519, and HKDF-SHA256.
- Forward secrecy on per-message keys after they advance (Double Ratchet).
- Replay-resistance on the X3DH handshake (one-time prekeys are consumed and deleted).
- Authenticity of bundle contents via Ed25519 signatures.
- Authenticated, encrypted at-rest storage (SQLCipher AES-256-CBC + per-page HMAC-SHA512), conditional on the SQLCipher key remaining secret - which in turn is conditional on the Secure Enclave operating as documented.

### Architectural properties (true by design, observable in code)

- No central server. The application has no networked dependency we operate. The egress audit panel in Settings → Security empirically verifies that every TCP connection from the process is to the local I2P bridge.
- Bundled `i2pd` integrity-pinned at runtime; tampered binaries refuse to start.
- App sandboxed; library validation enforced; CSP locks the webview to local IPC.
- Raw identity private keys are not exported by the app and are stored only inside the encrypted local vault. The recovery phrase can deterministically recreate them on a new device, so the seed phrase itself is the export channel and must be protected accordingly.

### Best-effort properties (typical-case true, adversary-dependent)

- IP-level metadata privacy. The I2P overlay hides the source/destination IP correlation from passive observers and from any single point on the path. A well-resourced adversary observing many peering points across a wide area, or an attacker who controls a non-trivial fraction of I2P routers, can probabilistically infer relationships through traffic-volume and timing correlation. We inherit I2P's anonymity properties, including their limits.
- Resilience against active disruption. I2P's tunnel-build process and 8/8 tunnel pool tolerate single-router failure well; coordinated denial against a specific destination is harder to mitigate.
- Delivery latency. Typical 0.5-2 s after warmup; cold-start delivery (fresh leaseset lookup + tunnel build) can take 5-30 s and is logged honestly in the bubble's status text rather than disguised.

### Out of scope (explicit non-promises)

- We do not promise deniability that you are running an I2P-based application. Your ISP can observe that you are connected to the I2P network. They cannot see what you are saying or to whom, but the network-fingerprint of *some* I2P client traffic is observable.
- We do not promise protection against on-device kernel compromise. Keys are in RAM during a session.
- We do not promise message-history portability across recovery. Restoring from the BIP39 phrase rebuilds your identity but not your past conversations - by design, since transferring that history would imply an off-device backup that itself becomes a target.
- We do not promise group-message security after a member is removed. The current sender-key model retains the removed member's ability to decrypt messages encrypted under chains they previously learned. The product avoids this by making rooms append-only at the UI layer; the cryptographic gap remains.
- We do not promise resistance to a global passive adversary. Tor doesn't either; nor does any non-mixnet messenger. If your adversary can observe the entire internet, you need a different tool.
- We do not promise quantum-safety against future cryptanalysis of ML-KEM. The hybrid construction means an attack on either X25519 or ML-KEM still leaves the other intact, but a simultaneous break of both - cryptographically unlikely, given they rest on entirely different hard problems - would compromise sessions.

---

## Architecture, end-to-end

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Whisper Desktop                              │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  React UI                                                       │  │
│  │  ↓ Tauri IPC (CSP-locked, self+ipc only)                        │  │
│  │  Rust core                                                      │  │
│  │   • Identity, Double Ratchet, PQ-X3DH                           │  │
│  │   • Sender-key engine (rooms)                                   │  │
│  │   • SQLCipher 4 database                                        │  │
│  │     AES-256-CBC + page-level HMAC-SHA512                        │  │
│  │     Argon2id(passphrase) → DEK → HKDF(DEK, SE-seed) → key       │  │
│  │   • Per-conversation TEE-encrypted message bodies               │  │
│  │   • I2P send queue + leaseset prewarm + ACK gate                │  │
│  └─────────────────┬──────────────────────────────────────────────┘  │
│                    │ SAM v3.3 over loopback                            │
│  ┌─────────────────▼──────────────────────────────────────────────┐  │
│  │  i2pd subprocess (sandboxed, SHA-256 pinned)                   │  │
│  │   • 2-hop tunnels × 8 in / 8 out                               │  │
│  │   • Encrypted leaseset published to NetDB                       │  │
│  │   • Garlic-routed message bundles                               │  │
│  └─────────────────┬──────────────────────────────────────────────┘  │
│                    │                                                   │
│              ┌─────▼─────┐                                             │
│              │ I2P Mesh  │  ← 4 hops between peers, all garlic-routed │
│              └─────┬─────┘                                             │
│                    │                                                   │
│         (mirror of the above on the recipient)                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Closing

Whisper is not trying to be the most popular messenger. It is trying to be the one whose architecture you can audit end-to-end, whose privacy guarantees survive a sophisticated but realistic adversary, and whose limits are stated plainly enough to evaluate fitness for a specific threat model.

The architecture rests on four pillars:

1. Standard, well-studied cryptographic primitives (Signal protocol family + NIST PQ standardization).
2. A transport whose anonymity properties are independent of any operator (I2P).
3. Hardware-anchored key storage on most modern Apple devices (Secure Enclave).
4. Honest scope: explicit guarantees, explicit limits, explicit threat-model boundaries.

Each pillar can be evaluated on its own. The combination is what makes Whisper a privacy-architecture decision rather than a privacy-marketing one.
