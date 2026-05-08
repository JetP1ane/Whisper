# Noctis Whisper - Lite Paper

A private, post-quantum, peer-to-peer messenger.
*One-pass overview. The full architecture lives in [WHITEPAPER.md](WHITEPAPER.md).*

---

## In one paragraph

Whisper is a desktop messenger with three properties most messengers do not combine: there is no server we operate, the network transport obscures who is talking to whom - not just what they are saying - and the cryptography is hybrid post-quantum, protecting today's traffic against future quantum-capable adversaries. Message contents leave the device only after end-to-end encryption, and the local vault is protected by SQLCipher with key material bound to your Mac's Secure-Enclave-backed Keychain. The transport runs over I2P, chosen because its bidirectional hidden-destination model and garlic routing fit peer-to-peer chat better than traditional client/server anonymity networks.

---

## Why this is different from normal E2EE messengers

Most end-to-end encrypted messengers protect message contents but still rely on provider-operated infrastructure for account discovery, push delivery, relays, abuse systems, or message queues. Whisper removes the operator from the delivery path entirely. The trade-off is that delivery depends on I2P availability, peer reachability, and local device state - there is no server to hold a message until you next come online, only a peer-to-peer retry queue on each side.

---

## How a message travels

```
   [ Alice's plaintext ]
            |
            |  [1] AEAD encrypt with ChaCha20-Poly1305
            |  [2] key from Double Ratchet (PQ-X3DH bootstrap)
            v
   [ ratchet ciphertext ]
            |
            |  [3] bundle into a garlic message, send through tunnels
            v
   [ Alice's hop 1 ]
            |
            v
   [ Alice's hop 2 ]
            |
            v
   [ Bob's hop 1 ]
            |
            v
   [ Bob's hop 2 ]
            |
            v
   [ ratchet ciphertext (now at Bob) ]
            |
            |  [5] decrypt under Bob's ratchet state
            v
   [ Bob's plaintext ]

   [4] Each hop strips one layer of encryption. No single hop
       knows both Alice's identity and Bob's identity.
```

**Five steps, four protections.**

| Step | Layer | What protects this |
|------|-------|--------------------|
| [1]  encrypt | ChaCha20-Poly1305 (AEAD) | symmetric ciphertext + auth tag |
| [2]  key agreement | PQ-X3DH (X25519 + ML-KEM-1024 hybrid) | hybrid post-quantum - an attacker must break **both** the classical and post-quantum legs to recover the session secret |
| [3]  forward route | I2P garlic routing through 2 hops | sender-side anonymity, no exit-node visibility |
| [4]  in transit | 4 hops total, each peels one layer | no single router sees both endpoints |
| [5]  decrypt | Double Ratchet | per-message keys; today's compromise doesn't decrypt yesterday |

---

## The four protections

```
+-----------------------------------------------------------------+
| [1] TRANSPORT  -- I2P, 4-hop garlic-routed                      |
|     no central server, no exit nodes, decentralized NetDB       |
|     sender/recipient IPs hidden from any single observer        |
+-----------------------------------------------------------------+
| [2] ENCRYPTION -- PQ-X3DH handshake + Double Ratchet            |
|     hybrid post-quantum; per-message forward secrecy            |
|     ChaCha20-Poly1305 AEAD                                      |
+-----------------------------------------------------------------+
| [3] STORAGE    -- SQLCipher 4 (AES-256-CBC + HMAC-SHA512)       |
|     every database page authenticated                           |
|     per-conversation TEE-encryption layer below SQLCipher       |
+-----------------------------------------------------------------+
| [4] HARDWARE   -- Keychain seed bound to the Secure Enclave     |
|     a cloned disk image cannot decrypt without the original     |
|     Mac's hardware-bound key material                           |
|     Touch ID gates the most sensitive operations                |
+-----------------------------------------------------------------+
                                +
+-----------------------------------------------------------------+
| Hardened Runtime  .  Library validation  .  App Sandbox         |
| i2pd binary SHA-256 pinned  .  CSP locked to self + IPC         |
| Live egress audit (every TCP socket visible to user)            |
+-----------------------------------------------------------------+
```

Each row is independently strong. The combination is what raises the bar.

---

## Why I2P, not Tor

Both networks anonymize traffic. They optimize for different shapes.

```
TOR -- anonymous outbound to public services
--------------------------------------------

   [ you ]
     |
     |  3-hop circuit (entry -> middle -> exit)
     v
   [ exit node ]  -->  [ public server ]
        |
        +-- exit node sees the plaintext destination + payload
            (for non-HTTPS traffic)


I2P -- anonymous between two hidden destinations
------------------------------------------------

   [ Alice ]                                          [ Bob ]
       |                                                 ^
       |  outbound tunnel                                |  inbound tunnel
       |  (2 hops)                                       |  (2 hops)
       v                                                 |
   [ hop A1 ] --> [ hop A2 ] --> [ hop B1 ] --> [ hop B2 ]

   - No exit node; traffic never leaves the I2P overlay
   - No directory authority; NetDB is a gossip-based DHT
   - Both endpoints are hidden destinations, not just one
```

| | Tor | I2P |
|---|---|---|
| Designed for | Outbound browsing | Bidirectional hidden services |
| Exit nodes | Yes (and they see plaintext for non-HTTPS) | None - traffic stays on overlay |
| Routing | One circuit per request | Garlic: many messages bundled per packet |
| Directory | Centralized authorities (~10 nodes) | Decentralized DHT (NetDB) |
| Hidden-service latency | 2-5 s | 0.5-2 s after warmup |

A note on Tor onion services. The diagram above shows Tor's outbound-browsing path with an exit node - that's the most common Tor flow. **Tor onion services do not use exit nodes**; traffic between two `.onion` peers stays inside the network. So the exit-node concern doesn't apply to onion-to-onion chat specifically. The deeper point is structural: Tor onion services were added to a network originally optimized around the anonymous-client / public-server case, while I2P was designed from day one for bidirectional hidden destinations. Whisper's traffic shape - peer-to-peer between two hidden destinations - is the shape I2P was built around.

For chat specifically:

- **Both endpoints want anonymity, not just one.** I2P treats both sides identically. Both have outbound and inbound tunnels, both publish hidden leasesets.
- **Chat traffic is bursty and small.** Garlic routing batches multiple frames per packet; a better fit than per-request circuits.
- **No central directory.** The I2P NetDB is a gossip-based DHT. There is no equivalent of Tor's directory authorities to subpoena for a global view of users.

Tor remains excellent for what it was built for. Whisper just doesn't have that shape of problem.

---

## Identity in a sentence

A user is an Ed25519 keypair. Its public key produces a deterministic three-word **Whisper ID** alias (`patrol-ozone-brick`-style) and a 60-digit **safety number** for verification. The 12-word recovery phrase is the only way to reproduce this identity on a new device - so guard it like a hardware key.

You add contacts by exchanging a `whisper://` link out-of-band - in person, via QR, or through a channel you trust. Each link is a signed bundle and is single-use: the OTPK it embeds is consumed by the first peer to complete the handshake. **If you want to add multiple contacts, mint a fresh link for each person** - sharing the same link with several people will only pair the first one.

---

## What's protected, and what isn't

**Strong (cryptographic):** message confidentiality and integrity, replay resistance on the X3DH handshake, forward secrecy after each ratchet step, authenticated at-rest storage, signature unforgeability on bundles. All conditional on the primitives being secure (X25519, ML-KEM-1024, Ed25519, ChaCha20-Poly1305) and the implementation being correct.

**True by design (architectural):** no central server, no operator-controlled directory, message plaintext is never sent over the network (contents leave the device only after end-to-end encryption), app is sandboxed and binary-pinned, every outbound socket from the Whisper process is visible in the UI.

**Best-effort (network-dependent):** IP-level metadata privacy via I2P (resists casual traffic analysis but not a global passive adversary), 0.5-2 s typical message latency after warmup, 30-day persistent retry queue for offline peers.

**Explicitly out of scope:**

- Concealing that you are using *some* I2P-based application (your ISP can see I2P traffic patterns).
- Defending against on-device kernel compromise (keys are in RAM during a session).
- Restoring message history from a recovery phrase (history is local-only by design).
- Group-message security after a member is removed (sender-key model retains revoked members' decryption ability - rooms are append-only by design).
- Resistance to a global passive adversary observing every peering point.

The full whitepaper has a tier-by-tier breakdown of each.

---

## The architecture in one picture

```
+-----------------------------------------------------------------+
|                       WHISPER (your Mac)                        |
|                                                                 |
|  +-----------------------------------------------------------+  |
|  |  React UI  --IPC-->  Rust core                            |  |
|  |                       - PQ-X3DH + Double Ratchet          |  |
|  |                       - Sender-key engine (rooms)         |  |
|  |                       - SQLCipher 4 vault                 |  |
|  |                                                           |  |
|  |  Argon2id(passphrase) --> DEK --> HKDF(DEK, kc seed)      |  |
|  |                                            |              |  |
|  |                       +--------------------+              |  |
|  |                       |                                   |  |
|  |               +-------v---------------------+             |  |
|  |               |  Login Keychain             |             |  |
|  |               |  (master key SE-bound on    |             |  |
|  |               |   Apple Silicon / T2)       |             |  |
|  |               +-----------------------------+             |  |
|  +--------------------------+--------------------------------+  |
|                             |                                   |
|                             |  SAM v3.3 (loopback)              |
|                             v                                   |
|  +-----------------------------------------------------------+  |
|  |  Bundled i2pd subprocess                                  |  |
|  |   - SHA-256-pinned binary, rejects tampering              |  |
|  |   - Sandboxed, randomized loopback ports                  |  |
|  |   - 2-hop tunnels x 8 inbound + 8 outbound                |  |
|  |   - Encrypted leaseset published to NetDB                 |  |
|  +--------------------------+--------------------------------+  |
+-----------------------------+-----------------------------------+
                              |
                       +------v------+
                       |  I2P MESH   |   <-- 4 hops between peers
                       +------+------+       all garlic-routed
                              |
                  (mirror of the above on Bob's Mac)
```

**At rest:** hardware-anchored Keychain seed → SQLCipher key → encrypted database → per-conversation TEE-encrypted message bodies.
**In flight:** PQ-X3DH bootstrap → Double Ratchet → ChaCha20-Poly1305 → I2P 4-hop garlic.
**Identity:** Ed25519 + X25519 + ML-KEM-1024, BIP39-recoverable.

---

## Read the whitepaper if…

- You want the full prekey lifecycle, async first-message mechanics, and SPK rotation story.
- You want the precise compromise scenarios (seed leaked, device locked, device unlocked, identity rotation).
- You want the architectural-properties / cryptographic-guarantees / best-effort / out-of-scope breakdown.
- You want the candid limits - including where Whisper is weaker than Android's StrongBox or what we don't yet automate.

The full document at [WHITEPAPER.md](WHITEPAPER.md) is built to survive a security review. This lite version is built to give you the shape of the system in five minutes.
