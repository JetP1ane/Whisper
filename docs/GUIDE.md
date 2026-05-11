# Whisper User Guide

This is the operational guide. Read it for *how to use* Whisper. For
the architecture and the threat model, see
[`WHITEPAPER.md`](../WHITEPAPER.md); for the condensed pitch see
[`LITEPAPER.md`](../LITEPAPER.md).

---

## Install

```sh
brew install --cask jetp1ane/noctis-whisper/noctis-whisper
```

Apple Silicon, macOS 12+. The cask is signed with an Apple Developer
ID and notarized by Apple, so Gatekeeper opens the app cleanly with no
"unidentified developer" warning. Direct `.dmg` downloads from the
[Releases page](https://github.com/JetP1ane/Whisper/releases) work too.

---

## First-time setup

When you launch Whisper for the first time you'll walk through three
steps, in order.

### 1. Choose a vault passphrase

Your passphrase encrypts the local database. It is **not** recoverable
- if you forget it, the only way back into your account is the
recovery phrase from step 3, which wipes the local message history
and rebuilds your identity from scratch.

Pick something long. Whisper runs Argon2id with ~256 MiB of memory
and 4 iterations against the passphrase, so even a relatively simple
phrase is computationally expensive to brute-force - but a *short*
passphrase is short regardless of how slow the derivation is. A
sentence you'd remember anyway is a good starting point.

### 2. Whisper ID alias

Your identity is an Ed25519 keypair generated locally. From its public
key, Whisper deterministically derives a **three-word alias** like
`shaft-tent-quarter`. The alias is human-readable but not
human-chosen: it cannot be squatted, and every alias maps to exactly
one identity key.

You can't change the alias without minting a new identity. Share it
along with whisper:// links so contacts can sanity-check that the link
they got matches the alias you told them.

### 3. Recovery phrase

You'll see a 12-word recovery phrase. **Write it down on paper or
store it in a hardware password manager.** Don't screenshot it. Don't
email it to yourself. Don't store it in iCloud Notes.

What the phrase does:

- It re-derives your Whisper ID and identity keys on a different
  device, in case this one is lost.
- It does **not** restore message history. Local message history is
  local-only by design.
- It is **not** a multi-device sync mechanism. See [Moving to a new
  device](#moving-to-a-new-device-or-recovering-from-a-loss) below.

Anyone who reads this phrase can take over your account. Treat it like
a hardware key, not like a backup.

---

## Adding a contact

Contacts are added via **whisper:// links**, not by usernames or
account searches. There is no global directory to look people up in.

### How it works

To add Bob:

1. Bob taps the `+` next to **Direct Messages** in his app and copies
   the `whisper://...` link Whisper generates.
2. Bob shares the link with you over a channel you trust - text
   message, encrypted email, in person, QR code.
3. You paste the link into your `+` dialog. Whisper verifies the
   bundle's signature, derives Bob's alias from his identity key, and
   adds him as a contact.
4. To send messages back, you mint your own link the same way and
   send it to Bob.

After both sides have added each other, messages flow.

### Why links are single-use

Each whisper:// link contains a one-time prekey (OTPK). The first
person to use the link to complete the handshake consumes the OTPK.
If you share the same link with a second person, they will appear to
add you successfully but their messages will never arrive - Whisper
on your side has no OTPK left to complete their bootstrap.

**Mint a fresh link for each person.** This is intentional and
non-negotiable: it's the property that prevents an attacker who
intercepts your link from using it after the legitimate recipient has
already used it.

### Verifying a contact

Two cryptographic checks happen automatically every time a link is
imported:

- The bundle's signature has to verify against the identity key it
  carries.
- The alias has to be the deterministic derivation of that identity
  key. A bundle that *claims* to be `patrol-ozone-brick` but whose
  identity key derives a different alias is rejected.

These prevent forgery but they cannot prevent a man-in-the-middle on
the channel that delivered the link. If an attacker substituted Bob's
link with one of their own, Whisper would happily import the
attacker's bundle as a *correctly signed identity* - just not Bob's.

For that case, use **safety numbers**. Open the contact's info panel,
tap **Verification**, and read the 60-digit fingerprint aloud over a
phone call you trust, or compare in person. If both sides see the
same safety number, the keys you each hold are unmodified. Mark the
contact as verified once you've confirmed.

You can chat with an unverified contact - Whisper will not block
that - but anything sensitive should wait until verification.

---

## Sending messages

### Direct messages

Type, hit Enter. The message bubble shows one of:

| Indicator | Meaning |
|---|---|
| (no badge) | Sending |
| Single check | Delivered to the recipient's device |
| (red banner) | Delivery failed - Whisper will retry on a backoff for up to 30 days |

The retry queue is persistent and survives app restarts and reboots.
If your contact comes back online a week from now, queued messages
will deliver then.

### Rooms

Rooms are group conversations. Each member encrypts their own
messages with their own chain key and shares that chain seed with
every other member via the pairwise channel established when they
added each other.

Two consequences worth understanding:

1. **Rooms are append-only by design.** There is no "remove member"
   button because removal requires every remaining member to rotate
   their chain keys, and a partial removal would still let the
   removed member decrypt future messages encrypted under chain keys
   they already have. If you need to drop someone, the practical
   recovery is to abandon the room and create a new one with fresh
   keys among the trusted members.
2. **Adding a member to an existing room** is fine. The new member
   auto-pairs with everyone else, and chain keys flow over the
   pairwise channels.

If membership churn is expected under adversarial conditions, rooms
are the wrong tool - use direct messages.

---

## Status indicators

Whisper shows network state in the top bar.

| State | Meaning | Expected duration |
|---|---|---|
| `i2p starting…` | The bundled `i2pd` subprocess is booting. | ~5-30 s on a fresh datadir, ~1-3 s on warm restarts |
| `Still connecting…` | I2P router is up; tunnels and leasesets are still building. | up to a minute or two on cold start; should not persist past ~3 min |
| `Connected` | Tunnels built, leaseset published, ready to send and receive. | normal operating state |

If `Still connecting…` persists indefinitely, see [App stuck on "Still
connecting"](#app-stuck-on-still-connecting) under troubleshooting.

---

## Using your own I2P router (advanced)

By default Whisper spawns its own i2pd subprocess inside the .app bundle.
That router is SHA-256 pinned (mismatches refuse to start), signed
alongside the rest of the app with our Apple Developer ID, and runs
under macOS Hardened Runtime + App Sandbox. For most users, that's the
right choice and you can ignore this section.

If you already run an I2P router yourself (i2pd via Homebrew, or Java
I2P) and want Whisper to share its NetDB, tunnels, and reseed state
instead of running a second router alongside it, you can point Whisper
at your router's SAM v3 bridge.

### Trust framing, plainly

The bundled router lives inside Whisper's trust boundary: every byte
is integrity-checked at launch, every dylib it loads is signed under
the same Developer ID, the subprocess is sandboxed and reaped on
shutdown.

The external option lives outside that boundary. Whisper can only
vouch for the SAM messages it sends and receives over the socket you
configure, and for the end-to-end E2E encryption inside those
messages. **It cannot vouch for your router's binary, its config, its
peer selection, its NetDB state, or any other transit-layer
behavior.** You're substituting your trust assumptions for Whisper's.

That's a fine choice if you're a privacy-conscious user who builds
their own router or audits their config carefully. It's a poor choice
if you're just clicking through settings without a reason.

### Setup with Homebrew i2pd

The fastest way to run an external router on macOS is via Homebrew.

```sh
# 1. Install i2pd
brew install i2pd

# 2. Enable SAM on the default port. Edit /opt/homebrew/etc/i2pd/i2pd.conf,
#    find the [sam] section, and uncomment the lines so it reads:
#
#      [sam]
#      enabled = true
#      address = 127.0.0.1
#      port = 7656
#      portudp = 7655

# 3. Start i2pd as a long-running service
brew services start i2pd

# 4. Verify SAM is up (should return "HELLO REPLY RESULT=OK VERSION=3.3")
printf 'HELLO VERSION MIN=3.0 MAX=3.3\n' | nc -w 3 127.0.0.1 7656
```

If `brew services start` doesn't open the port, run i2pd directly
instead (some macOS launchd plists have quirks):

```sh
/opt/homebrew/opt/i2pd/bin/i2pd \
  --datadir=/opt/homebrew/var/lib/i2pd \
  --conf=/opt/homebrew/etc/i2pd/i2pd.conf \
  --log=file --logfile=/opt/homebrew/var/log/i2pd/i2pd.log &
disown
```

Give i2pd 5-30 seconds on a fresh datadir to reseed and bind SAM.

### Switching Whisper to the external router

1. Open Whisper, unlock your vault.
2. Open **Settings → Security**.
3. Find the **I2P router** card.
4. Check "Use my own I2P router instead of the bundled one."
5. Fill in **Host** (`127.0.0.1` if your router is on the same Mac) and
   **Port** (`7656` for the i2pd default).
6. Click **Test connection**. Expect "✓ Test succeeded."
7. Click **Save**.
8. Lock the vault (`⌘L`) and unlock it again — this is what triggers
   Whisper to drop the bundled router and connect to yours.

To switch back to the bundled router, untick the same checkbox, click
Save, and lock+unlock.

### What changes when external is active

- The bundled i2pd subprocess does not start at app launch.
- Your I2P destination key is still stored in Whisper's local
  SQLCipher vault; only the *transport router* changes, not your
  identity.
- Existing contacts and message history are unchanged — only the
  route between your destination and the I2P mesh is now via the
  router you operate.
- The integrity pin in Whisper's startup path is skipped (we can't
  pin a binary we don't ship). Your router's integrity is your
  problem.
- Whisper still runs its own SAM session and master STREAM on top of
  your router; the protocol surface is identical.

### Remote routers

Whisper accepts any reachable host, not just loopback. You can point
it at an i2pd running on your LAN, on a Tailscale peer, on a VPS, or
anywhere else you can connect via TCP. **Doing so means exposing SAM
to your network**, which is a meaningful security choice — anyone who
can reach the port can create I2P sessions through your router. Only
do this when the network path is one you control and the routing
gain outweighs the exposure.

### When to use the recovery phrase

- This Mac is lost, broken, or being decommissioned and you want to
  restore your Whisper identity on a replacement.
- You're permanently switching to a new Mac and won't keep using the
  old one.

### When **not** to use the recovery phrase

- You want to use Whisper on both your laptop and desktop at once.
  This isn't supported. Each install registers a different network
  address even with the same recovery phrase, so contacts will only
  reach the device they originally paired with - and if both devices
  send messages to the same contact, their decryption chain will
  desync.

If you genuinely want Whisper on two machines, today the answer is to
treat them as separate identities (different recovery phrases,
different aliases, separate contact lists). Proper multi-device
support is a future protocol change, not a configuration toggle.

### What the recovery phrase preserves and what it doesn't

| Preserved | Not preserved |
|---|---|
| Your Whisper ID alias | Local message history |
| Your identity keys (Ed25519 / X25519 / ML-KEM) | Contact list |
| Your safety number with each existing contact | Open ratchet sessions |
|  | Pending sends in your retry queue |

Because contacts and message history are local-only, restoring on a
new device gives you the same identity but an empty inbox. You'll
need to re-add contacts via fresh whisper:// links.

### How to restore

On the new device's lock screen, tap **Forgot passphrase? Restore from
recovery phrase**, enter your 12 words, and choose a new passphrase.
Confirm the destructive-wipe gate. The app rebuilds your identity from
the seed.

Existing contacts who safety-number-verified your old keypair will see
the same safety number on the new device - the keys are the same. But
they have no automatic notification that you moved, so you'll want to
tell them out-of-band.

---

## Troubleshooting

### App stuck on "Still connecting…"

Most common cause: an orphan i2pd subprocess from a previous version
is holding the data dir's pid-file lock, blocking the new i2pd from
starting. As of v1.0.1 Whisper auto-cleans this on launch. If you're
on an older build, manual recovery:

```sh
pkill -9 -f "i2pd-bundle/i2pd"
pkill -f "noctis-whisper-desktop"
rm -f ~/Library/Containers/com.noctisprivacy.whisper/Data/Library/Application\ Support/com.noctisprivacy.whisper/default/i2p/i2pd.pid
open "/Applications/Whisper.app"
```

If the issue persists past a clean restart, check
`~/Library/Containers/com.noctisprivacy.whisper/Data/Library/Application Support/com.noctisprivacy.whisper/default/i2p/i2pd.log`.
Look for reseed errors (network connectivity to I2P reseed servers
blocked) or repeated tunnel-build failures (unusual ISP filtering).

### "sqlcipher: file is not a database" on unlock

This means the new app binary's code identity doesn't match the
keychain ACL on your existing vault. Two recovery paths:

1. **Preserve your data**: open Keychain Access, search for
   `com.noctisprivacy.whisper`, double-click the `vault_dek` item →
   Access Control → "Allow all applications to access this item" →
   Save Changes (it'll ask for your login password). Relaunch
   Whisper.
2. **Wipe and rebuild**: tap **Forgot passphrase? Restore from
   recovery phrase** on the lock screen and enter your 12 words.
   Local message history will be lost.

This was a regular issue during the 0.1.x ad-hoc-signed beta. From
v1.0.0 onward Whisper is signed with a stable Apple Developer ID, so
keychain ACLs persist across upgrades.

### `brew upgrade` says I'm on the latest version but I'm not

Local tap clone got into a stuck state. Force-reset:

```sh
brew update --force
brew update-reset jetp1ane/noctis-whisper
brew upgrade --cask noctis-whisper
```

If `brew update-reset` says "is not a Git repository", the tap dir on
disk is broken. Repair manually:

```sh
TAP_DIR="$(brew --repository)/Library/Taps/jetp1ane/homebrew-noctis-whisper"
rm -rf "$TAP_DIR"
mkdir -p "$(dirname "$TAP_DIR")"
git clone https://github.com/JetP1ane/homebrew-noctis-whisper.git "$TAP_DIR"
brew upgrade --cask noctis-whisper
```

### Contact added me but I don't see their messages

Most likely you minted *one* whisper:// link and shared it with two or
more people. The first to import consumes the embedded one-time
prekey. Subsequent imports look successful on the sender's side but
fail silently on yours.

**Fix**: mint a fresh link per recipient. Each link is a separate
single-use bundle.

### "Whisper would like to access data from other apps"

You'll see this prompt the first time the app starts under a new
signing identity (e.g. immediately after upgrading from a prior major
version). Click **Allow**. The prompt is macOS's App Sandbox
enforcement: the new binary's code identity needs explicit
authorization to read keychain items the previous binary created.

This shouldn't recur on routine upgrades, since v1.0.x and beyond all
ship under the same stable Developer ID. If you see it on every
launch, that's a regression - please file an issue.

### Touch ID prompts on operations that didn't used to need it

Sensitive operations (revealing the recovery phrase, viewing safety
numbers) are gated by a biometric prompt on every retrieval. This is
defense-in-depth: even if a malicious process attached to the running
Whisper session, it cannot trigger those operations without a
user-visible prompt the user can refuse.

If macOS isn't offering Touch ID on a Mac that has it, fall back to
your account password - Whisper accepts either.

---

## Privacy and safety practices

The cryptographic guarantees only matter if your operational hygiene
holds up. A short list:

- **Treat the recovery phrase like a hardware key.** Paper, hardware
  password manager, or split via Shamir between two trusted physical
  locations. Not iCloud Notes. Not a screenshot. Not a sticky note on
  the monitor.
- **Verify safety numbers for high-stakes contacts.** Out-of-band, on
  a channel the attacker doesn't control. Reading 60 digits over a
  phone call you trust is sufficient.
- **Mint fresh whisper:// links per recipient.** They're cheap to
  generate. Reusing them undermines the OTPK model.
- **Lock the vault (`⌘L`) when stepping away.** Locking clears
  in-memory keys and seals the database. An unlocked Whisper on an
  unattended machine is fully accessible.
- **Trust your hardware.** The hardware-anchored Keychain seed is
  what makes a stolen disk image insufficient to decrypt your vault.
  If you suspect the original device is compromised, the keys are
  effectively in the attacker's hands once macOS is unlocked - at
  that point, abandon the identity and re-mint from a fresh phrase.

For the full threat-model breakdown - what's strong, what's
best-effort, what's explicitly out of scope - see
[`WHITEPAPER.md`](../WHITEPAPER.md).

---

## Where to get help

- Bug or unexpected behavior:
  [open an issue](https://github.com/JetP1ane/Whisper/issues)
- Security vulnerability: open a private security advisory on the
  repo (Settings → Security → Advisories), not a public issue.
