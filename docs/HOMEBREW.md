# Distributing Whisper via Homebrew Cask

This is the install path for users who don't want to manually download
DMGs. Every release is signed with an Apple Developer ID and notarized
by Apple's notary service, so Gatekeeper opens it cleanly on direct
`.dmg` downloads as well as via brew. Brew Cask also strips macOS's
quarantine attribute on install for good measure.

Hardened-runtime entitlements remain in force, so the security
properties verified during the audit (Frida/lldb attach denial,
library validation) are unchanged.

## One-time setup

You need two GitHub repos:

1. **The project repo** — wherever this code lives. Releases are
   published here as GitHub Releases, with the built `.dmg` as the
   release asset.

2. **A Homebrew tap repo** — a separate, near-empty repo named
   `homebrew-noctis-whisper` (Homebrew expects the `homebrew-` prefix).
   This holds the cask file. Users tap it once and `brew install --cask`
   from then on.

### Steps

1. On GitHub, create both repos. Push this project to repo (1).

2. Open `homebrew/noctis-whisper.rb` and replace every `REPLACE_GH_USER`
   with your GitHub username. Commit. (After this first edit, the
   release script preserves the username on subsequent runs.)

3. In repo (2), create a `Casks/` directory. You'll commit the
   generated cask file there for each release.

4. Tell users how to install. The fully-qualified cask reference
   makes brew auto-tap, so it's a single command:

   ```
   brew install --cask <your-gh-user>/noctis-whisper/noctis-whisper
   ```

   Once the cask is accepted into homebrew/homebrew-cask, the same
   install works without the tap prefix as
   `brew install --cask noctis-whisper`.

## Per-release flow

Whenever you cut a new version:

1. Bump `version` in `src-tauri/tauri.conf.json`.

2. Run the release script:

   ```
   ./scripts/release.sh
   ```

   This builds the `.dmg` (including a fresh i2pd-bundle integrity
   manifest) and writes `dist/noctis-whisper.rb` with the version and
   SHA-256 already substituted.

3. Tag the release and push:

   ```
   git tag v0.1.0
   git push --tags
   ```

4. On GitHub, create a Release for the tag and upload `dist/*.dmg` as
   an asset.

5. In your tap repo, copy `dist/noctis-whisper.rb` to
   `Casks/noctis-whisper.rb`, commit, and push.

That's it. Users running `brew upgrade --cask noctis-whisper` pick up
the new version automatically; brew's `livecheck` (configured in the
cask) reads GitHub's atom feed to detect new tagged releases.

## Supporting both arm64 and x86_64

`release.sh` runs on whichever architecture you're building on, so the
generated cask only has the SHA-256 for that build. To ship a single
cask that serves both:

1. Run `release.sh` on an Apple Silicon Mac. Note the SHA-256 it
   reports for the `aarch64` build.
2. Run `release.sh` on an Intel Mac (or under Rosetta with an
   `x86_64-apple-darwin` Rust target). Note the SHA-256 for the `x64`
   build.
3. In the cask file, replace both `REPLACE_WITH_ARM64_SHA256` and
   `REPLACE_WITH_X86_SHA256` with their respective values.
4. Upload both DMGs to the same GitHub Release.

Most modern Mac users are on Apple Silicon. If you only build for arm64
initially, Intel users will get a clear error from brew about the
missing `on_intel` block — not a silent failure.

## What `brew uninstall --zap` removes

The cask's `zap` stanza wipes:

- The SQLCipher vault and attachments under
  `~/Library/Application Support/com.noctisprivacy.whisper`
- App-level caches and preferences
- WebKit and saved-state directories

What it does NOT remove (because brew can't unlock the user's keychain
without prompting):

- The hardware-bound seed under
  `com.noctisprivacy.whisper.hwseed`
- The vault DEK blob under
  `com.noctisprivacy.whisper.vault`

Users wanting a fully clean uninstall can run:

```
security delete-generic-password -s com.noctisprivacy.whisper.hwseed
security delete-generic-password -s com.noctisprivacy.whisper.vault
```

The cask comments mention this as well.

## Why not submit to homebrew/homebrew-cask directly?

You can, eventually. The community-managed cask repo accepts apps that
aren't notarized, but maintainers prefer projects with some traction
(active releases, real users, working CI). Self-hosting a tap is the
right move for early releases — full control, no review, instant
publishing. You can submit to the main cask repo later when the project
is established.
