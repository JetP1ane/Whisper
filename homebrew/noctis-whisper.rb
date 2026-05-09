# Source-of-truth Homebrew Cask for Whisper by Noctis Privacy.
#
# How releases work:
#   1. Run scripts/release.sh — it builds the .dmg, computes its SHA-256,
#      and writes a populated copy of this file to dist/noctis-whisper.rb.
#   2. Copy dist/noctis-whisper.rb into your homebrew tap repo at
#      Casks/noctis-whisper.rb, commit, and push.
#   3. Users install with one command — brew auto-taps on the
#      fully-qualified cask reference:
#        brew install --cask <YOUR_GH_USER>/noctis-whisper/noctis-whisper
#
# The cask filename and tap path stay `noctis-whisper` (Homebrew naming
# convention is stable; renaming it would break every existing user's
# `brew upgrade`). The .app's display name is "Whisper".
#
# Signed with Apple Developer ID and notarized by Apple's notary service,
# so Gatekeeper opens the app cleanly with no "unidentified developer"
# warning even on direct .dmg downloads (brew also strips
# com.apple.quarantine). Hardened-runtime entitlements remain in force —
# JIT, debugger attach, and DYLD_* env vars are all denied at the OS
# level.

cask "noctis-whisper" do
  version "1.0.2"

  # Apple Silicon-only for now — Intel build to follow.
  depends_on arch: :arm64
  sha256 "5b95bed2448027ebb8415ace018ca0b0d4b61551c96071188030efc35dc9f09b"
  url "https://github.com/JetP1ane/Whisper/releases/download/v#{version}/Whisper_#{version}_aarch64.dmg"

  name "Whisper"
  desc "Privacy-focused desktop messenger with hybrid post-quantum E2EE over I2P"
  homepage "https://github.com/JetP1ane/Whisper"

  # Matches src-tauri/tauri.conf.json's minimumSystemVersion.
  depends_on macos: ">= :monterey"

  app "Whisper.app"

  # GitHub Releases atom feed is the canonical version source.
  livecheck do
    url :url
    strategy :github_latest
  end

  # Full uninstall (`brew uninstall --zap noctis-whisper`) trashes the
  # local SQLCipher vault, attachments, and logs. The Keychain entries
  # under `com.noctisprivacy.whisper.*` are left intact — they require
  # an authenticated keychain unlock to remove and brew can't ask for
  # that. To wipe Keychain seeds manually, run:
  #
  #   security delete-generic-password -s com.noctisprivacy.whisper.default
  #
  # The two ~/Library/Logs entries cover both the legacy "Noctis Whisper"
  # logs from pre-1.0 builds and the current "Whisper" logs.
  zap trash: [
    "~/Library/Application Support/com.noctisprivacy.whisper",
    "~/Library/Containers/com.noctisprivacy.whisper",
    "~/Library/Preferences/com.noctisprivacy.whisper.plist",
    "~/Library/Caches/com.noctisprivacy.whisper",
    "~/Library/Logs/Whisper",
    "~/Library/Logs/Noctis Whisper",
    "~/Library/WebKit/com.noctisprivacy.whisper",
    "~/Library/HTTPStorages/com.noctisprivacy.whisper",
    "~/Library/Saved Application State/com.noctisprivacy.whisper.savedState",
  ]
end
