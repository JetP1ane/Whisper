# Source-of-truth Homebrew Cask for Noctis Whisper.
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
# Signed with Apple Developer ID and notarized by Apple's notary service
# from v0.1.3 onward, so Gatekeeper opens the app cleanly with no
# "unidentified developer" warning even on direct .dmg downloads (brew
# also strips com.apple.quarantine). Hardened-runtime entitlements
# remain in force — JIT, debugger attach, and DYLD_* env vars are all
# denied at the OS level.

cask "noctis-whisper" do
  version "0.1.3"

  # Apple Silicon-only for v0.1.0 — Intel build to follow.
  depends_on arch: :arm64
  sha256 "3c3adfcc773ca683c8f86512bb6ee8bdabce5aaa3ddb079872cb25df1a430e2b"
  url "https://github.com/JetP1ane/Whisper/releases/download/v#{version}/Noctis_Whisper_#{version}_aarch64.dmg"

  name "Noctis Whisper"
  desc "Privacy-focused desktop messenger with hybrid post-quantum E2EE over I2P"
  homepage "https://github.com/JetP1ane/Whisper"

  # Matches src-tauri/tauri.conf.json's minimumSystemVersion.
  depends_on macos: ">= :monterey"

  app "Noctis Whisper.app"

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
  #   security delete-generic-password -s com.noctisprivacy.whisper.hwseed
  #   security delete-generic-password -s com.noctisprivacy.whisper.vault
  #
  zap trash: [
    "~/Library/Application Support/com.noctisprivacy.whisper",
    "~/Library/Preferences/com.noctisprivacy.whisper.plist",
    "~/Library/Caches/com.noctisprivacy.whisper",
    "~/Library/Logs/Noctis Whisper",
    "~/Library/WebKit/com.noctisprivacy.whisper",
    "~/Library/HTTPStorages/com.noctisprivacy.whisper",
    "~/Library/Saved Application State/com.noctisprivacy.whisper.savedState",
  ]
end
