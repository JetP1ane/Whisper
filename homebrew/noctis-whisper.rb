# Source-of-truth Homebrew Cask for Noctis Whisper.
#
# How releases work:
#   1. Run scripts/release.sh — it builds the .dmg, computes its SHA-256,
#      and writes a populated copy of this file to dist/noctis-whisper.rb.
#   2. Copy dist/noctis-whisper.rb into your homebrew tap repo at
#      Casks/noctis-whisper.rb, commit, and push.
#   3. Users install with:
#        brew tap <YOUR_GH_USER>/noctis-whisper
#        brew install --cask noctis-whisper
#
# Why this works without an Apple Developer ID: brew cask installs strip
# the com.apple.quarantine extended attribute, so Gatekeeper never sees
# the app and there's no "unidentified developer" warning. The hardened-
# runtime entitlements (which block debugger/Frida attach) still apply.

cask "noctis-whisper" do
  version "0.1.0"

  # Apple Silicon-only for v0.1.0 — Intel build to follow.
  depends_on arch: :arm64
  sha256 "a536d124532dda852967b790c1ac3b5a16a80744d7efa7992da2b86fd016aba9"
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
