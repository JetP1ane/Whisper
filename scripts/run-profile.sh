#!/usr/bin/env bash
# Launch the Noctis Whisper desktop app under a named profile.
#
# Usage:
#   scripts/run-profile.sh alice
#   scripts/run-profile.sh bob
#
# Each profile gets its own:
#   - SQLCipher database  (~/Library/Application Support/com.noctisprivacy.whisper/<profile>/whisper.db)
#   - Vault marker        (same directory)
#   - macOS Keychain items (service: com.noctisprivacy.whisper.<profile>[.hwseed])
#
# Two profiles can run side-by-side and exchange messages through the local
# relay (start it with `scripts/run-relay.sh`). Their state is fully isolated.

set -euo pipefail

PROFILE="${1:-default}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/src-tauri/target/release/noctis-whisper-desktop"

if [[ ! -x "$BIN" ]]; then
  echo "release binary not built — running:"
  echo "  npm run build && cargo build --release --manifest-path src-tauri/Cargo.toml"
  echo
  ( cd "$ROOT" && npm run build )
  ( cd "$ROOT/src-tauri" && cargo build --release )
fi

# Sanitize the profile so it stays in [a-z0-9_-]
SAFE_PROFILE="$(echo "$PROFILE" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-' | head -c 32)"
if [[ -z "$SAFE_PROFILE" ]]; then
  echo "invalid profile name '$PROFILE'" >&2
  exit 1
fi

echo "launching profile: $SAFE_PROFILE"
echo "data dir:          ~/Library/Application Support/com.noctisprivacy.whisper/$SAFE_PROFILE/"
echo "keychain service:  com.noctisprivacy.whisper.$SAFE_PROFILE"
echo

NOCTIS_PROFILE="$SAFE_PROFILE" exec "$BIN"
