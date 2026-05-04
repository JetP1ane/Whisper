#!/usr/bin/env bash
# Build and run the local Whisper relay on :8080 with a fresh BadgerDB store.
#
# The desktop app's auto-connect URL is hardcoded to ws://127.0.0.1:8080/ws
# so this is the relay both profiles will talk to during local testing.

set -euo pipefail

RELAY_SRC="$HOME/Documents/whisper-relay"
RELAY_BIN="/tmp/whisper-relay"
RELAY_DB="/tmp/whisper-relay-db"

if [[ ! -d "$RELAY_SRC" ]]; then
  echo "relay source not found at $RELAY_SRC" >&2
  exit 1
fi

# Build with -linkmode=external so macOS gets the LC_UUID load command Go's
# internal linker omits in some toolchain configs.
echo "building relay…"
( cd "$RELAY_SRC" && go build -ldflags="-linkmode=external -s -w" -o "$RELAY_BIN" ./cmd/relay )

rm -rf "$RELAY_DB"
echo "starting relay on :8080 (db: $RELAY_DB)"
exec "$RELAY_BIN" -dev -dev-addr :8080 -db "$RELAY_DB"
