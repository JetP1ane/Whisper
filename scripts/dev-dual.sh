#!/usr/bin/env bash
#
# dev-dual.sh — launch two debug-mode Whisper instances side-by-side
#               for local pairing tests. Default profile + alice
#               profile, sequentially started so they don't race
#               on `pick_free_port()`.
#
# Usage:
#   scripts/dev-dual.sh
#
# What it does:
#   1. Kills any previous Whisper / i2pd instances on this machine.
#   2. Starts `npm run tauri:dev` in the foreground for the default
#      profile. Vite + Rust hot-reload are wired to this instance.
#   3. Waits until the default profile's i2pd subprocess is up.
#   4. Spawns a second instance under NOCTIS_PROFILE=alice in the
#      background, attached to the same Vite dev server.
#   5. Tails any stderr from the alice instance into the controlling
#      terminal so panics surface.
#
# To stop both: ⌘Q either window, or Ctrl-C this script (the trap
# kills both).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/src-tauri/target/debug/noctis-whisper-desktop"

cleanup() {
  echo
  echo "→ stopping all Whisper instances and orphaned i2pd…"
  pkill -f "noctis-whisper-desktop" 2>/dev/null || true
  pkill -f "i2pd-bundle/i2pd"      2>/dev/null || true
}
trap cleanup EXIT INT TERM

cleanup
sleep 1

# Pre-build the debug binary so the alice instance has something to
# launch. tauri:dev will rebuild on top of this; that's fine.
echo "→ pre-building the debug binary (so alice has something to launch)"
( cd "$REPO_ROOT/src-tauri" && cargo build --quiet )

if [[ ! -x "$BIN" ]]; then
  echo "error: expected binary at $BIN after build" >&2
  exit 1
fi

# Launch the default profile via tauri:dev in the background. We need
# its stdout for the build/log output; we keep it attached.
echo "→ launching default profile (dev runner)…"
( cd "$REPO_ROOT" && npm run tauri:dev ) &
DEV_RUNNER_PID=$!

# Wait until the default profile's i2pd shows up in ps. The dev runner
# spawns + restarts the binary as Rust files change, so we look for a
# running i2pd subprocess associated with the default profile rather
# than a specific PID.
echo "→ waiting for default profile's i2pd subprocess…"
DEADLINE=$(( $(date +%s) + 180 ))
until pgrep -f "i2pd-bundle/i2pd.*default/i2p" > /dev/null 2>&1; do
  if (( $(date +%s) > DEADLINE )); then
    echo "error: default i2pd did not start within 180s" >&2
    exit 1
  fi
  sleep 2
done
echo "→ default i2pd is up"

echo "→ launching alice profile (direct binary)…"
NOCTIS_PROFILE=alice "$BIN" &
ALICE_PID=$!

echo
echo "==========================================================="
echo "  default profile : tauri dev runner (hot-reload enabled)"
echo "  alice profile   : PID $ALICE_PID, direct binary"
echo
echo "  Both windows now open. Pair them via whisper:// link."
echo "  Ctrl-C this script to stop both."
echo "==========================================================="

# Wait for the dev runner to exit (user hit ⌘Q or Ctrl-C). The trap
# above kills the alice instance + any orphaned i2pd on shutdown.
wait $DEV_RUNNER_PID
