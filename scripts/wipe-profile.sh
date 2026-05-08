#!/usr/bin/env bash
#
# wipe-profile.sh — completely reset one or more Whisper profiles to
#                   first-launch state (no vault, no contacts, no
#                   identity). Useful for testing the onboarding flow.
#
# Usage:
#   scripts/wipe-profile.sh                     # default profile
#   scripts/wipe-profile.sh alice               # alice profile
#   scripts/wipe-profile.sh default alice       # both
#   scripts/wipe-profile.sh --all               # default + alice + bob
#   scripts/wipe-profile.sh -y default          # skip confirmation prompt
#
# What this removes per profile:
#   - ~/Library/Application Support/com.noctisprivacy.whisper/<profile>/
#       SQLCipher database (whisper.db)
#       Vault marker (tells the app "vault is initialized")
#       i2pd datadir + cached NetDB
#       Per-conversation attachment store
#   - macOS Keychain items under:
#       com.noctisprivacy.whisper.<profile>          (vault_dek, db_path_marker)
#       com.noctisprivacy.whisper.<profile>.hwseed   (db, tee, sealed)
#
# After wipe, launching with NOCTIS_PROFILE=<profile> shows the first-
# launch vault setup flow exactly as a brand-new install would.

set -euo pipefail

YES=0
PROFILES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) YES=1; shift ;;
    --all)    PROFILES+=(default alice bob); shift ;;
    -*)       echo "unknown flag: $1" >&2; exit 1 ;;
    *)        PROFILES+=("$1"); shift ;;
  esac
done

if [[ ${#PROFILES[@]} -eq 0 ]]; then
  PROFILES=(default)
fi

# Confirmation — the script wipes message history, contacts, and the
# vault passphrase. Recovery requires the BIP39 phrase shown at vault
# setup, which the user must already have stored externally.
echo "Profiles to wipe: ${PROFILES[*]}"
echo
echo "This destroys:"
echo "  - All locally stored messages, contacts, rooms"
echo "  - The vault passphrase (Argon2id-sealed Keychain blob)"
echo "  - The hardware-bound seed (Keychain)"
echo "  - The I2P destination + persisted NetDB"
echo
echo "Recoverable only via the 12-word BIP39 phrase shown at original"
echo "vault setup. If you don't have it, this is irreversible."
echo
if [[ $YES -ne 1 ]]; then
  read -r -p "Type 'wipe' to proceed: " confirm
  if [[ "$confirm" != "wipe" ]]; then
    echo "Aborted." >&2
    exit 1
  fi
fi

# Kill any running Whisper instances + their i2pd children. Without
# this, kill_on_drop normally tears down i2pd, but a wipe-while-running
# can leave the data dir partially recreated by the process before it
# exits. Belt and braces.
echo
echo "→ killing any running Whisper / i2pd processes"
pkill -f "noctis-whisper-desktop" 2>/dev/null || true
pkill -f "i2pd-bundle/i2pd"      2>/dev/null || true
sleep 1

for PROFILE in "${PROFILES[@]}"; do
  echo
  echo "==> wiping profile '$PROFILE'"

  DATA_DIR="$HOME/Library/Application Support/com.noctisprivacy.whisper/$PROFILE"
  if [[ -d "$DATA_DIR" ]]; then
    echo "  rm -rf $DATA_DIR"
    rm -rf "$DATA_DIR"
  else
    echo "  (no data dir)"
  fi

  SERVICE_VAULT="com.noctisprivacy.whisper.$PROFILE"
  SERVICE_HWSEED="com.noctisprivacy.whisper.$PROFILE.hwseed"
  # Account names hard-coded in src-tauri/src/crypto/keychain.rs and
  # secure_enclave.rs. Iterate so the script stays idempotent — it
  # silently skips any item that doesn't exist.
  for svc in "$SERVICE_VAULT" "$SERVICE_HWSEED"; do
    for account in vault_dek db_path_marker db tee sealed; do
      if security delete-generic-password -s "$svc" -a "$account" >/dev/null 2>&1; then
        echo "  keychain del: $svc / $account"
      fi
    done
  done
done

echo
echo "Done. Next launch under NOCTIS_PROFILE=<profile> will show the"
echo "first-launch vault setup flow."
