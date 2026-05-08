#!/usr/bin/env bash
#
# release.sh — build a release artifact + write a populated Homebrew
#              Cask file ready to commit into your tap repo.
#
# Usage:
#   ./scripts/release.sh
#
# What this does:
#   1. Reads the version from src-tauri/tauri.conf.json.
#   2. Runs `npm run tauri:build`, which itself runs scripts/bundle-i2pd.sh
#      first (so the per-file integrity manifest is fresh) and then
#      `tauri build` to produce a .dmg under
#      src-tauri/target/release/bundle/dmg/.
#   3. Computes SHA-256 of the produced .dmg.
#   4. Writes dist/noctis-whisper.rb — a copy of homebrew/noctis-whisper.rb
#      with the version + sha256 substituted in the right arch slot.
#   5. Copies the .dmg into dist/ for convenience.
#   6. Prints next steps (create GitHub Release, upload, push tap).
#
# Prerequisites:
#   - brew install i2pd      (consumed by bundle-i2pd.sh)
#   - npm install            (one-time, for the JS toolchain)
#   - On first release: a GitHub repo for this project + a separate
#     "tap" repo named homebrew-noctis-whisper (or homebrew-tap) on
#     your account. See docs/HOMEBREW.md for the one-time setup.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$REPO_ROOT/dist"
TEMPLATE="$REPO_ROOT/homebrew/noctis-whisper.rb"

if [ ! -f "$TEMPLATE" ]; then
  echo "error: cask template not found at $TEMPLATE" >&2
  exit 1
fi

# --- 1. Read version from tauri config ---
VERSION=$(node -p "require('$REPO_ROOT/src-tauri/tauri.conf.json').version")
echo "==> Version: $VERSION"

# --- 2. Build (this calls bundle-i2pd.sh and then tauri build) ---
echo "==> Running npm run tauri:build (this includes the i2pd bundle step)..."
cd "$REPO_ROOT"
npm run tauri:build

# --- 3. Find the produced .dmg ---
DMG_DIR="$REPO_ROOT/src-tauri/target/release/bundle/dmg"
DMG=""
for candidate in "$DMG_DIR"/*.dmg; do
  if [ -f "$candidate" ]; then
    DMG="$candidate"
    break
  fi
done
if [ -z "$DMG" ]; then
  echo "error: no .dmg produced under $DMG_DIR" >&2
  exit 1
fi
DMG_NAME="$(basename "$DMG")"
echo "==> Built: $DMG_NAME"

# --- 4. SHA-256 ---
SHA256="$(shasum -a 256 "$DMG" | awk '{print $1}')"
echo "==> SHA-256: $SHA256"

# --- 5. Detect arch from filename for the right cask slot ---
case "$DMG_NAME" in
  *aarch64*|*arm64*) ARCH=arm ;;
  *x64*|*x86_64*)    ARCH=intel ;;
  *)                 ARCH=unknown ;;
esac
echo "==> Architecture: $ARCH"

# --- 6. Generate populated cask file ---
mkdir -p "$DIST"
CASK="$DIST/noctis-whisper.rb"
cp "$TEMPLATE" "$CASK"

# Replace the version line.
# (We use a tab-friendly delimiter to avoid escaping forward slashes.)
sed -i.bak "s|^  version \".*\"|  version \"$VERSION\"|" "$CASK"

# Replace the right SHA-256 placeholder for this build's architecture.
case "$ARCH" in
  arm)
    sed -i.bak "s|REPLACE_WITH_ARM64_SHA256|$SHA256|" "$CASK"
    ;;
  intel)
    sed -i.bak "s|REPLACE_WITH_X86_SHA256|$SHA256|" "$CASK"
    ;;
  *)
    echo "warn: unrecognized arch in $DMG_NAME — sha256 placeholder not substituted" >&2
    ;;
esac
rm -f "$CASK.bak"

# --- 7. Stage the dmg under a canonical, brew-friendly filename ---
# Tauri sometimes emits filenames with spaces ("Noctis Whisper_..."),
# which gets percent-encoded in URLs and is awkward in scripts. Rename
# to underscores so the cask's URL pattern matches deterministically.
case "$ARCH" in
  arm)   ARCH_TAG="aarch64" ;;
  intel) ARCH_TAG="x64" ;;
  *)     ARCH_TAG="unknown" ;;
esac
CANONICAL_NAME="Noctis_Whisper_${VERSION}_${ARCH_TAG}.dmg"
cp "$DMG" "$DIST/$CANONICAL_NAME"
echo "==> Staged: dist/$CANONICAL_NAME"

# --- 8. Next-steps banner ---
cat <<EOF

==============================================================
Build complete.

  dist/$CANONICAL_NAME
  dist/noctis-whisper.rb

Next steps:

  1. (one-time) Edit dist/noctis-whisper.rb and replace any remaining
     REPLACE_GH_USER placeholders with your GitHub username. After this
     first edit, future runs of release.sh keep your username intact —
     they only refresh version + sha256.

     Once edited, copy the patched cask into homebrew/noctis-whisper.rb
     so the next release inherits your username automatically.

  2. Tag the commit and push:
       git tag v$VERSION
       git push --tags

  3. Create a GitHub Release for tag v$VERSION and upload:
       dist/$CANONICAL_NAME
     (the filename matters — the cask's URL pattern expects exactly
      this name, so don't rename it during upload.)

  4. Commit the cask file into your homebrew tap repo at
     Casks/noctis-whisper.rb, then push.

  5. Users install with:
       brew tap <your-gh-user>/noctis-whisper
       brew install --cask noctis-whisper

  Note: the second arch (the one not built on this machine) still has
  REPLACE_WITH_*_SHA256 in the cask. To support both arm64 and x86_64
  in one cask, run release.sh on each architecture and merge the two
  sha256 values into a single cask file.
==============================================================
EOF
