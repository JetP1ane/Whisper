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

# --- 2. Clean stale bundler artifacts before building ---
# Tauri's bundle_dmg.sh leaves a half-finished `rw.<pid>.<name>.dmg`
# behind in the macos/ bundle dir if a prior run was aborted (e.g.
# during the AppleScript "make Finder pretty" step). On the next run
# the leftover file confuses the AppleScript stage and the whole
# bundle step fails with a vague "failed to run bundle_dmg.sh".
# Purging the rw scratch + any prior final dmg is cheap and removes
# this footgun.
BUNDLE_DIR="$REPO_ROOT/src-tauri/target/release/bundle"
rm -f "$BUNDLE_DIR/macos/"rw.*.dmg "$BUNDLE_DIR/dmg/"*.dmg 2>/dev/null || true

# --- 3. Build (this calls bundle-i2pd.sh and then tauri build) ---
echo "==> Running npm run tauri:build (this includes the i2pd bundle step)..."
cd "$REPO_ROOT"
npm run tauri:build

# --- 4. Find the produced .dmg ---
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

# --- 5. SHA-256 ---
SHA256="$(shasum -a 256 "$DMG" | awk '{print $1}')"
echo "==> SHA-256: $SHA256"

# --- 6. Detect arch from filename for the right cask slot ---
case "$DMG_NAME" in
  *aarch64*|*arm64*) ARCH=arm ;;
  *x64*|*x86_64*)    ARCH=intel ;;
  *)                 ARCH=unknown ;;
esac
echo "==> Architecture: $ARCH"

# --- 7. Generate populated cask file ---
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

# --- 8. Stage the dmg under a canonical, brew-friendly filename ---
# Tauri emits "<productName>_<version>_<arch>.dmg". Stage under a
# brand-stable canonical filename so the cask URL pattern matches
# deterministically across product-name changes.
case "$ARCH" in
  arm)   ARCH_TAG="aarch64" ;;
  intel) ARCH_TAG="x64" ;;
  *)     ARCH_TAG="unknown" ;;
esac
CANONICAL_NAME="Whisper_${VERSION}_${ARCH_TAG}.dmg"
cp "$DMG" "$DIST/$CANONICAL_NAME"
echo "==> Staged: dist/$CANONICAL_NAME"

# --- 9. Next-steps banner ---
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

  5. Users install with one command (brew auto-taps from the
     fully-qualified cask reference):
       brew install --cask <your-gh-user>/noctis-whisper/noctis-whisper

  Note: the second arch (the one not built on this machine) still has
  REPLACE_WITH_*_SHA256 in the cask. To support both arm64 and x86_64
  in one cask, run release.sh on each architecture and merge the two
  sha256 values into a single cask file.
==============================================================
EOF
