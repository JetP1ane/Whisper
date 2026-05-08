#!/usr/bin/env bash
#
# bundle-i2pd.sh — prepare a self-contained i2pd tree under
#                  src-tauri/i2pd-bundle/ for the Tauri release build.
#
# What it does:
#   1. Copies the i2pd binary (Homebrew install for now; switch to a
#      source build later) into the bundle directory.
#   2. Walks its non-system dylib dependencies (openssl, boost,
#      miniupnpc) and copies each into bundle/lib/.
#   3. Rewrites the binary's load commands and each dylib's install
#      name + cross-references so everything resolves relative to
#      `@executable_path/../Resources/i2pd-bundle/lib/<name>` once
#      Tauri places the bundle inside .app/Contents/Resources/.
#   4. Copies i2pd's certificate bundle (reseed certs + family certs)
#      into bundle/certificates/ so a fresh datadir can bootstrap
#      without Internet-sourced cert downloads.
#
# Run before `npm run tauri:build` (or wire into a prebundle step).
# Re-running is idempotent — wipes and rebuilds bundle/ each time.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_DIR="$REPO_ROOT/src-tauri/i2pd-bundle"
LIB_DIR="$BUNDLE_DIR/lib"

# --- Locate source i2pd. Prefer Homebrew Apple Silicon, fall back to Intel. ---
if [ -x /opt/homebrew/opt/i2pd/bin/i2pd ]; then
  SRC_BIN=/opt/homebrew/opt/i2pd/bin/i2pd
  SRC_CERTS=/opt/homebrew/Cellar/i2pd/2.60.0/share/i2pd/certificates
elif [ -x /usr/local/opt/i2pd/bin/i2pd ]; then
  SRC_BIN=/usr/local/opt/i2pd/bin/i2pd
  SRC_CERTS=/usr/local/Cellar/i2pd/2.60.0/share/i2pd/certificates
else
  echo "error: i2pd not found via Homebrew. Run \`brew install i2pd\` first." >&2
  exit 1
fi

echo "→ source i2pd:  $SRC_BIN"
echo "→ source certs: $SRC_CERTS"

# --- Reset the bundle dir. ---
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR" "$LIB_DIR"

# --- Copy + identity files. ---
cp "$SRC_BIN" "$BUNDLE_DIR/i2pd"
chmod +w "$BUNDLE_DIR/i2pd"
cp -R "$SRC_CERTS" "$BUNDLE_DIR/certificates"
chmod -R +w "$BUNDLE_DIR/certificates"

# --- Walk dylib deps. Copies anything that's not in /usr/lib or
#     /System (Apple system frameworks, always present). Resolves
#     @loader_path/... references against the *original* directory
#     of the dylib (the Homebrew prefix), not against the bundle's
#     lib/ — that way we follow Homebrew's transitive graph. The
#     installed file in lib/ will have its load commands rewritten
#     after this walk completes.
copy_dylibs() {
  local target="$1"          # path on disk to inspect
  local source_dir="$2"      # Homebrew prefix the original came from
                             # (used to resolve @loader_path/...)
  local refs
  refs=$(otool -L "$target" | tail -n +2 | awk '{print $1}')
  local dep
  for dep in $refs; do
    # Skip system libs (always present on macOS).
    case "$dep" in
      /usr/lib/*|/System/*) continue ;;
    esac

    # Resolve relative references.
    local resolved="$dep"
    case "$dep" in
      @loader_path/*)
        resolved="$source_dir/${dep#@loader_path/}"
        ;;
      @executable_path/*|@rpath/*)
        # Already-rewritten or rpath-based — skip; if we previously
        # processed the underlying file, it's in our bundle by name.
        continue
        ;;
    esac

    local base
    base=$(basename "$resolved")
    if [ -f "$LIB_DIR/$base" ]; then
      continue
    fi
    if [ ! -f "$resolved" ]; then
      echo "  ! missing dep: $dep (resolved: $resolved) — skipping" >&2
      continue
    fi
    echo "  + lib  $base"
    cp -L "$resolved" "$LIB_DIR/$base"
    chmod +w "$LIB_DIR/$base"
    # Recurse with the source dir of this dep, not the bundle dir,
    # so further @loader_path lookups still hit Homebrew.
    copy_dylibs "$LIB_DIR/$base" "$(dirname "$resolved")"
  done
}

echo "→ walking dylib dependency graph"
copy_dylibs "$BUNDLE_DIR/i2pd" "$(dirname "$SRC_BIN")"

# --- Rewrite load commands. Each dylib reference inside i2pd and inside
#     each copied dylib gets rewritten to @executable_path-relative
#     paths. The .app layout once Tauri places the bundle:
#         Noctis Whisper.app/
#           Contents/
#             MacOS/noctis-whisper-desktop  (main binary)
#             Resources/
#               i2pd-bundle/
#                 i2pd                       (subprocess)
#                 lib/<dylibs>
#                 certificates/
#     The MAIN binary uses @executable_path = .../MacOS, so its tree to
#     reach a dylib is ../Resources/i2pd-bundle/lib/foo.dylib. The i2pd
#     subprocess is launched as a separate process so ITS @executable_path
#     is .../Resources/i2pd-bundle, and its tree to lib/ is just lib/foo.dylib.
#     Thus i2pd uses @executable_path/lib/<name>, and each dylib uses the
#     same. ---
rewrite_loads() {
  local target="$1"
  local self_name
  self_name=$(basename "$target")

  # Update install_name (id) on dylibs so any other binary that LC_LOADs
  # this lib by its install name will look in our @executable_path/lib.
  if [[ "$self_name" == *.dylib ]]; then
    install_name_tool -id "@executable_path/lib/$self_name" "$target"
  fi

  # Rewrite each non-system reference (including @loader_path-relative
  # ones — those are valid in the original Homebrew layout but break
  # once we move the dylib into our bundle's lib/, since @loader_path
  # for a file in lib/ points to lib/ itself which is exactly where
  # the sibling lives. We could leave @loader_path references alone,
  # but rewriting to @executable_path/lib/<base> is unambiguous and
  # robust against future moves).
  local deps
  deps=$(otool -L "$target" | tail -n +2 | awk '{print $1}')
  for dep in $deps; do
    case "$dep" in
      /usr/lib/*|/System/*) continue ;;
      @executable_path/*) continue ;;  # already correct
    esac
    local base
    base=$(basename "$dep")
    # Skip if we don't have this dep in our bundle (would create a
    # broken reference) — happens for unresolved @rpath that the
    # collection pass skipped.
    if [ ! -f "$LIB_DIR/$base" ]; then
      continue
    fi
    install_name_tool -change "$dep" "@executable_path/lib/$base" "$target"
  done
}

echo "→ rewriting load commands"
rewrite_loads "$BUNDLE_DIR/i2pd"
for dylib in "$LIB_DIR"/*.dylib; do
  [ -f "$dylib" ] || continue
  rewrite_loads "$dylib"
done

# --- Re-sign. install_name_tool invalidates the original signatures,
#     and Apple Silicon kernel KILLs unsigned mach-o on launch. Tauri's
#     final build pass only signs the main executable and outer .app
#     bundle — it does NOT recurse into Contents/Resources/, so any
#     nested mach-o we drop in here keeps whatever signature it has
#     when this script exits. Apple's notary service rejects bundles
#     whose nested mach-os aren't signed with the same Developer ID +
#     secure timestamp as the outer app. So we sign each one ourselves
#     here.
#
#     Identity selection (in priority order):
#       1. APPLE_SIGNING_IDENTITY env var (override)
#       2. tauri.conf.json bundle.macOS.signingIdentity
#       3. "-" (ad-hoc) for local dev builds
#     For real Developer ID identities we also pass --timestamp (Apple's
#     RFC 3161 timestamp server, required for notarization) and
#     --options runtime (hardened runtime, required for notarization).
#     Ad-hoc signing supports neither.
if [ -n "${APPLE_SIGNING_IDENTITY:-}" ]; then
  IDENTITY="$APPLE_SIGNING_IDENTITY"
else
  IDENTITY=$(node -p "require('$REPO_ROOT/src-tauri/tauri.conf.json').bundle.macOS.signingIdentity || '-'" 2>/dev/null || echo "-")
fi
echo "→ re-signing with identity: $IDENTITY"

sign_one() {
  local target="$1"
  if [ "$IDENTITY" = "-" ]; then
    codesign --force --sign - "$target"
  else
    codesign --force --sign "$IDENTITY" --timestamp --options runtime "$target"
  fi
}

codesign --remove-signature "$BUNDLE_DIR/i2pd" 2>/dev/null || true
for dylib in "$LIB_DIR"/*.dylib; do
  [ -f "$dylib" ] || continue
  codesign --remove-signature "$dylib" 2>/dev/null || true
done
# Sign dylibs first (i2pd's signature covers references to them, and
# nested signatures must be valid before the parent gets signed).
for dylib in "$LIB_DIR"/*.dylib; do
  [ -f "$dylib" ] || continue
  sign_one "$dylib"
done
sign_one "$BUNDLE_DIR/i2pd"

# --- Sanity check: launch i2pd --version with DYLD_PRINT_LIBRARIES off
#     to confirm the rewrite worked locally. If this fails, the .app will
#     also fail. ---
echo "→ sanity-check launch"
if "$BUNDLE_DIR/i2pd" --version 2>&1 | head -1; then
  echo "✓ bundle ready at $BUNDLE_DIR"
else
  echo "✗ bundled i2pd failed to launch — check rpath rewrites" >&2
  exit 1
fi

du -sh "$BUNDLE_DIR"
