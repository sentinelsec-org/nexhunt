#!/bin/bash
# Build NexHunt for distribution:
#   1. npm build (frontend + Electron)
#   2. PyArmor obfuscation on backend/nexhunt
#   3. Tarball + SHA256SUMS in dist/
#
# Usage:
#   bash tools/build-prod.sh
#   bash tools/build-prod.sh --skip-obfuscate
#   bash tools/build-prod.sh --obfuscate-licensing-only
# Run from the nexhunt-prod root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/backend'); from nexhunt.version import __version__; print(__version__)")"
ARCHIVE="nexhunt-${VERSION}.tar.gz"
SKIP_OBF=0
OBF_SCOPE="backend"

for arg in "$@"; do
  case "$arg" in
    --skip-obfuscate) SKIP_OBF=1 ;;
    --obfuscate-licensing-only) OBF_SCOPE="licensing" ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [ok] $1"; }
step() { echo; echo "==> $1"; }

cd "$ROOT"

step "Building frontend (npm run build)"
npm run build
ok "out/ generated"

step "Preparing backend bundle"
BUNDLE="$DIST/bundle"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE"

# Copy backend (excluding venv, __pycache__, *.db, *.pyc, token.txt)
rsync -a --exclude='venv/' --exclude='__pycache__/' --exclude='*.pyc' \
         --exclude='*.db' --exclude='token.txt' \
         "$ROOT/backend/" "$BUNDLE/backend/"

# Copy built Electron app
rsync -a "$ROOT/out/" "$BUNDLE/out/"

# Copy runtime files
cp "$ROOT/package.json" "$BUNDLE/"
cp "$ROOT/package-lock.json" "$BUNDLE/" 2>/dev/null || true
cp "$ROOT/start.sh" "$BUNDLE/" 2>/dev/null || true
cp "$ROOT/install.sh" "$BUNDLE/"

ok "Bundle assembled at $BUNDLE"

if [ "$SKIP_OBF" -eq 0 ]; then
  step "Obfuscating ${OBF_SCOPE} with PyArmor"
  if ! command -v pyarmor &>/dev/null; then
    pip install --break-system-packages -q pyarmor
  fi
  TMP_OBF="$(mktemp -d)"
  cd "$BUNDLE/backend"

  if [ "$OBF_SCOPE" = "licensing" ]; then
    pyarmor gen --output "$TMP_OBF" nexhunt/licensing
    rm -rf nexhunt/licensing
    cp -r "$TMP_OBF/licensing" nexhunt/licensing
  else
    pyarmor gen --recursive --output "$TMP_OBF" nexhunt
    rm -rf nexhunt
    cp -r "$TMP_OBF/nexhunt" nexhunt
    # PyArmor only transforms Python modules. Preserve package data files.
    if [ -d "$ROOT/backend/nexhunt/data" ]; then
      mkdir -p nexhunt/data
      rsync -a "$ROOT/backend/nexhunt/data/" nexhunt/data/
    fi
  fi

  # Runtime at backend root (same level as nexhunt/), importable as top-level package.
  cp -r "$TMP_OBF"/pyarmor_runtime_* ./
  rm -rf "$TMP_OBF"
  cd "$ROOT"
  ok "${OBF_SCOPE} obfuscated"
else
  ok "Obfuscation skipped (--skip-obfuscate)"
fi

step "Creating tarball"
mkdir -p "$DIST"
cd "$DIST"
tar -czf "$ARCHIVE" -C "$BUNDLE" .
sha256sum "$ARCHIVE" > SHA256SUMS
ok "$DIST/$ARCHIVE"
ok "$DIST/SHA256SUMS"

echo
echo "Build complete: $VERSION"
echo "  $DIST/$ARCHIVE"
echo "  $DIST/SHA256SUMS"
