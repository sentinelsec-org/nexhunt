#!/bin/bash
# Build NexHunt for distribution:
#   1. npm build (frontend + Electron)
#   2. PyArmor obfuscation on licensing/ only
#   3. Tarball + SHA256SUMS in dist/
#
# Usage: bash tools/build-prod.sh [--skip-obfuscate]
# Run from the nexhunt-prod root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/backend'); from nexhunt.version import __version__; print(__version__)")"
ARCHIVE="nexhunt-${VERSION}.tar.gz"
SKIP_OBF="${1:-}"

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
cp "$ROOT/start.sh" "$BUNDLE/" 2>/dev/null || true
cp "$ROOT/install.sh" "$BUNDLE/"

ok "Bundle assembled at $BUNDLE"

if [ "$SKIP_OBF" != "--skip-obfuscate" ]; then
  step "Obfuscating licensing/ with PyArmor"
  if ! command -v pyarmor &>/dev/null; then
    pip install --break-system-packages -q pyarmor
  fi
  # Run from backend/ — pyarmor outputs:
  #   TMP_OBF/licensing/              ← obfuscated .py files
  #   TMP_OBF/pyarmor_runtime_000000/ ← runtime (.so + __init__.py)
  # Runtime must sit at backend/ root so Python finds it on sys.path.
  TMP_OBF="$(mktemp -d)"
  cd "$BUNDLE/backend"
  pyarmor gen --output "$TMP_OBF" nexhunt/licensing
  rm -rf nexhunt/licensing
  cp -r "$TMP_OBF/licensing" nexhunt/licensing
  # Runtime at backend root (same level as nexhunt/), importable as top-level package
  cp -r "$TMP_OBF/pyarmor_runtime_000000" ./
  rm -rf "$TMP_OBF"
  cd "$ROOT"
  ok "licensing/ obfuscated"
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
