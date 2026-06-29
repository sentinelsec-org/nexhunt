#!/bin/bash
# Build NexHunt for distribution:
#   1. npm build (frontend + Electron)
#   2. Compile premium/licensing modules with Cython Stable ABI
#   3. Tarball + SHA256SUMS in dist/
#
# Usage:
#   bash tools/build-prod.sh
#   bash tools/build-prod.sh --skip-protection
#   bash tools/build-prod.sh --skip-obfuscate  # backwards-compatible alias
# Run from the nexhunt-prod root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/backend'); from nexhunt.version import __version__; print(__version__)")"
ARCHIVE="nexhunt-${VERSION}.tar.gz"
SKIP_PROTECTION=0
CYTHON_VERSION="3.2.6"
CYTHON_VENV="$DIST/cython-venv"
CYTHON_BUILD="$DIST/cython-build"

for arg in "$@"; do
  case "$arg" in
    --skip-protection|--skip-obfuscate) SKIP_PROTECTION=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

if [ "$SKIP_PROTECTION" -eq 0 ]; then
  PYTHON_HEADER="$(python3 -c 'import sysconfig; print(sysconfig.get_path("include") + "/Python.h")')"
  if [ ! -f "$PYTHON_HEADER" ]; then
    echo "Missing Python development headers. Install them with: sudo apt install python3-dev" >&2
    exit 2
  fi
  if [ ! -x "$CYTHON_VENV/bin/python" ]; then
    mkdir -p "$DIST"
    python3 -m venv "$CYTHON_VENV"
  fi
  INSTALLED_CYTHON="$($CYTHON_VENV/bin/python -c 'import Cython; print(Cython.__version__)' 2>/dev/null || true)"
  if [ "$INSTALLED_CYTHON" != "$CYTHON_VERSION" ]; then
    "$CYTHON_VENV/bin/pip" install -q --upgrade \
      "Cython==$CYTHON_VERSION" setuptools wheel
  fi
fi

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
         --exclude='*.db' --exclude='token.txt' --exclude='/nikto_*.txt' \
         "$ROOT/backend/" "$BUNDLE/backend/"

# Copy built Electron app
rsync -a "$ROOT/out/" "$BUNDLE/out/"

# Copy runtime files
cp "$ROOT/package.json" "$BUNDLE/"
cp "$ROOT/package-lock.json" "$BUNDLE/" 2>/dev/null || true
cp "$ROOT/start.sh" "$BUNDLE/" 2>/dev/null || true
cp "$ROOT/install.sh" "$BUNDLE/"
cp "$ROOT/install-toolchain.sh" "$BUNDLE/"
chmod +x "$BUNDLE/install.sh" "$BUNDLE/install-toolchain.sh" "$BUNDLE/start.sh" 2>/dev/null || true

ok "Bundle assembled at $BUNDLE"

if [ "$SKIP_PROTECTION" -eq 0 ]; then
  step "Compiling premium modules with Cython Stable ABI"
  "$CYTHON_VENV/bin/python" "$ROOT/tools/build-premium-cython.py" \
    "$BUNDLE/backend" "$CYTHON_BUILD"
  PYTHONPATH="$BUNDLE/backend" python3 -c \
    "from nexhunt.main import app; print(f'  [ok] compiled backend imports ({len(app.routes)} routes)')"
  ok "Premium modules compiled; original premium .py files removed"
else
  ok "Premium compilation skipped (--skip-protection)"
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
