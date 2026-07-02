#!/bin/bash
# Repair the binary payload of the npm Electron package. npm can report the
# package as up to date even when its postinstall download was interrupted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ELECTRON_DIR="$ROOT/node_modules/electron"

[ -f "$ELECTRON_DIR/package.json" ] || {
  echo "Electron npm package is not installed at $ELECTRON_DIR" >&2
  exit 1
}
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v unzip >/dev/null 2>&1 || { echo "unzip is required" >&2; exit 1; }

EXISTING="$(env -u ELECTRON_RUN_AS_NODE node -e "try { const fs=require('fs'); const p=require('electron'); if (typeof p === 'string' && fs.existsSync(p)) process.stdout.write(p) } catch (_) {}" 2>/dev/null)"
if [ -n "$EXISTING" ] && [ -x "$EXISTING" ]; then
  echo "Electron runtime is already installed: $EXISTING" >&2
  exit 0
fi

VERSION="$(node -p "require('$ELECTRON_DIR/package.json').version")"
case "$(uname -m)" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported Electron architecture: $(uname -m)" >&2; exit 1 ;;
esac

ARCHIVE="electron-v${VERSION}-linux-${ARCH}.zip"
EXPECTED="$(node -p "require('$ELECTRON_DIR/checksums.json')['$ARCHIVE'] || ''")"
[ -n "$EXPECTED" ] || { echo "No bundled checksum for $ARCHIVE" >&2; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
ZIP="$TMP_DIR/$ARCHIVE"
URL="https://github.com/electron/electron/releases/download/v${VERSION}/${ARCHIVE}"

echo "Downloading official Electron ${VERSION} runtime (${ARCH})..." >&2
curl -fL --retry 3 --connect-timeout 15 --max-time 300 -o "$ZIP" "$URL"
ACTUAL="$(sha256sum "$ZIP" | awk '{print $1}')"
[ "$ACTUAL" = "$EXPECTED" ] || {
  echo "Electron checksum mismatch" >&2
  exit 1
}

mkdir -p "$ELECTRON_DIR/dist"
unzip -oq "$ZIP" -d "$ELECTRON_DIR/dist"
printf '%s' electron > "$ELECTRON_DIR/path.txt"
chmod +x "$ELECTRON_DIR/dist/electron"

node -e "const fs=require('fs'); const p=require('$ELECTRON_DIR'); if (!p || !fs.existsSync(p)) process.exit(1)"
echo "Electron runtime repaired: $ELECTRON_DIR/dist/electron" >&2
