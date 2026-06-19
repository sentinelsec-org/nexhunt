#!/bin/bash
set -euo pipefail

REPO="sentinelsec-org/nexhunt"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash install.sh" >&2; exit 1; }

if ! command -v curl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y curl
fi
if ! command -v python3 >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3
fi

API_URL="https://api.github.com/repos/${REPO}/releases/latest"
LATEST_JSON="$(curl -fsSL "$API_URL")"

DEB_URL="$(printf '%s' "$LATEST_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((a['browser_download_url'] for a in d.get('assets',[]) if a['name'].endswith('.deb')), ''))")"
TAR_URL="$(printf '%s' "$LATEST_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((a['browser_download_url'] for a in d.get('assets',[]) if a['name'].endswith('.tar.gz')), ''))")"

if [ -n "$DEB_URL" ]; then
  echo "Downloading NexHunt .deb..."
  curl -fsSL -o "$TMP_DIR/nexhunt.deb" "$DEB_URL"
  apt install -y "$TMP_DIR/nexhunt.deb"
  exit 0
fi

[ -n "$TAR_URL" ] || { echo "No .deb or .tar.gz asset found in latest release." >&2; exit 1; }
echo "Downloading NexHunt tarball..."
curl -fsSL -o "$TMP_DIR/nexhunt.tar.gz" "$TAR_URL"
mkdir -p "$TMP_DIR/extract"
tar -xzf "$TMP_DIR/nexhunt.tar.gz" -C "$TMP_DIR/extract"
bash "$TMP_DIR/extract/install.sh"
