#!/bin/bash
set -euo pipefail

REPO="sentinelsec-org/nexhunt"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash install.sh" >&2; exit 1; }

if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
  DISTRO_FAMILY="debian"
  ARCH="$(dpkg --print-architecture)"
elif command -v pacman >/dev/null 2>&1; then
  DISTRO_FAMILY="arch"
  case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    *) ARCH="$(uname -m)" ;;
  esac
else
  echo "Unsupported Linux distribution. NexHunt currently supports Debian/Ubuntu/Kali and Arch/CachyOS." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
  if [ "$DISTRO_FAMILY" = "debian" ]; then
    apt-get update
    apt-get install -y ca-certificates curl coreutils
  else
    pacman -Sy --needed --noconfirm ca-certificates curl coreutils
  fi
fi

# Resolve the latest release tag via HTTP redirect instead of the GitHub REST
# API, which has a 60 req/hour unauthenticated rate limit per IP and returns
# 403 when exhausted.
LATEST_TAG="$(curl -fsSL --max-redirs 5 --retry 3 -o /dev/null -w '%{url_effective}' \
  "https://github.com/${REPO}/releases/latest" | sed -E 's|.*/tag/||')"
[ -n "$LATEST_TAG" ] || { echo "Could not determine the latest NexHunt release." >&2; exit 1; }
VERSION="${LATEST_TAG#v}"

SUMS_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/SHA256SUMS"
TAR_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/nexhunt-${VERSION}.tar.gz"
DEB_URL=""
if [ "$DISTRO_FAMILY" = "debian" ]; then
  DEB_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/nexhunt_${VERSION}_${ARCH}.deb"
fi

curl -fsSL --retry 3 -o "$TMP_DIR/SHA256SUMS" "$SUMS_URL"

download_and_verify() {
  local url="$1" name expected actual
  name="${url##*/}"
  echo "Downloading $name..." >&2
  curl -fsSL --retry 3 -o "$TMP_DIR/$name" "$url"
  expected="$(awk -v name="$name" '$2 == name { print $1; exit }' "$TMP_DIR/SHA256SUMS")"
  [ -n "$expected" ] || { echo "No checksum found for $name." >&2; return 1; }
  actual="$(sha256sum "$TMP_DIR/$name" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || { echo "Checksum mismatch for $name." >&2; return 1; }
  echo "Checksum verified: $name" >&2
  printf '%s\n' "$TMP_DIR/$name"
}

if [ -n "$DEB_URL" ]; then
  DEB_PATH="$(download_and_verify "$DEB_URL")"
  apt install -y "$DEB_PATH"
  bash /opt/nexhunt/install-toolchain.sh
  echo "NexHunt installed successfully. Start it with: nexhunt"
  exit 0
fi

[ "$ARCH" = "amd64" ] || { echo "No NexHunt package is available for architecture: ${ARCH:-unknown}." >&2; exit 1; }
[ -n "$TAR_URL" ] || { echo "No .deb or .tar.gz asset found in latest release." >&2; exit 1; }
echo "Installing NexHunt from tarball for ${DISTRO_FAMILY}/${ARCH}..."
TAR_PATH="$(download_and_verify "$TAR_URL")"
mkdir -p "$TMP_DIR/extract"
tar -xzf "$TAR_PATH" -C "$TMP_DIR/extract"
mkdir -p /opt/nexhunt
cp -a "$TMP_DIR/extract/." /opt/nexhunt/
bash /opt/nexhunt/install.sh
