#!/bin/bash
# Generate a source-free public repository tree under dist/public-repo.
#
# This does not touch the working tree or push anything. Review the generated
# folder, then publish it to the public GitHub repo when ready.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/public-repo"
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/backend'); from nexhunt.version import __version__; print(__version__)")"

step() { echo; echo "==> $1"; }
ok() { echo "  [ok] $1"; }

step "Generating source-free public repo"
rm -rf "$OUT"
mkdir -p "$OUT"

cp "$ROOT/README.md" "$OUT/README.md"
cp "$ROOT/README.es.md" "$OUT/README.es.md"
mkdir -p "$OUT/docs/screenshots"
cp "$ROOT"/docs/screenshots/*.png "$OUT/docs/screenshots/"

cat > "$OUT/install.sh" <<'INSTALL'
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

if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
  if [ "$DISTRO_FAMILY" = "debian" ]; then
    apt-get update
    apt-get install -y ca-certificates curl coreutils python3
  else
    pacman -Sy --needed --noconfirm ca-certificates curl coreutils python
  fi
fi

API_URL="https://api.github.com/repos/${REPO}/releases/latest"
LATEST_JSON="$(curl -fsSL --retry 3 --retry-all-errors "$API_URL")"

DEB_URL=""
if [ "$DISTRO_FAMILY" = "debian" ]; then
  DEB_URL="$(printf '%s' "$LATEST_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); arch='$ARCH'; print(next((a['browser_download_url'] for a in d.get('assets',[]) if a['name'].endswith('_'+arch+'.deb')), ''))")"
fi
TAR_URL="$(printf '%s' "$LATEST_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((a['browser_download_url'] for a in d.get('assets',[]) if a['name'].endswith('.tar.gz')), ''))")"
SUMS_URL="$(printf '%s' "$LATEST_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((a['browser_download_url'] for a in d.get('assets',[]) if a['name']=='SHA256SUMS'), ''))")"

[ -n "$SUMS_URL" ] || { echo "The latest release does not contain SHA256SUMS." >&2; exit 1; }
curl -fsSL --retry 3 --retry-all-errors -o "$TMP_DIR/SHA256SUMS" "$SUMS_URL"

download_and_verify() {
  local url="$1" name expected actual
  name="${url##*/}"
  echo "Downloading $name..." >&2
  curl -fsSL --retry 3 --retry-all-errors -o "$TMP_DIR/$name" "$url"
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
INSTALL

cat > "$OUT/.gitignore" <<'GITIGNORE'
*
!.gitignore
!README.md
!README.es.md
!install.sh
!docs/
!docs/screenshots/
!docs/screenshots/*.png
GITIGNORE

chmod +x "$OUT/install.sh"
ok "$OUT"

echo
echo "Review:"
echo "  $OUT"
echo
echo "Publish manually when ready, for example:"
echo "  rsync -a --delete $OUT/ /path/to/public-repo/"
echo "  git add -A && git commit -m 'Publish source-free installer repo'"
echo "  git push origin main --force-with-lease"
