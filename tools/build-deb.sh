#!/bin/bash
# Build a local .deb installer from dist/bundle.
#
# Usage:
#   bash tools/build-deb.sh
#   bash tools/build-deb.sh --skip-build
#
# The .deb contains the built Electron app plus obfuscated backend bundle under
# /opt/nexhunt. Its postinst prepares node_modules and the Python venv locally.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/backend'); from nexhunt.version import __version__; print(__version__)")"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
PKG="nexhunt_${VERSION}_${ARCH}"
DEBROOT="$DIST/debroot"
BUNDLE="$DIST/bundle"
SKIP_BUILD=0

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [ok] $1"; }
step() { echo; echo "==> $1"; }

cd "$ROOT"

if [ "$SKIP_BUILD" -eq 0 ]; then
  step "Building obfuscated bundle"
  bash "$ROOT/tools/build-prod.sh"
else
  [ -d "$BUNDLE" ] || { echo "Missing $BUNDLE. Run build-prod.sh first." >&2; exit 1; }
fi

step "Preparing Debian package root"
rm -rf "$DEBROOT"
mkdir -p "$DEBROOT/DEBIAN" "$DEBROOT/opt/nexhunt" "$DEBROOT/usr/local/bin" "$DEBROOT/usr/share/applications"
rsync -a "$BUNDLE/" "$DEBROOT/opt/nexhunt/"

cat > "$DEBROOT/DEBIAN/control" <<CONTROL
Package: nexhunt
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Sentinel Security <license@sentinelsec.online>
Depends: bash, ca-certificates, curl, wget, git, build-essential, python3, python3-venv, python3-pip, nodejs, npm, ruby, psmisc, x11-xserver-utils, libgtk-3-0, libnotify4, libnss3, libasound2, libxtst6, xdg-utils
Description: NexHunt bug bounty automation platform
 Local desktop app for recon, scanning, proxy workflows, exploitation, and PRO automation.
CONTROL

cat > "$DEBROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

cd /opt/nexhunt

if [ -f package-lock.json ]; then
  npm ci --omit=dev --no-audit --no-fund
else
  npm install --omit=dev --no-audit --no-fund
fi

[ -x /opt/nexhunt/node_modules/.bin/electron ] || {
  echo "Electron runtime was not installed" >&2
  exit 1
}

cd /opt/nexhunt/backend
if [ ! -d venv ]; then
  python3 -m venv venv
fi
. venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
deactivate

chmod +x /opt/nexhunt/start.sh 2>/dev/null || true
chmod +x /opt/nexhunt/install-toolchain.sh 2>/dev/null || true
chmod +x /usr/local/bin/nexhunt 2>/dev/null || true
xdg-desktop-menu install /usr/share/applications/nexhunt.desktop 2>/dev/null || true
exit 0
POSTINST

cat > "$DEBROOT/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  xdg-desktop-menu uninstall /usr/share/applications/nexhunt.desktop 2>/dev/null || true
fi
exit 0
PRERM

cat > "$DEBROOT/usr/local/bin/nexhunt" <<'LAUNCHER'
#!/bin/bash
exec /opt/nexhunt/start.sh "$@"
LAUNCHER

cat > "$DEBROOT/usr/share/applications/nexhunt.desktop" <<'DESKTOP'
[Desktop Entry]
Name=NexHunt
Comment=Bug Bounty Automation Platform by Sentinel Security
Exec=/usr/local/bin/nexhunt
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=Network;Security;
StartupWMClass=nexhunt
DESKTOP

chmod 0755 "$DEBROOT/DEBIAN/postinst" "$DEBROOT/DEBIAN/prerm" "$DEBROOT/usr/local/bin/nexhunt"
find "$DEBROOT" -type d -exec chmod 0755 {} +

step "Building .deb"
dpkg-deb --build "$DEBROOT" "$DIST/${PKG}.deb"
ok "$DIST/${PKG}.deb"

if [ -f "$DIST/SHA256SUMS" ]; then
    (cd "$DIST" && sha256sum "${PKG}.deb" >> SHA256SUMS)
    ok "Added ${PKG}.deb to SHA256SUMS"
fi

echo
echo "Install locally with:"
echo "  sudo apt install $DIST/${PKG}.deb"
