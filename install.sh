#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  NexHunt Installer — by Sentinel Security (nexhunt.myshopify.com)
#  Supports: Kali Linux / Debian / Ubuntu / Arch Linux / CachyOS
#
#  Usage:
#    sudo bash install.sh             # fresh install
#    sudo bash install.sh --update    # update to latest release
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MODE="install"
[ "${1:-}" = "--update" ] && MODE="update"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}+${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
err()  { echo -e "  ${RED}x${NC} $1"; }
step() { echo -e "\n${BLUE}${BOLD}[$((++STEP))/${TOTAL_STEPS}]${NC} ${BOLD}$1${NC}"; }
die()  { err "$1"; exit 1; }

NEXHUNT_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_BIN="$HOME/go/bin"
REPO="sentinelsec-org/nexhunt"

echo -e "\n${CYAN}${BOLD}"
echo "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗"
echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║"
echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║"
echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║"
echo "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"
echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}NexHunt${NC} — Bug Bounty Automation Platform"
echo -e "  ${CYAN}by Sentinel Security  •  nexhunt.myshopify.com${NC}"
echo -e "  Mode: ${BOLD}${MODE}${NC}   Dir: ${CYAN}${NEXHUNT_DIR}${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# UPDATE MODE: download latest release, extract, re-run installer
# ─────────────────────────────────────────────────────────────────────────────
if [ "$MODE" = "update" ]; then
  TOTAL_STEPS=3
  STEP=0
  step "Fetching latest release from GitHub"
  command -v curl &>/dev/null || apt-get install -y -qq curl
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  LATEST_JSON=$(curl -fsSL "$API_URL") || die "Could not reach GitHub API"
  ASSET_URL=$(echo "$LATEST_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assets = [a['browser_download_url'] for a in d.get('assets',[]) if a['name'].endswith('.tar.gz')]
print(assets[0] if assets else '')
")
  TAG=$(echo "$LATEST_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tag_name',''))")
  [ -z "$ASSET_URL" ] && die "No tarball found in release ${TAG}"
  ok "Latest release: ${TAG}"

  step "Downloading ${TAG}"
  TMP_DIR=$(mktemp -d)
  curl -fsSL -o "$TMP_DIR/nexhunt.tar.gz" "$ASSET_URL"

  SUMS_URL=$(echo "$LATEST_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assets = [a['browser_download_url'] for a in d.get('assets',[]) if a['name']=='SHA256SUMS']
print(assets[0] if assets else '')
")
  if [ -n "$SUMS_URL" ]; then
    curl -fsSL -o "$TMP_DIR/SHA256SUMS" "$SUMS_URL"
    (cd "$TMP_DIR" && sha256sum -c SHA256SUMS --ignore-missing) && ok "Checksum ok" || die "Checksum mismatch"
  else
    warn "No SHA256SUMS found in release — skipping checksum"
  fi

  step "Extracting and re-running installer"
  mkdir -p "$TMP_DIR/extract"
  tar -xzf "$TMP_DIR/nexhunt.tar.gz" -C "$TMP_DIR/extract"
  # Keep the installation at its stable path. Running from the temporary
  # extraction directory would leave the launcher pointing to deleted files.
  cp -a "$TMP_DIR/extract/." "$NEXHUNT_DIR/"
  bash "$NEXHUNT_DIR/install.sh"
  rm -rf "$TMP_DIR"
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# FRESH INSTALL
# ─────────────────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install.sh"

TOTAL_STEPS=5
STEP=0

# ─────────────────────────────────────────────────────────────────────────────
step "External security toolchain"
# ─────────────────────────────────────────────────────────────────────────────
TOOLCHAIN_SCRIPT="$NEXHUNT_DIR/install-toolchain.sh"
[ -f "$TOOLCHAIN_SCRIPT" ] || die "Missing install-toolchain.sh"
bash "$TOOLCHAIN_SCRIPT"
ok "External toolchain ready"

# ─────────────────────────────────────────────────────────────────────────────
step "Python backend (venv)"
# ─────────────────────────────────────────────────────────────────────────────
cd "$NEXHUNT_DIR/backend"
[ -d venv ] || python3 -m venv venv
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
deactivate
ok "Python venv ready at backend/venv"

# ─────────────────────────────────────────────────────────────────────────────
step "Node.js dependencies"
# ─────────────────────────────────────────────────────────────────────────────
cd "$NEXHUNT_DIR"
npm install --silent 2>/dev/null
ok "npm packages installed"

# ─────────────────────────────────────────────────────────────────────────────
step "Build NexHunt"
# ─────────────────────────────────────────────────────────────────────────────
if [ -f "$NEXHUNT_DIR/out/main/index.js" ] && [ ! -d "$NEXHUNT_DIR/src" ]; then
    ok "Using prebuilt Electron bundle"
else
    npm run build 2>&1 | tail -5
    ok "Build complete -> out/"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "Desktop integration"
# ─────────────────────────────────────────────────────────────────────────────

# Launcher script
cat > /usr/local/bin/nexhunt <<LAUNCHER
#!/bin/bash
exec "$NEXHUNT_DIR/start.sh" "\$@"
LAUNCHER
chmod +x /usr/local/bin/nexhunt
ok "nexhunt launcher -> /usr/local/bin/nexhunt"

# .desktop entry
ICON_PATH="$NEXHUNT_DIR/src/assets/icon.png"
[ -f "$ICON_PATH" ] || ICON_PATH="utilities-terminal"

mkdir -p /usr/share/applications
cat > /usr/share/applications/nexhunt.desktop <<DESKTOP
[Desktop Entry]
Name=NexHunt
Comment=Bug Bounty Automation Platform by Sentinel Security
Exec=/usr/local/bin/nexhunt
Icon=${ICON_PATH}
Terminal=false
Type=Application
Categories=Network;Security;
StartupWMClass=nexhunt
DESKTOP
xdg-desktop-menu install /usr/share/applications/nexhunt.desktop 2>/dev/null || true
ok ".desktop entry installed (/usr/share/applications/nexhunt.desktop)"

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}+------------------------------------------+"
echo -e "|   NexHunt installed successfully!       |"
echo -e "+------------------------------------------+${NC}"
echo ""
echo -e "  ${BOLD}Start:${NC}  nexhunt"
echo -e "        or: bash $NEXHUNT_DIR/start.sh"
echo ""
echo -e "  ${BOLD}Update:${NC} sudo bash $NEXHUNT_DIR/install.sh --update"
echo ""
echo -e "  ${BOLD}Tools status:${NC}"
TOOLS="nmap whatweb nikto sqlmap gobuster ffuf dirsearch amass httpx subfinder nuclei katana dalfox gau waybackurls gowitness arjun paramspider xsstrike commix interactsh-client trufflehog git-dumper"
for tool in $TOOLS; do
    if command -v "$tool" &>/dev/null; then
        echo -e "    ${GREEN}+${NC} $tool"
    else
        echo -e "    ${YELLOW}-${NC} $tool  (restart shell to refresh PATH)"
    fi
done
echo ""
echo -e "  ${CYAN}nexhunt.myshopify.com${NC}  •  Activate your PRO license in Settings -> License"
echo ""
