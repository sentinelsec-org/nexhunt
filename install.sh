#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  NexHunt Installer — by Sentinel Security (sentinelsec.online)
#  Supports: Kali Linux / Debian / Ubuntu
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
REPO="sentinelsec/nexhunt"

echo -e "\n${CYAN}${BOLD}"
echo "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗"
echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║"
echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║"
echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║"
echo "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"
echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}NexHunt${NC} — Bug Bounty Automation Platform"
echo -e "  ${CYAN}by Sentinel Security  •  sentinelsec.online${NC}"
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
  bash "$TMP_DIR/extract/install.sh"
  rm -rf "$TMP_DIR"
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# FRESH INSTALL
# ─────────────────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install.sh"

TOTAL_STEPS=9
STEP=0

# ─────────────────────────────────────────────────────────────────────────────
step "System dependencies (apt)"
# ─────────────────────────────────────────────────────────────────────────────
apt-get update -qq 2>/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    curl wget git build-essential coreutils \
    nmap nikto sqlmap gobuster dirsearch amass commix hydra cewl crunch \
    python3 python3-pip python3-venv python3-full \
    nodejs npm xterm \
    libgtk-3-0 libnotify4 libnss3 libasound2 libxtst6 xdg-utils \
    2>/dev/null || true

# Unpack rockyou if it ships gzipped (Kali default)
if [ ! -f /usr/share/wordlists/rockyou.txt ] && [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
fi

# Node.js v18+ required
NODE_VER=$(node --version 2>/dev/null | cut -d. -f1 | tr -d 'v' || echo "0")
if [ "$NODE_VER" -lt 18 ] 2>/dev/null; then
    warn "Node.js $NODE_VER too old — installing v20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
    apt-get install -y -qq nodejs
fi
ok "System packages ready  (Node $(node --version))"

# ─────────────────────────────────────────────────────────────────────────────
step "Go toolchain"
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    GO_VER="1.22.3"
    GO_ARCH="amd64"
    [ "$(uname -m)" = "aarch64" ] && GO_ARCH="arm64"
    wget -q "https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ok "Go ${GO_VER} installed"
else
    ok "$(go version)"
fi
export PATH="$PATH:$GO_BIN:/usr/local/go/bin"

# ─────────────────────────────────────────────────────────────────────────────
step "Go security tools (ProjectDiscovery + others)"
# ─────────────────────────────────────────────────────────────────────────────
go_install() {
    local name="$1" pkg="$2"
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
        return
    fi
    printf "  Installing %-24s ... " "$name"
    GOPATH="$HOME/go" go install "$pkg" 2>/dev/null && echo -e "${GREEN}ok${NC}" || echo -e "${YELLOW}failed${NC}"
}

go_install subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install dalfox       "github.com/hahwul/dalfox/v2@latest"
go_install gau          "github.com/lc/gau/v2/cmd/gau@latest"
go_install waybackurls  "github.com/tomnomnom/waybackurls@latest"
go_install gowitness    "github.com/sensepost/gowitness@latest"
go_install ffuf         "github.com/ffuf/ffuf/v2@latest"
go_install interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

# httpx (PD) — symlink to /usr/local/bin/httpx (overrides httpx-toolkit if present)
if ! /usr/local/bin/httpx --version &>/dev/null 2>&1; then
    printf "  Installing %-24s ... " "httpx (PD)"
    GOPATH="$HOME/go" go install "github.com/projectdiscovery/httpx/cmd/httpx@latest" 2>/dev/null \
        && ln -sf "$HOME/go/bin/httpx" /usr/local/bin/httpx \
        && echo -e "${GREEN}ok${NC}" || echo -e "${YELLOW}failed${NC}"
fi

for bin in subfinder nuclei katana dalfox gau waybackurls gowitness ffuf interactsh-client; do
    [ -f "$GO_BIN/$bin" ] && ln -sf "$GO_BIN/$bin" /usr/local/bin/$bin 2>/dev/null || true
done
ok "Go tools symlinked to /usr/local/bin"

# ─────────────────────────────────────────────────────────────────────────────
step "Python security tools"
# ─────────────────────────────────────────────────────────────────────────────
pip3_install() {
    printf "  Installing %-24s ... " "$1"
    pip3 install -q --break-system-packages "$1" 2>/dev/null \
        || pip3 install -q "$1" 2>/dev/null \
        && echo -e "${GREEN}ok${NC}" || echo -e "${YELLOW}skipped${NC}"
}
pip3_install arjun
pip3_install paramspider

if ! command -v xsstrike &>/dev/null; then
    printf "  Installing %-24s ... " "xsstrike"
    git clone -q https://github.com/s0md3v/XSStrike.git /opt/XSStrike 2>/dev/null || true
    pip3 install -q --break-system-packages -r /opt/XSStrike/requirements.txt 2>/dev/null || true
    printf '#!/bin/bash\ncd /opt/XSStrike && python3 xsstrike.py "$@"\n' > /usr/local/bin/xsstrike
    chmod +x /usr/local/bin/xsstrike
    echo -e "${GREEN}ok${NC}"
else
    ok "xsstrike already installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "PATH configuration"
# ─────────────────────────────────────────────────────────────────────────────
PATH_LINE="export PATH=\"\$PATH:$GO_BIN:/usr/local/go/bin\""
for rcfile in /root/.bashrc /root/.zshrc /home/kali/.bashrc /home/kali/.zshrc; do
    [ -f "$rcfile" ] || continue
    grep -q "go/bin" "$rcfile" 2>/dev/null && continue
    { echo ""; echo "# Go tools (NexHunt — Sentinel Security)"; echo "$PATH_LINE"; } >> "$rcfile"
done
export PATH="$PATH:$GO_BIN:/usr/local/go/bin"
ok "~/go/bin in PATH (restart shell or: source ~/.zshrc)"

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
npm run build 2>&1 | tail -5
ok "Build complete -> out/"

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
TOOLS="nmap nikto sqlmap gobuster ffuf dirsearch amass httpx subfinder nuclei katana dalfox gau waybackurls gowitness arjun xsstrike hydra"
for tool in $TOOLS; do
    if command -v "$tool" &>/dev/null; then
        echo -e "    ${GREEN}+${NC} $tool"
    else
        echo -e "    ${YELLOW}-${NC} $tool  (restart shell to refresh PATH)"
    fi
done
echo ""
echo -e "  ${CYAN}sentinelsec.online${NC}  •  Activate your PRO license in Settings -> License"
echo ""
