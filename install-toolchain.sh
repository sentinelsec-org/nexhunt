#!/bin/bash
# Install the external command-line tools used by NexHunt.
# This script is intentionally idempotent and is shared by the tarball and
# Debian and Arch-family installers so every installation path provides the
# same toolchain.
set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo bash install-toolchain.sh" >&2; exit 1; }

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}+${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
err()  { echo -e "  ${RED}x${NC} $1"; }

export HOME="/root"
export GOPATH="/root/go"
GO_BIN="$GOPATH/bin"
TOOLS_VENV="/opt/nexhunt-tooling"

echo "Installing NexHunt system dependencies..."
if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
  DISTRO_FAMILY="debian"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || { err "Could not refresh apt package metadata"; exit 1; }
  apt-get install -y -qq \
    bash ca-certificates curl wget git build-essential coreutils perl \
    python3 python3-pip python3-venv python3-full \
    nodejs npm ruby ruby-dev \
    xterm psmisc x11-xserver-utils \
    libgtk-3-0 libnotify4 libnss3 libasound2 libxtst6 xdg-utils \
    libcurl4-openssl-dev libxml2-dev libxslt1-dev zlib1g-dev \
    || { err "Could not install required Debian dependencies"; exit 1; }
  SECURITY_PACKAGES=(
    nmap whatweb nikto sqlmap dirsearch amass commix hydra cewl crunch seclists
    chromium wpscan
  )
elif command -v pacman >/dev/null 2>&1; then
  DISTRO_FAMILY="arch"
  pacman -Sy --needed --noconfirm \
    bash ca-certificates curl wget git base-devel coreutils perl \
    python python-pip nodejs npm ruby \
    xterm psmisc xorg-xhost \
    gtk3 libnotify nss alsa-lib libxtst xdg-utils \
    libxml2 libxslt zlib \
    || { err "Could not install required Arch/CachyOS dependencies"; exit 1; }
  SECURITY_PACKAGES=(
    nmap whatweb nikto sqlmap dirsearch amass hydra cewl crunch seclists
    chromium wpscan
  )
else
  err "Unsupported distribution: apt/dpkg or pacman is required"
  exit 1
fi

# Security packages vary by distribution. Install every package available in
# configured repositories, then use upstream fallbacks for required tools.
for package in "${SECURITY_PACKAGES[@]}"; do
  if [ "$DISTRO_FAMILY" = "debian" ]; then
    dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed" && continue
    apt-cache show "$package" >/dev/null 2>&1 || continue
    apt-get install -y -qq "$package" || warn "Could not install apt package: $package"
  else
    pacman -Q "$package" >/dev/null 2>&1 && continue
    pacman -Si "$package" >/dev/null 2>&1 || continue
    pacman -S --needed --noconfirm "$package" || warn "Could not install pacman package: $package"
  fi
done

# Node 18+ is required. Node 22 is the supported LTS fallback for distributions
# whose repositories still ship an older release.
NODE_MAJOR="$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)"
NODE_MAJOR="${NODE_MAJOR:-0}"
if [ "$NODE_MAJOR" -lt 18 ] 2>/dev/null; then
  if [ "$DISTRO_FAMILY" = "debian" ]; then
    warn "Node.js ${NODE_MAJOR} is too old; installing Node.js 22 LTS"
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y -qq nodejs
  else
    err "Node.js 18+ is required; update CachyOS/Arch and rerun the installer"
    exit 1
  fi
fi
ok "Node.js $(node --version)"

install_go() {
  local current="" go_tag go_arch archive checksum metadata
  if command -v go >/dev/null 2>&1; then
    current="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  fi
  if [ -n "$current" ] && [ "$(printf '%s\n' "1.24" "$current" | sort -V | sed -n '1p')" = "1.24" ]; then
    ok "$(go version)"
    return
  fi

  case "$(uname -m)" in
    x86_64) go_arch="amd64" ;;
    aarch64|arm64) go_arch="arm64" ;;
    *) err "Unsupported Go architecture: $(uname -m)"; return 1 ;;
  esac

  go_tag="$(curl -fsSL 'https://go.dev/VERSION?m=text' | sed -n '1p')"
  [ -n "$go_tag" ] || { err "Could not determine the current Go version"; return 1; }
  archive="${go_tag}.linux-${go_arch}.tar.gz"
  metadata="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all')"
  checksum="$(printf '%s' "$metadata" | python3 -c "import json,sys; name='$archive'; print(next((f['sha256'] for r in json.load(sys.stdin) for f in r.get('files',[]) if f['filename']==name), ''))")"
  [ -n "$checksum" ] || { err "No checksum published for $archive"; return 1; }

  curl -fsSL "https://go.dev/dl/$archive" -o "/tmp/$archive"
  printf '%s  %s\n' "$checksum" "/tmp/$archive" | sha256sum -c - >/dev/null
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/$archive"
  rm -f "/tmp/$archive"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ok "$(go version)"
}

install_go || exit 1
export PATH="/usr/local/go/bin:$GO_BIN:/usr/local/bin:$PATH"
mkdir -p "$GO_BIN"

GO_FAILURES=()
go_install() {
  local name="$1" package="$2" force="${3:-0}"
  if [ "$force" -eq 0 ] && command -v "$name" >/dev/null 2>&1; then
    ok "$name already installed"
    return
  fi
  printf "  Installing %-24s ... " "$name"
  if go install "$package"; then
    ln -sf "$GO_BIN/$name" "/usr/local/bin/$name"
    echo -e "${GREEN}ok${NC}"
  else
    echo -e "${RED}failed${NC}"
    GO_FAILURES+=("$name")
  fi
}

go_install subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install katana "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install dalfox "github.com/hahwul/dalfox/v2@latest"
go_install gau "github.com/lc/gau/v2/cmd/gau@latest"
go_install waybackurls "github.com/tomnomnom/waybackurls@latest"
go_install gowitness "github.com/sensepost/gowitness@latest"
go_install ffuf "github.com/ffuf/ffuf/v2@latest"
go_install gobuster "github.com/OJ/gobuster/v3@latest" 1
go_install interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
go_install trufflehog "github.com/trufflesecurity/trufflehog/v3@latest"
# Force the ProjectDiscovery binary so Python's httpx CLI cannot shadow it.
go_install httpx "github.com/projectdiscovery/httpx/cmd/httpx@latest" 1

if ! command -v amass >/dev/null 2>&1; then
  go_install amass "github.com/owasp-amass/amass/v4/...@master"
fi

echo "Installing Python security tools in $TOOLS_VENV..."
if [ ! -x "$TOOLS_VENV/bin/python" ]; then
  python3 -m venv "$TOOLS_VENV"
fi
"$TOOLS_VENV/bin/pip" install -q --upgrade pip setuptools wheel
PY_FAILURES=()
for package in arjun dirsearch; do
  if "$TOOLS_VENV/bin/pip" install -q --upgrade "$package"; then
    [ -x "$TOOLS_VENV/bin/$package" ] && ln -sf "$TOOLS_VENV/bin/$package" "/usr/local/bin/$package"
    ok "$package"
  else
    warn "Could not install Python tool: $package"
    PY_FAILURES+=("$package")
  fi
done

# ParamSpider is not published on PyPI; install the maintained upstream package.
if "$TOOLS_VENV/bin/pip" install -q --upgrade \
   "git+https://github.com/devanshbatham/ParamSpider.git"; then
  [ -x "$TOOLS_VENV/bin/paramspider" ] && \
    ln -sf "$TOOLS_VENV/bin/paramspider" /usr/local/bin/paramspider
  ok "paramspider"
else
  warn "Could not install Python tool: paramspider"
  PY_FAILURES+=("paramspider")
fi

# Upstream fallbacks for security packages commonly absent from Arch/CachyOS
# repositories. Wrappers keep every command in the global PATH.
if ! command -v whatweb >/dev/null 2>&1; then
  [ -d /opt/WhatWeb/.git ] || {
    rm -rf /opt/WhatWeb
    git clone -q --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/WhatWeb || true
  }
  if [ -f /opt/WhatWeb/whatweb ]; then
    cat > /usr/local/bin/whatweb <<'WHATWEB'
#!/bin/bash
exec ruby /opt/WhatWeb/whatweb "$@"
WHATWEB
    chmod +x /usr/local/bin/whatweb
    ok "whatweb"
  fi
fi

if ! command -v nikto >/dev/null 2>&1; then
  [ -d /opt/nikto/.git ] || {
    rm -rf /opt/nikto
    git clone -q --depth 1 https://github.com/sullo/nikto.git /opt/nikto || true
  }
  if [ -f /opt/nikto/program/nikto.pl ]; then
    cat > /usr/local/bin/nikto <<'NIKTO'
#!/bin/bash
exec perl /opt/nikto/program/nikto.pl "$@"
NIKTO
    chmod +x /usr/local/bin/nikto
    ok "nikto"
  fi
fi

if ! command -v sqlmap >/dev/null 2>&1; then
  [ -d /opt/sqlmap/.git ] || {
    rm -rf /opt/sqlmap
    git clone -q --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap || true
  }
  if [ -f /opt/sqlmap/sqlmap.py ]; then
    cat > /usr/local/bin/sqlmap <<'SQLMAP'
#!/bin/bash
exec /opt/nexhunt-tooling/bin/python /opt/sqlmap/sqlmap.py "$@"
SQLMAP
    chmod +x /usr/local/bin/sqlmap
    ok "sqlmap"
  fi
fi

if ! command -v commix >/dev/null 2>&1; then
  [ -d /opt/commix/.git ] || {
    rm -rf /opt/commix
    git clone -q --depth 1 https://github.com/commixproject/commix.git /opt/commix || true
  }
  if [ -f /opt/commix/requirements.txt ]; then
    "$TOOLS_VENV/bin/pip" install -q -r /opt/commix/requirements.txt || true
  fi
  if [ -f /opt/commix/commix.py ]; then
    cat > /usr/local/bin/commix <<'COMMIX'
#!/bin/bash
exec /opt/nexhunt-tooling/bin/python /opt/commix/commix.py "$@"
COMMIX
    chmod +x /usr/local/bin/commix
    ok "commix"
  fi
fi

if ! command -v xsstrike >/dev/null 2>&1; then
  if [ ! -d /opt/XSStrike/.git ]; then
    rm -rf /opt/XSStrike
    git clone -q --depth 1 https://github.com/s0md3v/XSStrike.git /opt/XSStrike || true
  fi
  if [ -f /opt/XSStrike/requirements.txt ] && \
     "$TOOLS_VENV/bin/pip" install -q -r /opt/XSStrike/requirements.txt; then
    cat > /usr/local/bin/xsstrike <<'XSSTRIKE'
#!/bin/bash
cd /opt/XSStrike
exec /opt/nexhunt-tooling/bin/python xsstrike.py "$@"
XSSTRIKE
    chmod +x /usr/local/bin/xsstrike
    ok "xsstrike"
  else
    PY_FAILURES+=("xsstrike")
  fi
fi

if ! command -v wpscan >/dev/null 2>&1; then
  gem install wpscan --no-document || warn "Could not install optional tool: wpscan"
fi

# Populate nuclei templates now so the first scan is ready to run.
if command -v nuclei >/dev/null 2>&1; then
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && id "$SUDO_USER" >/dev/null 2>&1; then
    TARGET_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    runuser -u "$SUDO_USER" -- env HOME="$TARGET_HOME" \
      nuclei -update-templates -silent || warn "Nuclei templates will update on first use"
  else
    nuclei -update-templates -silent || warn "Nuclei templates will update on first use"
  fi
fi

TOOLS=(
  subfinder amass httpx nmap whatweb waybackurls gau katana paramspider arjun
  nuclei nikto ffuf gobuster dirsearch sqlmap dalfox xsstrike commix gowitness
  interactsh-client trufflehog
)
MISSING=()
for tool in "${TOOLS[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || MISSING+=("$tool")
done

echo
if [ "${#MISSING[@]}" -gt 0 ]; then
  err "Toolchain incomplete. Missing: ${MISSING[*]}"
  exit 1
fi

ok "NexHunt toolchain ready (${#TOOLS[@]} tools)"
if command -v wpscan >/dev/null 2>&1; then
  ok "Optional WordPress scanner ready"
else
  warn "WPScan was not installed; the rest of NexHunt is ready"
fi
