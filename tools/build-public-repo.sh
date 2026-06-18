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

cat > "$OUT/README.md" <<'README'
# NexHunt

Bug bounty automation for Linux. NexHunt brings recon, scanning, proxy workflows, exploitation helpers, findings, and optional PRO automation into one desktop app.

> This public repository intentionally does **not** contain the application source code. Public users install signed release artifacts generated from the private build pipeline.

## Download

- Latest release: https://github.com/sentinelsec-org/nexhunt/releases/latest
- NexHunt PRO lifetime: https://nexhunt.myshopify.com/products/nexhunt-pro

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/sentinelsec-org/nexhunt/main/install.sh | sudo bash
```

The installer downloads the latest `.deb` from GitHub Releases when available. If no `.deb` is published for that release, it falls back to the `.tar.gz` bundle.

Manual install:

```bash
curl -L -o nexhunt.deb https://github.com/sentinelsec-org/nexhunt/releases/latest/download/nexhunt_1.2.0_amd64.deb
sudo apt install ./nexhunt.deb
```

## What You Get

- Full recon workflow: subdomains, live hosts, screenshots, crawling, archived URLs, parameters, ports.
- Vulnerability scanning: Nuclei, CVE correlation, ffuf/gobuster/dirsearch, Nikto.
- Exploitation helpers: SQLi, XSS, command injection, SSRF/OOB, JWT attacks.
- Proxy workflow: capture, repeater, site map, request replay.
- Project database, findings, methodology, workspace, and terminal.
- PRO: AI Copilot, automated pipelines, bulk attacks, Proxy Intruder, WordPress suite, business logic tooling.

## Requirements

- Linux: Kali, Debian, Ubuntu.
- Python 3.10+.
- Node.js 18+.
- Internet for install and tool downloads.
- Around 2 GB disk space once external tools are installed.

## PRO License

Buy NexHunt PRO from Shopify:

https://nexhunt.myshopify.com/products/nexhunt-pro

After payment, the license key is emailed automatically from `NexHunt <license@sentinelsec.online>`. Activate it inside NexHunt under Settings -> License.

## Source Code

The source code is private. This repo is only the public installer and release channel.

Generated from private build pipeline.
README

cat > "$OUT/README.es.md" <<'README'
# NexHunt

NexHunt es una app de escritorio para Linux orientada a bug bounty y pentesting.

Este repositorio publico intencionalmente **no** contiene el codigo fuente de la aplicacion.
Los instaladores y artefactos de release se publican desde el pipeline privado.

## Descargar

- Descarga gratis: https://github.com/sentinelsec-org/nexhunt/releases/latest
- NexHunt PRO: https://nexhunt.myshopify.com/products/nexhunt-pro

## Instalar

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/sentinelsec-org/nexhunt/main/install.sh | sudo bash
\`\`\`

O descarga el ultimo \`.deb\` o \`.tar.gz\` desde GitHub Releases.

Generado desde el pipeline privado.
README

cat > "$OUT/install.sh" <<'INSTALL'
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
INSTALL

cat > "$OUT/.gitignore" <<'GITIGNORE'
*
!.gitignore
!README.md
!README.es.md
!install.sh
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
