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
