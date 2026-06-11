# NexHunt

**Bug Bounty Automation Platform** by [Sentinel Security](https://sentinelsec.online)

> **Beta release** — actively developed. Expect rough edges. Feedback welcome via [Issues](https://github.com/sentinelsec-org/nexhunt/issues).

NexHunt is a Linux desktop app that automates the full bug bounty workflow: subdomain enumeration, live host probing, vulnerability scanning, exploitation, and AI-powered analysis — all from a single interface.

---

## Quick install

```bash
curl -fsSL https://github.com/sentinelsec-org/nexhunt/releases/download/v1.1.0/nexhunt-1.1.0.tar.gz | tar xz && sudo bash install.sh
```

Then run:

```bash
nexhunt
```

---

## What it does

| Phase | Tools |
|---|---|
| Recon | subfinder, amass, httpx, nmap, katana, gau, waybackurls, gowitness |
| Scanning | nuclei, ffuf, nikto, gobuster, dirsearch |
| Exploitation | sqlmap, dalfox, xsstrike, commix, paramspider, arjun |
| Proxy | capture, repeater, intruder (PRO) |
| Security tools | CORS scanner, 403 bypass, cloud bucket exposure, GitHub secret scanner, interactsh |
| AI Copilot | analysis, attack suggestions, report generation — **PRO** |

---

## Free vs PRO

| Feature | Free | PRO |
|---|:---:|:---:|
| Full recon suite | ✓ | ✓ |
| Single-target scanner | ✓ | ✓ |
| Single-target exploit | ✓ | ✓ |
| Proxy capture + repeater | ✓ | ✓ |
| Security tools | ✓ | ✓ |
| Findings DB, projects, methodology | ✓ | ✓ |
| AI Copilot (hosted) | — | ✓ |
| Automated pipelines (XSS/SQLi/JS) | — | ✓ |
| Bulk scanning (nuclei-bulk, full recon) | — | ✓ |
| Proxy Intruder (cluster bomb/pitchfork) | — | ✓ |
| JWT attack suite | — | ✓ |
| Business logic testing suite | — | ✓ |

[Get PRO →](https://sentinelsec.online/pricing)

---

## Requirements

- Linux (Kali, Debian, Ubuntu)
- Python 3.10+
- Node.js 18+
- Go 1.21+ (installed automatically if missing)
- Internet connection for initial tool installation

The installer handles everything else automatically.

---

## Activate PRO license

1. Purchase a license at [sentinelsec.online/pricing](https://sentinelsec.online/pricing)
2. Open NexHunt → Settings → License
3. Paste your license key and click Activate

PRO is machine-bound and validated online. Up to 7 days offline grace period.

---

## Update

```bash
sudo bash install.sh --update
```

Or use the in-app update notification (Settings → Updates).

---

## Issues and feedback

[github.com/sentinelsec-org/nexhunt/issues](https://github.com/sentinelsec-org/nexhunt/issues)

---

**Sentinel Security** — [sentinelsec.online](https://sentinelsec.online)
