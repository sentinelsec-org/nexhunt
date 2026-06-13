<div align="center">

```
███╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
████╗  ██║██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██╔██╗ ██║█████╗   ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║
██║╚██╗██║██╔══╝   ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║
██║ ╚████║███████╗██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
```

**Bug Bounty Automation Platform for Linux**

[![Version](https://img.shields.io/badge/version-1.2.0--beta-amber?style=flat-square)](https://github.com/sentinelsec-org/nexhunt/releases)
[![Platform](https://img.shields.io/badge/platform-Linux-green?style=flat-square)]()
[![License](https://img.shields.io/badge/license-Free%20%2F%20PRO-blue?style=flat-square)](https://sentinelsec-org.github.io/nexhunt/#pricing)
[![Made by](https://img.shields.io/badge/by-Sentinel%20Security-green?style=flat-square)](https://sentinelsec.online)

**[Download Free](https://github.com/sentinelsec-org/nexhunt/releases/latest)** · **[Get PRO](https://sentinelsec-org.github.io/nexhunt/#pricing)** · **[sentinelsec.online](https://sentinelsec.online)**

> ⚠️ **Beta release** — actively developed. Core features are stable. New tools and improvements drop regularly.

</div>

---

## What is NexHunt?

NexHunt is a **desktop app for bug bounty hunters and penetration testers** that replaces your messy collection of terminal tabs, scripts, and notes with a single, integrated workflow.

From the moment you create a project, NexHunt guides you through the full attack surface — from subdomain discovery all the way to exploiting findings and generating reports. Every tool's output feeds the next phase automatically. You find more, faster.

It runs **locally on your Linux machine**. No cloud, no data sent anywhere (except the PRO AI Copilot, which routes through Sentinel's privacy-respecting proxy). Your findings stay yours.

---

## 🗺️ The full workflow, in one app

### 🔍 Reconnaissance

![NexHunt Recon — subfinder, amass, httpx and gowitness pipeline running against mcdonalds.com.ar. 13 subdomains found, 10 live hosts probed, 282 endpoints discovered, screenshots captured automatically.](docs/screenshots/recon-pipeline.png)

> Real session: subfinder enumerated subdomains on mcdonalds.com.ar, httpx probed all of them in parallel, gowitness screenshotted every live host automatically.

The most complete recon pipeline you can run from a single button.

- **Subdomain enumeration** — subfinder + amass running in parallel, results merged and deduplicated automatically
- **Live host probing** — httpx identifies status codes, technologies, titles, and response fingerprints across all discovered hosts
- **Port scanning** — nmap on all live hosts, with service detection
- **Web crawling** — katana and linkfinder extract every endpoint, JS file, and form from live targets
- **URL history** — gau + waybackurls pull years of archived URLs from Wayback Machine and Common Crawl
- **Parameter discovery** — paramspider and arjun find hidden HTTP parameters across all collected URLs
- **Endpoint analysis** — analyzes discovered endpoints for interesting patterns, auth requirements, and potential attack surface
- **Screenshots** — gowitness automatically screenshots every live host so you can triage visually

> 💡 The **Full Recon** mode chains all of the above into one pipeline that runs while you grab a coffee.

---

### 🎯 Vulnerability Scanning

Find what's actually exploitable, not just what's detectable.

- **Nuclei** — 8,000+ community templates covering CVEs, misconfigurations, exposures, default credentials, and more. NexHunt pre-loads **OWASP Top 10 presets** and lets you run targeted scans per technology
- **CVE Correlation** — automatically matches discovered technologies (nginx, Apache, WordPress, Spring...) to known CVEs and runs targeted nuclei templates. One click per tech stack
- **Directory brute-force** — ffuf, gobuster, and dirsearch with smart wordlist selection based on detected server type
- **Web server audit** — nikto catches misconfigurations, outdated headers, and known server vulnerabilities

---

### 💥 Exploitation

Validate findings. Prove impact. Write better reports.

- **SQLi** — sqlmap on discovered parameters, automatically handles WAF evasion, tamper scripts, and DB enumeration
- **XSS** — dalfox (fast, accurate) and xsstrike (deep DOM analysis) on all collected endpoints
- **Command injection** — commix on forms and parameters with command injection indicators
- **SSRF / Open redirect** — interactsh-backed testing for out-of-band vulnerabilities
- **JWT attack suite** — 10 attacks (alg:none, empty signature, RS256→HS256 confusion, weak secret brute force, kid header injection, jku/x5u SSRF, privilege escalation, and more) with step-by-step guidance per attack

![NexHunt JWT Attacks — 10 JWT attack techniques with severity ratings (CRITICAL/HIGH/MED). Empty Signature attack selected, showing step-by-step instructions and a Run Attack button.](docs/screenshots/jwt-attacks.png)

---

### 🛡️ Security Tools

Specialized checks that most scanners miss.

- **CORS misconfiguration** — tests origin reflection, credential exposure, and wildcard policies across all live hosts
- **403 Bypass** — tries 20+ bypass techniques (header injection, path normalization, verb tampering) on forbidden endpoints
- **Cloud bucket exposure** — discovers misconfigured S3, GCS, and Azure Blob buckets associated with the target
- **GitHub secret scanning** — TruffleHog scans the target org's public repositories for leaked credentials, API keys, and tokens
- **OOB interaction** — interactsh listener for DNS/HTTP callbacks from blind injection points

---

### 🔀 Proxy & Traffic Analysis

Your HTTP Swiss knife, built into the workflow.

- **Live traffic capture** — intercept and inspect every request from your browser through NexHunt's proxy
- **Request editor** — modify and replay any captured request with full header and body control
- **HTTP Repeater** — save interesting requests and replay with modifications
- **Site Map** — Burp-style host/path tree built automatically from captured traffic
- **Proxy Intruder** *(PRO)* — automated fuzzing with cluster bomb and pitchfork attack modes, payload wordlists, and response filtering

![NexHunt Proxy Site Map — host/path tree built automatically from 44 captured requests across digitalproducts-test.mcdonalds.com.ar and www.mcdonalds.com.ar](docs/screenshots/proxy-sitemap.png)

---

### 🤖 AI Copilot *(PRO)*

A security-focused AI assistant that actually understands your findings.

- **Host analysis** — paste a hostname, get a full attack surface breakdown: what to look for, what tools to run, what vulnerabilities are likely given the tech stack
- **Finding analysis** — describe a behavior and get confirmation on severity, exploitation path, and report wording
- **Attack suggestions** — given your live hosts and discovered tech, get a prioritized list of what to attack next
- **Report generation** — turns your findings into a professional vulnerability report, ready to submit
- **Free-form chat** — ask anything security-related, get answers grounded in your current project context

The AI runs on Sentinel's hosted infrastructure. Your Groq/LLM API key is never needed — just your PRO license.

---

### ⚙️ More features

- **Projects** — full project isolation. Findings, recon data, notes, and settings are scoped per target
- **Findings database** — structured storage for every vulnerability found, with severity, evidence, and status tracking
- **Methodology** — built-in pentest methodology guide covering all phases, attack techniques, and checklists
- **Workspace** — notes, custom wordlists, and session data per project
- **Built-in terminal** — run arbitrary commands without leaving the app
- **Session management** — set cookies and extra headers globally for all requests through the proxy
- **Auto-update** — NexHunt checks for new releases and updates itself with one click

---

## 🆓 Free vs ⭐ PRO

The free tier is genuinely useful. No time limits, no feature degradation, no nag screens.

| Feature | Free | PRO |
|---|:---:|:---:|
| Full recon suite (subfinder, amass, httpx, nmap, katana, gau...) | ✅ | ✅ |
| Screenshot all hosts (gowitness) | ✅ | ✅ |
| Single-target scanner (nuclei, ffuf, nikto, gobuster, dirsearch) | ✅ | ✅ |
| CVE correlation per technology | ✅ | ✅ |
| Single-target exploitation (sqlmap, dalfox, xsstrike, commix) | ✅ | ✅ |
| Security tools (CORS, 403 bypass, cloud buckets, GitHub secrets) | ✅ | ✅ |
| Proxy capture + request editor + repeater | ✅ | ✅ |
| Findings database + projects + methodology | ✅ | ✅ |
| Built-in terminal + session management | ✅ | ✅ |
| **AI Copilot** (analysis, tips, report generation) | ❌ | ✅ |
| **Automated pipelines** (full XSS/SQLi/JS chain) | ❌ | ✅ |
| **Bulk scanning** (nuclei-bulk, full recon on all hosts) | ❌ | ✅ |
| **Bulk takeover check** across all discovered subdomains | ❌ | ✅ |
| **Endpoint check** across all discovered URLs | ❌ | ✅ |
| **Bulk CORS** scan across all live hosts | ❌ | ✅ |
| **Proxy Intruder** (cluster bomb / pitchfork) | ❌ | ✅ |
| **JWT attack suite** (algorithm confusion, key injection, claim forgery) | ❌ | ✅ |
| **Business logic testing** (IDOR, race conditions, param fuzzing) | ❌ | ✅ |
| Priority support | ❌ | ✅ |

**[→ Get PRO at sentinelsec.online](https://sentinelsec-org.github.io/nexhunt/#pricing)**

---

## ⚡ Installation

### One-liner

```bash
curl -fsSL https://github.com/sentinelsec-org/nexhunt/releases/download/v1.2.0/nexhunt-1.2.0.tar.gz | tar xz && sudo bash install.sh
```

The installer:
- Installs all 20+ security tools (nmap, nuclei, subfinder, ffuf, sqlmap, dalfox, gowitness, katana, gau, waybackurls, gobuster, nikto, dirsearch, commix, arjun, paramspider, xsstrike, amass, httpx, interactsh...)
- Sets up the Python backend in an isolated venv
- Builds the Electron frontend
- Adds `nexhunt` to your PATH
- Creates a `.desktop` entry for your app launcher

### Requirements

| Requirement | Notes |
|---|---|
| Linux | Kali, Debian, Ubuntu — tested on Kali 2024+ |
| Python 3.10+ | Available on all supported distros |
| Node.js 18+ | Installed automatically if missing |
| Go 1.21+ | Installed automatically if missing |
| ~2 GB disk | For all tools + venv + build |
| Internet | For initial install only |

### Update

```bash
sudo bash install.sh --update
```

Or from inside the app: **Settings → Updates → Check for updates**.

---

## 🔑 PRO License

1. Purchase at **[sentinelsec.online/pricing](https://sentinelsec-org.github.io/nexhunt/#pricing)**
2. Open NexHunt → **Settings → License**
3. Paste your key → **Activate**

- License is bound to your machine (hardware fingerprint)
- Validates online every 24h — works offline for up to 7 days
- Transfer to a new machine: deactivate first, then activate on the new one
- Questions: reach us at [sentinelsec.online](https://sentinelsec.online)

---

## 🛣️ Roadmap

- [ ] PDF / HTML professional report export
- [ ] Premium nuclei templates and custom wordlists (PRO)
- [ ] Windows support
- [ ] Team/shared project mode
- [ ] Scheduled automated scans
- [ ] API mode for CI/CD integration

Have a feature request? [Open an issue](https://github.com/sentinelsec-org/nexhunt/issues) — we read everything.

---

## 🐛 Known issues (beta)

- Very large targets (1000+ subdomains) may slow down the UI during recon — we're working on pagination
- gowitness requires a display server; headless environments need Xvfb
- amass is slow by design — use subfinder for faster results if time is tight

---

## 📄 License

NexHunt is proprietary software. The **free tier** is free to use indefinitely for personal and professional bug bounty work. The **PRO tier** requires a paid license. See [sentinelsec.online](https://sentinelsec.online) for terms.

---

<div align="center">

Built with 🖤 by **[Sentinel Security](https://sentinelsec.online)**

*NexHunt v1.2.0 beta — Linux*

</div>
