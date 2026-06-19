"""
WPScan adapter — WordPress black-box security scanner.

Runs wpscan with the default CLI output (streamed live to the terminal) and
parses the recognizable line markers into structured results as they arrive:
version, theme, plugins, users, vulnerabilities, interesting findings and
config/db backups. Vulnerabilities are emitted as findings; everything else
is emitted as typed `wp_*` recon results.
"""
import re
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

# Scan profiles -> --enumerate value + detection mode
PROFILES = {
    # version + interesting findings only (passive, fast, no plugin brute)
    "quick":    {"enumerate": None,                          "plugins_detection": "passive"},
    # vuln plugins/themes, timthumbs, config backups, db exports, users, media
    "standard": {"enumerate": "vp,vt,tt,cb,dbe,u,m",         "plugins_detection": "mixed"},
    # all plugins/themes aggressively + wider user range
    "thorough": {"enumerate": "ap,at,tt,cb,dbe,u1-30,m",     "plugins_detection": "aggressive"},
}

_VULN_KEYWORDS = ("rce", "remote code", "sql injection", "sqli", "arbitrary file upload",
                  "authentication bypass", "auth bypass", "deserialization", "unauthenticated")
_MED_KEYWORDS = ("xss", "cross-site scripting", "csrf", "ssrf", "lfi", "open redirect", "disclosure")


def _vuln_severity(title: str) -> str:
    t = title.lower()
    if any(k in t for k in _VULN_KEYWORDS):
        return "high"
    if any(k in t for k in _MED_KEYWORDS):
        return "medium"
    return "low"


class WpscanAdapter(ToolAdapter):
    name = "wpscan"
    binary_name = "wpscan"
    result_type = "wordpress"

    def _build_cmd(self, target: str, options: dict) -> list[str]:
        profile = options.get("profile", "standard")
        conf = PROFILES.get(profile, PROFILES["standard"])

        cmd = [
            self.binary_name,
            "--url", target,
            "--no-banner",
            "--format", "cli-no-color",
            "--no-update",
        ]

        if conf["enumerate"]:
            cmd += ["--enumerate", conf["enumerate"]]
        cmd += ["--plugins-detection", conf["plugins_detection"]]

        if options.get("stealthy"):
            cmd.append("--stealthy")
        elif options.get("random_user_agent"):
            cmd.append("--random-user-agent")

        if options.get("disable_tls_checks"):
            cmd.append("--disable-tls-checks")
        if options.get("force"):
            cmd.append("--force")

        token = options.get("api_token", "")
        if token:
            cmd += ["--api-token", token]

        cookie = options.get("session_cookies", "") or options.get("cookie", "")
        if cookie:
            cmd += ["--cookie-string", cookie]

        headers = options.get("session_headers", "")
        if headers:
            for h in headers.replace("\n", ",").split(","):
                h = h.strip()
                if h and ":" in h:
                    cmd += ["--headers", h]

        # Password attack (optional, dangerous) — only when a wordlist is given
        passwords = options.get("passwords", "")
        if passwords:
            cmd += ["--passwords", passwords]
            usernames = options.get("usernames", "")
            if usernames:
                cmd += ["--usernames", usernames]
            attack = options.get("password_attack", "")
            if attack:
                cmd += ["--password-attack", attack]

        return self._with_extra_args(cmd, options)

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = self._build_cmd(target, options)
        # Redact the api token in the echoed command
        echo = []
        skip = False
        for part in cmd:
            if skip:
                echo.append("***")
                skip = False
                continue
            echo.append(part)
            if part == "--api-token":
                skip = True
        yield {"_raw": True, "line": "$ " + " ".join(echo)}

        section = None   # tracks the current "[i] X Identified:" block

        async for line in self._run_subprocess(cmd, timeout=900):
            # Always stream the raw line to the terminal
            yield {"_raw": True, "line": line}

            stripped = line.strip()

            # Section headers
            m = re.match(r"\[i\]\s+(Plugin\(s\)|Theme\(s\)|User\(s\)|Config Backup\(s\))", stripped)
            if m:
                head = m.group(1)
                section = ("plugin" if "Plugin" in head else
                           "theme" if "Theme" in head else
                           "user" if "User" in head else
                           "config_backup")
                continue

            # WordPress version
            mv = re.search(r"WordPress version ([\d.]+) identified \(([^,)]+)", stripped)
            if mv:
                yield {"kind": "version", "value": mv.group(1),
                       "status": mv.group(2).strip(), "raw": stripped}
                continue

            # Theme in use (explicit line)
            mt = re.search(r"WordPress theme in use:\s*(\S+)", stripped)
            if mt:
                yield {"kind": "theme", "name": mt.group(1), "raw": stripped}
                continue

            # Vulnerability title (requires API token to appear)
            mvuln = re.match(r"\[!\]\s+Title:\s*(.+)", stripped)
            if mvuln:
                title = mvuln.group(1).strip()
                yield {"kind": "vuln", "title": title,
                       "severity": _vuln_severity(title), "url": target}
                continue

            # Interesting findings
            mi = re.match(r"\[\+\]\s+(.*(?:XML-RPC|xmlrpc|readme|Upload directory|directory listing|"
                          r"debug log|wp-cron|robots|Registration|WordPress readme|fpd|Full Path).*)",
                          stripped, re.IGNORECASE)
            if mi:
                yield {"kind": "interesting", "text": mi.group(1).strip(), "url": target}
                continue

            # Items under a section header: "[+] name"
            mitem = re.match(r"\[\+\]\s+(\S.*)$", stripped)
            if mitem and section:
                name = mitem.group(1).strip()
                # skip noise that is not an actual item name
                if name.lower().startswith(("url:", "started", "interesting", "finished",
                                            "requests done", "cached requests", "data sent",
                                            "data received", "memory used", "elapsed time",
                                            "wpscan db api")):
                    continue
                if section == "plugin":
                    yield {"kind": "plugin", "name": name, "url": target}
                elif section == "theme":
                    yield {"kind": "theme", "name": name, "url": target}
                elif section == "user":
                    yield {"kind": "user", "name": name, "url": target}
                elif section == "config_backup":
                    yield {"kind": "config_backup", "url": name}
                continue
