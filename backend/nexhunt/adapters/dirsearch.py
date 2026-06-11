import re
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

DEFAULT_WORDLIST = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"


class DirsearchAdapter(ToolAdapter):
    name = "dirsearch"
    binary_name = "dirsearch"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        extensions = options.get("extensions", "php,asp,aspx,jsp,html,js,txt,json,xml,bak")
        threads = str(options.get("threads", 20))
        wordlist = options.get("wordlist", "")

        cmd = [
            self.binary_name,
            "-u", target,
            "--no-color", "-q",
            "-e", extensions,
            "-t", threads,
        ]

        if wordlist:
            cmd.extend(["-w", wordlist])

        cookie = options.get("cookie", "") or options.get("session_cookies", "")
        if cookie:
            cmd.extend(["--cookie", cookie])
        session_headers = options.get("session_headers", "")
        if session_headers:
            for h in session_headers.replace("\r", "").split("\n"):
                h = h.strip()
                if h and ":" in h:
                    cmd.extend(["-H", h])

        # dirsearch v0.4+ output: "[HH:MM:SS] 200 -    4KB - http://target/path"
        # older output:          "  200  1234B  /path"
        pattern_new = re.compile(r"\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+[\d.]+\w+\s+-\s+(https?://\S+)")
        pattern_old = re.compile(r"\s+(\d{3})\s+[\d.]+\w+\s+(/\S+)")

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        async for line in self._run_subprocess(cmd, timeout=1800):
            url_found = None
            status = None

            m = pattern_new.match(line)
            if m:
                status, url_found = m.groups()
                # Extract path from full URL
                try:
                    from urllib.parse import urlparse
                    path = urlparse(url_found).path or "/"
                except Exception:
                    path = "/"
            else:
                m = pattern_old.match(line)
                if m:
                    status, path = m.groups()
                    url_found = f"{target.rstrip('/')}{path}"

            if status and url_found:
                status_int = int(status)
                severity = "low" if status_int == 200 else "info"
                yield {
                    "id": None,
                    "title": f"[Dirsearch] {path} ({status})",
                    "severity": severity,
                    "vuln_type": "directory-listing",
                    "url": url_found,
                    "parameter": None,
                    "evidence": f"Status: {status}",
                    "description": "Path found via directory scan",
                    "tool": "dirsearch",
                    "template_id": None,
                    "status": "new",
                    "notes": None,
                }
