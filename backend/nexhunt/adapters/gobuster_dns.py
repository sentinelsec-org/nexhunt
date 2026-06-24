import re
import os
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

DEFAULT_WORDLIST = "/home/kali/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
FALLBACK_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
FALLBACK_WORDLIST2 = "/usr/share/wordlists/dnsmap.txt"

_FOUND_RE = re.compile(r'Found:\s+([a-zA-Z0-9._-]+)(?:\s+\[([^\]]+)\])?')


class GobusterDnsAdapter(ToolAdapter):
    name = "gobuster-dns"
    binary_name = "gobuster"
    result_type = "subdomain"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        wordlist = options.get("wordlist", "")
        if not wordlist or not os.path.exists(wordlist):
            if os.path.exists(DEFAULT_WORDLIST):
                wordlist = DEFAULT_WORDLIST
            elif os.path.exists(FALLBACK_WORDLIST):
                wordlist = FALLBACK_WORDLIST
            else:
                wordlist = FALLBACK_WORDLIST2

        threads = str(options.get("threads", 50))
        resolver = options.get("resolver", "")

        cmd = [
            "stdbuf", "-oL",
            self.binary_name, "dns",
            "--domain", target,
            "-w", wordlist,
            "-t", threads,
            "--no-color",
            "--wildcard",
        ]
        if resolver:
            cmd.extend(["--resolver", resolver])

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}

        async for line in self._run_subprocess(cmd, timeout=1800, merge_stderr=True):
            line = line.strip()
            if not line:
                continue
            yield {"_raw": True, "line": line}

            m = _FOUND_RE.search(line)
            if not m:
                continue
            subdomain = m.group(1).lower().rstrip(".")
            ip_raw = (m.group(2) or "").strip()
            ip = ip_raw.split(",")[0].strip() if ip_raw else None

            yield {
                "subdomain": subdomain,
                "source": "gobuster-dns",
                "ip": ip,
                "status_code": None,
            }
