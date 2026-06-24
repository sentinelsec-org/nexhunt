import os
import re
import socket
import uuid
import httpx
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

DEFAULT_WORDLIST = "/home/kali/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
FALLBACK_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
FALLBACK_WORDLIST2 = "/usr/share/wordlists/dnsmap.txt"

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mKJH]|\[2K')
_RESULT_RE = re.compile(r'^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)')


class VhostFuzzerAdapter(ToolAdapter):
    name = "vhost-fuzzer"
    binary_name = "ffuf"
    result_type = "subdomain"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        wordlist = options.get("wordlist", "")
        if not wordlist or not os.path.exists(wordlist):
            for wl in [DEFAULT_WORDLIST, FALLBACK_WORDLIST, FALLBACK_WORDLIST2]:
                if os.path.exists(wl):
                    wordlist = wl
                    break

        port = str(options.get("port", "80"))
        threads = str(options.get("threads", "50"))
        scheme = "https" if port == "443" else "http"

        # Resolve domain to IP so vhost fuzzing hits the right server
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target

        port_suffix = "" if port in ("80", "443") else f":{port}"
        base_url = f"{scheme}://{ip}{port_suffix}"

        # Auto-detect baseline: random subdomain that won't exist
        fake_host = f"{uuid.uuid4().hex[:12]}.{target}"
        baseline_size = None
        try:
            async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False) as client:
                resp = await client.get(base_url, headers={"Host": fake_host})
                baseline_size = len(resp.content)
        except Exception:
            pass

        filter_arg = options.get("filter_size", str(baseline_size) if baseline_size is not None else "")

        cmd = [
            self.binary_name,
            "-w", wordlist,
            "-u", base_url,
            "-H", f"Host: FUZZ.{target}",
            "-mc", "all",
            "-t", threads,
            "-timeout", "5",
            "-noninteractive",
            "-ic",
        ]
        if filter_arg:
            cmd.extend(["-fs", filter_arg])

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        yield {"_raw": True, "line": f"  Target IP: {ip} | Baseline size: {baseline_size}b (filtered out)"}

        async for raw_line in self._run_subprocess(cmd, timeout=1800, merge_stderr=True):
            line = _ANSI_RE.sub("", raw_line).strip()
            if not line:
                continue
            yield {"_raw": True, "line": line}

            m = _RESULT_RE.match(line)
            if not m:
                continue
            word, status, _size = m.group(1), int(m.group(2)), m.group(3)
            subdomain = f"{word}.{target}"
            yield {
                "subdomain": subdomain,
                "source": "vhost-fuzzer",
                "ip": ip,
                "status_code": status,
            }
