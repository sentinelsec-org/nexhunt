import re
import os
import logging
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST = "/home/kali/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
FALLBACK_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"
FALLBACK_WORDLIST2 = "/usr/share/wordlists/dirb/common.txt"


class GobusterAdapter(ToolAdapter):
    name = "gobuster"
    binary_name = "gobuster"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        wordlist = options.get("wordlist", "")
        if not wordlist or not os.path.exists(wordlist):
            if os.path.exists(DEFAULT_WORDLIST):
                wordlist = DEFAULT_WORDLIST
            elif os.path.exists(FALLBACK_WORDLIST):
                wordlist = FALLBACK_WORDLIST
            else:
                wordlist = FALLBACK_WORDLIST2

        threads = str(options.get("threads", 20))
        extensions = options.get("extensions", "")
        match_codes = options.get("match_codes", "")
        exclude_len = options.get("exclude_length", "")
        cookie = options.get("cookie", "") or options.get("session_cookies", "")
        session_headers = options.get("session_headers", "")

        # stdbuf -oL forces line-buffered stdout so lines stream in real-time
        # instead of being held in the pipe buffer until process exits
        cmd = [
            "stdbuf", "-oL",
            self.binary_name, "dir",
            "-u", target,
            "-w", wordlist,
            "-t", threads,
            "--no-color",
            "--no-progress",
        ]

        if match_codes:
            # gobuster 3.6+ requires clearing the default blacklist (404) when
            # using -s, otherwise it errors: "status-codes and status-codes-blacklist
            # are both set". Pass an empty string to disable the blacklist.
            cmd.extend(["-s", match_codes, "--status-codes-blacklist", ""])
        if exclude_len:
            cmd.extend(["--exclude-length", exclude_len])
        if extensions:
            cmd.extend(["-x", extensions])
        if cookie:
            cmd.extend(["-c", cookie])
        if session_headers:
            for h in session_headers.replace("\r", "").split("\n"):
                h = h.strip()
                if h and ":" in h:
                    cmd.extend(["-H", h])

        # Gobuster output lines look like:
        # /admin                (Status: 200) [Size: 3495, Words: 425, Lines: 68, Duration: 1ms]
        # /.htaccess            (Status: 403) [Size: 276]
        pattern = re.compile(
            r"\s*(/?[^\s(]+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)",
            re.IGNORECASE,
        )

        cmd = self._with_extra_args(cmd, options)
        logger.info(f"[gobuster] cmd: {' '.join(cmd)}")
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}

        # merge_stderr=True so connection errors / auth errors appear in the
        # terminal instead of being silently dropped into the debug log
        async for line in self._run_subprocess(cmd, timeout=1800, merge_stderr=True):
            line = line.strip()
            if not line:
                continue

            # Always stream raw line to terminal output
            yield {"_raw": True, "line": line}

            match = pattern.search(line)
            if not match:
                continue

            path, status, size = match.groups()
            if not path.startswith("/"):
                path = "/" + path
            status_int = int(status)

            # Severity mapping for directory brute-force results:
            # 200/204 = real content → medium (potentially exploitable)
            # 301/302 = redirect   → info
            # 401/403 = exists but restricted → low (good to know)
            # everything else      → info
            if status_int in (200, 204):
                severity = "medium"
            elif status_int in (401, 403):
                severity = "low"
            else:
                severity = "info"

            yield {
                "_raw": False,
                "id": None,
                "title": f"[Gobuster] {path} ({status})",
                "severity": severity,
                "vuln_type": "directory-listing",
                "url": f"{target.rstrip('/')}{path}",
                "parameter": None,
                "evidence": f"Status: {status} | Size: {size} bytes",
                "description": "Path discovered via directory brute-force",
                "tool": "gobuster",
                "template_id": None,
                "status": "new",
                "notes": None,
            }
