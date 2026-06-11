import re
import subprocess
import asyncio
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

LINKFINDER_PATH = "/opt/linkfinder/linkfinder.py"


class LinkFinderAdapter(ToolAdapter):
    name = "linkfinder"
    binary_name = "python3"
    result_type = "url"

    async def check_installed(self) -> bool:
        import os
        return os.path.exists(LINKFINDER_PATH)

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cookie = options.get("cookie", "") or options.get("session_cookies", "")
        domain_mode_raw = options.get("domain_mode", False)
        domain_mode = domain_mode_raw is True or str(domain_mode_raw).lower() == 'true'

        # -d crawls the whole domain recursively collecting all JS files
        # without -d it just parses the single given URL/file
        cmd = [
            "python3", LINKFINDER_PATH,
            "-i", target,
            "-o", "cli",
        ]

        if domain_mode:
            cmd.append("-d")

        if cookie:
            cmd.extend(["-c", cookie])

        cmd = self._with_extra_args(cmd, options)

        seen: set[str] = set()

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").strip()
            if not line or line in seen:
                continue
            seen.add(line)

            # Skip obviously bad lines (HTML output, etc.)
            if line.startswith("<") or line.startswith("Running"):
                continue

            # Normalise: add host if relative path
            url = line
            if url.startswith("/") and not url.startswith("//"):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                url = base + url
            elif not url.startswith("http") and not url.startswith("/"):
                # likely a relative path fragment, prefix with base
                from urllib.parse import urlparse
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                url = base + "/" + url

            has_params = "?" in url and "=" in url
            yield {
                "url": url,
                "raw": line,
                "method": "GET",
                "source": "linkfinder",
                "status_code": None,
                "content_type": None,
                "has_params": has_params,
                "is_form": False,
            }

        await proc.wait()
