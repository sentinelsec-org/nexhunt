import os
import re
import shutil
import asyncio
from urllib.parse import urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter
from nexhunt.config import settings


def _url_to_filename(url: str) -> str:
    """Convert a URL to a safe filename, same format gowitness used."""
    return re.sub(r'[^\w\-.]', '-', url.rstrip('/')) + '.jpeg'


class GowitnessAdapter(ToolAdapter):
    name = "gowitness"
    binary_name = "chromium"
    result_type = "screenshot"

    async def check_installed(self) -> bool:
        return bool(
            shutil.which("chromium") or
            shutil.which("chromium-browser") or
            shutil.which("google-chrome")
        )

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        screenshots_dir = options.get("screenshots_dir", settings.screenshots_dir)
        os.makedirs(screenshots_dir, exist_ok=True)

        chromium = (
            shutil.which("chromium") or
            shutil.which("chromium-browser") or
            shutil.which("google-chrome")
        )

        filename = _url_to_filename(target)
        out_path = os.path.join(screenshots_dir, filename)

        cookie = options.get("cookie", "") or options.get("session_cookies", "")

        cmd = [
            chromium,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            f"--screenshot={out_path}",
            "--window-size=1280,720",
            "--virtual-time-budget=5000",
            "--hide-scrollbars",
        ]

        if cookie:
            parsed = urlparse(target)
            cmd.append(f"--cookie={parsed.netloc}={cookie}")

        session_headers = options.get("session_headers", "")
        if session_headers:
            for h in session_headers.replace("\n", ",").split(","):
                h = h.strip()
                if h and ":" in h:
                    cmd.extend(["--add-headers", h])

        cmd.append(target)

        yield {"_raw": True, "line": f"[screenshot] Capturing {target}..."}

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            yield {"_raw": True, "line": f"[screenshot] Timeout for {target}"}
            return

        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            yield {
                "_raw": False,
                "url": target,
                "path": out_path,
                "filename": filename,
                "screenshot_url": f"/screenshots/{filename}",
            }
        else:
            err = stderr.decode(errors="replace").strip().splitlines()
            hint = next((l for l in err if "error" in l.lower()), err[-1] if err else "no output")
            yield {"_raw": True, "line": f"[screenshot] Failed for {target}: {hint}"}
