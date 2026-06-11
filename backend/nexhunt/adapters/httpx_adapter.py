import json
import os
import tempfile
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    binary_name = "httpx"
    result_type = "url"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        # Support batch probing from a list of targets (e.g. found subdomains)
        targets_list = options.get("targets", [])

        tmpfile = None
        try:
            if targets_list:
                # Write all targets to a temp file and use -l flag
                fd, tmpfile = tempfile.mkstemp(suffix=".txt", prefix="httpx_")
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(targets_list))
                cmd = [
                    self.binary_name,
                    "-l", tmpfile,
                    "-json", "-silent",
                    "-follow-redirects",
                    "-title",
                    "-tech-detect",
                    "-status-code",
                    "-ip",
                ]
            else:
                cmd = [
                    self.binary_name,
                    "-u", target,
                    "-json", "-silent",
                    "-follow-redirects",
                    "-title",
                    "-tech-detect",
                    "-status-code",
                    "-ip",
                ]

            if options.get("threads"):
                cmd.extend(["-threads", str(options["threads"])])

            cookie = options.get("session_cookies", "")
            if cookie:
                cmd.extend(["-H", f"Cookie: {cookie}"])
            session_headers = options.get("session_headers", "")
            if session_headers:
                for h in session_headers.replace("\r", "").split("\n"):
                    h = h.strip()
                    if h and ":" in h:
                        cmd.extend(["-H", h])

            cmd = self._with_extra_args(cmd, options)
            yield {"_raw": True, "line": "$ " + " ".join(cmd)}
            async for line in self._run_subprocess(cmd, timeout=300):
                try:
                    data = json.loads(line)
                    # httpx JSON uses "status-code" (older) or "status_code" (newer)
                    status = data.get("status-code") or data.get("status_code")
                    techs = data.get("technologies") or data.get("tech") or []
                    if isinstance(techs, str):
                        techs = [techs]
                    yield {
                        "url": data.get("url", ""),
                        "host": data.get("host", data.get("input", "")),
                        "source": "httpx",
                        "status_code": status,
                        "content_type": data.get("content-type", data.get("content_type", "")),
                        "title": data.get("title", ""),
                        "technologies": techs,
                        "ip": data.get("a", [data.get("host", "")])[0] if isinstance(data.get("a"), list) else data.get("host", ""),
                        "alive": True,
                    }
                except (json.JSONDecodeError, KeyError):
                    continue
        finally:
            if tmpfile and os.path.exists(tmpfile):
                os.unlink(tmpfile)
