import json
import os
import shutil
import tempfile
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter
from nexhunt.services.privacy_route import _mask_proxy, privacy_route


def _resolve_httpx() -> str:
    """Return the ProjectDiscovery httpx binary, not the python3-httpx CLI.

    Both install a binary named `httpx`. On Kali, python3-httpx owns
    /usr/bin/httpx (a `#!`-script wrapper that has no -l/-u flags) and shadows
    the Go tool depending on PATH order, which breaks Probe All. Pick the real
    PD binary by skipping any wrapper script (the Go binary is ELF).
    """
    candidates = []
    tk = shutil.which("httpx-toolkit")
    if tk:
        candidates.append(tk)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, "httpx")
        if p not in candidates and os.path.isfile(p) and os.access(p, os.X_OK):
            candidates.append(p)
    candidates.append("/root/go/bin/httpx")
    for p in candidates:
        try:
            with open(p, "rb") as f:
                if f.read(2) == b"#!":  # python3-httpx wrapper script
                    continue
        except OSError:
            continue
        return p
    return "httpx"


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    binary_name = _resolve_httpx()
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
                    "-timeout", "10",
                    "-retries", "2",
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
                    "-timeout", "10",
                    "-retries", "2",
                ]

            # ProjectDiscovery httpx is written in Go and does not consistently
            # honor SOCKS URLs from HTTP_PROXY. Pass the active NexHunt route
            # explicitly so Tor/custom routing cannot turn Probe All into a
            # silent zero-result run.
            route_proxy = privacy_route.proxy_url if privacy_route.mode in {"tor", "custom"} else ""
            if route_proxy:
                cmd.extend(["-proxy", route_proxy])

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
            display_cmd = [_mask_proxy(part) if part == route_proxy else part for part in cmd]
            yield {"_raw": True, "line": "$ " + " ".join(display_cmd)}
            async for line in self._run_subprocess(cmd, timeout=300, check_exit=True):
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
