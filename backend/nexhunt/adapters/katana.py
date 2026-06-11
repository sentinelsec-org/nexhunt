from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class KatanaAdapter(ToolAdapter):
    name = "katana"
    binary_name = "katana"
    result_type = "url"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        depth = str(options.get("depth", 3))
        concurrency = str(options.get("concurrency", 10))
        rate_limit = str(options.get("rate_limit", 150))

        cmd = [
            self.binary_name,
            "-u", target,
            "-silent",
            "-no-color",
            "-depth", depth,
            "-concurrency", concurrency,
            "-rate-limit", rate_limit,
        ]

        if options.get("headless"):
            cmd.extend(["-hl", "-sc", "-no-sandbox"])

        if options.get("js_crawl", True):
            cmd.append("-jc")

        if options.get("crawl_forms", True):
            cmd.append("-aff")

        if options.get("scope"):
            cmd.extend(["-cs", options["scope"]])

        cookie = options.get("cookie", "") or options.get("session_cookies", "")
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])

        all_headers = options.get("headers", "") or options.get("session_headers", "")
        if all_headers:
            for h in all_headers.replace("\n", ",").split(","):
                h = h.strip()
                if h and ":" in h:
                    cmd.extend(["-H", h])

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        async for line in self._run_subprocess(cmd, timeout=600):
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            yield {
                "url": url,
                "method": "GET",
                "source": "katana",
                "status_code": None,
                "content_type": None,
                "has_params": "?" in url and "=" in url,
                "is_form": False,
            }
