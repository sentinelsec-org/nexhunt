from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class WaybackurlsAdapter(ToolAdapter):
    name = "waybackurls"
    binary_name = "waybackurls"
    result_type = "url"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [self.binary_name, target]
        cmd = self._with_extra_args(cmd, options)

        async for line in self._run_subprocess(cmd):
            url = line.strip()
            if url.startswith("http"):
                yield {
                    "url": url,
                    "source": "waybackurls",
                    "status_code": None,
                    "content_type": None,
                }
