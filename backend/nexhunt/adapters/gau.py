from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class GauAdapter(ToolAdapter):
    name = "gau"
    binary_name = "gau"
    result_type = "url"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [self.binary_name, target, "--threads", "5"]
        cmd = self._with_extra_args(cmd, options)

        async for line in self._run_subprocess(cmd):
            url = line.strip()
            if url.startswith("http"):
                yield {
                    "url": url,
                    "source": "gau",
                    "status_code": None,
                    "content_type": None,
                }
