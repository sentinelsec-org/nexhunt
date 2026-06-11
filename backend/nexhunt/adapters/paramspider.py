from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class ParamspiderAdapter(ToolAdapter):
    name = "paramspider"
    binary_name = "paramspider"
    result_type = "url"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [self.binary_name, "-d", target, "--quiet"]
        cmd = self._with_extra_args(cmd, options)

        async for line in self._run_subprocess(cmd):
            url = line.strip()
            if url.startswith("http") and "=" in url:
                yield {
                    "url": url,
                    "source": "paramspider",
                    "status_code": None,
                    "content_type": None,
                }
