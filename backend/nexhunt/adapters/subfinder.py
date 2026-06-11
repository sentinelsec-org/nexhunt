import json
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    binary_name = "subfinder"
    result_type = "subdomain"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [self.binary_name, "-d", target, "-json", "-silent"]
        if options.get("recursive"):
            cmd.append("-recursive")

        cmd = self._with_extra_args(cmd, options)
        async for line in self._run_subprocess(cmd):
            try:
                data = json.loads(line)
                yield {
                    "subdomain": data.get("host", ""),
                    "source": data.get("source", "subfinder"),
                    "ip": data.get("ip", None),
                    "status_code": None,
                }
            except (json.JSONDecodeError, KeyError):
                continue
