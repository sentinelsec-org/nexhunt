from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class AmassAdapter(ToolAdapter):
    name = "amass"
    binary_name = "amass"
    result_type = "subdomain"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        if options.get("active") or options.get("brute"):
            # Active resolution + DNS brute-force — finds hosts hidden behind wildcard certs
            cmd = [self.binary_name, "enum", "-active", "-brute", "-d", target, "-silent"]
        else:
            cmd = [self.binary_name, "enum", "-passive", "-d", target, "-silent"]
        cmd = self._with_extra_args(cmd, options)

        async for line in self._run_subprocess(cmd, timeout=600):
            line = line.strip()
            if line and "." in line and not line.startswith("["):
                yield {
                    "subdomain": line,
                    "source": "amass",
                    "ip": None,
                    "status_code": None,
                }
