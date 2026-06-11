import json
import os
import tempfile
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class ArjunAdapter(ToolAdapter):
    name = "arjun"
    binary_name = "arjun"
    result_type = "url"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        fd, outfile = tempfile.mkstemp(suffix=".json", prefix="arjun_")
        os.close(fd)

        cmd = [self.binary_name, "-u", target, "--stable", "-oJ", outfile]
        if options.get("method"):
            cmd.extend(["-m", options["method"]])
        cmd = self._with_extra_args(cmd, options)

        try:
            # Consume subprocess output (arjun logs progress to stdout)
            async for _ in self._run_subprocess(cmd, timeout=300):
                pass

            # Read the JSON results file after subprocess completes
            if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
                with open(outfile) as f:
                    data = json.load(f)

                # arjun JSON format: {"url": [...params...]} or list of {url, params}
                if isinstance(data, dict):
                    for url, params in data.items():
                        for param in (params if isinstance(params, list) else []):
                            yield {
                                "url": f"{url}?{param}=FUZZ",
                                "source": "arjun",
                                "status_code": None,
                                "content_type": None,
                            }
                elif isinstance(data, list):
                    for entry in data:
                        url = entry.get("url", target)
                        for param in entry.get("params", []):
                            yield {
                                "url": f"{url}?{param}=FUZZ",
                                "source": "arjun",
                                "status_code": None,
                                "content_type": None,
                            }
        finally:
            if os.path.exists(outfile):
                os.unlink(outfile)
