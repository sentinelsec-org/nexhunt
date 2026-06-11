import re
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    binary_name = "nikto"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [self.binary_name, "-h", target, "-nointeractive", "-Format", "txt"]
        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}

        async for line in self._run_subprocess(cmd, timeout=300):
            # Nikto finding lines start with "+ "
            if line.startswith("+ ") and ":" in line:
                # Determine rough severity from content
                lower = line.lower()
                severity = "info"
                if any(w in lower for w in ["vuln", "exploit", "inject", "xss", "overflow"]):
                    severity = "medium"
                if any(w in lower for w in ["critical", "rce", "remote code"]):
                    severity = "high"

                yield {
                    "id": None,
                    "title": line[2:80],
                    "severity": severity,
                    "vuln_type": None,
                    "url": target,
                    "parameter": None,
                    "evidence": line[2:],
                    "description": None,
                    "tool": "nikto",
                    "template_id": None,
                    "status": "new",
                    "notes": None,
                }
