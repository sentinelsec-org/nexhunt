from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class XsstrikeAdapter(ToolAdapter):
    name = "xsstrike"
    binary_name = "xsstrike"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [self.binary_name, "-u", target, "--skip-dom"]
        cmd = self._with_extra_args(cmd, options)

        async for line in self._run_subprocess(cmd, timeout=300):
            lower = line.lower()
            if "xss" in lower and ("found" in lower or "vulnerable" in lower or "payload" in lower):
                yield {
                    "id": None,
                    "title": f"[XSStrike] XSS — {target}",
                    "severity": "high",
                    "vuln_type": "xss",
                    "url": target,
                    "parameter": None,
                    "evidence": line.strip(),
                    "description": "Cross-Site Scripting detected by XSStrike",
                    "tool": "xsstrike",
                    "template_id": None,
                    "status": "new",
                    "notes": None,
                }
