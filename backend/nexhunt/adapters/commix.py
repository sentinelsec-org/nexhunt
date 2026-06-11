from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class CommixAdapter(ToolAdapter):
    name = "commix"
    binary_name = "commix"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        cmd = [
            self.binary_name,
            "--url", target,
            "--batch",
            "--level", "2"
        ]
        cmd = self._with_extra_args(cmd, options)

        async for line in self._run_subprocess(cmd, timeout=300):
            yield line  # Raw output

            lower = line.lower()
            if "is vulnerable" in lower or "command injection" in lower:
                yield {
                    "id": None,
                    "title": "Command Injection vulnerability found",
                    "severity": "critical",
                    "vuln_type": "rce",
                    "url": target,
                    "parameter": None,
                    "evidence": line.strip(),
                    "description": "Command Injection - commix",
                    "tool": "commix",
                    "template_id": None,
                    "status": "new",
                    "notes": None,
                }
