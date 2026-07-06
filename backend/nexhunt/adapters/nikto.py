import re
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    binary_name = "nikto"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        # `-Format` is only meaningful when Nikto writes a report. Without an
        # explicit `-output`, Nikto 2.6 tries to create an auto-named file in
        # its process working directory (often /var/lib/nikto), which is not
        # writable by the NexHunt desktop user. NexHunt consumes stdout, so no
        # report file is needed here.
        cmd = [self.binary_name, "-h", target, "-nointeractive"]
        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}

        timeout = int(options.get("timeout", 900))
        async for line in self._run_subprocess(cmd, timeout=timeout, merge_stderr=True, check_exit=True):
            clean = line.replace("[STDERR] ", "")
            yield {"_raw": True, "line": clean}
            # Nikto finding lines start with "+ "
            if clean.startswith("+ ") and ":" in clean:
                # Determine rough severity from content
                lower = clean.lower()
                severity = "info"
                if any(w in lower for w in ["vuln", "exploit", "inject", "xss", "overflow"]):
                    severity = "medium"
                if any(w in lower for w in ["critical", "rce", "remote code"]):
                    severity = "high"

                yield {
                    "id": None,
                    "title": clean[2:80],
                    "severity": severity,
                    "vuln_type": None,
                    "url": target,
                    "parameter": None,
                    "evidence": clean[2:],
                    "description": None,
                    "tool": "nikto",
                    "template_id": None,
                    "status": "new",
                    "notes": None,
                }
