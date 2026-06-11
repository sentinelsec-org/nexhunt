import json
import os
import tempfile
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class DalfoxAdapter(ToolAdapter):
    name = "dalfox"
    binary_name = "dalfox"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        """
        Supports two modes:
        - Single URL:  target = "https://example.com/page?q=test"
        - Bulk (pipe): options["targets"] = ["url1", "url2", ...]
        """
        targets_list = options.get("targets", [])

        base_flags = ["--no-color", "--silence"]

        # Blind XSS callback
        if options.get("blind"):
            base_flags.extend(["-b", options["blind"]])

        # Cookie
        if options.get("cookie"):
            base_flags.extend(["-C", options["cookie"]])

        # Custom header
        if options.get("header"):
            base_flags.extend(["-H", options["header"]])

        # Specific parameter to test
        if options.get("param"):
            base_flags.extend(["-p", options["param"]])

        # Custom payload
        if options.get("custom_payload"):
            base_flags.extend(["--custom-payload", options["custom_payload"]])

        # Worker threads
        workers = str(options.get("workers", 10))
        base_flags.extend(["--worker", workers])

        # Output format: json gives structured results
        base_flags.extend(["--format", "json"])

        base_flags = self._with_extra_args(base_flags, options)

        if targets_list:
            # Pipe mode — write all targets to temp file, use 'file' subcommand
            fd, tmpfile = tempfile.mkstemp(suffix=".txt", prefix="dalfox_")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(targets_list))
                cmd = [self.binary_name, "file", tmpfile] + base_flags
                async for result in self._parse_dalfox_output(cmd, targets_list[0] if targets_list else target):
                    yield result
            finally:
                if os.path.exists(tmpfile):
                    os.unlink(tmpfile)
        else:
            cmd = [self.binary_name, "url", target] + base_flags
            async for result in self._parse_dalfox_output(cmd, target):
                yield result

    async def _parse_dalfox_output(self, cmd: list, base_target: str) -> AsyncIterator[dict]:
        """Parse dalfox JSON output lines into finding dicts."""
        async for line in self._run_subprocess(cmd, timeout=900):
            line = line.strip()
            if not line:
                continue

            # Dalfox with --format json outputs one JSON object per finding
            try:
                data = json.loads(line)
                poc_type = data.get("type", "")
                if poc_type in ("V", "G", "R"):  # Verified / Good / Reflected
                    severity = "high" if poc_type == "V" else "medium"
                    yield {
                        "id": None,
                        "title": f"[Dalfox] XSS — {data.get('param', 'unknown param')} @ {data.get('url', base_target)}",
                        "severity": severity,
                        "vuln_type": "xss",
                        "url": data.get("url", base_target),
                        "parameter": data.get("param"),
                        "evidence": data.get("poc", data.get("payload", "")),
                        "description": f"Cross-Site Scripting via parameter '{data.get('param', '?')}'. Type: {poc_type}",
                        "tool": "dalfox",
                        "template_id": None,
                        "status": "new",
                        "notes": None,
                    }
            except (json.JSONDecodeError, ValueError):
                # Dalfox also emits progress lines — forward as raw output for terminal
                if "[POC]" in line or "[V]" in line or "[G]" in line or "XSS" in line.upper():
                    yield {
                        "id": None,
                        "title": f"[Dalfox] {line[:120]}",
                        "severity": "high",
                        "vuln_type": "xss",
                        "url": base_target,
                        "parameter": None,
                        "evidence": line,
                        "description": "XSS detected by dalfox",
                        "tool": "dalfox",
                        "template_id": None,
                        "status": "new",
                        "notes": None,
                    }
