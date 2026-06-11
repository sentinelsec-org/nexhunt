import re
import shlex
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    name = "nmap"
    binary_name = "nmap"
    result_type = "port"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        ports = options.get("ports", "1-1000")
        extra_flags = options.get("flags", "")

        # Strip protocol prefix — nmap works with hostnames/IPs, not URLs
        clean_target = re.sub(r"^https?://", "", target).rstrip("/").split("/")[0]

        cmd = [
            self.binary_name,
            "-sV",    # version detection
            "-sC",    # default scripts
            "--open",
            "-p", ports,
            "-T4",
            clean_target,
        ]

        if extra_flags:
            try:
                cmd.extend(shlex.split(extra_flags))
            except ValueError:
                pass
        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}

        current_ip = clean_target
        current_port_data: dict | None = None
        script_lines: list[str] = []

        async for line in self._run_subprocess(cmd, timeout=600, merge_stderr=True):
            clean = line.replace("[STDERR] ", "").strip()

            # Always stream raw output
            yield {"_raw": True, "line": clean}

            # Parse "Nmap scan report for X"
            ip_match = re.match(r"Nmap scan report for (.+)", clean)
            if ip_match:
                # Flush pending port if any
                if current_port_data:
                    if script_lines:
                        current_port_data["scripts"] = "\n".join(script_lines)
                    yield current_port_data
                    current_port_data = None
                    script_lines = []
                current_ip = ip_match.group(1).strip()
                continue

            # Parse open port lines: "80/tcp   open  http    Apache httpd 2.4.41"
            port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", clean)
            if port_match:
                # Flush previous port
                if current_port_data:
                    if script_lines:
                        current_port_data["scripts"] = "\n".join(script_lines)
                    yield current_port_data
                    script_lines = []

                current_port_data = {
                    "_raw": False,
                    "ip": current_ip,
                    "port": int(port_match.group(1)),
                    "proto": port_match.group(2),
                    "service": port_match.group(3),
                    "version": port_match.group(4).strip() or None,
                    "scripts": "",
                }
                continue

            # Parse script output lines (indented with |)
            if current_port_data and (clean.startswith("|") or clean.startswith("| ")):
                script_lines.append(clean)
                continue

            # If we hit a blank line or a new section, flush port
            if current_port_data and clean == "":
                if script_lines:
                    current_port_data["scripts"] = "\n".join(script_lines)
                yield current_port_data
                current_port_data = None
                script_lines = []

        # Flush last port
        if current_port_data:
            if script_lines:
                current_port_data["scripts"] = "\n".join(script_lines)
            yield current_port_data
