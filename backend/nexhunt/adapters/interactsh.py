import json
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class InteractshAdapter(ToolAdapter):
    name = "interactsh"
    binary_name = "interactsh-client"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        server = options.get("server", "https://oast.pro")
        timeout = int(options.get("timeout", 300))

        cmd = [self.binary_name, "-server", server, "-json", "-v"]
        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        yield {"_raw": True, "line": "[interactsh] Starting OOB listener..."}

        async for line in self._run_subprocess(cmd, timeout=timeout, merge_stderr=True):
            # Host announcement: [INF] Listing on <host>
            if "[INF]" in line:
                for word in line.split():
                    word = word.strip("[].,")
                    if any(s in word for s in (".oast.", ".interactsh.", ".interact.sh")):
                        host = word
                        yield {"_raw": True, "line": f"[interactsh] Host ready: {host}"}
                        yield {
                            "_raw": False, "id": None,
                            "title": f"[OOB] Interactsh listener: {host}",
                            "severity": "info", "vuln_type": "oast",
                            "url": f"http://{host}", "parameter": None,
                            "evidence": (
                                f"OOB host: {host}\n\nPayload examples:\n"
                                f"SSRF:    http://{host}\n"
                                f"XSS:     <script src='http://{host}'></script>\n"
                                f"XXE:     <!ENTITY e SYSTEM 'http://{host}'>\n"
                                f"DNS:     $(nslookup {host})"
                            ),
                            "description": "OOB listener active. Use the host in SSRF/XSS/XXE/blind-SQLi payloads.",
                            "tool": "interactsh", "template_id": "interactsh-host", "status": "new",
                        }
                        break
                yield {"_raw": True, "line": line}
                continue

            if not line.strip():
                continue

            try:
                data = json.loads(line)
                proto = data.get("protocol", "unknown")
                from_addr = data.get("remote-address", "unknown")
                raw = str(data.get("raw-request", data.get("raw-data", "")))[:1000]

                yield {"_raw": True, "line": f"[interactsh] CALLBACK {proto.upper()} from {from_addr}"}
                yield {
                    "_raw": False, "id": None,
                    "title": f"[OOB] {proto.upper()} callback from {from_addr}",
                    "severity": "high", "vuln_type": "oast",
                    "url": target or "",  "parameter": None,
                    "evidence": f"Protocol: {proto}\nFrom: {from_addr}\nTime: {data.get('timestamp', '')}\nData:\n{raw}",
                    "description": f"OOB callback via {proto.upper()} from {from_addr} — confirms target made an outbound request.",
                    "tool": "interactsh", "template_id": f"interactsh-{proto}", "status": "new",
                }
            except json.JSONDecodeError:
                yield {"_raw": True, "line": line}
