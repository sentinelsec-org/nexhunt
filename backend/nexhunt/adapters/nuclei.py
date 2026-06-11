import json
import os
import tempfile
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

# Default template path — detected at startup
_DEFAULT_TEMPLATES = os.path.expanduser("~/nuclei-templates")


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    binary_name = "nuclei"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        severity = options.get("severity", "info,low,medium,high,critical")
        tags = options.get("tags", "")
        templates = options.get("templates", "")
        rate_limit = str(options.get("rate_limit", 100))
        timeout = int(options.get("timeout", 600))
        request_timeout = int(options.get("request_timeout", 10))
        concurrency = str(options.get("concurrency", 25))
        exclude_tags = options.get("exclude_tags", "")
        scan_type = options.get("scan_type", "")
        proxy = options.get("proxy", "")
        headers = options.get("headers", "")  # comma-separated "Name: Value" pairs

        # Support bulk scanning: if options["targets"] is a list, write to temp file
        targets_list: list[str] = options.get("targets", [])
        targets_file: str | None = None

        cmd = [
            self.binary_name,
            "-jsonl",
            "-no-color",
            "-rl", rate_limit,
            "-c", concurrency,
            "-timeout", str(request_timeout),
            "-duc",    # disable update check
            "-ni",     # no interactsh (no OOB dependency)
        ]

        if targets_list:
            fd, targets_file = tempfile.mkstemp(suffix=".txt", prefix="nexhunt_nuclei_")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(targets_list))
            except Exception:
                pass
            cmd.extend(["-l", targets_file])
        else:
            cmd.extend(["-u", target])

        # Template selection: explicit > scan_type preset > default fast set
        if templates:
            if not os.path.isabs(templates):
                templates = os.path.join(_DEFAULT_TEMPLATES, templates)
            cmd.extend(["-t", templates])
        elif scan_type == "cves":
            cmd.extend(["-t", f"{_DEFAULT_TEMPLATES}/http/cves/"])
        elif scan_type == "misconfig":
            cmd.extend(["-t", f"{_DEFAULT_TEMPLATES}/http/misconfiguration/"])
        elif scan_type == "exposure":
            cmd.extend(["-t", f"{_DEFAULT_TEMPLATES}/http/exposures/"])
        elif scan_type == "takeover":
            cmd.extend(["-t", f"{_DEFAULT_TEMPLATES}/http/takeovers/"])
        elif scan_type == "default-logins":
            cmd.extend(["-t", f"{_DEFAULT_TEMPLATES}/http/default-logins/"])
        elif scan_type == "ssrf":
            cmd.extend(["-tags", "ssrf,redirect"])
        elif scan_type == "xss":
            cmd.extend(["-tags", "xss"])
        elif scan_type == "sqli":
            cmd.extend(["-tags", "sqli,sql-injection"])
        elif scan_type == "idor":
            cmd.extend(["-tags", "idor"])
        elif scan_type == "auth-bypass":
            cmd.extend(["-tags", "auth-bypass,authentication"])
        elif scan_type == "jwt":
            cmd.extend(["-tags", "jwt"])
        elif scan_type == "cors":
            # Template tags: cors,generic,misconfig,vuln (NOT "misconfiguration")
            cmd.extend(["-t", f"{_DEFAULT_TEMPLATES}/http/vulnerabilities/generic/cors-misconfig.yaml"])
        elif scan_type == "xxe":
            cmd.extend(["-tags", "xxe"])
        elif scan_type == "ssti":
            cmd.extend(["-tags", "ssti"])
        elif scan_type == "lfi":
            cmd.extend(["-tags", "lfi,path-traversal,directory-traversal"])
        elif scan_type == "rce":
            cmd.extend(["-tags", "rce"])
        elif scan_type == "oast":
            cmd.extend(["-tags", "oast,collaborator,interactsh"])
        elif scan_type == "api":
            cmd.extend(["-tags", "api,rest,graphql"])
        elif scan_type == "cloud":
            cmd.extend(["-tags", "aws,gcp,azure,cloud"])
        elif scan_type == "full-owasp":
            # OWASP Top 10 — comprehensive coverage
            cmd.extend([
                "-tags", "sqli,xss,ssrf,idor,auth-bypass,cors,lfi,rce,xxe,ssti,redirect,misconfig",
            ])
        elif scan_type == "owasp-a01":
            cmd.extend(["-tags", "idor,bac,access-control"])
        elif scan_type == "owasp-a02":
            cmd.extend(["-tags", "jwt,auth-bypass,authentication,session"])
        elif scan_type == "owasp-a03":
            cmd.extend(["-tags", "sqli,xss,ssti,xxe,ssrf,lfi,rce,injection"])
        elif scan_type == "owasp-a05":
            cmd.extend(["-tags", "cors,misconfig,misconfiguration,headers"])
        elif scan_type == "owasp-a06":
            cmd.extend(["-tags", "cves,vulns,outdated"])
        elif scan_type == "owasp-a07":
            cmd.extend(["-tags", "auth-bypass,authentication,default-login"])
        else:
            # Default: technologies + exposures + misconfiguration (fast, useful)
            cmd.extend([
                "-t", f"{_DEFAULT_TEMPLATES}/http/technologies/",
                "-t", f"{_DEFAULT_TEMPLATES}/http/exposures/",
                "-t", f"{_DEFAULT_TEMPLATES}/http/misconfiguration/",
            ])

        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        if exclude_tags:
            cmd.extend(["-etags", exclude_tags])
        if proxy:
            cmd.extend(["-proxy", proxy])

        # Session cookies take priority over per-tool cookie field
        session_cookies = options.get("session_cookies", "")
        if session_cookies:
            cmd.extend(["-H", f"Cookie: {session_cookies}"])

        # Custom headers: comma-separated or newline-separated "Header: Value"
        all_headers = headers or options.get("session_headers", "")
        if all_headers:
            raw_headers = [h.strip() for h in all_headers.replace("\n", ",").split(",") if h.strip() and ":" in h]
            for h in raw_headers:
                cmd.extend(["-H", h])

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        try:
            async for line in self._run_subprocess(cmd, timeout=timeout, merge_stderr=True):
                # Pass [INF]/[WRN]/[ERR] lines straight through as raw output
                if line.startswith("[INF]") or line.startswith("[WRN]") or line.startswith("[ERR]") \
                        or line.startswith("[STDERR] [INF]") or line.startswith("[STDERR] [WRN]") \
                        or line.startswith("[STDERR] [ERR]"):
                    clean = line.replace("[STDERR] ", "")
                    yield {"_raw": True, "line": clean}
                    continue

                # Try to parse as JSONL finding
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    classification = info.get("classification", {})

                    # Build rich evidence combining extracted results, request/response
                    evidence_parts = []
                    extracted = data.get("extracted-results", [])
                    if extracted:
                        evidence_parts.append("Extracted: " + ", ".join(str(e) for e in extracted[:5]))
                    if data.get("curl-command"):
                        evidence_parts.append("cURL:\n" + data["curl-command"])
                    if data.get("request"):
                        req = data["request"]
                        if len(req) > 1500:
                            req = req[:1500] + "\n[truncated]"
                        evidence_parts.append("Request:\n" + req)
                    if data.get("response"):
                        resp = data["response"]
                        if len(resp) > 1000:
                            resp = resp[:1000] + "\n[truncated]"
                        evidence_parts.append("Response:\n" + resp)

                    evidence = "\n\n".join(evidence_parts) if evidence_parts else None

                    # CVSS / CVE info in description
                    desc_parts = []
                    if info.get("description"):
                        desc_parts.append(info["description"])
                    if classification.get("cve-id"):
                        cves = classification["cve-id"]
                        if isinstance(cves, list):
                            cves = ", ".join(cves)
                        desc_parts.append(f"CVE: {cves}")
                    if classification.get("cvss-score"):
                        desc_parts.append(f"CVSS: {classification['cvss-score']}")
                    if classification.get("cwe-id"):
                        cwes = classification["cwe-id"]
                        if isinstance(cwes, list):
                            cwes = ", ".join(cwes)
                        desc_parts.append(f"CWE: {cwes}")
                    if info.get("reference"):
                        refs = info["reference"]
                        if isinstance(refs, list):
                            refs = refs[:3]
                            desc_parts.append("Refs: " + ", ".join(refs))

                    description = " | ".join(desc_parts) if desc_parts else ""

                    # Tags for context
                    tags_list = info.get("tags", [])
                    if isinstance(tags_list, list):
                        tags_str = ",".join(tags_list)
                    else:
                        tags_str = str(tags_list)

                    yield {
                        "_raw": False,
                        "id": None,
                        "title": f"[Nuclei] {info.get('name', 'Unknown')}",
                        "severity": info.get("severity", "info"),
                        "vuln_type": data.get("type", None),
                        "url": data.get("matched-at", target),
                        "parameter": data.get("matched-at", "").split("?")[-1] if "?" in data.get("matched-at", "") else None,
                        "evidence": evidence,
                        "description": description,
                        "tool": "nuclei",
                        "template_id": data.get("template-id"),
                        "status": "new",
                        "notes": tags_str if tags_str else None,
                    }
                except (json.JSONDecodeError, KeyError):
                    if line.strip():
                        yield {"_raw": True, "line": line}
        finally:
            # Clean up temp targets file
            if targets_file and os.path.exists(targets_file):
                try:
                    os.unlink(targets_file)
                except OSError:
                    pass
