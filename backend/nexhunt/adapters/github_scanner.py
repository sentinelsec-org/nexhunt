import re
import json
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


def _domain_to_org(value: str) -> str:
    """acme.com / https://www.acme-corp.io/x -> acme / acme-corp (GitHub org guess)."""
    from urllib.parse import urlparse
    v = value.strip()
    if v.startswith(("http://", "https://")):
        v = urlparse(v).netloc or v
    v = re.sub(r"^www\.", "", v)
    v = v.split("/")[0]
    if "." in v:                      # looks like a domain — take the first label
        v = v.split(".")[0]
    return v


class GithubScannerAdapter(ToolAdapter):
    name = "github_scanner"
    binary_name = "trufflehog"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        clean = target.strip()

        if "github.com" in clean or options.get("mode") == "repo":
            cmd = [self.binary_name, "github", "--repo", clean, "--json"]
        else:
            # Accept a plain org name OR a domain (acme.com -> org "acme")
            org = _domain_to_org(clean)
            if org != clean:
                yield {"_raw": True, "line": f"  Derived GitHub org '{org}' from '{clean}'"}
            cmd = [self.binary_name, "github", "--org", org, "--json"]

        # Verification ON (no --no-verification): trufflehog confirms each secret is
        # still live against its issuing API, which drives the verified/critical badge.
        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}

        async for line in self._run_subprocess(cmd, timeout=600, merge_stderr=True):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                detector = data.get("DetectorName", "Secret")
                verified = data.get("Verified", False)
                raw = data.get("Raw", "")
                gh = data.get("SourceMetadata", {}).get("Data", {}).get("Github", {})
                file_path = gh.get("file", "")
                repo = gh.get("repository", "")
                link = gh.get("link", "")
                masked = (raw[:6] + "*" * max(0, len(raw) - 6)) if raw else "***"
                severity = "critical" if verified else "high"

                yield {
                    "_raw": False, "id": None,
                    "title": f"[GitHub] {detector} {'(verified)' if verified else 'found'} in {repo or target}",
                    "severity": severity, "vuln_type": "secret-exposure",
                    "url": link or f"https://github.com/{target}",
                    "parameter": detector,
                    "evidence": f"Detector: {detector}\nVerified: {verified}\nSecret: {masked}\nFile: {file_path}\nRepo: {repo}\nLink: {link}",
                    "description": f"Secret type '{detector}' in '{repo}'. {'Verified active.' if verified else 'Verify manually.'}",
                    "tool": "github_scanner", "template_id": f"github-{detector.lower().replace(' ', '-')}", "status": "new",
                }
                yield {"_raw": True, "line": f"  [{detector}] {'VERIFIED' if verified else 'found'} in {file_path or repo}"}
            except json.JSONDecodeError:
                yield {"_raw": True, "line": line}
