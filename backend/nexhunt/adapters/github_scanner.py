import json
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class GithubScannerAdapter(ToolAdapter):
    name = "github_scanner"
    binary_name = "trufflehog"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        clean = target.strip()
        # Strip scheme from non-GitHub URLs (user may paste their bug bounty target URL)
        if clean.startswith(("http://", "https://")) and "github.com" not in clean:
            from urllib.parse import urlparse
            clean = urlparse(clean).netloc or clean

        if "github.com" in clean or options.get("mode") == "repo":
            cmd = [self.binary_name, "github", "--repo", clean, "--json", "--no-verification"]
        else:
            cmd = [self.binary_name, "github", "--org", clean, "--json", "--no-verification"]

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
