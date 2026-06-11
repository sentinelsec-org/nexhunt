import re
import httpx
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


def _bucket_names(company: str) -> list[str]:
    name = re.sub(r'\.(com|net|org|io|co|app|dev|xyz|me|co\.uk)$', '', company.lower())
    name = re.sub(r'^www\.', '', name)
    name = re.sub(r'[^a-z0-9-]', '-', name).strip('-')
    short = name.replace('-', '')
    buckets: set[str] = set()
    for base in (name, short):
        for sfx in ('', '-backup', '-dev', '-staging', '-prod', '-assets', '-static',
                    '-media', '-uploads', '-files', '-data', '-logs', '-public',
                    '-private', '-internal', '-api', '-cdn', '-images', '-releases'):
            n = f"{base}{sfx}"
            if 3 <= len(n) <= 63:
                buckets.add(n)
    return sorted(buckets)


class CloudBucketsAdapter(ToolAdapter):
    name = "cloud_buckets"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        providers = options.get("providers", ["s3", "gcs", "azure"])
        names = _bucket_names(target)
        yield {"_raw": True, "line": f"$ cloud-buckets {target} ({len(names)} names, providers: {','.join(providers)})"}

        async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False) as client:
            for bucket in names:
                for provider in providers:
                    if provider == "s3":
                        url = f"https://{bucket}.s3.amazonaws.com/"
                    elif provider == "gcs":
                        url = f"https://storage.googleapis.com/{bucket}/"
                    elif provider == "azure":
                        url = f"https://{bucket}.blob.core.windows.net/"
                    else:
                        continue
                    try:
                        resp = await client.head(url)
                        code = resp.status_code
                        if code in (404, 400, 410):
                            continue
                        yield {"_raw": True, "line": f"  [{provider.upper()}] {bucket} -> {code}"}
                        if code == 200:
                            sev, title = "high", f"[Cloud] Public {provider.upper()} bucket: {bucket}"
                            desc = f"Bucket '{bucket}' on {provider.upper()} is publicly readable."
                        elif code == 403:
                            sev, title = "info", f"[Cloud] {provider.upper()} bucket exists (private): {bucket}"
                            desc = f"Bucket '{bucket}' exists but is private. Confirm ownership."
                        else:
                            continue
                        yield {
                            "_raw": False, "id": None,
                            "title": title, "severity": sev, "vuln_type": "cloud-misconfiguration",
                            "url": url, "parameter": None,
                            "evidence": f"Provider: {provider.upper()}\nBucket: {bucket}\nURL: {url}\nStatus: {code}",
                            "description": desc,
                            "tool": "cloud_buckets", "template_id": f"cloud-{provider}-{code}", "status": "new",
                        }
                    except Exception:
                        pass  # DNS NXDOMAIN = bucket doesn't exist
