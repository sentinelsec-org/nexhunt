import re
import httpx
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


_SUFFIXES = (
    '', '-backup', '-backups', '-dev', '-staging', '-prod', '-production',
    '-assets', '-static', '-media', '-uploads', '-files', '-data', '-db',
    '-dump', '-logs', '-public', '-private', '-internal', '-api', '-cdn',
    '-images', '-releases', '-artifacts', '-config', '-secrets', '-tmp',
    '-test', '-archive', '-old', '-bak', '-web', '-app',
)


def _bucket_names(company: str) -> list[str]:
    name = re.sub(r'\.(com|net|org|io|co|app|dev|xyz|me|co\.uk)$', '', company.lower())
    name = re.sub(r'^www\.', '', name)
    name = re.sub(r'[^a-z0-9-]', '-', name).strip('-')
    short = name.replace('-', '')
    buckets: set[str] = set()
    for base in (name, short):
        for sfx in _SUFFIXES:
            n = f"{base}{sfx}".strip('-')
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
        import asyncio

        providers = options.get("providers", ["s3", "gcs", "azure", "do"])
        names = _bucket_names(target)

        def _url(provider: str, bucket: str) -> str | None:
            if provider == "s3":
                return f"https://{bucket}.s3.amazonaws.com/"
            if provider == "gcs":
                return f"https://storage.googleapis.com/{bucket}/"
            if provider == "azure":
                return f"https://{bucket}.blob.core.windows.net/{bucket}?restype=container&comp=list"
            if provider == "do":
                return f"https://{bucket}.nyc3.digitaloceanspaces.com/"
            return None

        def _list_cmd(provider: str, bucket: str, url: str) -> str:
            if provider == "s3":
                return f"aws s3 ls s3://{bucket} --no-sign-request"
            if provider == "gcs":
                return f"gsutil ls gs://{bucket}"
            return f"curl -ks '{url}'"

        tasks = [(p, b, _url(p, b)) for b in names for p in providers if _url(p, b)]
        yield {"_raw": True, "line": f"$ cloud-buckets {target} ({len(tasks)} checks, providers: {','.join(providers)})"}

        async def _probe(client, provider: str, bucket: str, url: str) -> list[dict]:
            try:
                resp = await client.get(url)
            except Exception:
                return []  # DNS NXDOMAIN = bucket doesn't exist
            code = resp.status_code
            if code in (404, 400, 410):
                return []
            out = [{"_raw": True, "line": f"  [{provider.upper()}] {bucket} -> {code}"}]
            if code == 200:
                sev, title = "high", f"[Cloud] Public {provider.upper()} bucket: {bucket}"
                desc = (f"Bucket '{bucket}' on {provider.upper()} is publicly readable — "
                        f"anyone can list and download its objects.")
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                listing = (f"\nObjects listed ({len(keys)}): " + ", ".join(keys[:8])
                           + (" ..." if len(keys) > 8 else "")) if keys else ""
            elif code == 403:
                sev, title = "info", f"[Cloud] {provider.upper()} bucket exists (private): {bucket}"
                desc = f"Bucket '{bucket}' exists but is private (403). Confirm ownership; try authenticated/region tricks."
                listing = ""
            else:
                return out
            out.append({
                "_raw": False, "id": None,
                "title": title, "severity": sev, "vuln_type": "cloud-misconfiguration",
                "url": url, "parameter": None,
                "evidence": (
                    f"Provider: {provider.upper()}\nBucket: {bucket}\nURL: {url}\nStatus: {code}"
                    f"{listing}\nList contents:\n  {_list_cmd(provider, bucket, url)}"
                ),
                "description": desc,
                "tool": "cloud_buckets", "template_id": f"cloud-{provider}-{code}", "status": "new",
            })
            return out

        concurrency = 20
        async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False) as client:
            for i in range(0, len(tasks), concurrency):
                batch = tasks[i:i + concurrency]
                results = await asyncio.gather(*[_probe(client, p, b, u) for p, b, u in batch])
                for chunk in results:
                    for item in chunk:
                        yield item
