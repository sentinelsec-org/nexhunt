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


# Real bucket references in HTML/JS/URLs -> (provider, bucket[, region]).
_REF_PATTERNS = [
    (re.compile(r'([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9.\-]*amazonaws\.com', re.I), 's3'),
    # path-style: only when the s3 host starts the authority (avoid catching the object key
    # of a virtual-hosted URL like bucket.s3.amazonaws.com/KEY)
    (re.compile(r'(?<![a-z0-9.\-])s3[.\-][a-z0-9.\-]*amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])', re.I), 's3'),
    (re.compile(r'([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com', re.I), 'gcs'),
    (re.compile(r'(?<![a-z0-9.\-])storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])', re.I), 'gcs'),
    (re.compile(r'([a-z0-9]{3,24})\.blob\.core\.windows\.net', re.I), 'azure'),
    (re.compile(r'([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.([a-z0-9\-]+)\.digitaloceanspaces\.com', re.I), 'do'),
]


def _buckets_from_text(text: str) -> set[tuple]:
    """Extract real (provider, bucket) bucket references from page/JS text."""
    found: set[tuple] = set()
    for pat, provider in _REF_PATTERNS:
        for m in pat.finditer(text):
            bucket = m.group(1).lower()
            if 3 <= len(bucket) <= 63:
                found.add((provider, bucket))
    return found


def bucket_test_url(provider: str, bucket: str) -> str | None:
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


async def probe_bucket(client, provider: str, bucket: str, source: str = "referenced") -> list[dict]:
    """GET a bucket and return [raw line, finding?] if it is public (200) or exists (403)."""
    url = bucket_test_url(provider, bucket)
    if not url:
        return []
    try:
        resp = await client.get(url)
    except Exception:
        return []  # DNS NXDOMAIN = bucket doesn't exist
    code = resp.status_code
    if code in (404, 400, 410):
        return []
    ref = source == "referenced"
    tag = " (referenced in app)" if ref else ""
    out = [{"_raw": True, "line": f"  [{provider.upper()}] {bucket} -> {code}{tag}"}]
    if code == 200:
        sev, title = "high", f"[Cloud] Public {provider.upper()} bucket: {bucket}"
        desc = (f"Bucket '{bucket}' on {provider.upper()} is publicly readable — "
                f"anyone can list and download its objects."
                + (" This bucket is referenced directly in the target's pages/JS." if ref else ""))
        keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
        listing = (f"\nObjects listed ({len(keys)}): " + ", ".join(keys[:8])
                   + (" ..." if len(keys) > 8 else "")) if keys else ""
    elif code == 403:
        sev = "low" if ref else "info"
        title = f"[Cloud] {provider.upper()} bucket exists (private): {bucket}"
        desc = (f"Bucket '{bucket}' exists but is private (403)."
                + (" Referenced in the app, so it is in use — worth probing object-level ACLs."
                   if ref else " Confirm ownership; try authenticated/region tricks."))
        listing = ""
    else:
        return out
    out.append({
        "_raw": False, "id": None,
        "title": title, "severity": sev, "vuln_type": "cloud-misconfiguration",
        "url": url, "parameter": None,
        "evidence": (
            f"Provider: {provider.upper()}\nBucket: {bucket}\nSource: {source}\nURL: {url}\nStatus: {code}"
            f"{listing}\nList contents:\n  {_list_cmd(provider, bucket, url)}"
        ),
        "description": desc,
        "tool": "cloud_buckets", "template_id": f"cloud-{provider}-{code}", "status": "new",
    })
    return out


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

        # source: "guessed" (name permutations) or "referenced" (found in the app's HTML/JS)
        tasks: list[tuple] = [(p, b, bucket_test_url(p, b), "guessed")
                              for b in names for p in providers if bucket_test_url(p, b)]

        # URLs already discovered by Recon/crawler (passed from the frontend).
        seed_urls = [u for u in (options.get("seed_urls") or []) if isinstance(u, str) and u]

        concurrency = 20
        async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False) as client:
            # Mine real bucket references from the target's homepage, its JS, and Recon URLs.
            mined: set[tuple] = set()
            text = ""
            from urllib.parse import urljoin

            # Recon seed URLs: the URL strings themselves may be bucket links, and any .js
            # among them is worth reading for more references.
            text += "\n".join(seed_urls)
            seed_js = [u for u in seed_urls if u.split("?")[0].lower().endswith(".js")][:30]

            if "." in target or target.startswith("http"):
                base_url = target if target.startswith("http") else f"https://{target}"
                try:
                    home = await client.get(base_url, timeout=8)
                    text += "\n" + home.text
                    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', home.text, re.I)[:20]
                    home_js = [urljoin(base_url, s) for s in srcs]
                except Exception as e:
                    home_js = []
                    yield {"_raw": True, "line": f"  Fetching {base_url} failed: {e}"}
            else:
                home_js = []

            js_urls = list(dict.fromkeys(home_js + seed_js))[:40]
            if js_urls:
                js_bodies = await asyncio.gather(
                    *[client.get(u, timeout=8) for u in js_urls], return_exceptions=True
                )
                for r in js_bodies:
                    if not isinstance(r, Exception):
                        text += "\n" + r.text

            mined = _buckets_from_text(text)
            if mined:
                yield {"_raw": True, "line": f"  Mined {len(mined)} bucket reference(s) from homepage + {len(js_urls)} JS + {len(seed_urls)} Recon URLs"}

            seen_urls = {u for _, _, u, _ in tasks}
            for provider, bucket in mined:
                if provider not in providers:
                    continue
                u = bucket_test_url(provider, bucket)
                if u and u not in seen_urls:
                    tasks.insert(0, (provider, bucket, u, "referenced"))  # probe referenced first
                    seen_urls.add(u)

            yield {"_raw": True, "line": f"$ cloud-buckets {target} ({len(tasks)} checks: {len(mined)} referenced + guessed, providers: {','.join(providers)})"}

            for i in range(0, len(tasks), concurrency):
                batch = tasks[i:i + concurrency]
                results = await asyncio.gather(*[probe_bucket(client, p, b, s) for p, b, u, s in batch])
                for chunk in results:
                    for item in chunk:
                        yield item
