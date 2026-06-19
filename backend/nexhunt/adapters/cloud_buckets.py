import re
import secrets
import httpx
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

_S3_STYLE = ("s3", "gcs", "do")  # share the same XML listing/ACL/policy API shape

_SENSITIVE_PATTERNS = [re.compile(p, re.I) for p in (
    r'\.env(\.|$)', r'\.sql(\.gz)?$', r'\.sqlite3?$', r'\.zip$', r'\.tar(\.gz)?$',
    r'\.7z$', r'\.rar$', r'\.bak$', r'backup', r'\.pem$', r'\.key$', r'id_rsa',
    r'credential', r'secret', r'password', r'\.pfx$', r'\.p12$', r'wp-config\.php',
    r'\.git[/_]', r'\.aws[/_]credentials', r'\.npmrc', r'dump\.sql', r'\.kdbx$',
    r'\.ovpn$', r'\.pgpass$', r'\.htpasswd$', r'config\.(json|ya?ml)$',
)]


def _classify_sensitive(names: list[str]) -> list[str]:
    return [n for n in names if any(p.search(n) for p in _SENSITIVE_PATTERNS)][:30]


_SUFFIXES = (
    '', '-backup', '-backups', '-dev', '-staging', '-prod', '-production',
    '-assets', '-static', '-media', '-uploads', '-files', '-data', '-db',
    '-dump', '-logs', '-public', '-private', '-internal', '-api', '-cdn',
    '-images', '-releases', '-artifacts', '-config', '-secrets', '-tmp',
    '-test', '-archive', '-old', '-bak', '-web', '-app',
)


def _bucket_names(company: str) -> list[str]:
    company = company.strip().lower()
    # If a full URL/path was passed, derive permutations from the hostname, not
    # the whole URL (otherwise we get garbage like "https---storage-googleapis...").
    if "://" in company or "/" in company:
        from urllib.parse import urlparse
        parsed = urlparse(company if "://" in company else "http://" + company)
        company = parsed.hostname or company
    # A provider host (the bucket is in the path/subdomain, mined separately) has
    # no meaningful company name to permute — skip guessing on it.
    if any(h in company for h in ("amazonaws.com", "googleapis.com", "blob.core.windows.net", "digitaloceanspaces.com")):
        return []
    name = re.sub(r'\.(com|net|org|io|co|app|dev|xyz|me|co\.uk)$', '', company)
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


async def _paginate_s3style(client, base_url: str, keys: list[str], truncated: bool) -> list[str]:
    """S3/GCS/DO share the same ListBucketResult XML — page via ?marker= (capped ~10k keys)."""
    marker = keys[-1] if keys else None
    pages = 0
    while truncated and marker and pages < 9:
        try:
            resp = await client.get(base_url, params={"marker": marker})
        except Exception:
            break
        if resp.status_code != 200:
            break
        page_keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
        if not page_keys:
            break
        keys.extend(page_keys)
        truncated = "<IsTruncated>true</IsTruncated>" in resp.text
        marker = page_keys[-1]
        pages += 1
    return keys


async def _paginate_azure(client, base_url: str, names: list[str], next_marker: str | None) -> list[str]:
    pages = 0
    while next_marker and pages < 9:
        try:
            resp = await client.get(base_url, params={"marker": next_marker})
        except Exception:
            break
        if resp.status_code != 200:
            break
        names.extend(re.findall(r"<Name>([^<]+)</Name>", resp.text))
        m = re.search(r"<NextMarker>([^<]*)</NextMarker>", resp.text)
        next_marker = m.group(1) if m and m.group(1) else None
        pages += 1
    return names


async def probe_acl_policy(client, provider: str, bucket: str, base_url: str) -> list[dict]:
    """Check if the ACL/policy document itself is publicly readable, independent of listing access."""
    if provider not in _S3_STYLE:
        return []
    out = []
    for suffix in ("acl", "policy"):
        try:
            resp = await client.get(base_url, params={suffix: ""})
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        body = resp.text
        if suffix == "acl":
            grants = re.findall(
                r'<Grantee>.*?(AllUsers|AllAuthenticatedUsers).*?</Grantee>\s*<Permission>([A-Z_]+)</Permission>',
                body, re.S,
            )
            if not grants:
                continue
            perms = sorted({g[1] for g in grants})
            groups = sorted({g[0] for g in grants})
            sev = "critical" if any(p in ("WRITE", "WRITE_ACP", "FULL_CONTROL") for p in perms) else "high"
            out.append({
                "_raw": False, "id": None,
                "title": f"[Cloud] {provider.upper()} bucket ACL grants public access: {bucket}",
                "severity": sev, "vuln_type": "cloud-misconfiguration",
                "url": f"{base_url}?acl", "parameter": None,
                "evidence": f"Provider: {provider.upper()}\nBucket: {bucket}\nPublic grants: {', '.join(perms)} to {'/'.join(groups)}\nGET {base_url}?acl",
                "description": f"The bucket ACL is itself publicly readable and grants {', '.join(perms)} to {'/'.join(groups)} — independent of whether plain listing is blocked.",
                "tool": "cloud_buckets", "template_id": f"cloud-{provider}-acl", "status": "new",
            })
        else:
            if "Principal" not in body:
                continue
            if not re.search(r'"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})', body):
                continue
            actions = re.findall(r'"Action"\s*:\s*"?([^",\]]+)', body)
            sev = "critical" if any("put" in a.lower() or a.strip() == "s3:*" for a in actions) else "high"
            out.append({
                "_raw": False, "id": None,
                "title": f"[Cloud] {provider.upper()} bucket policy allows public access: {bucket}",
                "severity": sev, "vuln_type": "cloud-misconfiguration",
                "url": f"{base_url}?policy", "parameter": None,
                "evidence": f"Provider: {provider.upper()}\nBucket: {bucket}\nActions: {', '.join(actions) or '?'}\nGET {base_url}?policy\n\n{body[:1500]}",
                "description": "The bucket policy is publicly readable and grants a wildcard Principal access" + (f" to: {', '.join(actions)}." if actions else "."),
                "tool": "cloud_buckets", "template_id": f"cloud-{provider}-policy", "status": "new",
            })
    return out


async def probe_write(client, provider: str, bucket: str, base_url: str) -> list[dict]:
    """Attempt to PUT (and immediately delete) a harmless marker object — proves write takeover, not just a read finding."""
    test_key = f"nexhunt-write-test-{secrets.token_hex(6)}.txt"
    content = (
        b"NexHunt authorized security test artifact.\n"
        b"If you found this file, a security tester verified this bucket "
        b"accepts unauthenticated writes. Safe to delete.\n"
    )
    if provider == "azure":
        put_url = f"{base_url.split('?')[0]}/{test_key}"
        headers = {"x-ms-blob-type": "BlockBlob", "x-ms-version": "2021-08-06"}
    else:
        put_url = f"{base_url}{test_key}"
        headers = {}
    try:
        resp = await client.put(put_url, content=content, headers=headers)
    except Exception:
        return []
    if resp.status_code not in (200, 201, 204):
        return []
    cleaned = False
    try:
        del_resp = await client.delete(put_url, headers=headers)
        cleaned = del_resp.status_code in (200, 202, 204)
    except Exception:
        pass
    return [{
        "_raw": False, "id": None,
        "title": f"[Cloud] {provider.upper()} bucket allows unauthenticated WRITE: {bucket}",
        "severity": "critical", "vuln_type": "cloud-misconfiguration",
        "url": put_url, "parameter": None,
        "evidence": (
            f"Provider: {provider.upper()}\nBucket: {bucket}\nPUT {put_url} -> {resp.status_code}\n"
            + ("Test object deleted after verification." if cleaned
               else f"Test object COULD NOT be auto-deleted — remove manually: {put_url}")
        ),
        "description": (
            "Anyone can write/overwrite objects in this bucket without authentication — full takeover risk "
            "(defacement, malware hosting, supply-chain injection into anything the site serves from it)."
        ),
        "tool": "cloud_buckets", "template_id": f"cloud-{provider}-write", "status": "new",
    }]


async def probe_bucket(client, provider: str, bucket: str, source: str = "referenced", test_write: bool = False) -> list[dict]:
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
        if provider == "azure":
            names = re.findall(r"<Name>([^<]+)</Name>", resp.text)
            m = re.search(r"<NextMarker>([^<]*)</NextMarker>", resp.text)
            next_marker = m.group(1) if m and m.group(1) else None
            if next_marker:
                names = await _paginate_azure(client, url, names, next_marker)
        else:
            names = re.findall(r"<Key>([^<]+)</Key>", resp.text)
            truncated = "<IsTruncated>true</IsTruncated>" in resp.text
            if truncated and names:
                names = await _paginate_s3style(client, url, names, truncated)

        sensitive = _classify_sensitive(names)
        sev, title = "high", f"[Cloud] Public {provider.upper()} bucket: {bucket}"
        desc = (f"Bucket '{bucket}' on {provider.upper()} is publicly readable — "
                f"anyone can list and download its objects ({len(names)} found)."
                + (" This bucket is referenced directly in the target's pages/JS." if ref else ""))
        listing = (f"\nObjects listed ({len(names)}): " + ", ".join(names[:8])
                   + (" ..." if len(names) > 8 else "")) if names else ""
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
        if sensitive:
            out.append({
                "_raw": False, "id": None,
                "title": f"[Cloud] Sensitive files exposed in public bucket: {bucket}",
                "severity": "critical", "vuln_type": "cloud-misconfiguration",
                "url": url, "parameter": None,
                "evidence": f"Provider: {provider.upper()}\nBucket: {bucket}\nSensitive object(s): " + ", ".join(sensitive),
                "description": (
                    f"{len(sensitive)} object name(s) in this public bucket match known-sensitive patterns "
                    "(env files, SQL/DB dumps, archives, private keys, credentials...). Pull and review them."
                ),
                "tool": "cloud_buckets", "template_id": f"cloud-{provider}-sensitive", "status": "new",
            })
    elif code == 403:
        sev = "low" if ref else "info"
        title = f"[Cloud] {provider.upper()} bucket exists (private): {bucket}"
        desc = (f"Bucket '{bucket}' exists but is private (403)."
                + (" Referenced in the app, so it is in use — worth probing object-level ACLs."
                   if ref else " Confirm ownership; try authenticated/region tricks."))
        out.append({
            "_raw": False, "id": None,
            "title": title, "severity": sev, "vuln_type": "cloud-misconfiguration",
            "url": url, "parameter": None,
            "evidence": f"Provider: {provider.upper()}\nBucket: {bucket}\nSource: {source}\nURL: {url}\nStatus: {code}",
            "description": desc,
            "tool": "cloud_buckets", "template_id": f"cloud-{provider}-{code}", "status": "new",
        })

    # ACL/policy can be exposed independently of whether plain listing succeeded.
    out.extend(await probe_acl_policy(client, provider, bucket, url))

    # Write-test is an active probe against the target's real infrastructure —
    # only run it on buckets actually referenced by the target, never on guessed
    # names that might belong to an unrelated third party.
    if test_write and ref:
        out.extend(await probe_write(client, provider, bucket, url))

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
        test_write = bool(options.get("test_write"))
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

            # The target itself may already be a bucket URL (e.g. someone pastes
            # storage.googleapis.com/cdn-ehub) — mine it directly.
            text += target + "\n"

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
            if test_write:
                yield {"_raw": True, "line": "  [!] Write-test enabled: will attempt to PUT+DELETE a small marker object on referenced buckets"}

            for i in range(0, len(tasks), concurrency):
                batch = tasks[i:i + concurrency]
                results = await asyncio.gather(*[probe_bucket(client, p, b, s, test_write) for p, b, u, s in batch])
                for chunk in results:
                    for item in chunk:
                        yield item
