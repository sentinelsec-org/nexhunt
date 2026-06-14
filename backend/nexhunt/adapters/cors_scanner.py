import httpx
from urllib.parse import urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

_TESTS = [
    ("arbitrary_reflection", lambda d: "https://evil.attacker.com"),
    ("null_origin",          lambda d: "null"),
    ("subdomain_bypass",     lambda d: f"https://evil.{d}"),
    ("prefix_bypass",        lambda d: f"https://{d}.evil.com"),
    ("suffix_bypass",        lambda d: f"https://{d}evil.com"),
    ("not_anchored_regex",   lambda d: f"https://evil{d}"),
    ("http_bypass",          lambda d: f"http://{d}"),
    ("trusted_subdomain",    lambda d: f"https://notareal.{d}"),
]


class CorsScannerAdapter(ToolAdapter):
    name = "cors"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        url = target if "://" in target else f"https://{target}"
        yield {"_raw": True, "line": f"$ cors-scan {url}"}

        parsed = urlparse(url)
        domain = parsed.hostname or parsed.path.strip("/")

        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            for test_name, origin_fn in _TESTS:
                origin = origin_fn(domain)
                try:
                    resp = await client.get(url, headers={"Origin": origin})
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
                    reflected = bool(
                        acao and acao not in ("*", "")
                        and (acao == origin or (origin == "null" and acao == "null"))
                    )
                    yield {"_raw": True, "line": f"  [{test_name}] acao={acao or '(none)'} acac={acac} reflected={reflected}"}

                    if not reflected:
                        # Wildcard ACAO is not origin-reflection but still notable.
                        if acao == "*" and test_name == "arbitrary_reflection":
                            yield {
                                "_raw": False, "id": None,
                                "title": f"[CORS] Wildcard ACAO (*) on {url}",
                                "severity": "low", "vuln_type": "cors", "url": url, "parameter": "Origin",
                                "evidence": (
                                    f"ACAO: *\nStatus: {resp.status_code}\n"
                                    f"Reproduce:\n  curl -ks -H 'Origin: https://evil.attacker.com' -I '{url}' | grep -i access-control"
                                ),
                                "description": "ACAO is '*'. Any origin can read non-credentialed responses. Low impact unless the endpoint returns sensitive data without auth.",
                                "tool": "cors", "template_id": "cors-wildcard", "status": "new",
                            }
                        continue

                    severity = "critical" if (reflected and acac and test_name == "arbitrary_reflection") \
                        else "high" if (reflected and acac) \
                        else "medium"

                    impact = (
                        " ACAC:true — an attacker page can read this origin's credentialed responses "
                        "(session data, tokens, PII) via a cross-origin fetch with credentials:'include'."
                        if acac else
                        " ACAC is not set, so credentialed reads are blocked; impact is limited to unauthenticated data."
                    )

                    yield {
                        "_raw": False, "id": None,
                        "title": f"[CORS] {test_name.replace('_', ' ').title()} on {url}",
                        "severity": severity, "vuln_type": "cors", "url": url,
                        "parameter": "Origin",
                        "evidence": (
                            f"Test: {test_name}\nOrigin sent: {origin}\n"
                            f"ACAO: {acao}\n"
                            f"ACAC: {resp.headers.get('access-control-allow-credentials', 'not set')}\n"
                            f"Status: {resp.status_code}\n"
                            f"Reproduce:\n  curl -ks -H 'Origin: {origin}' -I '{url}' | grep -i access-control"
                        ),
                        "description": (
                            f"CORS misconfiguration ({test_name}): origin '{origin}' is reflected in ACAO." + impact
                        ),
                        "tool": "cors", "template_id": f"cors-{test_name}", "status": "new",
                    }
                except Exception as e:
                    yield {"_raw": True, "line": f"  [{test_name}] error: {e}"}
